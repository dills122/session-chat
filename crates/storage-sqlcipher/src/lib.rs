#![forbid(unsafe_code)]

//! SQLCipher-backed MLS persistence candidate for Session Chat.

use std::{
    ops::{Deref, DerefMut},
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};

use mls_rs_core::{
    crypto::HpkeSecretKey,
    error::IntoAnyError,
    group::{EpochRecord, GroupState, GroupStateStorage},
    key_package::{KeyPackageData, KeyPackageStorage},
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const MAX_GROUP_ID_BYTES: usize = 255;
const MAX_MLS_STATE_BYTES: usize = 2 * 1024 * 1024;
const MAX_EPOCH_WRITES: usize = 64;
const MAX_KEY_PACKAGE_BYTES: usize = 16 * 1024;
const MAX_SECRET_KEY_BYTES: usize = 4 * 1024;

// SQLCipher's bundled OpenSSL provider owns process-global activation state.
// Serialize every native call, including connection setup and teardown, so
// separate vault connections cannot race that lifecycle on any platform.
static SQLCIPHER_PROVIDER: Mutex<()> = Mutex::new(());

/// Exact raw database key released only while the client vault is unsealed.
///
/// This type intentionally implements neither `Clone`, `Debug`, nor `Display`.
pub struct VaultKey([u8; 32]);

impl VaultKey {
    /// Accepts one nonzero externally protected 256-bit database key.
    pub fn new(key: [u8; 32]) -> Result<Self, StoreError> {
        if key.iter().all(|byte| *byte == 0) {
            return Err(StoreError::Rejected);
        }
        Ok(Self(key))
    }

    fn raw_key_pragma(&self) -> Zeroizing<String> {
        let mut pragma = Zeroizing::new(String::with_capacity(88));
        pragma.push_str("PRAGMA key = \"x'");
        for byte in self.0 {
            use std::fmt::Write as _;
            write!(&mut pragma, "{byte:02X}").expect("writing to a String cannot fail");
        }
        pragma.push_str("'\";");
        pragma
    }
}

impl Drop for VaultKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Coarse failure from the encrypted storage boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StoreError {
    /// Input, keying, configuration, integrity, or persistence was rejected.
    #[error("encrypted storage operation rejected")]
    Rejected,
    /// A retained identifier was reused for different state.
    #[error("encrypted storage conflict")]
    Conflict,
    /// A deterministic pre-commit fault was injected.
    #[error("injected encrypted storage failure")]
    InjectedFailure,
    /// Commit may have succeeded and must be recovered by transaction ID.
    #[error("encrypted storage outcome unknown")]
    OutcomeUnknown,
}

impl From<rusqlite::Error> for StoreError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Rejected
    }
}

impl IntoAnyError for StoreError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

/// Deterministic persistence fault used only by retained conformance tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistenceFault {
    /// No injected fault.
    None,
    /// Fail after every write but before SQL commit.
    BeforeCommit,
    /// Commit succeeds but the caller receives an ambiguous result.
    AfterCommit,
}

/// Secret-free invitation lifecycle view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvitationState {
    /// Exact invitation generation is reserved.
    Reserved,
    /// Reservation was atomically consumed with membership state.
    Consumed,
}

/// Secret-free recovery view for one inviter transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InviterRecovery {
    /// Committed MLS epoch after the Add.
    pub epoch_after: u64,
    /// Whether the encrypted Welcome awaits delivery.
    pub welcome_pending: bool,
}

/// Secret-free recovery view for one joining-client transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JoinerRecovery {
    /// Joined MLS group whose state committed with KeyPackage consumption.
    pub group_id: [u8; 32],
}

/// Exact owner-local joiner transaction expected around the next MLS write.
///
/// This value binds the group snapshot to deletion of one exact one-time
/// KeyPackage. It intentionally implements neither `Clone`, `Debug`, nor
/// `Display`.
pub struct JoinerTransaction {
    transaction_id: [u8; 16],
    group_id: [u8; 32],
    key_package_reference: [u8; 32],
}

impl JoinerTransaction {
    /// Accepts nonzero fixed identifiers for one joining-client transaction.
    pub fn new(
        transaction_id: [u8; 16],
        group_id: [u8; 32],
        key_package_reference: [u8; 32],
    ) -> Result<Self, StoreError> {
        if all_zero(&transaction_id) || all_zero(&group_id) || all_zero(&key_package_reference) {
            return Err(StoreError::Rejected);
        }
        Ok(Self {
            transaction_id,
            group_id,
            key_package_reference,
        })
    }
}

/// Complete inviter-owned application metadata staged for one MLS write.
///
/// The MLS snapshot itself comes only from the configured `mls-rs` provider
/// call. This type intentionally implements neither `Clone`, `Debug`, nor
/// `Display` and zeroizes secret-bearing buffers on drop.
pub struct InviterJoinTransaction {
    transaction_id: [u8; 16],
    invitation_id: [u8; 16],
    invitation_generation: [u8; 64],
    join_request_id: [u8; 16],
    request_fingerprint: [u8; 32],
    group_id: [u8; 32],
    epoch_before: u64,
    epoch_after: u64,
    approval_record: Vec<u8>,
    welcome: Vec<u8>,
    endpoint: Vec<u8>,
    outbox_expires_at: u64,
}

impl InviterJoinTransaction {
    /// Validates every bound before the value can be staged.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transaction_id: [u8; 16],
        invitation_id: [u8; 16],
        invitation_generation: [u8; 64],
        join_request_id: [u8; 16],
        request_fingerprint: [u8; 32],
        group_id: [u8; 32],
        epoch_before: u64,
        epoch_after: u64,
        approval_record: Vec<u8>,
        welcome: Vec<u8>,
        endpoint: Vec<u8>,
        outbox_expires_at: u64,
    ) -> Result<Self, StoreError> {
        let value = Self {
            transaction_id,
            invitation_id,
            invitation_generation,
            join_request_id,
            request_fingerprint,
            group_id,
            epoch_before,
            epoch_after,
            approval_record,
            welcome,
            endpoint,
            outbox_expires_at,
        };
        validate_inviter(&value, 0)?;
        Ok(value)
    }
}

impl Drop for InviterJoinTransaction {
    fn drop(&mut self) {
        self.invitation_generation.zeroize();
        self.join_request_id.zeroize();
        self.request_fingerprint.zeroize();
        self.approval_record.zeroize();
        self.welcome.zeroize();
        self.endpoint.zeroize();
    }
}

struct StagedInviter {
    transaction: InviterJoinTransaction,
    now_unix_seconds: u64,
    fault: PersistenceFault,
}

struct StagedJoiner {
    transaction: JoinerTransaction,
    fault: PersistenceFault,
}

struct PendingJoiner {
    transaction: JoinerTransaction,
    fault: PersistenceFault,
    already_committed: bool,
}

struct ProcessBoundConnection(Option<Connection>);

impl ProcessBoundConnection {
    fn new(connection: Connection) -> Self {
        Self(Some(connection))
    }
}

impl Deref for ProcessBoundConnection {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        self.0
            .as_ref()
            .expect("the SQLCipher connection exists until drop")
    }
}

impl DerefMut for ProcessBoundConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
            .as_mut()
            .expect("the SQLCipher connection exists until drop")
    }
}

impl Drop for ProcessBoundConnection {
    fn drop(&mut self) {
        let _provider = SQLCIPHER_PROVIDER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        drop(self.0.take());
    }
}

struct StorageInner {
    connection: ProcessBoundConnection,
    staged_inviter: Option<StagedInviter>,
    staged_joiner: Option<StagedJoiner>,
    pending_joiner: Option<PendingJoiner>,
}

struct StorageGuard<'a> {
    // Drop the connection-specific guard before releasing the provider guard.
    inner: MutexGuard<'a, StorageInner>,
    _provider: MutexGuard<'static, ()>,
}

impl Deref for StorageGuard<'_> {
    type Target = StorageInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for StorageGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// Cloneable SQLCipher provider handle shared by the MLS and application layers.
///
/// One keyed connection is serialized behind a mutex. Closing the last handle
/// closes the keyed database. This adapter is a bounded durability candidate;
/// it does not establish platform key protection or rollback resistance.
#[derive(Clone)]
pub struct SqlCipherStorage {
    inner: Arc<Mutex<StorageInner>>,
}

impl SqlCipherStorage {
    /// Creates a new encrypted database and schema.
    pub fn create(path: &Path, key: VaultKey) -> Result<Self, StoreError> {
        Self::open_internal(path, key, true)
    }

    /// Opens an existing encrypted database without attempting migration.
    pub fn open(path: &Path, key: VaultKey) -> Result<Self, StoreError> {
        Self::open_internal(path, key, false)
    }

    /// Persists one exact inviter-owned reservation before membership begins.
    pub fn seed_reservation(
        &self,
        invitation_id: [u8; 16],
        invitation_generation: [u8; 64],
        join_request_id: [u8; 16],
        expires_at: u64,
        now_unix_seconds: u64,
    ) -> Result<(), StoreError> {
        if all_zero(&invitation_id)
            || all_zero(&invitation_generation)
            || all_zero(&join_request_id)
            || expires_at <= now_unix_seconds
            || expires_at > i64::MAX as u64
        {
            return Err(StoreError::Rejected);
        }
        self.lock()?.connection.execute(
            "INSERT INTO reservations(
                 invitation_id, generation, join_request_id, expires_at, state
             ) VALUES (?1, ?2, ?3, ?4, 1)",
            params![
                invitation_id,
                invitation_generation,
                join_request_id,
                expires_at as i64
            ],
        )?;
        Ok(())
    }

    /// Stages exact application metadata for the next real MLS group write.
    pub fn stage_inviter(
        &self,
        transaction: InviterJoinTransaction,
        now_unix_seconds: u64,
        fault: PersistenceFault,
    ) -> Result<(), StoreError> {
        validate_inviter(&transaction, now_unix_seconds)?;
        let mut inner = self.lock()?;
        if inner.staged_inviter.is_some()
            || inner.staged_joiner.is_some()
            || inner.pending_joiner.is_some()
        {
            return Err(StoreError::Conflict);
        }
        inner.staged_inviter = Some(StagedInviter {
            transaction,
            now_unix_seconds,
            fault,
        });
        Ok(())
    }

    /// Stages one exact joining-client transaction for the next MLS write.
    pub fn stage_joiner(
        &self,
        transaction: JoinerTransaction,
        fault: PersistenceFault,
    ) -> Result<(), StoreError> {
        let mut inner = self.lock()?;
        if inner.staged_inviter.is_some()
            || inner.staged_joiner.is_some()
            || inner.pending_joiner.is_some()
        {
            return Err(StoreError::Conflict);
        }
        inner.staged_joiner = Some(StagedJoiner { transaction, fault });
        Ok(())
    }

    /// Returns the retained secret-free invitation state.
    pub fn invitation_state(
        &self,
        invitation_id: &[u8; 16],
    ) -> Result<Option<InvitationState>, StoreError> {
        self.lock()?
            .connection
            .query_row(
                "SELECT state FROM reservations WHERE invitation_id = ?1",
                params![invitation_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(|state| match state {
                1 => Ok(InvitationState::Reserved),
                2 => Ok(InvitationState::Consumed),
                _ => Err(StoreError::Rejected),
            })
            .transpose()
    }

    /// Recovers one inviter transaction without releasing secret-bearing rows.
    pub fn recover_inviter(
        &self,
        transaction_id: &[u8; 16],
    ) -> Result<Option<InviterRecovery>, StoreError> {
        self.lock()?
            .connection
            .query_row(
                "SELECT epoch_after, outbox_state
                 FROM inviter_joins WHERE transaction_id = ?1",
                params![transaction_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
            .map(|(epoch_after, outbox_state)| {
                if epoch_after < 0 || outbox_state != 1 {
                    return Err(StoreError::Rejected);
                }
                Ok(InviterRecovery {
                    epoch_after: epoch_after as u64,
                    welcome_pending: true,
                })
            })
            .transpose()
    }

    /// Recovers a committed joiner transaction without returning key material.
    pub fn recover_joiner(
        &self,
        transaction_id: &[u8; 16],
    ) -> Result<Option<JoinerRecovery>, StoreError> {
        let inner = self.lock()?;
        if inner.pending_joiner.is_some() {
            return Err(StoreError::Rejected);
        }
        inner
            .connection
            .query_row(
                "SELECT group_id FROM joiner_commits WHERE transaction_id = ?1",
                params![transaction_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|group_id| {
                let group_id = group_id.try_into().map_err(|_| StoreError::Rejected)?;
                Ok(JoinerRecovery { group_id })
            })
            .transpose()
    }

    /// Reports whether one exact one-time KeyPackage remains retained.
    pub fn key_package_exists(&self, reference: &[u8; 32]) -> Result<bool, StoreError> {
        Ok(self
            .lock()?
            .connection
            .query_row(
                "SELECT 1 FROM key_packages WHERE key_package_ref = ?1",
                params![reference],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some())
    }

    /// Returns the active SQLCipher version, rejecting a plaintext SQLite build.
    pub fn cipher_version(&self) -> Result<String, StoreError> {
        self.lock()?
            .connection
            .query_row("PRAGMA cipher_version;", [], |row| row.get(0))
            .map_err(Into::into)
    }

    /// Runs SQLCipher's per-page HMAC integrity verification.
    pub fn integrity_check(&self) -> Result<bool, StoreError> {
        let inner = self.lock()?;
        let mut statement = inner.connection.prepare("PRAGMA cipher_integrity_check;")?;
        let mut rows = statement.query([])?;
        Ok(rows.next()?.is_none())
    }

    fn lock(&self) -> Result<StorageGuard<'_>, StoreError> {
        let provider = SQLCIPHER_PROVIDER
            .lock()
            .map_err(|_| StoreError::Rejected)?;
        let inner = self.inner.lock().map_err(|_| StoreError::Rejected)?;
        Ok(StorageGuard {
            inner,
            _provider: provider,
        })
    }

    fn open_internal(path: &Path, key: VaultKey, create: bool) -> Result<Self, StoreError> {
        let _provider = SQLCIPHER_PROVIDER
            .lock()
            .map_err(|_| StoreError::Rejected)?;
        let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        if create {
            flags |= OpenFlags::SQLITE_OPEN_CREATE;
        }
        let connection = Connection::open_with_flags(path, flags)?;

        // Source: https://www.zetetic.net/sqlcipher/sqlcipher-api/#pragma-key
        connection.execute_batch(&key.raw_key_pragma())?;
        connection.execute_batch("PRAGMA cipher_memory_security = ON;")?;
        let _: i64 =
            connection.query_row("SELECT count(*) FROM sqlite_master;", [], |row| row.get(0))?;
        let cipher_version: String =
            connection.query_row("PRAGMA cipher_version;", [], |row| row.get(0))?;
        if cipher_version.is_empty() {
            return Err(StoreError::Rejected);
        }
        connection.execute_batch(
            "PRAGMA journal_mode = DELETE;
             PRAGMA synchronous = FULL;
             PRAGMA temp_store = MEMORY;
             PRAGMA secure_delete = ON;
             PRAGMA trusted_schema = OFF;
             PRAGMA foreign_keys = ON;",
        )?;
        if create {
            create_schema(&connection)?;
        } else {
            let version: i64 =
                connection.query_row("SELECT schema_version FROM storage_metadata", [], |row| {
                    row.get(0)
                })?;
            if version != 1 {
                return Err(StoreError::Rejected);
            }
        }

        Ok(Self {
            inner: Arc::new(Mutex::new(StorageInner {
                connection: ProcessBoundConnection::new(connection),
                staged_inviter: None,
                staged_joiner: None,
                pending_joiner: None,
            })),
        })
    }
}

impl GroupStateStorage for SqlCipherStorage {
    type Error = StoreError;

    fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        self.lock()?
            .connection
            .query_row(
                "SELECT state FROM mls_groups WHERE group_id = ?1",
                params![group_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map(|value| value.map(Zeroizing::new))
            .map_err(Into::into)
    }

    fn epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        if epoch_id > i64::MAX as u64 {
            return Err(StoreError::Rejected);
        }
        self.lock()?
            .connection
            .query_row(
                "SELECT data FROM mls_epochs WHERE group_id = ?1 AND epoch_id = ?2",
                params![group_id, epoch_id as i64],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map(|value| value.map(Zeroizing::new))
            .map_err(Into::into)
    }

    fn write(
        &mut self,
        state: GroupState,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        validate_mls_write(&state, &epoch_inserts, &epoch_updates)?;
        let mut inner = self.lock()?;
        if let Some(staged) = inner.staged_inviter.take() {
            return commit_inviter(
                &mut inner.connection,
                &staged,
                &state,
                &epoch_inserts,
                &epoch_updates,
            );
        }
        let staged = inner.staged_joiner.take().ok_or(StoreError::Rejected)?;
        begin_joiner(&mut inner, staged, &state, &epoch_inserts, &epoch_updates)
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        let value = self.lock()?.connection.query_row(
            "SELECT max(epoch_id) FROM mls_epochs WHERE group_id = ?1",
            params![group_id],
            |row| row.get::<_, Option<i64>>(0),
        )?;
        value
            .map(|epoch| u64::try_from(epoch).map_err(|_| StoreError::Rejected))
            .transpose()
    }
}

impl KeyPackageStorage for SqlCipherStorage {
    type Error = StoreError;

    fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        if id.len() != 32 {
            return Err(StoreError::Rejected);
        }
        let mut inner = self.lock()?;
        let pending = inner.pending_joiner.take().ok_or(StoreError::Rejected)?;
        if id != pending.transaction.key_package_reference {
            rollback(&inner.connection);
            return Err(StoreError::Rejected);
        }
        if pending.already_committed {
            return if key_package_exists_on(&inner.connection, id)? {
                Err(StoreError::Conflict)
            } else {
                Ok(())
            };
        }
        let changed = match inner.connection.execute(
            "DELETE FROM key_packages WHERE key_package_ref = ?1",
            params![id],
        ) {
            Ok(changed) => changed,
            Err(_) => {
                rollback(&inner.connection);
                return Err(StoreError::Rejected);
            }
        };
        if changed != 1 || pending.fault == PersistenceFault::BeforeCommit {
            rollback(&inner.connection);
            return if pending.fault == PersistenceFault::BeforeCommit {
                Err(StoreError::InjectedFailure)
            } else {
                Err(StoreError::Rejected)
            };
        }
        if inner.connection.execute_batch("COMMIT;").is_err() {
            rollback(&inner.connection);
            return Err(StoreError::Rejected);
        }
        if pending.fault == PersistenceFault::AfterCommit {
            Err(StoreError::OutcomeUnknown)
        } else {
            Ok(())
        }
    }

    fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<(), Self::Error> {
        if id.len() != 32
            || pkg.key_package_bytes.is_empty()
            || pkg.key_package_bytes.len() > MAX_KEY_PACKAGE_BYTES
            || pkg.init_key.is_empty()
            || pkg.init_key.len() > MAX_SECRET_KEY_BYTES
            || pkg.leaf_node_key.is_empty()
            || pkg.leaf_node_key.len() > MAX_SECRET_KEY_BYTES
            || pkg.expiration == 0
            || pkg.expiration > i64::MAX as u64
        {
            return Err(StoreError::Rejected);
        }
        self.lock()?.connection.execute(
            "INSERT INTO key_packages(
                 key_package_ref, key_package, init_key, leaf_key, expires_at
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                id,
                pkg.key_package_bytes,
                pkg.init_key.as_ref(),
                pkg.leaf_node_key.as_ref(),
                pkg.expiration as i64
            ],
        )?;
        Ok(())
    }

    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
        if id.len() != 32 {
            return Err(StoreError::Rejected);
        }
        self.lock()?
            .connection
            .query_row(
                "SELECT key_package, init_key, leaf_key, expires_at
                 FROM key_packages WHERE key_package_ref = ?1",
                params![id],
                |row| {
                    let expiration = row.get::<_, i64>(3)?;
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        expiration,
                    ))
                },
            )
            .optional()?
            .map(|(key_package, init_key, leaf_key, expiration)| {
                if key_package.is_empty()
                    || key_package.len() > MAX_KEY_PACKAGE_BYTES
                    || init_key.is_empty()
                    || init_key.len() > MAX_SECRET_KEY_BYTES
                    || leaf_key.is_empty()
                    || leaf_key.len() > MAX_SECRET_KEY_BYTES
                    || expiration <= 0
                {
                    return Err(StoreError::Rejected);
                }
                Ok(KeyPackageData::new(
                    key_package,
                    HpkeSecretKey::from(init_key),
                    HpkeSecretKey::from(leaf_key),
                    expiration as u64,
                ))
            })
            .transpose()
    }
}

fn create_schema(connection: &Connection) -> Result<(), StoreError> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;
         CREATE TABLE storage_metadata (
             schema_version INTEGER NOT NULL CHECK(schema_version = 1)
         ) STRICT;
         INSERT INTO storage_metadata(schema_version) VALUES (1);

         CREATE TABLE reservations (
             invitation_id BLOB PRIMARY KEY CHECK(length(invitation_id) = 16),
             generation BLOB NOT NULL CHECK(length(generation) = 64),
             join_request_id BLOB NOT NULL CHECK(length(join_request_id) = 16),
             expires_at INTEGER NOT NULL CHECK(expires_at > 0),
             state INTEGER NOT NULL CHECK(state IN (1, 2))
         ) STRICT;

         CREATE TABLE inviter_joins (
             transaction_id BLOB PRIMARY KEY CHECK(length(transaction_id) = 16),
             invitation_id BLOB NOT NULL UNIQUE REFERENCES reservations(invitation_id),
             generation BLOB NOT NULL CHECK(length(generation) = 64),
             join_request_id BLOB NOT NULL UNIQUE CHECK(length(join_request_id) = 16),
             request_fingerprint BLOB NOT NULL CHECK(length(request_fingerprint) = 32),
             group_id BLOB NOT NULL CHECK(length(group_id) = 32),
             epoch_before INTEGER NOT NULL CHECK(epoch_before >= 0),
             epoch_after INTEGER NOT NULL CHECK(epoch_after = epoch_before + 1),
             approval_record BLOB NOT NULL CHECK(length(approval_record) BETWEEN 1 AND 4096),
             welcome BLOB NOT NULL CHECK(length(welcome) BETWEEN 1 AND 65536),
             endpoint BLOB NOT NULL CHECK(length(endpoint) BETWEEN 1 AND 4096),
             outbox_expires_at INTEGER NOT NULL CHECK(outbox_expires_at > 0),
             outbox_state INTEGER NOT NULL CHECK(outbox_state = 1)
         ) STRICT;

         CREATE TABLE mls_groups (
             group_id BLOB PRIMARY KEY CHECK(length(group_id) BETWEEN 1 AND 255),
             state BLOB NOT NULL CHECK(length(state) BETWEEN 1 AND 2097152)
         ) STRICT;

         CREATE TABLE mls_epochs (
             group_id BLOB NOT NULL REFERENCES mls_groups(group_id),
             epoch_id INTEGER NOT NULL CHECK(epoch_id >= 0),
             data BLOB NOT NULL CHECK(length(data) BETWEEN 1 AND 2097152),
             PRIMARY KEY(group_id, epoch_id)
         ) STRICT;

         CREATE TABLE key_packages (
             key_package_ref BLOB PRIMARY KEY CHECK(length(key_package_ref) = 32),
             key_package BLOB NOT NULL CHECK(length(key_package) BETWEEN 1 AND 16384),
             init_key BLOB NOT NULL CHECK(length(init_key) BETWEEN 1 AND 4096),
             leaf_key BLOB NOT NULL CHECK(length(leaf_key) BETWEEN 1 AND 4096),
             expires_at INTEGER NOT NULL CHECK(expires_at > 0)
         ) STRICT;

         CREATE TABLE joiner_commits (
             transaction_id BLOB PRIMARY KEY CHECK(length(transaction_id) = 16),
             group_id BLOB NOT NULL UNIQUE CHECK(length(group_id) = 32),
             key_package_ref BLOB NOT NULL UNIQUE CHECK(length(key_package_ref) = 32)
         ) STRICT;
         COMMIT;",
    )?;
    Ok(())
}

fn commit_inviter(
    connection: &mut Connection,
    staged: &StagedInviter,
    state: &GroupState,
    epoch_inserts: &[EpochRecord],
    epoch_updates: &[EpochRecord],
) -> Result<(), StoreError> {
    let commit = &staged.transaction;
    if state.id.as_slice() != commit.group_id || commit.epoch_after > i64::MAX as u64 {
        return Err(StoreError::Rejected);
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let existing = transaction
        .query_row(
            "SELECT 1 FROM inviter_joins WHERE transaction_id = ?1",
            params![commit.transaction_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some();
    if existing {
        let exact = transaction
            .query_row(
                "SELECT 1 FROM inviter_joins j
                 JOIN mls_groups g ON g.group_id = j.group_id
                 WHERE j.transaction_id = ?1 AND j.invitation_id = ?2
                   AND j.generation = ?3 AND j.join_request_id = ?4
                   AND j.request_fingerprint = ?5 AND j.group_id = ?6
                   AND j.epoch_before = ?7 AND j.epoch_after = ?8
                   AND j.approval_record = ?9 AND j.welcome = ?10
                   AND j.endpoint = ?11 AND j.outbox_expires_at = ?12
                   AND g.state = ?13",
                params![
                    commit.transaction_id,
                    commit.invitation_id,
                    commit.invitation_generation,
                    commit.join_request_id,
                    commit.request_fingerprint,
                    commit.group_id,
                    commit.epoch_before as i64,
                    commit.epoch_after as i64,
                    commit.approval_record,
                    commit.welcome,
                    commit.endpoint,
                    commit.outbox_expires_at as i64,
                    state.data.as_slice()
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some();
        return if exact {
            Ok(())
        } else {
            Err(StoreError::Conflict)
        };
    }

    let reservation_matches = transaction
        .query_row(
            "SELECT 1 FROM reservations
             WHERE invitation_id = ?1 AND generation = ?2 AND join_request_id = ?3
               AND expires_at > ?4 AND state = 1",
            params![
                commit.invitation_id,
                commit.invitation_generation,
                commit.join_request_id,
                staged.now_unix_seconds as i64
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some();
    if !reservation_matches {
        return Err(StoreError::Rejected);
    }

    persist_mls(&transaction, state, epoch_inserts, epoch_updates)?;
    transaction.execute(
        "INSERT INTO inviter_joins(
             transaction_id, invitation_id, generation, join_request_id,
             request_fingerprint, group_id, epoch_before, epoch_after,
             approval_record, welcome, endpoint, outbox_expires_at, outbox_state
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 1)",
        params![
            commit.transaction_id,
            commit.invitation_id,
            commit.invitation_generation,
            commit.join_request_id,
            commit.request_fingerprint,
            commit.group_id,
            commit.epoch_before as i64,
            commit.epoch_after as i64,
            commit.approval_record,
            commit.welcome,
            commit.endpoint,
            commit.outbox_expires_at as i64
        ],
    )?;
    let changed = transaction.execute(
        "UPDATE reservations SET state = 2
         WHERE invitation_id = ?1 AND generation = ?2
           AND join_request_id = ?3 AND state = 1",
        params![
            commit.invitation_id,
            commit.invitation_generation,
            commit.join_request_id
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::Rejected);
    }
    if staged.fault == PersistenceFault::BeforeCommit {
        return Err(StoreError::InjectedFailure);
    }
    transaction.commit()?;
    if staged.fault == PersistenceFault::AfterCommit {
        Err(StoreError::OutcomeUnknown)
    } else {
        Ok(())
    }
}

fn begin_joiner(
    inner: &mut StorageInner,
    staged: StagedJoiner,
    state: &GroupState,
    epoch_inserts: &[EpochRecord],
    epoch_updates: &[EpochRecord],
) -> Result<(), StoreError> {
    if state.id.as_slice() != staged.transaction.group_id {
        return Err(StoreError::Rejected);
    }
    let existing = inner
        .connection
        .query_row(
            "SELECT 1 FROM joiner_commits WHERE transaction_id = ?1",
            params![staged.transaction.transaction_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some();
    if existing {
        let exact = inner
            .connection
            .query_row(
                "SELECT 1 FROM joiner_commits j
                 JOIN mls_groups g ON g.group_id = j.group_id
                 WHERE j.transaction_id = ?1 AND j.group_id = ?2
                   AND j.key_package_ref = ?3 AND g.state = ?4",
                params![
                    staged.transaction.transaction_id,
                    staged.transaction.group_id,
                    staged.transaction.key_package_reference,
                    state.data.as_slice()
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some();
        if !exact
            || key_package_exists_on(&inner.connection, &staged.transaction.key_package_reference)?
        {
            return Err(StoreError::Conflict);
        }
        inner.pending_joiner = Some(PendingJoiner {
            transaction: staged.transaction,
            fault: staged.fault,
            already_committed: true,
        });
        return Ok(());
    }

    inner.connection.execute_batch("BEGIN IMMEDIATE;")?;
    let result = (|| {
        if !key_package_exists_on(&inner.connection, &staged.transaction.key_package_reference)? {
            return Err(StoreError::Rejected);
        }
        persist_mls(&inner.connection, state, epoch_inserts, epoch_updates)?;
        inner.connection.execute(
            "INSERT INTO joiner_commits(transaction_id, group_id, key_package_ref)
             VALUES (?1, ?2, ?3)",
            params![
                staged.transaction.transaction_id,
                staged.transaction.group_id,
                staged.transaction.key_package_reference
            ],
        )?;
        Ok(())
    })();
    if let Err(error) = result {
        rollback(&inner.connection);
        return Err(error);
    }
    inner.pending_joiner = Some(PendingJoiner {
        transaction: staged.transaction,
        fault: staged.fault,
        already_committed: false,
    });
    Ok(())
}

fn persist_mls(
    transaction: &Connection,
    state: &GroupState,
    epoch_inserts: &[EpochRecord],
    epoch_updates: &[EpochRecord],
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO mls_groups(group_id, state) VALUES (?1, ?2)
         ON CONFLICT(group_id) DO UPDATE SET state = excluded.state",
        params![state.id, state.data.as_slice()],
    )?;
    for epoch in epoch_inserts {
        transaction.execute(
            "INSERT INTO mls_epochs(group_id, epoch_id, data) VALUES (?1, ?2, ?3)",
            params![state.id, epoch.id as i64, epoch.data.as_slice()],
        )?;
    }
    for epoch in epoch_updates {
        let changed = transaction.execute(
            "UPDATE mls_epochs SET data = ?3 WHERE group_id = ?1 AND epoch_id = ?2",
            params![state.id, epoch.id as i64, epoch.data.as_slice()],
        )?;
        if changed != 1 {
            return Err(StoreError::Rejected);
        }
    }
    Ok(())
}

fn key_package_exists_on(connection: &Connection, reference: &[u8]) -> Result<bool, StoreError> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM key_packages WHERE key_package_ref = ?1",
            params![reference],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some())
}

fn rollback(connection: &Connection) {
    let _ = connection.execute_batch("ROLLBACK;");
}

fn validate_inviter(
    transaction: &InviterJoinTransaction,
    now_unix_seconds: u64,
) -> Result<(), StoreError> {
    if all_zero(&transaction.transaction_id)
        || all_zero(&transaction.invitation_id)
        || all_zero(&transaction.invitation_generation)
        || all_zero(&transaction.join_request_id)
        || all_zero(&transaction.request_fingerprint)
        || all_zero(&transaction.group_id)
        || transaction.epoch_before.checked_add(1) != Some(transaction.epoch_after)
        || transaction.epoch_after > i64::MAX as u64
        || transaction.approval_record.is_empty()
        || transaction.approval_record.len() > 4_096
        || transaction.welcome.is_empty()
        || transaction.welcome.len() > 65_536
        || transaction.endpoint.is_empty()
        || transaction.endpoint.len() > 4_096
        || transaction.outbox_expires_at <= now_unix_seconds
        || transaction.outbox_expires_at > i64::MAX as u64
        || now_unix_seconds > i64::MAX as u64
    {
        return Err(StoreError::Rejected);
    }
    Ok(())
}

fn validate_mls_write(
    state: &GroupState,
    epoch_inserts: &[EpochRecord],
    epoch_updates: &[EpochRecord],
) -> Result<(), StoreError> {
    if state.id.is_empty()
        || state.id.len() > MAX_GROUP_ID_BYTES
        || state.data.is_empty()
        || state.data.len() > MAX_MLS_STATE_BYTES
        || epoch_inserts.len() > MAX_EPOCH_WRITES
        || epoch_updates.len() > MAX_EPOCH_WRITES
        || epoch_inserts.iter().chain(epoch_updates).any(|epoch| {
            epoch.id > i64::MAX as u64
                || epoch.data.is_empty()
                || epoch.data.len() > MAX_MLS_STATE_BYTES
        })
    {
        return Err(StoreError::Rejected);
    }
    Ok(())
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
