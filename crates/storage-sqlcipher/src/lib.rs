#![forbid(unsafe_code)]

//! SQLCipher-backed MLS persistence candidate for Session Chat.

#[cfg(all(session_chat_storage_fault_testing, not(debug_assertions)))]
compile_error!("session_chat_storage_fault_testing requires debug assertions");

/// Checked, debug-only process-fault protocol and storage entry points.
#[cfg(session_chat_storage_fault_testing)]
#[doc(hidden)]
pub mod fault_testing;

use std::{
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
use session_crypto_mls::{
    DurableClientIdentityRecord, DurableClientIdentityStorage, SESSION_GROUP_ID_BYTES,
    SessionGroupId,
};
use session_protocol::{LocalWelcomeDepositEndpoint, OpaqueEnvelope};
use session_transport::{LeasedWelcome, OutboxPortError, WelcomeOutboxPort};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const MAX_GROUP_ID_BYTES: usize = 255;
const MAX_MLS_STATE_BYTES: usize = 2 * 1024 * 1024;
const MAX_EPOCH_WRITES: usize = 64;
const MAX_KEY_PACKAGE_BYTES: usize = 16 * 1024;
const MAX_SECRET_KEY_BYTES: usize = 4 * 1024;
const SCHEMA_VERSION: u32 = 4;
const STORE_ID_BYTES: usize = 16;
const LEASE_ID_BYTES: usize = 16;
const OUTBOX_PENDING: i64 = 1;
const OUTBOX_LEASED: i64 = 2;
const OUTBOX_DELIVERED: i64 = 3;
const OUTBOX_ATTEMPTS_EXHAUSTED: i64 = 4;
const OUTBOX_EXPIRED: i64 = 5;
const MAXIMUM_LEASE_SECONDS: u64 = 3_600;

/// Persisted delivery-attempt bound for the initial durable LocalV1 outbox.
pub const MAXIMUM_WELCOME_DELIVERY_ATTEMPTS: u32 = 3;

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

/// Secret-free durable Welcome-outbox lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WelcomeOutboxState {
    /// Committed and eligible for a delivery lease.
    Pending,
    /// Owned temporarily by one exact live lease.
    Leased,
    /// The adapter accepted the exact Welcome deposit.
    Delivered,
    /// The persisted delivery-attempt bound was reached.
    AttemptsExhausted,
    /// The owner-local Welcome lifetime elapsed.
    Expired,
}

/// Secret-free recovery view for one inviter transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InviterRecovery {
    /// Committed MLS epoch after the Add.
    pub epoch_after: u64,
    /// Durable Welcome delivery state.
    pub outbox_state: WelcomeOutboxState,
    /// Number of authoritative leases issued.
    pub delivery_attempts: u32,
}

/// Opaque authority for one exact SQLCipher-owned Welcome lease.
///
/// This value intentionally implements neither diagnostics nor cloning. A
/// result is accepted only by the same open scope, persistent store identity,
/// and exact live transaction/generation/lease tuple that issued it.
pub struct SqlCipherWelcomeLease {
    open_scope: Arc<()>,
    store_id: [u8; STORE_ID_BYTES],
    transaction_id: [u8; 16],
    generation: u64,
    lease_id: [u8; LEASE_ID_BYTES],
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

struct StorageInner {
    connection: Connection,
    staged_inviter: Option<StagedInviter>,
    staged_joiner: Option<StagedJoiner>,
    pending_joiner: Option<PendingJoiner>,
}

/// Cloneable SQLCipher provider handle shared by the MLS and application layers.
///
/// One keyed connection is serialized behind a mutex. Closing the last handle
/// closes the keyed database. This adapter is a bounded durability candidate;
/// it does not establish platform key protection or rollback resistance.
#[derive(Clone)]
pub struct SqlCipherStorage {
    inner: Arc<Mutex<StorageInner>>,
    lease_scope: Arc<()>,
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
                "SELECT epoch_after, outbox_state, delivery_attempts,
                        maximum_delivery_attempts
                 FROM inviter_joins WHERE transaction_id = ?1",
                params![transaction_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?
            .map(
                |(epoch_after, outbox_state, delivery_attempts, maximum_delivery_attempts)| {
                    if epoch_after < 0
                        || delivery_attempts < 0
                        || maximum_delivery_attempts <= 0
                        || maximum_delivery_attempts > 32
                        || delivery_attempts > maximum_delivery_attempts
                    {
                        return Err(StoreError::Rejected);
                    }
                    Ok(InviterRecovery {
                        epoch_after: epoch_after as u64,
                        outbox_state: decode_outbox_state(outbox_state)?,
                        delivery_attempts: delivery_attempts as u32,
                    })
                },
            )
            .transpose()
    }

    /// Returns the exact storage schema version after keying and migration.
    pub fn schema_version(&self) -> Result<u32, StoreError> {
        let version = self.lock()?.connection.query_row(
            "SELECT schema_version FROM storage_metadata",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        u32::try_from(version).map_err(|_| StoreError::Rejected)
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

    fn lock(&self) -> Result<MutexGuard<'_, StorageInner>, StoreError> {
        self.inner.lock().map_err(|_| StoreError::Rejected)
    }

    fn open_internal(path: &Path, key: VaultKey, create: bool) -> Result<Self, StoreError> {
        let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        if create {
            flags |= OpenFlags::SQLITE_OPEN_CREATE;
        }
        let connection = Connection::open_with_flags(path, flags)?;

        // Source: https://www.zetetic.net/sqlcipher/sqlcipher-api/#pragma-key
        connection.execute_batch(&key.raw_key_pragma())?;
        // Keep SQLCipher's default crypto-allocation sanitization. Do not enable
        // process-wide `cipher_memory_security`: it cannot be disabled again and
        // the pinned Windows provider has overflowed during wrong-key validation
        // when this optional mode is enabled.
        // Source: https://www.zetetic.net/sqlcipher/sqlcipher-api/#pragma-cipher-memory-security
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
        validate_connection_configuration(&connection)?;
        if create {
            create_schema(&connection)?;
        } else {
            let mut versions = schema_versions(&connection)?;
            if versions == (0, 1) {
                migrate_schema_v1_to_v2(&connection)?;
                versions = schema_versions(&connection)?;
            }
            if versions == (2, 2) {
                migrate_schema_v2_to_v3(&connection)?;
                versions = schema_versions(&connection)?;
            }
            if versions == (3, 3) {
                migrate_schema_v3_to_v4(&connection)?;
                versions = schema_versions(&connection)?;
            }
            if versions != (SCHEMA_VERSION, i64::from(SCHEMA_VERSION)) {
                return Err(StoreError::Rejected);
            }
        }
        validate_schema_v4(&connection)?;

        Ok(Self {
            inner: Arc::new(Mutex::new(StorageInner {
                connection,
                staged_inviter: None,
                staged_joiner: None,
                pending_joiner: None,
            })),
            lease_scope: Arc::new(()),
        })
    }
}

impl DurableClientIdentityStorage for SqlCipherStorage {
    type Error = StoreError;

    fn load_client_identity(
        &self,
        group_id: &SessionGroupId,
    ) -> Result<Option<DurableClientIdentityRecord>, Self::Error> {
        let retained = self
            .lock()?
            .connection
            .query_row(
                "SELECT group_id, identity_record FROM mls_client_identity
                 WHERE singleton = 1",
                [],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(StoreError::from)?;
        let Some((stored_group_id, encoded)) = retained else {
            return Ok(None);
        };
        let encoded = DurableClientIdentityRecord::from_storage_bytes(encoded)
            .map_err(|_| StoreError::Rejected)?;
        if stored_group_id.as_slice() != group_id.as_bytes() {
            return Err(StoreError::Conflict);
        }
        Ok(Some(encoded))
    }

    fn insert_client_identity(
        &self,
        group_id: &SessionGroupId,
        encoded: DurableClientIdentityRecord,
    ) -> Result<(), Self::Error> {
        let encoded = encoded.into_storage_bytes();
        self.lock()?.connection.execute(
            "INSERT INTO mls_client_identity(singleton, group_id, identity_record)
             VALUES (1, ?1, ?2)",
            params![group_id.as_bytes(), encoded.as_slice()],
        )?;
        Ok(())
    }
}

impl WelcomeOutboxPort for SqlCipherStorage {
    type Lease = SqlCipherWelcomeLease;

    fn lease_next(
        &mut self,
        now_unix_seconds: u64,
        lease_seconds: u64,
    ) -> Result<Option<LeasedWelcome<Self::Lease>>, OutboxPortError> {
        if now_unix_seconds > i64::MAX as u64
            || lease_seconds == 0
            || lease_seconds > MAXIMUM_LEASE_SECONDS
        {
            return Err(OutboxPortError::Conflict);
        }
        let lease_expires_at = now_unix_seconds
            .checked_add(lease_seconds)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(OutboxPortError::Conflict)?;
        let mut inner = self.lock().map_err(map_outbox_store_error)?;
        let transaction = inner
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| OutboxPortError::Internal)?;
        transaction
            .execute(
                "UPDATE inviter_joins
                 SET outbox_state = ?1, lease_id = NULL, lease_expires_at = NULL
                 WHERE outbox_state IN (?2, ?3) AND outbox_expires_at <= ?4",
                params![
                    OUTBOX_EXPIRED,
                    OUTBOX_PENDING,
                    OUTBOX_LEASED,
                    now_unix_seconds as i64
                ],
            )
            .map_err(|_| OutboxPortError::Internal)?;
        transaction
            .execute(
                "UPDATE inviter_joins
                 SET outbox_state = ?1, lease_id = NULL, lease_expires_at = NULL
                 WHERE delivery_attempts >= maximum_delivery_attempts
                   AND outbox_expires_at > ?2
                   AND (
                       outbox_state = ?3
                       OR (outbox_state = ?4 AND lease_expires_at <= ?2)
                   )",
                params![
                    OUTBOX_ATTEMPTS_EXHAUSTED,
                    now_unix_seconds as i64,
                    OUTBOX_PENDING,
                    OUTBOX_LEASED
                ],
            )
            .map_err(|_| OutboxPortError::Internal)?;

        let candidate = transaction
            .query_row(
                "SELECT transaction_id, welcome, endpoint, outbox_expires_at, lease_generation
                 FROM inviter_joins
                 WHERE outbox_expires_at >= ?1
                   AND delivery_attempts < maximum_delivery_attempts
                   AND (
                       outbox_state = ?2
                       OR (outbox_state = ?3 AND lease_expires_at <= ?4)
                   )
                 ORDER BY transaction_id
                 LIMIT 1",
                params![
                    lease_expires_at as i64,
                    OUTBOX_PENDING,
                    OUTBOX_LEASED,
                    now_unix_seconds as i64
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| OutboxPortError::Internal)?;
        let Some((transaction_id, welcome, endpoint, outbox_expires_at, generation)) = candidate
        else {
            transaction
                .commit()
                .map_err(|_| OutboxPortError::Internal)?;
            return Ok(None);
        };
        let transaction_id: [u8; 16] = transaction_id
            .try_into()
            .map_err(|_| OutboxPortError::Internal)?;
        let outbox_expires_at =
            u64::try_from(outbox_expires_at).map_err(|_| OutboxPortError::Internal)?;
        validate_delivery_material(&welcome, &endpoint, outbox_expires_at)
            .map_err(map_outbox_store_error)?;
        let generation = u64::try_from(generation)
            .ok()
            .and_then(|value| value.checked_add(1))
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(OutboxPortError::Internal)?;
        let lease_id = random_nonzero_identifier(&transaction).map_err(map_outbox_store_error)?;
        let store_id = store_id_on(&transaction).map_err(map_outbox_store_error)?;
        let changed = transaction
            .execute(
                "UPDATE inviter_joins
                 SET outbox_state = ?1,
                     delivery_attempts = delivery_attempts + 1,
                     lease_generation = ?2,
                     lease_id = ?3,
                     lease_expires_at = ?4
                 WHERE transaction_id = ?5 AND lease_generation = ?6
                   AND outbox_expires_at >= ?4
                   AND delivery_attempts < maximum_delivery_attempts
                   AND (
                       outbox_state = ?7
                       OR (outbox_state = ?8 AND lease_expires_at <= ?9)
                   )",
                params![
                    OUTBOX_LEASED,
                    generation as i64,
                    lease_id,
                    lease_expires_at as i64,
                    transaction_id,
                    (generation - 1) as i64,
                    OUTBOX_PENDING,
                    OUTBOX_LEASED,
                    now_unix_seconds as i64
                ],
            )
            .map_err(|_| OutboxPortError::Internal)?;
        if changed != 1 {
            return Err(OutboxPortError::Conflict);
        }
        transaction
            .commit()
            .map_err(|_| OutboxPortError::Internal)?;
        Ok(Some(LeasedWelcome::from_owner(
            SqlCipherWelcomeLease {
                open_scope: Arc::clone(&self.lease_scope),
                store_id,
                transaction_id,
                generation,
                lease_id,
            },
            welcome,
            endpoint,
            outbox_expires_at,
        )))
    }

    fn report_accepted(
        &mut self,
        lease: Self::Lease,
        now_unix_seconds: u64,
    ) -> Result<(), OutboxPortError> {
        if now_unix_seconds > i64::MAX as u64 {
            return Err(OutboxPortError::Conflict);
        }
        if !Arc::ptr_eq(&self.lease_scope, &lease.open_scope) {
            return Err(OutboxPortError::Conflict);
        }
        let mut inner = self.lock().map_err(map_outbox_store_error)?;
        let transaction = inner
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| OutboxPortError::Internal)?;
        if store_id_on(&transaction).map_err(map_outbox_store_error)? != lease.store_id {
            return Err(OutboxPortError::Conflict);
        }
        let changed = transaction
            .execute(
                "UPDATE inviter_joins
                 SET outbox_state = ?1, lease_id = NULL, lease_expires_at = NULL
                 WHERE transaction_id = ?2 AND outbox_state = ?3
                   AND lease_generation = ?4 AND lease_id = ?5
                   AND lease_expires_at > ?6 AND outbox_expires_at > ?6",
                params![
                    OUTBOX_DELIVERED,
                    lease.transaction_id,
                    OUTBOX_LEASED,
                    lease.generation as i64,
                    lease.lease_id,
                    now_unix_seconds as i64
                ],
            )
            .map_err(|_| OutboxPortError::Internal)?;
        if changed == 1 {
            transaction
                .commit()
                .map_err(|_| OutboxPortError::Internal)?;
            return Ok(());
        }
        transaction
            .execute(
                "UPDATE inviter_joins
                 SET outbox_state = ?1, lease_id = NULL, lease_expires_at = NULL
                 WHERE transaction_id = ?2 AND outbox_state = ?3
                   AND lease_generation = ?4 AND lease_id = ?5
                   AND outbox_expires_at <= ?6",
                params![
                    OUTBOX_EXPIRED,
                    lease.transaction_id,
                    OUTBOX_LEASED,
                    lease.generation as i64,
                    lease.lease_id,
                    now_unix_seconds as i64
                ],
            )
            .map_err(|_| OutboxPortError::Internal)?;
        transaction
            .commit()
            .map_err(|_| OutboxPortError::Internal)?;
        Err(OutboxPortError::Conflict)
    }

    fn report_failed(&mut self, lease: Self::Lease) -> Result<(), OutboxPortError> {
        if !Arc::ptr_eq(&self.lease_scope, &lease.open_scope) {
            return Err(OutboxPortError::Conflict);
        }
        let mut inner = self.lock().map_err(map_outbox_store_error)?;
        let transaction = inner
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| OutboxPortError::Internal)?;
        if store_id_on(&transaction).map_err(map_outbox_store_error)? != lease.store_id {
            return Err(OutboxPortError::Conflict);
        }
        let changed = transaction
            .execute(
                "UPDATE inviter_joins
                 SET outbox_state = CASE
                         WHEN delivery_attempts >= maximum_delivery_attempts THEN ?1
                         ELSE ?2
                     END,
                     lease_id = NULL,
                     lease_expires_at = NULL
                 WHERE transaction_id = ?3 AND outbox_state = ?4
                   AND lease_generation = ?5 AND lease_id = ?6",
                params![
                    OUTBOX_ATTEMPTS_EXHAUSTED,
                    OUTBOX_PENDING,
                    lease.transaction_id,
                    OUTBOX_LEASED,
                    lease.generation as i64,
                    lease.lease_id
                ],
            )
            .map_err(|_| OutboxPortError::Internal)?;
        if changed != 1 {
            return Err(OutboxPortError::Conflict);
        }
        transaction.commit().map_err(|_| OutboxPortError::Internal)
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
    let store_id = random_nonzero_identifier(connection)?;
    connection.execute_batch(
        "BEGIN IMMEDIATE;
         CREATE TABLE storage_metadata (
             singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
             schema_version INTEGER NOT NULL CHECK(schema_version = 4),
             store_id BLOB NOT NULL UNIQUE CHECK(length(store_id) = 16)
         ) STRICT;

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
             outbox_state INTEGER NOT NULL CHECK(outbox_state BETWEEN 1 AND 5),
             delivery_attempts INTEGER NOT NULL
                 CHECK(delivery_attempts BETWEEN 0 AND 32),
             maximum_delivery_attempts INTEGER NOT NULL
                 CHECK(maximum_delivery_attempts BETWEEN 1 AND 32),
             lease_generation INTEGER NOT NULL CHECK(lease_generation >= 0),
             lease_id BLOB CHECK(lease_id IS NULL OR length(lease_id) = 16),
             lease_expires_at INTEGER CHECK(lease_expires_at IS NULL OR lease_expires_at > 0),
             CHECK(
                 (outbox_state = 2 AND lease_id IS NOT NULL AND lease_expires_at IS NOT NULL)
                 OR (outbox_state IN (1, 3, 4, 5) AND lease_id IS NULL AND lease_expires_at IS NULL)
             ),
             CHECK(delivery_attempts <= maximum_delivery_attempts),
             CHECK(outbox_state != 4 OR delivery_attempts = maximum_delivery_attempts)
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

         CREATE TABLE mls_client_identity (
             singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
             group_id BLOB NOT NULL UNIQUE CHECK(length(group_id) = 32),
             identity_record BLOB NOT NULL CHECK(length(identity_record) = 141)
         ) STRICT;
         PRAGMA user_version = 4;",
    )?;
    if connection
        .execute(
            "INSERT INTO storage_metadata(singleton, schema_version, store_id) VALUES (1, 4, ?1)",
            params![store_id],
        )
        .is_err()
    {
        rollback(connection);
        return Err(StoreError::Rejected);
    }
    connection.execute_batch("COMMIT;")?;
    Ok(())
}

fn migrate_schema_v1_to_v2(connection: &Connection) -> Result<(), StoreError> {
    let store_id = random_nonzero_identifier(connection)?;
    connection.execute_batch(
        "BEGIN EXCLUSIVE;
         ALTER TABLE storage_metadata RENAME TO storage_metadata_v1;
         CREATE TABLE storage_metadata (
             singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
             schema_version INTEGER NOT NULL CHECK(schema_version = 2),
             store_id BLOB NOT NULL UNIQUE CHECK(length(store_id) = 16)
         ) STRICT;

         ALTER TABLE inviter_joins RENAME TO inviter_joins_v1;
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
             outbox_state INTEGER NOT NULL CHECK(outbox_state BETWEEN 1 AND 5),
             delivery_attempts INTEGER NOT NULL
                 CHECK(delivery_attempts BETWEEN 0 AND 32),
             maximum_delivery_attempts INTEGER NOT NULL
                 CHECK(maximum_delivery_attempts BETWEEN 1 AND 32),
             lease_generation INTEGER NOT NULL CHECK(lease_generation >= 0),
             lease_id BLOB CHECK(lease_id IS NULL OR length(lease_id) = 16),
             lease_expires_at INTEGER CHECK(lease_expires_at IS NULL OR lease_expires_at > 0),
             CHECK(
                 (outbox_state = 2 AND lease_id IS NOT NULL AND lease_expires_at IS NOT NULL)
                 OR (outbox_state IN (1, 3, 4, 5) AND lease_id IS NULL AND lease_expires_at IS NULL)
             ),
             CHECK(delivery_attempts <= maximum_delivery_attempts),
             CHECK(outbox_state != 4 OR delivery_attempts = maximum_delivery_attempts)
         ) STRICT;",
    )?;
    let migration = (|| {
        connection.execute(
            "INSERT INTO storage_metadata(singleton, schema_version, store_id)
             VALUES (1, 2, ?1)",
            params![store_id],
        )?;
        connection.execute_batch(
            "INSERT INTO inviter_joins(
                 transaction_id, invitation_id, generation, join_request_id,
                 request_fingerprint, group_id, epoch_before, epoch_after,
                 approval_record, welcome, endpoint, outbox_expires_at, outbox_state,
                 delivery_attempts, maximum_delivery_attempts, lease_generation,
                 lease_id, lease_expires_at
             )
             SELECT transaction_id, invitation_id, generation, join_request_id,
                    request_fingerprint, group_id, epoch_before, epoch_after,
                    approval_record, welcome, endpoint, outbox_expires_at, 1,
                    0, 3, 0, NULL, NULL
             FROM inviter_joins_v1;",
        )?;
        {
            let mut statement = connection
                .prepare("SELECT welcome, endpoint, outbox_expires_at FROM inviter_joins")?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let welcome = row.get::<_, Vec<u8>>(0)?;
                let endpoint = row.get::<_, Vec<u8>>(1)?;
                let outbox_expires_at =
                    u64::try_from(row.get::<_, i64>(2)?).map_err(|_| StoreError::Rejected)?;
                validate_delivery_material(&welcome, &endpoint, outbox_expires_at)?;
            }
        }
        connection.execute_batch(
            "DROP TABLE inviter_joins_v1;
             DROP TABLE storage_metadata_v1;
             PRAGMA user_version = 2;
             COMMIT;",
        )?;
        Ok(())
    })();
    if migration.is_err() {
        rollback(connection);
    }
    migration
}

fn migrate_schema_v2_to_v3(connection: &Connection) -> Result<(), StoreError> {
    let migration = (|| {
        connection.execute_batch(
            "BEGIN EXCLUSIVE;
             ALTER TABLE storage_metadata RENAME TO storage_metadata_v2;
             CREATE TABLE storage_metadata (
                 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                 schema_version INTEGER NOT NULL CHECK(schema_version = 3),
                 store_id BLOB NOT NULL UNIQUE CHECK(length(store_id) = 16)
             ) STRICT;
             INSERT INTO storage_metadata(singleton, schema_version, store_id)
                 SELECT singleton, 3, store_id FROM storage_metadata_v2;
             CREATE TABLE mls_client_identity (
                 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                 identity_record BLOB NOT NULL CHECK(length(identity_record) = 141)
             ) STRICT;
             DROP TABLE storage_metadata_v2;
             PRAGMA user_version = 3;
             COMMIT;",
        )?;
        Ok(())
    })();
    if migration.is_err() {
        rollback(connection);
    }
    migration
}

fn migrate_schema_v3_to_v4(connection: &Connection) -> Result<(), StoreError> {
    let migration = (|| {
        connection.execute_batch(
            "BEGIN EXCLUSIVE;
             ALTER TABLE storage_metadata RENAME TO storage_metadata_v3;
             CREATE TABLE storage_metadata (
                 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                 schema_version INTEGER NOT NULL CHECK(schema_version = 4),
                 store_id BLOB NOT NULL UNIQUE CHECK(length(store_id) = 16)
             ) STRICT;
             INSERT INTO storage_metadata(singleton, schema_version, store_id)
                 SELECT singleton, 4, store_id FROM storage_metadata_v3;
             ALTER TABLE mls_client_identity RENAME TO mls_client_identity_v3;
             CREATE TABLE mls_client_identity (
                 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                 group_id BLOB NOT NULL UNIQUE CHECK(length(group_id) = 32),
                 identity_record BLOB NOT NULL CHECK(length(identity_record) = 141)
             ) STRICT;",
        )?;
        let identity_count: i64 =
            connection.query_row("SELECT count(*) FROM mls_client_identity_v3", [], |row| {
                row.get(0)
            })?;
        if identity_count > 1 {
            return Err(StoreError::Rejected);
        }
        if identity_count == 1 {
            let (group_count, group_id): (i64, Option<Vec<u8>>) = connection.query_row(
                "SELECT count(*), min(group_id) FROM mls_groups",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let group_id = group_id.ok_or(StoreError::Rejected)?;
            if group_count != 1 || group_id.len() != SESSION_GROUP_ID_BYTES || all_zero(&group_id) {
                return Err(StoreError::Rejected);
            }
            connection.execute(
                "INSERT INTO mls_client_identity(singleton, group_id, identity_record)
                 SELECT singleton, ?1, identity_record FROM mls_client_identity_v3",
                params![group_id],
            )?;
        }
        connection.execute_batch(
            "DROP TABLE mls_client_identity_v3;
             DROP TABLE storage_metadata_v3;
             PRAGMA user_version = 4;
             COMMIT;",
        )?;
        Ok(())
    })();
    if migration.is_err() {
        rollback(connection);
    }
    migration
}

fn validate_schema_v4(connection: &Connection) -> Result<(), StoreError> {
    let rows = connection.query_row(
        "SELECT count(*), min(schema_version), max(schema_version), min(store_id)
         FROM storage_metadata",
        [],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
            ))
        },
    )?;
    let store_id = rows.3.ok_or(StoreError::Rejected)?;
    if application_schema_version(connection)? != SCHEMA_VERSION
        || rows.0 != 1
        || rows.1 != Some(i64::from(SCHEMA_VERSION))
        || rows.2 != Some(i64::from(SCHEMA_VERSION))
        || store_id.len() != STORE_ID_BYTES
        || all_zero(&store_id)
    {
        return Err(StoreError::Rejected);
    }
    let invalid_identity_rows: i64 = connection.query_row(
        "SELECT count(*) FROM mls_client_identity
         WHERE length(group_id) != 32 OR group_id = zeroblob(32)",
        [],
        |row| row.get(0),
    )?;
    if invalid_identity_rows != 0 {
        return Err(StoreError::Rejected);
    }
    Ok(())
}

fn schema_versions(connection: &Connection) -> Result<(u32, i64), StoreError> {
    Ok((
        application_schema_version(connection)?,
        connection.query_row("SELECT schema_version FROM storage_metadata", [], |row| {
            row.get(0)
        })?,
    ))
}

fn application_schema_version(connection: &Connection) -> Result<u32, StoreError> {
    let version = connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?;
    u32::try_from(version).map_err(|_| StoreError::Rejected)
}

fn validate_connection_configuration(connection: &Connection) -> Result<(), StoreError> {
    let journal_mode =
        connection.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))?;
    let synchronous = connection.query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))?;
    let temp_store = connection.query_row("PRAGMA temp_store", [], |row| row.get::<_, i64>(0))?;
    let secure_delete =
        connection.query_row("PRAGMA secure_delete", [], |row| row.get::<_, i64>(0))?;
    let trusted_schema =
        connection.query_row("PRAGMA trusted_schema", [], |row| row.get::<_, i64>(0))?;
    let foreign_keys =
        connection.query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))?;
    if !journal_mode.eq_ignore_ascii_case("delete")
        || synchronous != 2
        || temp_store != 2
        || secure_delete != 1
        || trusted_schema != 0
        || foreign_keys != 1
    {
        return Err(StoreError::Rejected);
    }
    Ok(())
}

fn random_nonzero_identifier(connection: &Connection) -> Result<[u8; 16], StoreError> {
    for _ in 0..4 {
        let bytes: Vec<u8> = connection.query_row("SELECT randomblob(16)", [], |row| row.get(0))?;
        let identifier: [u8; 16] = bytes.try_into().map_err(|_| StoreError::Rejected)?;
        if !all_zero(&identifier) {
            return Ok(identifier);
        }
    }
    Err(StoreError::Rejected)
}

fn decode_outbox_state(value: i64) -> Result<WelcomeOutboxState, StoreError> {
    match value {
        OUTBOX_PENDING => Ok(WelcomeOutboxState::Pending),
        OUTBOX_LEASED => Ok(WelcomeOutboxState::Leased),
        OUTBOX_DELIVERED => Ok(WelcomeOutboxState::Delivered),
        OUTBOX_ATTEMPTS_EXHAUSTED => Ok(WelcomeOutboxState::AttemptsExhausted),
        OUTBOX_EXPIRED => Ok(WelcomeOutboxState::Expired),
        _ => Err(StoreError::Rejected),
    }
}

fn store_id_on(connection: &Connection) -> Result<[u8; STORE_ID_BYTES], StoreError> {
    let bytes: Vec<u8> = connection.query_row(
        "SELECT store_id FROM storage_metadata WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let store_id: [u8; STORE_ID_BYTES] = bytes.try_into().map_err(|_| StoreError::Rejected)?;
    if all_zero(&store_id) {
        return Err(StoreError::Rejected);
    }
    Ok(store_id)
}

fn validate_delivery_material(
    welcome: &[u8],
    endpoint: &[u8],
    outbox_expires_at: u64,
) -> Result<(), StoreError> {
    let envelope = OpaqueEnvelope::decode_canonical(welcome).map_err(|_| StoreError::Rejected)?;
    let endpoint = LocalWelcomeDepositEndpoint::decode_canonical(endpoint)
        .map_err(|_| StoreError::Rejected)?;
    if all_zero(envelope.envelope_id())
        || outbox_expires_at > envelope.expires_at_unix_seconds()
        || envelope.expires_at_unix_seconds() > endpoint.expires_at_unix_seconds()
    {
        return Err(StoreError::Rejected);
    }
    Ok(())
}

fn map_outbox_store_error(error: StoreError) -> OutboxPortError {
    match error {
        StoreError::Conflict => OutboxPortError::Conflict,
        StoreError::Rejected | StoreError::InjectedFailure | StoreError::OutcomeUnknown => {
            OutboxPortError::Internal
        }
    }
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
             approval_record, welcome, endpoint, outbox_expires_at, outbox_state,
             delivery_attempts, maximum_delivery_attempts, lease_generation,
             lease_id, lease_expires_at
         ) VALUES (
             ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
             1, 0, ?13, 0, NULL, NULL
         )",
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
            i64::from(MAXIMUM_WELCOME_DELIVERY_ATTEMPTS)
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
    validate_delivery_material(
        &transaction.welcome,
        &transaction.endpoint,
        transaction.outbox_expires_at,
    )
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
