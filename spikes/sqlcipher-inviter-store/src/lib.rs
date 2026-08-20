#![forbid(unsafe_code)]

//! Disposable SQLCipher compatibility experiment for inviter-owned state.

use std::{path::Path, sync::Mutex};

use mls_rs_core::{
    error::IntoAnyError,
    group::{EpochRecord, GroupState, GroupStateStorage},
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Exact raw key released only while the client vault is unsealed.
pub struct VaultKey([u8; 32]);

impl VaultKey {
    /// Accepts a nonzero 256-bit raw database key.
    pub fn new(key: [u8; 32]) -> Result<Self, StoreError> {
        if key.iter().all(|byte| *byte == 0) {
            return Err(StoreError::Rejected);
        }
        Ok(Self(key))
    }

    fn raw_key_pragma(&self) -> String {
        let mut hex = String::with_capacity(64);
        for byte in self.0 {
            use std::fmt::Write as _;
            write!(&mut hex, "{byte:02X}").expect("writing to a String cannot fail");
        }
        // SQLCipher requires this exact BLOB-literal wrapper for raw key data.
        // Every interpolated character is generated from the fixed hex alphabet.
        format!("PRAGMA key = \"x'{hex}'\";")
    }
}

/// Exact invitation reservation mirrored for the transaction spike.
pub struct Reservation {
    invitation_id: [u8; 16],
    generation: [u8; 64],
    join_request_id: [u8; 16],
    expires_at: u64,
}

impl Reservation {
    /// Constructs one nonzero, finite reservation.
    pub fn new(
        invitation_id: [u8; 16],
        generation: [u8; 64],
        join_request_id: [u8; 16],
        expires_at: u64,
    ) -> Result<Self, StoreError> {
        if all_zero(&invitation_id)
            || all_zero(&generation)
            || all_zero(&join_request_id)
            || expires_at == 0
            || expires_at > i64::MAX as u64
        {
            return Err(StoreError::Rejected);
        }
        Ok(Self {
            invitation_id,
            generation,
            join_request_id,
            expires_at,
        })
    }
}

/// Complete secret-bearing input to the disposable SQL transaction.
pub struct JoinCommit {
    transaction_id: [u8; 16],
    invitation_id: [u8; 16],
    generation: [u8; 64],
    join_request_id: [u8; 16],
    request_fingerprint: [u8; 32],
    group_id: Vec<u8>,
    epoch_before: u64,
    epoch_after: u64,
    approval_record: Vec<u8>,
    mls_state: Vec<u8>,
    welcome: Vec<u8>,
    endpoint: Vec<u8>,
    outbox_expires_at: u64,
}

impl JoinCommit {
    /// Constructs an input whose exact bounds are checked before SQL begins.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        transaction_id: [u8; 16],
        invitation_id: [u8; 16],
        generation: [u8; 64],
        join_request_id: [u8; 16],
        request_fingerprint: [u8; 32],
        group_id: Vec<u8>,
        epoch_before: u64,
        epoch_after: u64,
        approval_record: Vec<u8>,
        mls_state: Vec<u8>,
        welcome: Vec<u8>,
        endpoint: Vec<u8>,
        outbox_expires_at: u64,
    ) -> Self {
        Self {
            transaction_id,
            invitation_id,
            generation,
            join_request_id,
            request_fingerprint,
            group_id,
            epoch_before,
            epoch_after,
            approval_record,
            mls_state,
            welcome,
            endpoint,
            outbox_expires_at,
        }
    }
}

impl Drop for JoinCommit {
    fn drop(&mut self) {
        self.request_fingerprint.zeroize();
        self.approval_record.zeroize();
        self.mls_state.zeroize();
        self.welcome.zeroize();
        self.endpoint.zeroize();
    }
}

/// Deterministic SQL-transaction fault point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitFault {
    /// No injected fault.
    None,
    /// Return after all writes but before SQL commit.
    BeforeCommit,
    /// Terminate the spike process after writes and before SQL commit.
    ExitBeforeCommit,
    /// SQL commit succeeds but its result is reported as unknown.
    AfterCommit,
}

/// Exact retry result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitOutcome {
    /// This call committed the transaction.
    Committed,
    /// The exact transaction already existed.
    AlreadyCommitted,
}

/// Secret-free invitation state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvitationState {
    /// Awaiting transaction commit.
    Reserved,
    /// Atomically consumed with the join record.
    Consumed,
}

/// Secret-free outbox state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboxState {
    /// Awaiting delivery.
    Pending,
}

/// Secret-free durable recovery view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryView {
    /// Persisted MLS epoch after Add.
    pub epoch_after: u64,
    /// Persisted Welcome outbox state.
    pub outbox_state: OutboxState,
    /// Persisted delivery attempt count.
    pub delivery_attempts: u32,
}

impl Drop for VaultKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Coarse failure from the disposable storage boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StoreError {
    /// The key, database, configuration, or integrity check was rejected.
    #[error("encrypted store operation rejected")]
    Rejected,
    /// A transaction or replay identifier conflicted with retained state.
    #[error("encrypted store conflict")]
    Conflict,
    /// A deterministic pre-commit failure was injected.
    #[error("injected encrypted store failure")]
    InjectedFailure,
    /// SQL commit succeeded but the caller must recover its result.
    #[error("encrypted store outcome unknown")]
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

/// Keyed SQLCipher connection owned only while the vault is unsealed.
pub struct SqlCipherStore {
    connection: Connection,
}

impl SqlCipherStore {
    /// Creates or initializes one encrypted spike database.
    pub fn create(path: &Path, key: VaultKey) -> Result<Self, StoreError> {
        Self::open_internal(path, key, true)
    }

    /// Opens an existing encrypted spike database.
    pub fn open(path: &Path, key: VaultKey) -> Result<Self, StoreError> {
        Self::open_internal(path, key, false)
    }

    /// Returns the active SQLCipher version, rejecting plaintext SQLite builds.
    pub fn cipher_version(&self) -> Result<String, StoreError> {
        self.connection
            .query_row("PRAGMA cipher_version;", [], |row| row.get(0))
            .map_err(Into::into)
    }

    /// Runs SQLCipher's independent per-page HMAC verification.
    pub fn integrity_check(&self) -> Result<bool, StoreError> {
        let mut statement = self.connection.prepare("PRAGMA cipher_integrity_check;")?;
        let mut rows = statement.query([])?;
        Ok(rows.next()?.is_none())
    }

    /// Persists the exact pre-existing invitation reservation.
    pub fn seed_reservation(
        &mut self,
        reservation: &Reservation,
        now_unix_seconds: u64,
    ) -> Result<(), StoreError> {
        if reservation.expires_at <= now_unix_seconds || now_unix_seconds > i64::MAX as u64 {
            return Err(StoreError::Rejected);
        }
        self.connection.execute(
            "INSERT INTO reservations(
                 invitation_id, generation, join_request_id, expires_at, state
             ) VALUES (?1, ?2, ?3, ?4, 1)",
            params![
                reservation.invitation_id,
                reservation.generation,
                reservation.join_request_id,
                reservation.expires_at as i64,
            ],
        )?;
        Ok(())
    }

    /// Commits invitation, replay, approval, MLS snapshot, and Welcome atomically.
    pub fn commit_join(
        &mut self,
        commit: &JoinCommit,
        now_unix_seconds: u64,
        fault: CommitFault,
    ) -> Result<CommitOutcome, StoreError> {
        self.commit_join_internal(commit, now_unix_seconds, fault, None, &[], &[])
    }

    fn commit_join_internal(
        &mut self,
        commit: &JoinCommit,
        now_unix_seconds: u64,
        fault: CommitFault,
        group_state: Option<&GroupState>,
        epoch_inserts: &[EpochRecord],
        epoch_updates: &[EpochRecord],
    ) -> Result<CommitOutcome, StoreError> {
        validate_join_commit(commit, now_unix_seconds)?;
        if let Some(state) = group_state {
            validate_mls_write(commit, state, epoch_inserts, epoch_updates)?;
        } else if !epoch_inserts.is_empty() || !epoch_updates.is_empty() {
            return Err(StoreError::Rejected);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some(stored) = load_join(&transaction, &commit.transaction_id)? {
            return if stored.matches(commit) {
                Ok(CommitOutcome::AlreadyCommitted)
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
                    commit.generation,
                    commit.join_request_id,
                    now_unix_seconds as i64,
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some();
        if !reservation_matches {
            return Err(StoreError::Rejected);
        }

        if let Some(state) = group_state {
            persist_mls_write(&transaction, state, epoch_inserts, epoch_updates)?;
        }

        transaction.execute(
            "INSERT INTO join_transactions(
                 transaction_id, invitation_id, generation, join_request_id,
                 request_fingerprint, group_id, epoch_before, epoch_after,
                 approval_record, mls_state, welcome, endpoint,
                 outbox_expires_at, outbox_state, delivery_attempts
             ) VALUES (
                 ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 1, 0
             )",
            params![
                commit.transaction_id,
                commit.invitation_id,
                commit.generation,
                commit.join_request_id,
                commit.request_fingerprint,
                commit.group_id,
                commit.epoch_before as i64,
                commit.epoch_after as i64,
                commit.approval_record,
                commit.mls_state,
                commit.welcome,
                commit.endpoint,
                commit.outbox_expires_at as i64,
            ],
        )?;
        let changed = transaction.execute(
            "UPDATE reservations SET state = 2
             WHERE invitation_id = ?1 AND generation = ?2
               AND join_request_id = ?3 AND state = 1",
            params![
                commit.invitation_id,
                commit.generation,
                commit.join_request_id
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Rejected);
        }
        if fault == CommitFault::BeforeCommit {
            return Err(StoreError::InjectedFailure);
        }
        if fault == CommitFault::ExitBeforeCommit {
            std::process::exit(86);
        }
        transaction.commit()?;
        if fault == CommitFault::AfterCommit {
            Err(StoreError::OutcomeUnknown)
        } else {
            Ok(CommitOutcome::Committed)
        }
    }

    /// Recovers one secret-free transaction view.
    pub fn recover(&self, transaction_id: &[u8; 16]) -> Result<Option<RecoveryView>, StoreError> {
        self.connection
            .query_row(
                "SELECT epoch_after, outbox_state, delivery_attempts
                 FROM join_transactions WHERE transaction_id = ?1",
                params![transaction_id],
                |row| {
                    let epoch_after = row.get::<_, i64>(0)?;
                    let outbox_state = row.get::<_, i64>(1)?;
                    let delivery_attempts = row.get::<_, i64>(2)?;
                    Ok((epoch_after, outbox_state, delivery_attempts))
                },
            )
            .optional()?
            .map(|(epoch_after, outbox_state, delivery_attempts)| {
                if epoch_after < 0
                    || outbox_state != 1
                    || !(0..=i64::from(u32::MAX)).contains(&delivery_attempts)
                {
                    return Err(StoreError::Rejected);
                }
                Ok(RecoveryView {
                    epoch_after: epoch_after as u64,
                    outbox_state: OutboxState::Pending,
                    delivery_attempts: delivery_attempts as u32,
                })
            })
            .transpose()
    }

    /// Returns a secret-free view of one invitation row.
    pub fn invitation_state(
        &self,
        invitation_id: &[u8; 16],
    ) -> Result<Option<InvitationState>, StoreError> {
        self.connection
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

    fn mls_state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        self.connection
            .query_row(
                "SELECT state FROM mls_groups WHERE group_id = ?1",
                params![group_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map(|value| value.map(Zeroizing::new))
            .map_err(Into::into)
    }

    fn mls_epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        if epoch_id > i64::MAX as u64 {
            return Err(StoreError::Rejected);
        }
        self.connection
            .query_row(
                "SELECT data FROM mls_epochs WHERE group_id = ?1 AND epoch_id = ?2",
                params![group_id, epoch_id as i64],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map(|value| value.map(Zeroizing::new))
            .map_err(Into::into)
    }

    fn maximum_mls_epoch(&self, group_id: &[u8]) -> Result<Option<u64>, StoreError> {
        let value = self.connection.query_row(
            "SELECT max(epoch_id) FROM mls_epochs WHERE group_id = ?1",
            params![group_id],
            |row| row.get::<_, Option<i64>>(0),
        )?;
        value
            .map(|epoch| u64::try_from(epoch).map_err(|_| StoreError::Rejected))
            .transpose()
    }

    fn open_internal(path: &Path, key: VaultKey, create: bool) -> Result<Self, StoreError> {
        let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        if create {
            flags |= OpenFlags::SQLITE_OPEN_CREATE;
        }
        let connection = Connection::open_with_flags(path, flags)?;

        // Source: https://www.zetetic.net/sqlcipher/sqlcipher-api/#pragma-key
        connection.execute_batch(&key.raw_key_pragma())?;
        connection.execute_batch("PRAGMA cipher_memory_security = ON;")?;

        // SQLCipher defers key validation until the first page read.
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
            connection.execute_batch(
                "CREATE TABLE IF NOT EXISTS spike_metadata (
                     schema_version INTEGER NOT NULL CHECK (schema_version = 1)
                 ) STRICT;
                 INSERT INTO spike_metadata(schema_version)
                 SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM spike_metadata);

                 CREATE TABLE IF NOT EXISTS reservations (
                     invitation_id BLOB PRIMARY KEY CHECK(length(invitation_id) = 16),
                     generation BLOB NOT NULL CHECK(length(generation) = 64),
                     join_request_id BLOB NOT NULL CHECK(length(join_request_id) = 16),
                     expires_at INTEGER NOT NULL CHECK(expires_at > 0),
                     state INTEGER NOT NULL CHECK(state IN (1, 2))
                 ) STRICT;

                 CREATE TABLE IF NOT EXISTS join_transactions (
                     transaction_id BLOB PRIMARY KEY CHECK(length(transaction_id) = 16),
                     invitation_id BLOB NOT NULL UNIQUE REFERENCES reservations(invitation_id),
                     generation BLOB NOT NULL CHECK(length(generation) = 64),
                     join_request_id BLOB NOT NULL UNIQUE CHECK(length(join_request_id) = 16),
                     request_fingerprint BLOB NOT NULL CHECK(length(request_fingerprint) = 32),
                     group_id BLOB NOT NULL CHECK(length(group_id) BETWEEN 1 AND 255),
                     epoch_before INTEGER NOT NULL CHECK(epoch_before >= 0),
                     epoch_after INTEGER NOT NULL CHECK(epoch_after = epoch_before + 1),
                     approval_record BLOB NOT NULL CHECK(length(approval_record) BETWEEN 1 AND 4096),
                     mls_state BLOB NOT NULL CHECK(length(mls_state) BETWEEN 1 AND 2097152),
                     welcome BLOB NOT NULL CHECK(length(welcome) BETWEEN 1 AND 65536),
                     endpoint BLOB NOT NULL CHECK(length(endpoint) BETWEEN 1 AND 4096),
                     outbox_expires_at INTEGER NOT NULL CHECK(outbox_expires_at > 0),
                     outbox_state INTEGER NOT NULL CHECK(outbox_state = 1),
                     delivery_attempts INTEGER NOT NULL CHECK(delivery_attempts >= 0)
                 ) STRICT;

                 CREATE TABLE IF NOT EXISTS mls_groups (
                     group_id BLOB PRIMARY KEY CHECK(length(group_id) BETWEEN 1 AND 255),
                     state BLOB NOT NULL CHECK(length(state) BETWEEN 1 AND 2097152)
                 ) STRICT;

                 CREATE TABLE IF NOT EXISTS mls_epochs (
                     group_id BLOB NOT NULL REFERENCES mls_groups(group_id),
                     epoch_id INTEGER NOT NULL CHECK(epoch_id >= 0),
                     data BLOB NOT NULL CHECK(length(data) BETWEEN 1 AND 2097152),
                     PRIMARY KEY(group_id, epoch_id)
                 ) STRICT;",
            )?;
        }
        Ok(Self { connection })
    }
}

struct StagedJoin {
    commit: JoinCommit,
    now_unix_seconds: u64,
    fault: CommitFault,
}

/// Exact `mls-rs` storage hook coupled to one staged inviter transaction.
pub struct MlsTransactionalStorage {
    store: Mutex<SqlCipherStore>,
    staged: Option<StagedJoin>,
}

impl MlsTransactionalStorage {
    /// Wraps one keyed database connection as an MLS storage provider.
    #[must_use]
    pub fn new(store: SqlCipherStore) -> Self {
        Self {
            store: Mutex::new(store),
            staged: None,
        }
    }

    /// Stages one exact inviter commit for the next MLS storage write.
    pub fn stage_join(
        &mut self,
        commit: JoinCommit,
        now_unix_seconds: u64,
        fault: CommitFault,
    ) -> Result<(), StoreError> {
        if self.staged.is_some() {
            return Err(StoreError::Conflict);
        }
        validate_join_commit(&commit, now_unix_seconds)?;
        self.staged = Some(StagedJoin {
            commit,
            now_unix_seconds,
            fault,
        });
        Ok(())
    }

    /// Recovers a staged transaction's secret-free durable result.
    pub fn recover(&self, transaction_id: &[u8; 16]) -> Result<Option<RecoveryView>, StoreError> {
        self.store
            .lock()
            .map_err(|_| StoreError::Rejected)?
            .recover(transaction_id)
    }

    /// Returns the durable invitation state.
    pub fn invitation_state(
        &self,
        invitation_id: &[u8; 16],
    ) -> Result<Option<InvitationState>, StoreError> {
        self.store
            .lock()
            .map_err(|_| StoreError::Rejected)?
            .invitation_state(invitation_id)
    }
}

impl GroupStateStorage for MlsTransactionalStorage {
    type Error = StoreError;

    fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        self.store
            .lock()
            .map_err(|_| StoreError::Rejected)?
            .mls_state(group_id)
    }

    fn epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        self.store
            .lock()
            .map_err(|_| StoreError::Rejected)?
            .mls_epoch(group_id, epoch_id)
    }

    fn write(
        &mut self,
        state: GroupState,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        let staged = self.staged.take().ok_or(StoreError::Rejected)?;
        let store = self.store.get_mut().map_err(|_| StoreError::Rejected)?;
        store
            .commit_join_internal(
                &staged.commit,
                staged.now_unix_seconds,
                staged.fault,
                Some(&state),
                &epoch_inserts,
                &epoch_updates,
            )
            .map(|_| ())
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        self.store
            .lock()
            .map_err(|_| StoreError::Rejected)?
            .maximum_mls_epoch(group_id)
    }
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn validate_mls_write(
    commit: &JoinCommit,
    state: &GroupState,
    epoch_inserts: &[EpochRecord],
    epoch_updates: &[EpochRecord],
) -> Result<(), StoreError> {
    if state.id != commit.group_id
        || state.data.as_slice() != commit.mls_state
        || epoch_inserts.len() > 64
        || epoch_updates.len() > 64
        || epoch_inserts.iter().chain(epoch_updates).any(|epoch| {
            epoch.id > i64::MAX as u64 || epoch.data.is_empty() || epoch.data.len() > 2_097_152
        })
    {
        return Err(StoreError::Rejected);
    }
    Ok(())
}

fn persist_mls_write(
    transaction: &rusqlite::Transaction<'_>,
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

struct StoredJoin {
    invitation_id: Vec<u8>,
    generation: Vec<u8>,
    join_request_id: Vec<u8>,
    request_fingerprint: Vec<u8>,
    group_id: Vec<u8>,
    epoch_before: i64,
    epoch_after: i64,
    approval_record: Vec<u8>,
    mls_state: Vec<u8>,
    welcome: Vec<u8>,
    endpoint: Vec<u8>,
    outbox_expires_at: i64,
}

impl StoredJoin {
    fn matches(&self, commit: &JoinCommit) -> bool {
        self.invitation_id == commit.invitation_id
            && self.generation == commit.generation
            && self.join_request_id == commit.join_request_id
            && self.request_fingerprint == commit.request_fingerprint
            && self.group_id == commit.group_id
            && self.epoch_before == commit.epoch_before as i64
            && self.epoch_after == commit.epoch_after as i64
            && self.approval_record == commit.approval_record
            && self.mls_state == commit.mls_state
            && self.welcome == commit.welcome
            && self.endpoint == commit.endpoint
            && self.outbox_expires_at == commit.outbox_expires_at as i64
    }
}

fn load_join(
    transaction: &rusqlite::Transaction<'_>,
    transaction_id: &[u8; 16],
) -> Result<Option<StoredJoin>, StoreError> {
    transaction
        .query_row(
            "SELECT invitation_id, generation, join_request_id, request_fingerprint,
                    group_id, epoch_before, epoch_after, approval_record, mls_state,
                    welcome, endpoint, outbox_expires_at
             FROM join_transactions WHERE transaction_id = ?1",
            params![transaction_id],
            |row| {
                Ok(StoredJoin {
                    invitation_id: row.get(0)?,
                    generation: row.get(1)?,
                    join_request_id: row.get(2)?,
                    request_fingerprint: row.get(3)?,
                    group_id: row.get(4)?,
                    epoch_before: row.get(5)?,
                    epoch_after: row.get(6)?,
                    approval_record: row.get(7)?,
                    mls_state: row.get(8)?,
                    welcome: row.get(9)?,
                    endpoint: row.get(10)?,
                    outbox_expires_at: row.get(11)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn validate_join_commit(commit: &JoinCommit, now_unix_seconds: u64) -> Result<(), StoreError> {
    if all_zero(&commit.transaction_id)
        || all_zero(&commit.invitation_id)
        || all_zero(&commit.generation)
        || all_zero(&commit.join_request_id)
        || all_zero(&commit.request_fingerprint)
        || commit.group_id.is_empty()
        || commit.group_id.len() > 255
        || commit.approval_record.is_empty()
        || commit.approval_record.len() > 4_096
        || commit.mls_state.is_empty()
        || commit.mls_state.len() > 2_097_152
        || commit.welcome.is_empty()
        || commit.welcome.len() > 65_536
        || commit.endpoint.is_empty()
        || commit.endpoint.len() > 4_096
        || commit.epoch_before.checked_add(1) != Some(commit.epoch_after)
        || commit.epoch_after > i64::MAX as u64
        || now_unix_seconds > i64::MAX as u64
        || commit.outbox_expires_at <= now_unix_seconds
        || commit.outbox_expires_at > i64::MAX as u64
    {
        return Err(StoreError::Rejected);
    }
    Ok(())
}
