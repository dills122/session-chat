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
    time::Instant,
};

use mls_rs_core::{
    crypto::HpkeSecretKey,
    error::IntoAnyError,
    group::{EpochRecord, GroupState, GroupStateStorage},
    key_package::{KeyPackageData, KeyPackageStorage},
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use session_crypto_hpke::{
    GeneratedCapabilityInvitationV2, InvitationHpkePrivateKeyStorageRef, InvitationJoinProtector,
    InvitationOpeningContextPersistenceError, InvitationOpeningContextSink, JoinProtectionError,
    StoredInvitationHpkePrivateKey,
};
use session_crypto_mls::{
    CommittedAdditionStorageBinding, DurableClientIdentityRecord, DurableClientIdentityStorage,
    SESSION_GROUP_ID_BYTES, SessionGroupId,
};
use session_protocol::{LocalWelcomeDepositEndpoint, OpaqueEnvelope, SignedCapabilityInvitationV2};
use session_transport::{LeasedWelcome, OutboxPortError, WelcomeOutboxPort};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const MAX_GROUP_ID_BYTES: usize = 255;
const MAX_MLS_STATE_BYTES: usize = 2 * 1024 * 1024;
const MAX_EPOCH_WRITES: usize = 64;
const MAX_KEY_PACKAGE_BYTES: usize = 16 * 1024;
const MAX_SECRET_KEY_BYTES: usize = 4 * 1024;
const SCHEMA_VERSION: u32 = 5;
const STORE_ID_BYTES: usize = 16;
const LEASE_ID_BYTES: usize = 16;
const OUTBOX_PENDING: i64 = 1;
const OUTBOX_LEASED: i64 = 2;
const OUTBOX_DELIVERED: i64 = 3;
const OUTBOX_ATTEMPTS_EXHAUSTED: i64 = 4;
const OUTBOX_EXPIRED: i64 = 5;
const MAXIMUM_LEASE_SECONDS: u64 = 3_600;
const OPENING_AVAILABLE: i64 = 1;
const OPENING_RESERVED: i64 = 2;
const OPENING_CONSUMED: i64 = 3;
const OPENING_UNUSABLE: i64 = 4;
const AUTHORIZATION_PENDING_APPROVAL: i64 = 1;
const AUTHORIZATION_APPROVED_PENDING_MEMBERSHIP: i64 = 2;
const AUTHORIZATION_MEMBERSHIP_OUTCOME_UNKNOWN: i64 = 3;
const AUTHORIZATION_COMMITTED: i64 = 4;
const AUTHORIZATION_REJECTED: i64 = 5;
const AUTHORIZATION_ABANDONED: i64 = 6;

/// Fixed Phase 1 ceiling for simultaneously live invitation opening contexts.
pub const MAXIMUM_LIVE_INVITATION_OPENING_CONTEXTS: usize = 8;
/// Maximum retained authorization attempts accepted by the Phase 1 owner.
pub const MAXIMUM_RETAINED_AUTHORIZATION_ATTEMPTS: usize = 8;

/// Persisted bounds for the Phase 1 durable authorization owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationPolicy {
    maximum_live_invitations: usize,
    maximum_retained_attempts: usize,
}

impl AuthorizationPolicy {
    /// Creates policy values within the closed Phase 1 range of one through eight.
    pub fn new(
        maximum_live_invitations: usize,
        maximum_retained_attempts: usize,
    ) -> Result<Self, StoreError> {
        if !(1..=MAXIMUM_LIVE_INVITATION_OPENING_CONTEXTS).contains(&maximum_live_invitations)
            || !(1..=MAXIMUM_RETAINED_AUTHORIZATION_ATTEMPTS).contains(&maximum_retained_attempts)
        {
            return Err(StoreError::Rejected);
        }
        Ok(Self {
            maximum_live_invitations,
            maximum_retained_attempts,
        })
    }

    const fn phase_one() -> Self {
        Self {
            maximum_live_invitations: MAXIMUM_LIVE_INVITATION_OPENING_CONTEXTS,
            maximum_retained_attempts: MAXIMUM_RETAINED_AUTHORIZATION_ATTEMPTS,
        }
    }
}

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
    /// A retained request identifier, nonce, or fingerprint was replayed.
    #[error("encrypted storage replay rejected")]
    Replay,
    /// A retained bounded owner ledger has reached its configured capacity.
    #[error("encrypted storage capacity reached")]
    CapacityExceeded,
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

/// Secret-free lifecycle view for one durable invitation opening context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvitationOpeningState {
    /// The exact signed invitation and matching private key remain usable.
    Available,
    /// One exact authorization attempt owns this generation.
    Reserved,
    /// Successful membership permanently consumed this generation.
    Consumed,
    /// Validation or expiration terminalized the context.
    Unusable,
}

/// Secret-free lifecycle of one retained authorization shadow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationState {
    /// Automated checks passed and an explicit decision is pending.
    PendingApproval,
    /// Explicit approval was recorded but membership storage has not begun.
    ApprovedPendingMembership,
    /// Membership storage may have begun and only exact recovery may resolve it.
    MembershipOutcomeUnknown,
    /// Exact membership recovery proved the transaction committed.
    Committed,
    /// An explicit rejection terminalized the request.
    Rejected,
    /// Restart or proven non-commit terminalized the request.
    Abandoned,
}

/// Exact non-authorizing fields retained after automated admission succeeds.
///
/// This value intentionally implements neither `Clone`, `Debug`, nor generic
/// serialization. It contains no KeyPackage bytes, provider proof, HPKE-open
/// plaintext, bearer capability, or membership authority.
pub struct AuthorizationShadowInput {
    invitation_id: [u8; 16],
    invitation_generation: [u8; 64],
    invitation_challenge: [u8; 32],
    join_request_id: [u8; 16],
    request_nonce: [u8; 32],
    intended_verifier: [u8; 32],
    key_package_reference: [u8; 32],
    credential_identity: [u8; 32],
    leaf_signature_key: [u8; 32],
    request_fingerprint: [u8; 32],
    request_issued_at: u64,
    request_expires_at: u64,
    invitation_expires_at: u64,
}

impl AuthorizationShadowInput {
    /// Validates the fixed Phase 1 binding tuple without retaining KeyPackage bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        invitation_id: [u8; 16],
        invitation_generation: [u8; 64],
        invitation_challenge: [u8; 32],
        join_request_id: [u8; 16],
        request_nonce: [u8; 32],
        intended_verifier: [u8; 32],
        key_package_reference: [u8; 32],
        credential_identity: [u8; 32],
        leaf_signature_key: [u8; 32],
        request_fingerprint: [u8; 32],
        request_issued_at: u64,
        request_expires_at: u64,
        invitation_expires_at: u64,
    ) -> Result<Self, StoreError> {
        if all_zero(&invitation_id)
            || all_zero(&invitation_generation)
            || all_zero(&invitation_challenge)
            || all_zero(&join_request_id)
            || all_zero(&request_nonce)
            || all_zero(&intended_verifier)
            || all_zero(&key_package_reference)
            || all_zero(&credential_identity)
            || all_zero(&leaf_signature_key)
            || all_zero(&request_fingerprint)
            || request_issued_at == 0
            || request_expires_at <= request_issued_at
            || request_expires_at > invitation_expires_at
            || invitation_expires_at > i64::MAX as u64
        {
            return Err(StoreError::Rejected);
        }
        Ok(Self {
            invitation_id,
            invitation_generation,
            invitation_challenge,
            join_request_id,
            request_nonce,
            intended_verifier,
            key_package_reference,
            credential_identity,
            leaf_signature_key,
            request_fingerprint,
            request_issued_at,
            request_expires_at,
            invitation_expires_at,
        })
    }
}

impl Drop for AuthorizationShadowInput {
    fn drop(&mut self) {
        self.invitation_generation.zeroize();
        self.invitation_challenge.zeroize();
        self.join_request_id.zeroize();
        self.request_nonce.zeroize();
        self.intended_verifier.zeroize();
        self.key_package_reference.zeroize();
        self.credential_identity.zeroize();
        self.leaf_signature_key.zeroize();
        self.request_fingerprint.zeroize();
    }
}

struct AuthorizationHandle {
    open_scope: Arc<()>,
    store_id: [u8; STORE_ID_BYTES],
    attempt_id: [u8; 16],
    invitation_id: [u8; 16],
    invitation_generation: [u8; 64],
}

/// Open-scope authority for one exact pending authorization attempt.
pub struct PendingAuthorization(AuthorizationHandle);

impl PendingAuthorization {
    /// Returns the non-authorizing identifier used for state recovery.
    #[must_use]
    pub const fn attempt_id(&self) -> &[u8; 16] {
        &self.0.attempt_id
    }
}

/// Open-scope authority for one exact approved pre-membership attempt.
pub struct ApprovedAuthorization(AuthorizationHandle);

impl ApprovedAuthorization {
    /// Returns the non-authorizing identifier used for state recovery.
    #[must_use]
    pub const fn attempt_id(&self) -> &[u8; 16] {
        &self.0.attempt_id
    }
}

/// Proof that the exact membership transaction ID committed before membership may begin.
pub struct MembershipAuthorization {
    open_scope: Arc<()>,
    store_id: [u8; STORE_ID_BYTES],
    attempt_id: [u8; 16],
    transaction_id: [u8; 16],
}

impl MembershipAuthorization {
    /// Returns the non-authorizing authorization-attempt identifier.
    #[must_use]
    pub const fn attempt_id(&self) -> &[u8; 16] {
        &self.attempt_id
    }

    /// Returns the exact transaction identifier required for later recovery.
    #[must_use]
    pub const fn transaction_id(&self) -> &[u8; 16] {
        &self.transaction_id
    }
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
    authorization: Option<MembershipAuthorization>,
    addition: Option<CommittedAdditionStorageBinding>,
    now_unix_seconds: u64,
    staged_at: Instant,
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
    live_pre_membership_attempts: Vec<[u8; 16]>,
    live_membership_attempts: Vec<[u8; 16]>,
    #[cfg(session_chat_storage_fault_testing)]
    fault_observer: Option<fault_testing::FaultObserver>,
}

enum OpenMode {
    Default,
    #[cfg(session_chat_storage_fault_testing)]
    ObservedDefault(fault_testing::FaultObserver),
    #[cfg(session_chat_storage_fault_testing)]
    ObservedFaultVfs(fault_testing::FaultObserver),
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
    authorization_policy: AuthorizationPolicy,
}

struct SqlCipherInvitationOpeningSink<'a> {
    storage: &'a SqlCipherStorage,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    now_unix_seconds: u64,
}

impl InvitationOpeningContextSink for SqlCipherInvitationOpeningSink<'_> {
    type Error = StoreError;

    fn persist_opening_context(
        &mut self,
        invitation: &SignedCapabilityInvitationV2,
        canonical_invitation: &[u8],
        private_key: InvitationHpkePrivateKeyStorageRef<'_>,
    ) -> Result<(), Self::Error> {
        private_key.persist_with(|private_key| {
            let mut inner = self.storage.lock()?;
            let transaction = inner
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            compact_expired_authorization_state(&transaction, self.now_unix_seconds as i64)?;
            let live_count: i64 = transaction.query_row(
                "SELECT count(*) FROM invitation_opening_contexts",
                [],
                |row| row.get(0),
            )?;
            if live_count < 0
                || live_count as usize >= self.storage.authorization_policy.maximum_live_invitations
            {
                return Err(StoreError::CapacityExceeded);
            }
            transaction.execute(
                "INSERT INTO invitation_opening_contexts(
                     invitation_id, generation, signed_invitation, hpke_private_key,
                     issued_at, expires_at, state
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    invitation.invitation_id(),
                    invitation.signature(),
                    canonical_invitation,
                    private_key,
                    self.issued_at_unix_seconds as i64,
                    self.expires_at_unix_seconds as i64,
                    OPENING_AVAILABLE,
                ],
            )?;
            transaction.commit()?;
            Ok(())
        })
    }
}

impl SqlCipherStorage {
    /// Creates a new encrypted database and schema.
    pub fn create(path: &Path, key: VaultKey) -> Result<Self, StoreError> {
        Self::create_with_authorization_policy(path, key, AuthorizationPolicy::phase_one())
    }

    /// Opens an existing encrypted database without attempting migration.
    pub fn open(path: &Path, key: VaultKey) -> Result<Self, StoreError> {
        Self::open_with_authorization_policy(path, key, AuthorizationPolicy::phase_one())
    }

    /// Creates a new encrypted database with exact persisted authorization bounds.
    pub fn create_with_authorization_policy(
        path: &Path,
        key: VaultKey,
        policy: AuthorizationPolicy,
    ) -> Result<Self, StoreError> {
        Self::open_internal(path, key, true, OpenMode::Default, policy)
    }

    /// Opens an encrypted database only when its persisted authorization bounds match.
    pub fn open_with_authorization_policy(
        path: &Path,
        key: VaultKey,
        policy: AuthorizationPolicy,
    ) -> Result<Self, StoreError> {
        Self::open_internal(path, key, false, OpenMode::Default, policy)
    }

    /// Generates and atomically persists one opening context before returning it for publication.
    pub fn issue_capability_invitation(
        &self,
        protector: &dyn InvitationJoinProtector,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<GeneratedCapabilityInvitationV2, StoreError> {
        if issued_at_unix_seconds == 0
            || issued_at_unix_seconds > now_unix_seconds
            || expires_at_unix_seconds <= now_unix_seconds
            || expires_at_unix_seconds > i64::MAX as u64
            || now_unix_seconds > i64::MAX as u64
        {
            return Err(StoreError::Rejected);
        }
        let generated = protector
            .generate_capability_invitation(issued_at_unix_seconds, expires_at_unix_seconds)
            .map_err(map_join_protection_error)?;
        let mut sink = SqlCipherInvitationOpeningSink {
            storage: self,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            now_unix_seconds,
        };
        generated
            .persist_opening_context(&mut sink)
            .map_err(|error| match error {
                InvitationOpeningContextPersistenceError::Protection(error) => {
                    map_join_protection_error(error)
                }
                InvitationOpeningContextPersistenceError::Storage(error) => error,
            })?;
        Ok(generated)
    }

    /// Reloads one available opening context after revalidating every stored binding.
    pub fn load_capability_invitation(
        &self,
        protector: &dyn InvitationJoinProtector,
        invitation_id: &[u8; 16],
        now_unix_seconds: u64,
    ) -> Result<Option<GeneratedCapabilityInvitationV2>, StoreError> {
        if all_zero(invitation_id) || now_unix_seconds > i64::MAX as u64 {
            return Err(StoreError::Rejected);
        }
        let mut inner = self.lock()?;
        let transaction = inner
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored = transaction
            .query_row(
                "SELECT generation, signed_invitation, hpke_private_key,
                        issued_at, expires_at, state
                 FROM invitation_opening_contexts WHERE invitation_id = ?1",
                params![invitation_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((generation, canonical_invitation, private_key, issued_at, expires_at, state)) =
            stored
        else {
            return Ok(None);
        };
        let canonical_invitation = Zeroizing::new(canonical_invitation);
        let private_key = Zeroizing::new(private_key);
        if state != OPENING_AVAILABLE {
            return Err(StoreError::Rejected);
        }
        if expires_at <= now_unix_seconds as i64 {
            terminalize_opening_context(&transaction, invitation_id)?;
            transaction.commit()?;
            return Err(StoreError::Rejected);
        }
        let private_key = match stored_invitation_private_key(private_key.as_slice()) {
            Ok(private_key) => private_key,
            Err(_) => {
                terminalize_opening_context(&transaction, invitation_id)?;
                transaction.commit()?;
                return Err(StoreError::Rejected);
            }
        };
        let restoration =
            protector.restore_capability_invitation(canonical_invitation.as_slice(), private_key);
        let restored = match restoration {
            Ok(restored) => restored,
            Err(_) => {
                terminalize_opening_context(&transaction, invitation_id)?;
                transaction.commit()?;
                return Err(StoreError::Rejected);
            }
        };
        let bindings_match = generation == restored.invitation().signature()
            && restored.invitation().invitation_id() == invitation_id
            && issued_at >= 0
            && issued_at as u64 == restored.invitation().issued_at_unix_seconds()
            && expires_at > 0
            && expires_at as u64 == restored.invitation().expires_at_unix_seconds();
        if !bindings_match {
            terminalize_opening_context(&transaction, invitation_id)?;
            transaction.commit()?;
            return Err(StoreError::Rejected);
        }
        transaction.commit()?;
        Ok(Some(restored))
    }

    /// Returns the secret-free lifecycle of one stored opening context.
    pub fn invitation_opening_state(
        &self,
        invitation_id: &[u8; 16],
    ) -> Result<Option<InvitationOpeningState>, StoreError> {
        self.lock()?
            .connection
            .query_row(
                "SELECT state FROM invitation_opening_contexts WHERE invitation_id = ?1",
                params![invitation_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(|state| match state {
                OPENING_AVAILABLE => Ok(InvitationOpeningState::Available),
                OPENING_RESERVED => Ok(InvitationOpeningState::Reserved),
                OPENING_CONSUMED => Ok(InvitationOpeningState::Consumed),
                OPENING_UNUSABLE => Ok(InvitationOpeningState::Unusable),
                _ => Err(StoreError::Rejected),
            })
            .transpose()
    }

    /// Atomically retains one verified, non-authorizing request shadow and reserves its invitation.
    pub fn reserve_authorization(
        &self,
        protector: &dyn InvitationJoinProtector,
        input: AuthorizationShadowInput,
        now_unix_seconds: u64,
    ) -> Result<PendingAuthorization, StoreError> {
        if now_unix_seconds > i64::MAX as u64
            || input.request_issued_at > now_unix_seconds
            || input.request_expires_at <= now_unix_seconds
            || input.invitation_expires_at <= now_unix_seconds
        {
            return Err(StoreError::Rejected);
        }
        let mut inner = self.lock()?;
        if inner.live_pre_membership_attempts.len()
            >= self.authorization_policy.maximum_retained_attempts
        {
            return Err(StoreError::CapacityExceeded);
        }
        let transaction = inner
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        compact_expired_authorization_state(&transaction, now_unix_seconds as i64)?;
        let replayed = transaction
            .query_row(
                "SELECT 1 FROM authorization_attempts
                 WHERE generation = ?1 AND invitation_expires_at > ?2
                   AND (join_request_id = ?3 OR request_nonce = ?4 OR request_fingerprint = ?5)",
                params![
                    &input.invitation_generation,
                    now_unix_seconds as i64,
                    &input.join_request_id,
                    &input.request_nonce,
                    &input.request_fingerprint,
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some();
        if replayed {
            return Err(StoreError::Replay);
        }
        let retained_attempts: i64 =
            transaction.query_row("SELECT count(*) FROM authorization_attempts", [], |row| {
                row.get(0)
            })?;
        if retained_attempts < 0
            || retained_attempts as usize >= self.authorization_policy.maximum_retained_attempts
        {
            return Err(StoreError::CapacityExceeded);
        }
        let opening = transaction
            .query_row(
                "SELECT signed_invitation, hpke_private_key, expires_at, state
                 FROM invitation_opening_contexts
                 WHERE invitation_id = ?1 AND generation = ?2",
                params![&input.invitation_id, &input.invitation_generation],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StoreError::Conflict)?;
        let canonical_invitation = Zeroizing::new(opening.0);
        let private_key = Zeroizing::new(opening.1);
        if opening.2 <= now_unix_seconds as i64
            || opening.2 as u64 != input.invitation_expires_at
            || opening.3 != OPENING_AVAILABLE
        {
            return Err(StoreError::Conflict);
        }
        let private_key = match stored_invitation_private_key(private_key.as_slice()) {
            Ok(private_key) => private_key,
            Err(_) => {
                terminalize_opening_context(&transaction, &input.invitation_id)?;
                transaction.commit()?;
                return Err(StoreError::Rejected);
            }
        };
        let restoration =
            protector.restore_capability_invitation(canonical_invitation.as_slice(), private_key);
        let restored = match restoration {
            Ok(restored) => restored,
            Err(_) => {
                terminalize_opening_context(&transaction, &input.invitation_id)?;
                transaction.commit()?;
                return Err(StoreError::Rejected);
            }
        };
        if restored.invitation().invitation_id() != &input.invitation_id
            || restored.invitation().signature() != &input.invitation_generation
            || restored.invitation().join_challenge() != &input.invitation_challenge
            || restored.invitation().inviter_verifying_key() != &input.intended_verifier
            || restored.invitation().expires_at_unix_seconds() != input.invitation_expires_at
        {
            return Err(StoreError::Conflict);
        }
        let attempt_id = random_nonzero_identifier(&transaction)?;
        transaction.execute(
            "INSERT INTO authorization_attempts(
                 attempt_id, invitation_id, generation, invitation_challenge,
                 join_request_id, request_nonce, intended_verifier,
                 key_package_reference, mls_protocol_version, mls_ciphersuite,
                 credential_type, credential_identity, leaf_signature_key,
                 admission_proof_version, request_fingerprint, request_issued_at,
                 request_expires_at, invitation_expires_at, state, transaction_id
             ) VALUES (
                 ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, 1, 1, ?9, ?10, 1,
                 ?11, ?12, ?13, ?14, ?15, NULL
             )",
            params![
                attempt_id,
                &input.invitation_id,
                &input.invitation_generation,
                &input.invitation_challenge,
                &input.join_request_id,
                &input.request_nonce,
                &input.intended_verifier,
                &input.key_package_reference,
                &input.credential_identity,
                &input.leaf_signature_key,
                &input.request_fingerprint,
                input.request_issued_at as i64,
                input.request_expires_at as i64,
                input.invitation_expires_at as i64,
                AUTHORIZATION_PENDING_APPROVAL,
            ],
        )?;
        let changed = transaction.execute(
            "UPDATE invitation_opening_contexts SET state = ?1
             WHERE invitation_id = ?2 AND generation = ?3 AND state = ?4",
            params![
                OPENING_RESERVED,
                &input.invitation_id,
                &input.invitation_generation,
                OPENING_AVAILABLE,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict);
        }
        let store_id = store_id_on(&transaction)?;
        transaction.commit()?;
        inner.live_pre_membership_attempts.push(attempt_id);
        Ok(PendingAuthorization(AuthorizationHandle {
            open_scope: Arc::clone(&self.lease_scope),
            store_id,
            attempt_id,
            invitation_id: input.invitation_id,
            invitation_generation: input.invitation_generation,
        }))
    }

    /// Returns the secret-free retained state for one authorization attempt.
    pub fn authorization_state(
        &self,
        attempt_id: &[u8; 16],
    ) -> Result<Option<AuthorizationState>, StoreError> {
        self.lock()?
            .connection
            .query_row(
                "SELECT state FROM authorization_attempts WHERE attempt_id = ?1",
                params![attempt_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(decode_authorization_state)
            .transpose()
    }

    /// Records one explicit approval without reconstructing membership authority.
    pub fn approve_authorization(
        &self,
        pending: PendingAuthorization,
        protector: &dyn InvitationJoinProtector,
        now_unix_seconds: u64,
    ) -> Result<ApprovedAuthorization, StoreError> {
        if now_unix_seconds > i64::MAX as u64
            || !Arc::ptr_eq(&self.lease_scope, &pending.0.open_scope)
        {
            return Err(StoreError::Conflict);
        }
        let mut inner = self.lock()?;
        let transaction = inner
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_authorization_handle(&transaction, &pending.0, AUTHORIZATION_PENDING_APPROVAL)?;
        if authorization_is_expired(&transaction, &pending.0, now_unix_seconds)? {
            abandon_expired_authorization(
                &transaction,
                &pending.0,
                AUTHORIZATION_PENDING_APPROVAL,
                protector,
                now_unix_seconds,
            )?;
            transaction.commit()?;
            inner
                .live_pre_membership_attempts
                .retain(|attempt| attempt != &pending.0.attempt_id);
            return Err(StoreError::Rejected);
        }
        let changed = transaction.execute(
            "UPDATE authorization_attempts SET state = ?1
             WHERE attempt_id = ?2 AND state = ?3
               AND request_expires_at > ?4 AND invitation_expires_at > ?4",
            params![
                AUTHORIZATION_APPROVED_PENDING_MEMBERSHIP,
                pending.0.attempt_id,
                AUTHORIZATION_PENDING_APPROVAL,
                now_unix_seconds as i64,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict);
        }
        transaction.commit()?;
        Ok(ApprovedAuthorization(pending.0))
    }

    /// Persists the exact transaction ID before membership storage may begin.
    pub fn begin_membership_authorization(
        &self,
        approved: ApprovedAuthorization,
        transaction_id: [u8; 16],
        protector: &dyn InvitationJoinProtector,
        now_unix_seconds: u64,
    ) -> Result<MembershipAuthorization, StoreError> {
        if all_zero(&transaction_id)
            || now_unix_seconds > i64::MAX as u64
            || !Arc::ptr_eq(&self.lease_scope, &approved.0.open_scope)
        {
            return Err(StoreError::Conflict);
        }
        let mut inner = self.lock()?;
        if inner.live_membership_attempts.len()
            >= self.authorization_policy.maximum_retained_attempts
        {
            return Err(StoreError::CapacityExceeded);
        }
        let transaction = inner
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_authorization_handle(
            &transaction,
            &approved.0,
            AUTHORIZATION_APPROVED_PENDING_MEMBERSHIP,
        )?;
        if authorization_is_expired(&transaction, &approved.0, now_unix_seconds)? {
            abandon_expired_authorization(
                &transaction,
                &approved.0,
                AUTHORIZATION_APPROVED_PENDING_MEMBERSHIP,
                protector,
                now_unix_seconds,
            )?;
            transaction.commit()?;
            inner
                .live_pre_membership_attempts
                .retain(|attempt| attempt != &approved.0.attempt_id);
            return Err(StoreError::Rejected);
        }
        let changed = transaction.execute(
            "UPDATE authorization_attempts
             SET state = ?1, transaction_id = ?2
             WHERE attempt_id = ?3 AND state = ?4
               AND request_expires_at > ?5 AND invitation_expires_at > ?5",
            params![
                AUTHORIZATION_MEMBERSHIP_OUTCOME_UNKNOWN,
                transaction_id,
                approved.0.attempt_id,
                AUTHORIZATION_APPROVED_PENDING_MEMBERSHIP,
                now_unix_seconds as i64,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict);
        }
        transaction.commit()?;
        inner.live_membership_attempts.push(approved.0.attempt_id);
        inner
            .live_pre_membership_attempts
            .retain(|attempt| attempt != &approved.0.attempt_id);
        Ok(MembershipAuthorization {
            open_scope: approved.0.open_scope,
            store_id: approved.0.store_id,
            attempt_id: approved.0.attempt_id,
            transaction_id,
        })
    }

    /// Abandons one pending pre-approval attempt while retaining replay state.
    pub fn abandon_pending_authorization(
        &self,
        pending: PendingAuthorization,
        protector: &dyn InvitationJoinProtector,
        now_unix_seconds: u64,
    ) -> Result<(), StoreError> {
        if now_unix_seconds > i64::MAX as u64
            || !Arc::ptr_eq(&self.lease_scope, &pending.0.open_scope)
        {
            return Err(StoreError::Conflict);
        }
        let mut inner = self.lock()?;
        let transaction = inner
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_authorization_handle(&transaction, &pending.0, AUTHORIZATION_PENDING_APPROVAL)?;
        let changed = transaction.execute(
            "UPDATE authorization_attempts SET state = ?1
             WHERE attempt_id = ?2 AND state = ?3",
            params![
                AUTHORIZATION_ABANDONED,
                pending.0.attempt_id,
                AUTHORIZATION_PENDING_APPROVAL,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict);
        }
        release_opening_context(
            &transaction,
            protector,
            &pending.0.invitation_id,
            &pending.0.invitation_generation,
            now_unix_seconds,
        )?;
        transaction.commit()?;
        inner
            .live_pre_membership_attempts
            .retain(|attempt| attempt != &pending.0.attempt_id);
        Ok(())
    }

    /// Records one explicit rejection, retaining replay while releasing only its invitation.
    pub fn reject_authorization(
        &self,
        pending: PendingAuthorization,
        protector: &dyn InvitationJoinProtector,
        now_unix_seconds: u64,
    ) -> Result<(), StoreError> {
        if now_unix_seconds > i64::MAX as u64
            || !Arc::ptr_eq(&self.lease_scope, &pending.0.open_scope)
        {
            return Err(StoreError::Conflict);
        }
        let mut inner = self.lock()?;
        let transaction = inner
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_authorization_handle(&transaction, &pending.0, AUTHORIZATION_PENDING_APPROVAL)?;
        let changed = transaction.execute(
            "UPDATE authorization_attempts SET state = ?1
             WHERE attempt_id = ?2 AND state = ?3",
            params![
                AUTHORIZATION_REJECTED,
                pending.0.attempt_id,
                AUTHORIZATION_PENDING_APPROVAL,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict);
        }
        release_opening_context(
            &transaction,
            protector,
            &pending.0.invitation_id,
            &pending.0.invitation_generation,
            now_unix_seconds,
        )?;
        transaction.commit()?;
        inner
            .live_pre_membership_attempts
            .retain(|attempt| attempt != &pending.0.attempt_id);
        Ok(())
    }

    /// Abandons one approved pre-membership attempt while retaining replay state.
    pub fn abandon_approved_authorization(
        &self,
        approved: ApprovedAuthorization,
        protector: &dyn InvitationJoinProtector,
        now_unix_seconds: u64,
    ) -> Result<(), StoreError> {
        if now_unix_seconds > i64::MAX as u64
            || !Arc::ptr_eq(&self.lease_scope, &approved.0.open_scope)
        {
            return Err(StoreError::Conflict);
        }
        let mut inner = self.lock()?;
        let transaction = inner
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_authorization_handle(
            &transaction,
            &approved.0,
            AUTHORIZATION_APPROVED_PENDING_MEMBERSHIP,
        )?;
        let changed = transaction.execute(
            "UPDATE authorization_attempts SET state = ?1
             WHERE attempt_id = ?2 AND state = ?3",
            params![
                AUTHORIZATION_ABANDONED,
                approved.0.attempt_id,
                AUTHORIZATION_APPROVED_PENDING_MEMBERSHIP,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict);
        }
        release_opening_context(
            &transaction,
            protector,
            &approved.0.invitation_id,
            &approved.0.invitation_generation,
            now_unix_seconds,
        )?;
        transaction.commit()?;
        inner
            .live_pre_membership_attempts
            .retain(|attempt| attempt != &approved.0.attempt_id);
        Ok(())
    }

    /// Abandons every live pre-membership shadow after process restart.
    pub fn recover_pre_membership_authorizations(
        &self,
        protector: &dyn InvitationJoinProtector,
        now_unix_seconds: u64,
    ) -> Result<usize, StoreError> {
        if now_unix_seconds > i64::MAX as u64 {
            return Err(StoreError::Rejected);
        }
        let mut inner = self.lock()?;
        let live_attempts = inner.live_pre_membership_attempts.clone();
        let transaction = inner
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let attempts = {
            let mut statement = transaction.prepare(
                "SELECT attempt_id, invitation_id, generation
                 FROM authorization_attempts
                 WHERE state IN (?1, ?2)
                 ORDER BY attempt_id",
            )?;
            let rows = statement.query_map(
                params![
                    AUTHORIZATION_PENDING_APPROVAL,
                    AUTHORIZATION_APPROVED_PENDING_MEMBERSHIP
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        if attempts.iter().any(|(attempt_id, _, _)| {
            live_attempts
                .iter()
                .any(|live| live.as_slice() == attempt_id)
        }) {
            return Err(StoreError::Conflict);
        }
        for (attempt_id, invitation_id, generation) in &attempts {
            let attempt_id: [u8; 16] = attempt_id
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Rejected)?;
            let invitation_id: [u8; 16] = invitation_id
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Rejected)?;
            let generation: [u8; 64] = generation
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Rejected)?;
            let changed = transaction.execute(
                "UPDATE authorization_attempts SET state = ?1
                 WHERE attempt_id = ?2 AND state IN (?3, ?4)",
                params![
                    AUTHORIZATION_ABANDONED,
                    attempt_id,
                    AUTHORIZATION_PENDING_APPROVAL,
                    AUTHORIZATION_APPROVED_PENDING_MEMBERSHIP,
                ],
            )?;
            if changed != 1 {
                return Err(StoreError::Conflict);
            }
            release_opening_context(
                &transaction,
                protector,
                &invitation_id,
                &generation,
                now_unix_seconds,
            )?;
        }
        transaction.commit()?;
        Ok(attempts.len())
    }

    /// Resolves one outcome-unknown authorization from the exact retained inviter transaction.
    ///
    /// Recovery is rejected while the originating open scope still owns the live membership
    /// attempt. A fresh scope treats a missing exact inviter transaction as proven uncommitted.
    pub fn recover_authorization_outcome(
        &self,
        attempt_id: &[u8; 16],
        transaction_id: &[u8; 16],
        protector: &dyn InvitationJoinProtector,
        now_unix_seconds: u64,
    ) -> Result<AuthorizationState, StoreError> {
        if all_zero(attempt_id) || all_zero(transaction_id) || now_unix_seconds > i64::MAX as u64 {
            return Err(StoreError::Rejected);
        }
        let mut inner = self.lock()?;
        if inner
            .live_membership_attempts
            .iter()
            .any(|live| live == attempt_id)
        {
            return Err(StoreError::Conflict);
        }
        let transaction = inner
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let authorization = transaction
            .query_row(
                "SELECT invitation_id, generation, join_request_id,
                        request_fingerprint, transaction_id, state
                 FROM authorization_attempts
                 WHERE attempt_id = ?1 AND transaction_id = ?2",
                params![attempt_id, transaction_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StoreError::Conflict)?;
        let invitation_id: [u8; 16] = authorization
            .0
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Rejected)?;
        let generation: [u8; 64] = authorization
            .1
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Rejected)?;
        let join_request_id: [u8; 16] = authorization
            .2
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Rejected)?;
        let request_fingerprint: [u8; 32] = authorization
            .3
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Rejected)?;
        if authorization.4.as_slice() != transaction_id {
            return Err(StoreError::Conflict);
        }
        let authorization_state = decode_authorization_state(authorization.5)?;
        let committed = transaction
            .query_row(
                "SELECT invitation_id, generation, join_request_id, request_fingerprint
                 FROM inviter_joins WHERE transaction_id = ?1",
                params![transaction_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()?;
        if let Some(committed) = &committed
            && (committed.0.as_slice() != invitation_id
                || committed.1.as_slice() != generation
                || committed.2.as_slice() != join_request_id
                || committed.3.as_slice() != request_fingerprint)
        {
            return Err(StoreError::Conflict);
        }
        match authorization_state {
            AuthorizationState::Committed => {
                if committed.is_none() {
                    return Err(StoreError::Conflict);
                }
                let opening_state = transaction
                    .query_row(
                        "SELECT state FROM invitation_opening_contexts
                         WHERE invitation_id = ?1 AND generation = ?2",
                        params![invitation_id, generation],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()?;
                if opening_state != Some(OPENING_CONSUMED) {
                    return Err(StoreError::Conflict);
                }
                transaction.commit()?;
                return Ok(AuthorizationState::Committed);
            }
            AuthorizationState::Abandoned => {
                if committed.is_some() {
                    return Err(StoreError::Conflict);
                }
                transaction.commit()?;
                return Ok(AuthorizationState::Abandoned);
            }
            AuthorizationState::MembershipOutcomeUnknown => {}
            AuthorizationState::PendingApproval
            | AuthorizationState::ApprovedPendingMembership
            | AuthorizationState::Rejected => {
                return Err(StoreError::Conflict);
            }
        }
        let resolved = if committed.is_some() {
            let changed = transaction.execute(
                "UPDATE invitation_opening_contexts
                 SET state = ?1, hpke_private_key = zeroblob(32)
                 WHERE invitation_id = ?2 AND generation = ?3 AND state = ?4",
                params![
                    OPENING_CONSUMED,
                    invitation_id,
                    generation,
                    OPENING_RESERVED,
                ],
            )?;
            if changed != 1 {
                return Err(StoreError::Conflict);
            }
            AUTHORIZATION_COMMITTED
        } else {
            release_opening_context(
                &transaction,
                protector,
                &invitation_id,
                &generation,
                now_unix_seconds,
            )?;
            AUTHORIZATION_ABANDONED
        };
        let changed = transaction.execute(
            "UPDATE authorization_attempts SET state = ?1
             WHERE attempt_id = ?2 AND transaction_id = ?3 AND state = ?4",
            params![
                resolved,
                attempt_id,
                transaction_id,
                AUTHORIZATION_MEMBERSHIP_OUTCOME_UNKNOWN,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict);
        }
        transaction.commit()?;
        decode_authorization_state(resolved)
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
        let changed = self.lock()?.connection.execute(
            "INSERT INTO reservations(
                 invitation_id, generation, join_request_id, expires_at, state
             ) SELECT ?1, ?2, ?3, ?4, 1
             WHERE NOT EXISTS (
                 SELECT 1 FROM invitation_opening_contexts
                 WHERE invitation_id = ?1 AND generation = ?2
             )",
            params![
                invitation_id,
                invitation_generation,
                join_request_id,
                expires_at as i64
            ],
        )?;
        if changed == 1 {
            Ok(())
        } else {
            Err(StoreError::Conflict)
        }
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
            authorization: None,
            addition: None,
            now_unix_seconds,
            staged_at: Instant::now(),
            fault,
        });
        Ok(())
    }

    /// Stages one inviter transaction under its exact durable membership authorization.
    pub fn stage_authorized_inviter(
        &self,
        authorization: MembershipAuthorization,
        addition: CommittedAdditionStorageBinding,
        transaction: InviterJoinTransaction,
        now_unix_seconds: u64,
        fault: PersistenceFault,
    ) -> Result<(), StoreError> {
        if !Arc::ptr_eq(&self.lease_scope, &authorization.open_scope) {
            return Err(StoreError::Conflict);
        }
        let attempt_id = authorization.attempt_id;
        if let Err(error) = validate_inviter(&transaction, now_unix_seconds) {
            self.lock()?
                .live_membership_attempts
                .retain(|live| live != &attempt_id);
            return Err(error);
        }
        let mut inner = self.lock()?;
        if authorization.transaction_id != transaction.transaction_id
            || inner.staged_inviter.is_some()
            || inner.staged_joiner.is_some()
            || inner.pending_joiner.is_some()
            || store_id_on(&inner.connection)? != authorization.store_id
            || !authorization_matches_inviter(
                &inner.connection,
                &authorization,
                &addition,
                &transaction,
                AUTHORIZATION_MEMBERSHIP_OUTCOME_UNKNOWN,
                now_unix_seconds,
            )?
        {
            inner
                .live_membership_attempts
                .retain(|live| live != &attempt_id);
            return Err(StoreError::Conflict);
        }
        inner.staged_inviter = Some(StagedInviter {
            transaction,
            authorization: Some(authorization),
            addition: Some(addition),
            now_unix_seconds,
            staged_at: Instant::now(),
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

    fn open_internal(
        path: &Path,
        key: VaultKey,
        create: bool,
        mode: OpenMode,
        authorization_policy: AuthorizationPolicy,
    ) -> Result<Self, StoreError> {
        let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        if create {
            flags |= OpenFlags::SQLITE_OPEN_CREATE;
        }
        let connection = match &mode {
            OpenMode::Default => Connection::open_with_flags(path, flags)?,
            #[cfg(session_chat_storage_fault_testing)]
            OpenMode::ObservedDefault(_) => Connection::open_with_flags(path, flags)?,
            #[cfg(session_chat_storage_fault_testing)]
            OpenMode::ObservedFaultVfs(_) => {
                Connection::open_with_flags_and_vfs(path, flags, fault_testing::FAULT_VFS_NAME)?
            }
        };
        #[cfg(session_chat_storage_fault_testing)]
        let fault_observer = match mode {
            OpenMode::Default => None,
            OpenMode::ObservedDefault(observer) | OpenMode::ObservedFaultVfs(observer) => {
                Some(observer)
            }
        };

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
            create_schema(&connection, authorization_policy)?;
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
            if versions == (4, 4) {
                migrate_schema_v4_to_v5(&connection, authorization_policy)?;
                versions = schema_versions(&connection)?;
            }
            if versions != (SCHEMA_VERSION, i64::from(SCHEMA_VERSION)) {
                return Err(StoreError::Rejected);
            }
        }
        validate_schema_v5(&connection, authorization_policy)?;

        Ok(Self {
            inner: Arc::new(Mutex::new(StorageInner {
                connection,
                staged_inviter: None,
                staged_joiner: None,
                pending_joiner: None,
                live_pre_membership_attempts: Vec::new(),
                live_membership_attempts: Vec::new(),
                #[cfg(session_chat_storage_fault_testing)]
                fault_observer,
            })),
            lease_scope: Arc::new(()),
            authorization_policy,
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
        #[cfg(session_chat_storage_fault_testing)]
        let fault_observer = inner.fault_observer.clone();
        if let Some(staged) = inner.staged_inviter.take() {
            let authorization_attempt = staged
                .authorization
                .as_ref()
                .map(|authorization| authorization.attempt_id);
            let result = commit_inviter(
                &mut inner.connection,
                &staged,
                &state,
                &epoch_inserts,
                &epoch_updates,
                #[cfg(session_chat_storage_fault_testing)]
                fault_observer.as_ref(),
            );
            if let Some(attempt_id) = authorization_attempt {
                inner
                    .live_membership_attempts
                    .retain(|live| live != &attempt_id);
            }
            return result;
        }
        let staged = inner.staged_joiner.take().ok_or(StoreError::Rejected)?;
        begin_joiner(
            &mut inner,
            staged,
            &state,
            &epoch_inserts,
            &epoch_updates,
            #[cfg(session_chat_storage_fault_testing)]
            fault_observer.as_ref(),
        )
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
        #[cfg(session_chat_storage_fault_testing)]
        let fault_observer = inner.fault_observer.clone();
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
        #[cfg(session_chat_storage_fault_testing)]
        if emit_fault_checkpoint(
            fault_observer.as_ref(),
            fault_testing::Checkpoint::JoinerBeforeKeyPackageDelete,
            0,
        )
        .is_err()
        {
            rollback(&inner.connection);
            return Err(StoreError::Rejected);
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
        if changed != 1 {
            rollback(&inner.connection);
            return Err(StoreError::Rejected);
        }
        #[cfg(session_chat_storage_fault_testing)]
        if emit_fault_checkpoint(
            fault_observer.as_ref(),
            fault_testing::Checkpoint::JoinerAfterKeyPackageDelete,
            0,
        )
        .is_err()
        {
            rollback(&inner.connection);
            return Err(StoreError::Rejected);
        }
        #[cfg(session_chat_storage_fault_testing)]
        if emit_fault_checkpoint(
            fault_observer.as_ref(),
            fault_testing::Checkpoint::JoinerBeforeCommit,
            0,
        )
        .is_err()
        {
            rollback(&inner.connection);
            return Err(StoreError::Rejected);
        }
        if pending.fault == PersistenceFault::BeforeCommit {
            rollback(&inner.connection);
            return Err(StoreError::InjectedFailure);
        }
        if inner.connection.execute_batch("COMMIT;").is_err() {
            rollback(&inner.connection);
            return Err(StoreError::Rejected);
        }
        #[cfg(session_chat_storage_fault_testing)]
        emit_fault_checkpoint(
            fault_observer.as_ref(),
            fault_testing::Checkpoint::JoinerAfterCommitReturn,
            0,
        )
        .map_err(|_| StoreError::OutcomeUnknown)?;
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

fn create_schema(
    connection: &Connection,
    authorization_policy: AuthorizationPolicy,
) -> Result<(), StoreError> {
    let store_id = random_nonzero_identifier(connection)?;
    connection.execute_batch(
        "BEGIN IMMEDIATE;
         CREATE TABLE storage_metadata (
             singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
             schema_version INTEGER NOT NULL CHECK(schema_version = 5),
             store_id BLOB NOT NULL UNIQUE CHECK(length(store_id) = 16),
             maximum_live_invitations INTEGER NOT NULL
                 CHECK(maximum_live_invitations BETWEEN 1 AND 8),
             maximum_retained_attempts INTEGER NOT NULL
                 CHECK(maximum_retained_attempts BETWEEN 1 AND 8)
         ) STRICT;

         CREATE TABLE reservations (
             invitation_id BLOB PRIMARY KEY CHECK(length(invitation_id) = 16),
             generation BLOB NOT NULL CHECK(length(generation) = 64),
             join_request_id BLOB NOT NULL CHECK(length(join_request_id) = 16),
             expires_at INTEGER NOT NULL CHECK(expires_at > 0),
             state INTEGER NOT NULL CHECK(state IN (1, 2))
         ) STRICT;

         CREATE TABLE authorization_attempts (
             attempt_id BLOB PRIMARY KEY CHECK(length(attempt_id) = 16),
             invitation_id BLOB NOT NULL REFERENCES invitation_opening_contexts(invitation_id),
             generation BLOB NOT NULL CHECK(length(generation) = 64),
             invitation_challenge BLOB NOT NULL CHECK(length(invitation_challenge) = 32),
             join_request_id BLOB NOT NULL CHECK(length(join_request_id) = 16),
             request_nonce BLOB NOT NULL CHECK(length(request_nonce) = 32),
             intended_verifier BLOB NOT NULL CHECK(length(intended_verifier) = 32),
             key_package_reference BLOB NOT NULL CHECK(length(key_package_reference) = 32),
             mls_protocol_version INTEGER NOT NULL CHECK(mls_protocol_version = 1),
             mls_ciphersuite INTEGER NOT NULL CHECK(mls_ciphersuite = 1),
             credential_type INTEGER NOT NULL CHECK(credential_type = 1),
             credential_identity BLOB NOT NULL CHECK(length(credential_identity) = 32),
             leaf_signature_key BLOB NOT NULL CHECK(length(leaf_signature_key) = 32),
             admission_proof_version INTEGER NOT NULL CHECK(admission_proof_version = 1),
             request_fingerprint BLOB NOT NULL CHECK(length(request_fingerprint) = 32),
             request_issued_at INTEGER NOT NULL CHECK(request_issued_at > 0),
             request_expires_at INTEGER NOT NULL CHECK(request_expires_at > request_issued_at),
             invitation_expires_at INTEGER NOT NULL
                 CHECK(invitation_expires_at >= request_expires_at),
             state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 6),
             transaction_id BLOB CHECK(transaction_id IS NULL OR length(transaction_id) = 16),
             UNIQUE(transaction_id),
             UNIQUE(generation, join_request_id),
             UNIQUE(generation, request_nonce),
             UNIQUE(generation, request_fingerprint),
             CHECK(
                 (state IN (1, 2, 5) AND transaction_id IS NULL)
                 OR (state IN (3, 4) AND transaction_id IS NOT NULL)
                 OR state = 6
             )
         ) STRICT;

         CREATE TABLE invitation_opening_contexts (
             invitation_id BLOB PRIMARY KEY CHECK(length(invitation_id) = 16),
             generation BLOB NOT NULL UNIQUE CHECK(length(generation) = 64),
             signed_invitation BLOB NOT NULL
                 CHECK(length(signed_invitation) BETWEEN 1 AND 512),
             hpke_private_key BLOB NOT NULL CHECK(length(hpke_private_key) = 32),
             issued_at INTEGER NOT NULL CHECK(issued_at > 0),
             expires_at INTEGER NOT NULL CHECK(expires_at > issued_at),
             state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 4)
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
         PRAGMA user_version = 5;",
    )?;
    if connection
        .execute(
            "INSERT INTO storage_metadata(
                 singleton, schema_version, store_id,
                 maximum_live_invitations, maximum_retained_attempts
             ) VALUES (1, 5, ?1, ?2, ?3)",
            params![
                store_id,
                authorization_policy.maximum_live_invitations as i64,
                authorization_policy.maximum_retained_attempts as i64,
            ],
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

fn migrate_schema_v4_to_v5(
    connection: &Connection,
    authorization_policy: AuthorizationPolicy,
) -> Result<(), StoreError> {
    let migration = (|| {
        connection.execute_batch(
            "BEGIN EXCLUSIVE;
             ALTER TABLE storage_metadata RENAME TO storage_metadata_v4;
             CREATE TABLE storage_metadata (
                 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                 schema_version INTEGER NOT NULL CHECK(schema_version = 5),
                 store_id BLOB NOT NULL UNIQUE CHECK(length(store_id) = 16),
                 maximum_live_invitations INTEGER NOT NULL
                     CHECK(maximum_live_invitations BETWEEN 1 AND 8),
                 maximum_retained_attempts INTEGER NOT NULL
                     CHECK(maximum_retained_attempts BETWEEN 1 AND 8)
             ) STRICT;",
        )?;
        connection.execute(
            "INSERT INTO storage_metadata(
                 singleton, schema_version, store_id,
                 maximum_live_invitations, maximum_retained_attempts
             ) SELECT singleton, 5, store_id, ?1, ?2 FROM storage_metadata_v4",
            params![
                authorization_policy.maximum_live_invitations as i64,
                authorization_policy.maximum_retained_attempts as i64,
            ],
        )?;
        connection.execute_batch(
            "CREATE TABLE invitation_opening_contexts (
                 invitation_id BLOB PRIMARY KEY CHECK(length(invitation_id) = 16),
                 generation BLOB NOT NULL UNIQUE CHECK(length(generation) = 64),
                 signed_invitation BLOB NOT NULL
                     CHECK(length(signed_invitation) BETWEEN 1 AND 512),
                 hpke_private_key BLOB NOT NULL CHECK(length(hpke_private_key) = 32),
                 issued_at INTEGER NOT NULL CHECK(issued_at > 0),
                 expires_at INTEGER NOT NULL CHECK(expires_at > issued_at),
                 state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 4)
             ) STRICT;
             CREATE TABLE authorization_attempts (
                 attempt_id BLOB PRIMARY KEY CHECK(length(attempt_id) = 16),
                 invitation_id BLOB NOT NULL REFERENCES invitation_opening_contexts(invitation_id),
                 generation BLOB NOT NULL CHECK(length(generation) = 64),
                 invitation_challenge BLOB NOT NULL CHECK(length(invitation_challenge) = 32),
                 join_request_id BLOB NOT NULL CHECK(length(join_request_id) = 16),
                 request_nonce BLOB NOT NULL CHECK(length(request_nonce) = 32),
                 intended_verifier BLOB NOT NULL CHECK(length(intended_verifier) = 32),
                 key_package_reference BLOB NOT NULL CHECK(length(key_package_reference) = 32),
                 mls_protocol_version INTEGER NOT NULL CHECK(mls_protocol_version = 1),
                 mls_ciphersuite INTEGER NOT NULL CHECK(mls_ciphersuite = 1),
                 credential_type INTEGER NOT NULL CHECK(credential_type = 1),
                 credential_identity BLOB NOT NULL CHECK(length(credential_identity) = 32),
                 leaf_signature_key BLOB NOT NULL CHECK(length(leaf_signature_key) = 32),
                 admission_proof_version INTEGER NOT NULL CHECK(admission_proof_version = 1),
                 request_fingerprint BLOB NOT NULL CHECK(length(request_fingerprint) = 32),
                 request_issued_at INTEGER NOT NULL CHECK(request_issued_at > 0),
                 request_expires_at INTEGER NOT NULL
                     CHECK(request_expires_at > request_issued_at),
                 invitation_expires_at INTEGER NOT NULL
                     CHECK(invitation_expires_at >= request_expires_at),
                 state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 6),
                 transaction_id BLOB CHECK(transaction_id IS NULL OR length(transaction_id) = 16),
                 UNIQUE(transaction_id),
                 UNIQUE(generation, join_request_id),
                 UNIQUE(generation, request_nonce),
                 UNIQUE(generation, request_fingerprint),
                 CHECK(
                     (state IN (1, 2, 5) AND transaction_id IS NULL)
                     OR (state IN (3, 4) AND transaction_id IS NOT NULL)
                     OR state = 6
                 )
             ) STRICT;
             DROP TABLE storage_metadata_v4;
             PRAGMA user_version = 5;
             COMMIT;",
        )?;
        Ok(())
    })();
    if migration.is_err() {
        rollback(connection);
    }
    migration
}

fn validate_schema_v5(
    connection: &Connection,
    authorization_policy: AuthorizationPolicy,
) -> Result<(), StoreError> {
    let rows = connection.query_row(
        "SELECT count(*), min(schema_version), max(schema_version), min(store_id),
                min(maximum_live_invitations), min(maximum_retained_attempts)
         FROM storage_metadata",
        [],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, Option<i64>>(5)?,
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
    if rows.4 != Some(authorization_policy.maximum_live_invitations as i64)
        || rows.5 != Some(authorization_policy.maximum_retained_attempts as i64)
    {
        return Err(StoreError::Conflict);
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
    let invalid_opening_rows: i64 = connection.query_row(
        "SELECT count(*) FROM invitation_opening_contexts
         WHERE invitation_id = zeroblob(16)
            OR generation = zeroblob(64)
            OR (state IN (?1, ?2) AND hpke_private_key = zeroblob(32))
            OR (state IN (?3, ?4) AND hpke_private_key != zeroblob(32))",
        params![
            OPENING_AVAILABLE,
            OPENING_RESERVED,
            OPENING_CONSUMED,
            OPENING_UNUSABLE,
        ],
        |row| row.get(0),
    )?;
    if invalid_opening_rows != 0 {
        return Err(StoreError::Rejected);
    }
    let opening_rows: i64 = connection.query_row(
        "SELECT count(*) FROM invitation_opening_contexts",
        [],
        |row| row.get(0),
    )?;
    let authorization_rows: i64 =
        connection.query_row("SELECT count(*) FROM authorization_attempts", [], |row| {
            row.get(0)
        })?;
    if opening_rows < 0
        || opening_rows as usize > authorization_policy.maximum_live_invitations
        || authorization_rows < 0
        || authorization_rows as usize > authorization_policy.maximum_retained_attempts
    {
        return Err(StoreError::Rejected);
    }
    let invalid_authorization_rows: i64 = connection.query_row(
        "SELECT count(*)
         FROM authorization_attempts AS a
         LEFT JOIN invitation_opening_contexts AS i
           ON i.invitation_id = a.invitation_id AND i.generation = a.generation
         WHERE i.invitation_id IS NULL
            OR a.attempt_id = zeroblob(16)
            OR a.invitation_id = zeroblob(16)
            OR a.generation = zeroblob(64)
            OR a.invitation_challenge = zeroblob(32)
            OR a.join_request_id = zeroblob(16)
            OR a.request_nonce = zeroblob(32)
            OR a.intended_verifier = zeroblob(32)
            OR a.key_package_reference = zeroblob(32)
            OR a.credential_identity = zeroblob(32)
            OR a.leaf_signature_key = zeroblob(32)
            OR a.request_fingerprint = zeroblob(32)
            OR a.invitation_expires_at != i.expires_at
            OR (a.transaction_id IS NOT NULL AND a.transaction_id = zeroblob(16))",
        [],
        |row| row.get(0),
    )?;
    if invalid_authorization_rows != 0 {
        return Err(StoreError::Rejected);
    }
    let invalid_authorization_ownership: i64 = connection.query_row(
        "SELECT count(*) FROM invitation_opening_contexts AS i
         WHERE (
             i.state = ?1 AND 1 != (
                 SELECT count(*) FROM authorization_attempts AS a
                 WHERE a.invitation_id = i.invitation_id
                   AND a.generation = i.generation
                   AND a.state IN (?2, ?3, ?4)
             )
         ) OR (
             i.state != ?1 AND EXISTS (
                 SELECT 1 FROM authorization_attempts AS a
                 WHERE a.invitation_id = i.invitation_id
                   AND a.generation = i.generation
                   AND a.state IN (?2, ?3, ?4)
             )
         )",
        params![
            OPENING_RESERVED,
            AUTHORIZATION_PENDING_APPROVAL,
            AUTHORIZATION_APPROVED_PENDING_MEMBERSHIP,
            AUTHORIZATION_MEMBERSHIP_OUTCOME_UNKNOWN,
        ],
        |row| row.get(0),
    )?;
    if invalid_authorization_ownership != 0 {
        return Err(StoreError::Rejected);
    }
    let invalid_committed_authorizations: i64 = connection.query_row(
        "SELECT count(*) FROM authorization_attempts AS a
         LEFT JOIN invitation_opening_contexts AS i
           ON i.invitation_id = a.invitation_id AND i.generation = a.generation
         LEFT JOIN inviter_joins AS j
           ON j.transaction_id = a.transaction_id
          AND j.invitation_id = a.invitation_id AND j.generation = a.generation
          AND j.join_request_id = a.join_request_id
          AND j.request_fingerprint = a.request_fingerprint
         LEFT JOIN reservations AS r
           ON r.invitation_id = a.invitation_id AND r.generation = a.generation
          AND r.join_request_id = a.join_request_id
         WHERE a.state = ?1
           AND (i.state IS NULL OR i.state != ?2 OR j.transaction_id IS NULL
                OR r.state IS NULL OR r.state != 2)",
        params![AUTHORIZATION_COMMITTED, OPENING_CONSUMED],
        |row| row.get(0),
    )?;
    let invalid_abandoned_authorizations: i64 = connection.query_row(
        "SELECT count(*) FROM authorization_attempts AS a
         JOIN inviter_joins AS j ON j.transaction_id = a.transaction_id
         WHERE a.state = ?1",
        params![AUTHORIZATION_ABANDONED],
        |row| row.get(0),
    )?;
    let invalid_opening_owned_results: i64 = connection.query_row(
        "SELECT count(*) FROM inviter_joins AS j
         JOIN invitation_opening_contexts AS i
           ON i.invitation_id = j.invitation_id AND i.generation = j.generation
         LEFT JOIN authorization_attempts AS a
           ON a.transaction_id = j.transaction_id
          AND a.invitation_id = j.invitation_id AND a.generation = j.generation
          AND a.join_request_id = j.join_request_id
          AND a.request_fingerprint = j.request_fingerprint
          AND a.state = ?1
         WHERE a.attempt_id IS NULL",
        params![AUTHORIZATION_COMMITTED],
        |row| row.get(0),
    )?;
    let invalid_consumed_openings: i64 = connection.query_row(
        "SELECT count(*) FROM invitation_opening_contexts AS i
         WHERE i.state = ?1 AND NOT EXISTS (
             SELECT 1 FROM authorization_attempts AS a
             WHERE a.invitation_id = i.invitation_id AND a.generation = i.generation
               AND a.state = ?2
         )",
        params![OPENING_CONSUMED, AUTHORIZATION_COMMITTED],
        |row| row.get(0),
    )?;
    if invalid_committed_authorizations != 0
        || invalid_abandoned_authorizations != 0
        || invalid_opening_owned_results != 0
        || invalid_consumed_openings != 0
    {
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

fn map_join_protection_error(_: JoinProtectionError) -> StoreError {
    StoreError::Rejected
}

fn stored_invitation_private_key(
    bytes: &[u8],
) -> Result<StoredInvitationHpkePrivateKey, StoreError> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| StoreError::Rejected)?;
    StoredInvitationHpkePrivateKey::from_bytes(Zeroizing::new(bytes))
        .map_err(map_join_protection_error)
}

fn compact_expired_authorization_state(
    connection: &Connection,
    now_unix_seconds: i64,
) -> Result<(), StoreError> {
    connection.execute(
        "UPDATE invitation_opening_contexts
         SET state = ?1, hpke_private_key = zeroblob(32)
         WHERE state = ?2 AND expires_at <= ?3
           AND EXISTS (
               SELECT 1 FROM authorization_attempts AS a
               WHERE a.invitation_id = invitation_opening_contexts.invitation_id
                 AND a.generation = invitation_opening_contexts.generation
                 AND a.invitation_expires_at <= ?3
                 AND a.state IN (?4, ?5, ?6)
           )",
        params![
            OPENING_UNUSABLE,
            OPENING_RESERVED,
            now_unix_seconds,
            AUTHORIZATION_COMMITTED,
            AUTHORIZATION_REJECTED,
            AUTHORIZATION_ABANDONED,
        ],
    )?;
    connection.execute(
        "DELETE FROM authorization_attempts
         WHERE invitation_expires_at <= ?1 AND state IN (?2, ?3, ?4)",
        params![
            now_unix_seconds,
            AUTHORIZATION_COMMITTED,
            AUTHORIZATION_REJECTED,
            AUTHORIZATION_ABANDONED,
        ],
    )?;
    connection.execute(
        "UPDATE invitation_opening_contexts
         SET state = ?1, hpke_private_key = zeroblob(32)
         WHERE state = ?2 AND expires_at <= ?3",
        params![OPENING_UNUSABLE, OPENING_AVAILABLE, now_unix_seconds],
    )?;
    connection.execute(
        "DELETE FROM invitation_opening_contexts
         WHERE state IN (?1, ?2) AND expires_at <= ?3",
        params![OPENING_UNUSABLE, OPENING_CONSUMED, now_unix_seconds],
    )?;
    Ok(())
}

fn terminalize_opening_context(
    connection: &Connection,
    invitation_id: &[u8; 16],
) -> Result<(), StoreError> {
    let changed = connection.execute(
        "UPDATE invitation_opening_contexts
         SET state = ?1, hpke_private_key = zeroblob(32)
         WHERE invitation_id = ?2 AND state = ?3",
        params![OPENING_UNUSABLE, invitation_id, OPENING_AVAILABLE],
    )?;
    if changed != 1 {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

fn validate_authorization_handle(
    connection: &Connection,
    handle: &AuthorizationHandle,
    expected_state: i64,
) -> Result<(), StoreError> {
    if store_id_on(connection)? != handle.store_id {
        return Err(StoreError::Conflict);
    }
    let exact = connection
        .query_row(
            "SELECT 1 FROM authorization_attempts AS a
             JOIN invitation_opening_contexts AS i
               ON i.invitation_id = a.invitation_id AND i.generation = a.generation
             WHERE a.attempt_id = ?1 AND a.invitation_id = ?2
               AND a.generation = ?3 AND a.state = ?4 AND i.state = ?5",
            params![
                handle.attempt_id,
                handle.invitation_id,
                handle.invitation_generation,
                expected_state,
                OPENING_RESERVED,
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some();
    if !exact {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

fn authorization_matches_inviter(
    connection: &Connection,
    authorization: &MembershipAuthorization,
    addition: &CommittedAdditionStorageBinding,
    inviter: &InviterJoinTransaction,
    expected_state: i64,
    now_unix_seconds: u64,
) -> Result<bool, StoreError> {
    let welcome =
        OpaqueEnvelope::decode_canonical(&inviter.welcome).map_err(|_| StoreError::Rejected)?;
    if addition.group_id() != &inviter.group_id
        || addition.epoch_before() != inviter.epoch_before
        || addition.epoch_after() != inviter.epoch_after
        || addition.welcome().as_bytes() != welcome.ciphertext()
    {
        return Ok(false);
    }
    Ok(connection
        .query_row(
            "SELECT 1 FROM authorization_attempts AS a
             JOIN invitation_opening_contexts AS i
               ON i.invitation_id = a.invitation_id AND i.generation = a.generation
             WHERE a.attempt_id = ?1 AND a.transaction_id = ?2
               AND a.invitation_id = ?3 AND a.generation = ?4
               AND a.join_request_id = ?5 AND a.request_fingerprint = ?6
               AND a.key_package_reference = ?7 AND a.credential_identity = ?8
               AND a.leaf_signature_key = ?9 AND a.state = ?10
               AND a.request_expires_at > ?11
               AND a.invitation_expires_at > ?11 AND i.state = ?12",
            params![
                authorization.attempt_id,
                authorization.transaction_id,
                inviter.invitation_id,
                inviter.invitation_generation,
                inviter.join_request_id,
                inviter.request_fingerprint,
                addition.key_package_reference(),
                addition.credential_identity(),
                addition.leaf_signature_key(),
                expected_state,
                now_unix_seconds as i64,
                OPENING_RESERVED,
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some())
}

fn authorization_is_expired(
    connection: &Connection,
    handle: &AuthorizationHandle,
    now_unix_seconds: u64,
) -> Result<bool, StoreError> {
    connection
        .query_row(
            "SELECT request_expires_at <= ?1 OR invitation_expires_at <= ?1
             FROM authorization_attempts WHERE attempt_id = ?2",
            params![now_unix_seconds as i64, handle.attempt_id],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
}

fn abandon_expired_authorization(
    connection: &Connection,
    handle: &AuthorizationHandle,
    expected_state: i64,
    protector: &dyn InvitationJoinProtector,
    now_unix_seconds: u64,
) -> Result<(), StoreError> {
    let changed = connection.execute(
        "UPDATE authorization_attempts SET state = ?1
         WHERE attempt_id = ?2 AND state = ?3",
        params![AUTHORIZATION_ABANDONED, handle.attempt_id, expected_state],
    )?;
    if changed != 1 {
        return Err(StoreError::Conflict);
    }
    release_opening_context(
        connection,
        protector,
        &handle.invitation_id,
        &handle.invitation_generation,
        now_unix_seconds,
    )
}

fn release_opening_context(
    connection: &Connection,
    protector: &dyn InvitationJoinProtector,
    invitation_id: &[u8; 16],
    generation: &[u8; 64],
    now_unix_seconds: u64,
) -> Result<(), StoreError> {
    let opening = connection
        .query_row(
            "SELECT signed_invitation, hpke_private_key, expires_at, state
             FROM invitation_opening_contexts
             WHERE invitation_id = ?1 AND generation = ?2",
            params![invitation_id, generation],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or(StoreError::Conflict)?;
    if opening.3 != OPENING_RESERVED {
        return Err(StoreError::Conflict);
    }
    let canonical_invitation = Zeroizing::new(opening.0);
    let private_key = Zeroizing::new(opening.1);
    let restored = stored_invitation_private_key(private_key.as_slice())
        .ok()
        .and_then(|private_key| {
            protector
                .restore_capability_invitation(canonical_invitation.as_slice(), private_key)
                .ok()
        });
    let usable = opening.2 > now_unix_seconds as i64
        && restored.as_ref().is_some_and(|restored| {
            restored.invitation().invitation_id() == invitation_id
                && restored.invitation().signature() == generation
                && restored.invitation().expires_at_unix_seconds() == opening.2 as u64
        });
    let changed = if usable {
        connection.execute(
            "UPDATE invitation_opening_contexts SET state = ?1
             WHERE invitation_id = ?2 AND generation = ?3 AND state = ?4",
            params![
                OPENING_AVAILABLE,
                invitation_id,
                generation,
                OPENING_RESERVED,
            ],
        )?
    } else {
        connection.execute(
            "UPDATE invitation_opening_contexts
             SET state = ?1, hpke_private_key = zeroblob(32)
             WHERE invitation_id = ?2 AND generation = ?3 AND state = ?4",
            params![
                OPENING_UNUSABLE,
                invitation_id,
                generation,
                OPENING_RESERVED,
            ],
        )?
    };
    if changed != 1 {
        return Err(StoreError::Conflict);
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

fn decode_authorization_state(value: i64) -> Result<AuthorizationState, StoreError> {
    match value {
        AUTHORIZATION_PENDING_APPROVAL => Ok(AuthorizationState::PendingApproval),
        AUTHORIZATION_APPROVED_PENDING_MEMBERSHIP => {
            Ok(AuthorizationState::ApprovedPendingMembership)
        }
        AUTHORIZATION_MEMBERSHIP_OUTCOME_UNKNOWN => {
            Ok(AuthorizationState::MembershipOutcomeUnknown)
        }
        AUTHORIZATION_COMMITTED => Ok(AuthorizationState::Committed),
        AUTHORIZATION_REJECTED => Ok(AuthorizationState::Rejected),
        AUTHORIZATION_ABANDONED => Ok(AuthorizationState::Abandoned),
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
        StoreError::Rejected
        | StoreError::InjectedFailure
        | StoreError::OutcomeUnknown
        | StoreError::Replay
        | StoreError::CapacityExceeded => OutboxPortError::Internal,
    }
}

fn commit_inviter(
    connection: &mut Connection,
    staged: &StagedInviter,
    state: &GroupState,
    epoch_inserts: &[EpochRecord],
    epoch_updates: &[EpochRecord],
    #[cfg(session_chat_storage_fault_testing)] fault_observer: Option<
        &fault_testing::FaultObserver,
    >,
) -> Result<(), StoreError> {
    let commit = &staged.transaction;
    if state.id.as_slice() != commit.group_id || commit.epoch_after > i64::MAX as u64 {
        return Err(StoreError::Rejected);
    }
    #[cfg(session_chat_storage_fault_testing)]
    emit_fault_checkpoint(
        fault_observer,
        fault_testing::Checkpoint::InviterBeforeBegin,
        0,
    )?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let commit_now_unix_seconds = staged
        .now_unix_seconds
        .checked_add(staged.staged_at.elapsed().as_secs())
        .ok_or(StoreError::Rejected)?;
    validate_inviter(commit, commit_now_unix_seconds)?;
    if let (Some(authorization), Some(addition)) = (&staged.authorization, &staged.addition) {
        if !addition.authorizes_current_provider_write(state, epoch_inserts, epoch_updates)
            || store_id_on(&transaction)? != authorization.store_id
            || !authorization_matches_inviter(
                &transaction,
                authorization,
                addition,
                commit,
                AUTHORIZATION_MEMBERSHIP_OUTCOME_UNKNOWN,
                commit_now_unix_seconds,
            )?
        {
            return Err(StoreError::Conflict);
        }
    } else if staged.authorization.is_none() && staged.addition.is_none() {
        let durable_opening_exists = transaction
            .query_row(
                "SELECT 1 FROM invitation_opening_contexts
                 WHERE invitation_id = ?1 AND generation = ?2",
                params![commit.invitation_id, commit.invitation_generation],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some();
        if durable_opening_exists {
            return Err(StoreError::Conflict);
        }
    } else {
        return Err(StoreError::Rejected);
    }
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

    if staged.authorization.is_none() {
        let reservation_matches = transaction
            .query_row(
                "SELECT 1 FROM reservations
                 WHERE invitation_id = ?1 AND generation = ?2 AND join_request_id = ?3
                   AND expires_at > ?4 AND state = 1",
                params![
                    commit.invitation_id,
                    commit.invitation_generation,
                    commit.join_request_id,
                    commit_now_unix_seconds as i64
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some();
        if !reservation_matches {
            return Err(StoreError::Rejected);
        }
    }

    persist_mls(
        &transaction,
        state,
        epoch_inserts,
        epoch_updates,
        #[cfg(session_chat_storage_fault_testing)]
        fault_observer,
        #[cfg(session_chat_storage_fault_testing)]
        fault_testing::Scenario::InviterTransaction,
    )?;
    if let Some(authorization) = &staged.authorization {
        let invitation_expires_at: i64 = transaction.query_row(
            "SELECT invitation_expires_at FROM authorization_attempts
             WHERE attempt_id = ?1 AND transaction_id = ?2 AND state = ?3",
            params![
                authorization.attempt_id,
                authorization.transaction_id,
                AUTHORIZATION_MEMBERSHIP_OUTCOME_UNKNOWN,
            ],
            |row| row.get(0),
        )?;
        transaction.execute(
            "INSERT INTO reservations(
                 invitation_id, generation, join_request_id, expires_at, state
             ) VALUES (?1, ?2, ?3, ?4, 2)",
            params![
                commit.invitation_id,
                commit.invitation_generation,
                commit.join_request_id,
                invitation_expires_at,
            ],
        )?;
    }
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
    #[cfg(session_chat_storage_fault_testing)]
    emit_fault_checkpoint(
        fault_observer,
        fault_testing::Checkpoint::InviterAfterJoinInsert,
        0,
    )?;
    if let Some(authorization) = &staged.authorization {
        let changed = transaction.execute(
            "UPDATE authorization_attempts SET state = ?1
             WHERE attempt_id = ?2 AND transaction_id = ?3 AND state = ?4",
            params![
                AUTHORIZATION_COMMITTED,
                authorization.attempt_id,
                authorization.transaction_id,
                AUTHORIZATION_MEMBERSHIP_OUTCOME_UNKNOWN,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict);
        }
        let changed = transaction.execute(
            "UPDATE invitation_opening_contexts
             SET state = ?1, hpke_private_key = zeroblob(32)
             WHERE invitation_id = ?2 AND generation = ?3 AND state = ?4",
            params![
                OPENING_CONSUMED,
                commit.invitation_id,
                commit.invitation_generation,
                OPENING_RESERVED,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict);
        }
    } else {
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
    }
    #[cfg(session_chat_storage_fault_testing)]
    emit_fault_checkpoint(
        fault_observer,
        fault_testing::Checkpoint::InviterAfterReservationConsumed,
        0,
    )?;
    #[cfg(session_chat_storage_fault_testing)]
    emit_fault_checkpoint(
        fault_observer,
        fault_testing::Checkpoint::InviterBeforeCommit,
        0,
    )?;
    if staged.fault == PersistenceFault::BeforeCommit {
        return Err(StoreError::InjectedFailure);
    }
    transaction.commit()?;
    #[cfg(session_chat_storage_fault_testing)]
    emit_fault_checkpoint(
        fault_observer,
        fault_testing::Checkpoint::InviterAfterCommitReturn,
        0,
    )
    .map_err(|_| StoreError::OutcomeUnknown)?;
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
    #[cfg(session_chat_storage_fault_testing)] fault_observer: Option<
        &fault_testing::FaultObserver,
    >,
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

    #[cfg(session_chat_storage_fault_testing)]
    emit_fault_checkpoint(
        fault_observer,
        fault_testing::Checkpoint::JoinerBeforeBegin,
        0,
    )?;
    inner.connection.execute_batch("BEGIN IMMEDIATE;")?;
    let result = (|| {
        if !key_package_exists_on(&inner.connection, &staged.transaction.key_package_reference)? {
            return Err(StoreError::Rejected);
        }
        persist_mls(
            &inner.connection,
            state,
            epoch_inserts,
            epoch_updates,
            #[cfg(session_chat_storage_fault_testing)]
            fault_observer,
            #[cfg(session_chat_storage_fault_testing)]
            fault_testing::Scenario::JoinerTransaction,
        )?;
        inner.connection.execute(
            "INSERT INTO joiner_commits(transaction_id, group_id, key_package_ref)
             VALUES (?1, ?2, ?3)",
            params![
                staged.transaction.transaction_id,
                staged.transaction.group_id,
                staged.transaction.key_package_reference
            ],
        )?;
        #[cfg(session_chat_storage_fault_testing)]
        emit_fault_checkpoint(
            fault_observer,
            fault_testing::Checkpoint::JoinerAfterCommitInsert,
            0,
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
    #[cfg(session_chat_storage_fault_testing)] fault_observer: Option<
        &fault_testing::FaultObserver,
    >,
    #[cfg(session_chat_storage_fault_testing)] scenario: fault_testing::Scenario,
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO mls_groups(group_id, state) VALUES (?1, ?2)
         ON CONFLICT(group_id) DO UPDATE SET state = excluded.state",
        params![state.id, state.data.as_slice()],
    )?;
    #[cfg(session_chat_storage_fault_testing)]
    emit_fault_checkpoint(
        fault_observer,
        match scenario {
            fault_testing::Scenario::InviterTransaction => {
                fault_testing::Checkpoint::InviterAfterGroupUpsert
            }
            fault_testing::Scenario::JoinerTransaction => {
                fault_testing::Checkpoint::JoinerAfterGroupUpsert
            }
        },
        0,
    )?;
    #[cfg(session_chat_storage_fault_testing)]
    let mut insert_occurrence = 0_u8;
    for epoch in epoch_inserts {
        transaction.execute(
            "INSERT INTO mls_epochs(group_id, epoch_id, data) VALUES (?1, ?2, ?3)",
            params![state.id, epoch.id as i64, epoch.data.as_slice()],
        )?;
        #[cfg(session_chat_storage_fault_testing)]
        emit_fault_checkpoint(
            fault_observer,
            match scenario {
                fault_testing::Scenario::InviterTransaction => {
                    fault_testing::Checkpoint::InviterAfterEpochInsert
                }
                fault_testing::Scenario::JoinerTransaction => {
                    fault_testing::Checkpoint::JoinerAfterEpochInsert
                }
            },
            insert_occurrence,
        )?;
        #[cfg(session_chat_storage_fault_testing)]
        {
            insert_occurrence = insert_occurrence
                .checked_add(1)
                .ok_or(StoreError::Rejected)?;
        }
    }
    #[cfg(session_chat_storage_fault_testing)]
    let mut update_occurrence = 0_u8;
    for epoch in epoch_updates {
        let changed = transaction.execute(
            "UPDATE mls_epochs SET data = ?3 WHERE group_id = ?1 AND epoch_id = ?2",
            params![state.id, epoch.id as i64, epoch.data.as_slice()],
        )?;
        if changed != 1 {
            return Err(StoreError::Rejected);
        }
        #[cfg(session_chat_storage_fault_testing)]
        emit_fault_checkpoint(
            fault_observer,
            match scenario {
                fault_testing::Scenario::InviterTransaction => {
                    fault_testing::Checkpoint::InviterAfterEpochUpdate
                }
                fault_testing::Scenario::JoinerTransaction => {
                    fault_testing::Checkpoint::JoinerAfterEpochUpdate
                }
            },
            update_occurrence,
        )?;
        #[cfg(session_chat_storage_fault_testing)]
        {
            update_occurrence = update_occurrence
                .checked_add(1)
                .ok_or(StoreError::Rejected)?;
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

#[cfg(session_chat_storage_fault_testing)]
fn emit_fault_checkpoint(
    observer: Option<&fault_testing::FaultObserver>,
    checkpoint: fault_testing::Checkpoint,
    occurrence: u8,
) -> Result<(), StoreError> {
    observer
        .map(|observer| observer.checkpoint(checkpoint, occurrence))
        .transpose()
        .map(|_| ())
        .map_err(|_| StoreError::Rejected)
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
