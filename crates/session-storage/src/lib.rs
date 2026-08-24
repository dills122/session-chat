#![forbid(unsafe_code)]

//! Sealed-vault and opaque-inbox contracts plus deterministic conformance models.

use std::{collections::BTreeMap, error::Error};

use session_protocol::{MAX_ENVELOPE_CIPHERTEXT_BYTES, OpaqueEnvelope};
use thiserror::Error;
use zeroize::Zeroize;

/// Fixed byte length of a session-scoped vault identifier.
pub const SESSION_ID_BYTES: usize = 32;
/// Fixed byte length of one externally protected session data key.
pub const SESSION_KEY_BYTES: usize = 32;
/// Pre-parser outer bound for one canonical opaque-envelope encoding.
pub const MAX_ENCODED_OPAQUE_ENVELOPE_BYTES: usize = MAX_ENVELOPE_CIPHERTEXT_BYTES + 64;

/// Coarse failure from the storage and vault boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VaultError {
    /// A configured lifetime or capacity was zero or overflowed.
    #[error("invalid vault policy")]
    InvalidPolicy,
    /// The state, session, time, token, or untrusted input was rejected.
    #[error("vault operation rejected")]
    Rejected,
    /// A stale or foreign linear transition token was supplied.
    #[error("vault transition reservation mismatch")]
    ReservationMismatch,
    /// A configured bounded collection is full.
    #[error("vault capacity reached")]
    CapacityExceeded,
    /// The selected key protector failed without exposing provider detail.
    #[error("vault key protector failed")]
    ProviderFailure,
}

/// Nonzero session-scoped identifier used to select one vault compartment.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SessionId([u8; SESSION_ID_BYTES]);

impl SessionId {
    /// Accepts one provider-generated nonzero session identifier.
    pub fn new(bytes: [u8; SESSION_ID_BYTES]) -> Result<Self, VaultError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(VaultError::Rejected);
        }
        Ok(Self(bytes))
    }

    /// Borrows the identifier bytes. This value is not key material.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SESSION_ID_BYTES] {
        &self.0
    }
}

/// Named minimum protection required by one vault policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectionLevel {
    /// Deterministic conformance tests may use an in-memory protector.
    TestOnly,
    /// The key is encrypted at rest without claiming device binding or presence.
    EncryptedAtRest,
    /// The key is OS-protected, device-only, and excluded from migration/backup.
    DeviceBound,
    /// Device-bound protection additionally requires a fresh platform prompt.
    FreshUserPresence,
}

/// Where a protector retains or wraps the vault key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyStorageProtection {
    /// Plain fixture material retained only for deterministic tests.
    TestOnly,
    /// The application stores only a cryptographically wrapped key.
    ApplicationWrapped,
    /// An operating-system credential or protected-data service.
    OperatingSystem,
    /// Hardware-backed protection demonstrated by the concrete adapter.
    SecureHardware,
}

/// Factual device-binding behavior demonstrated by one adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceBinding {
    /// Binding has not been established on this platform/configuration.
    Unknown,
    /// Access follows a user profile and may not be device-only.
    UserProfile,
    /// The protected value cannot migrate to another device through backup.
    ThisDeviceOnly,
}

/// Factual user-presence behavior demonstrated by one adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserPresence {
    /// No user-presence evidence is required for retrieval.
    None,
    /// Retrieval depends on an already-unlocked device or user session.
    DeviceUnlock,
    /// Retrieval requires a fresh platform-mediated prompt.
    FreshPrompt,
}

/// Factual backup or migration behavior demonstrated by one adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupExposure {
    /// Backup behavior has not been established.
    Unknown,
    /// The protected value may roam, migrate, or enter a backup.
    MayBackup,
    /// The selected platform class excludes backup and device migration.
    Excluded,
}

/// Factual protection dimensions reported by a reviewed concrete adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectorCapabilities {
    key_storage: KeyStorageProtection,
    device_binding: DeviceBinding,
    user_presence: UserPresence,
    backup_exposure: BackupExposure,
}

impl ProtectorCapabilities {
    /// Records the exact behavior established for one adapter configuration.
    #[must_use]
    pub const fn new(
        key_storage: KeyStorageProtection,
        device_binding: DeviceBinding,
        user_presence: UserPresence,
        backup_exposure: BackupExposure,
    ) -> Self {
        Self {
            key_storage,
            device_binding,
            user_presence,
            backup_exposure,
        }
    }

    /// Returns whether these facts satisfy one named minimum policy.
    #[must_use]
    pub const fn supports(self, level: ProtectionLevel) -> bool {
        match level {
            ProtectionLevel::TestOnly => true,
            ProtectionLevel::EncryptedAtRest => matches!(
                self.key_storage,
                KeyStorageProtection::ApplicationWrapped
                    | KeyStorageProtection::OperatingSystem
                    | KeyStorageProtection::SecureHardware
            ),
            ProtectionLevel::DeviceBound => {
                matches!(
                    self.key_storage,
                    KeyStorageProtection::OperatingSystem | KeyStorageProtection::SecureHardware
                ) && matches!(self.device_binding, DeviceBinding::ThisDeviceOnly)
                    && matches!(self.backup_exposure, BackupExposure::Excluded)
            }
            ProtectionLevel::FreshUserPresence => {
                self.supports(ProtectionLevel::DeviceBound)
                    && matches!(self.user_presence, UserPresence::FreshPrompt)
            }
        }
    }
}

/// Unlock and idle bounds for the deterministic vault lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VaultPolicy {
    unlock_timeout_seconds: u64,
    idle_timeout_seconds: u64,
    minimum_protection: ProtectionLevel,
}

impl VaultPolicy {
    /// Creates a fail-closed lifecycle policy.
    pub fn new(unlock_timeout_seconds: u64, idle_timeout_seconds: u64) -> Result<Self, VaultError> {
        if unlock_timeout_seconds == 0 || idle_timeout_seconds == 0 {
            return Err(VaultError::InvalidPolicy);
        }
        Ok(Self {
            unlock_timeout_seconds,
            idle_timeout_seconds,
            minimum_protection: ProtectionLevel::TestOnly,
        })
    }

    /// Creates a lifecycle policy with an explicit minimum protector claim.
    pub fn new_with_protection(
        unlock_timeout_seconds: u64,
        idle_timeout_seconds: u64,
        minimum_protection: ProtectionLevel,
    ) -> Result<Self, VaultError> {
        let mut policy = Self::new(unlock_timeout_seconds, idle_timeout_seconds)?;
        policy.minimum_protection = minimum_protection;
        Ok(policy)
    }

    /// Returns the minimum evidence required before a key may be unsealed.
    #[must_use]
    pub const fn minimum_protection(self) -> ProtectionLevel {
        self.minimum_protection
    }
}

/// Bounds for the always-sealed opaque inbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpaqueInboxPolicy {
    maximum_lifetime_seconds: u64,
    maximum_envelopes: usize,
    maximum_total_encoded_bytes: usize,
}

impl OpaqueInboxPolicy {
    /// Creates nonzero inbox lifetime, count, and byte bounds.
    pub fn new(
        maximum_lifetime_seconds: u64,
        maximum_envelopes: usize,
        maximum_total_encoded_bytes: usize,
    ) -> Result<Self, VaultError> {
        if maximum_lifetime_seconds == 0
            || maximum_envelopes == 0
            || maximum_total_encoded_bytes == 0
        {
            return Err(VaultError::InvalidPolicy);
        }
        Ok(Self {
            maximum_lifetime_seconds,
            maximum_envelopes,
            maximum_total_encoded_bytes,
        })
    }
}

/// Result of storing one bounded canonical opaque envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboxAppendOutcome {
    /// A new envelope generation was retained.
    Stored,
    /// The byte-identical envelope was already retained.
    AlreadyStored,
}

struct OpaqueInboxRecord {
    encoded: Vec<u8>,
    expires_at_unix_seconds: u64,
    insertion_generation: u64,
}

/// Linear local-import value released only to the exact open vault generation.
///
/// Import completion removes only the local sealed-inbox copy. It is not remote
/// delivery acknowledgement authority. This type intentionally implements
/// neither `Clone`, `Debug`, nor `Display` because it owns ciphertext bytes.
pub struct PendingOpaqueImport {
    session_id: SessionId,
    open_generation: u64,
    envelope_id: [u8; 16],
    insertion_generation: u64,
    envelope: OpaqueEnvelope,
}

impl PendingOpaqueImport {
    /// Borrows the exact canonical envelope decoded after vault unlock.
    #[must_use]
    pub const fn envelope(&self) -> &OpaqueEnvelope {
        &self.envelope
    }
}

/// Read-only public view of the vault lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultState {
    /// No session key is available to privileged operations.
    Sealed,
    /// A bounded platform-protector operation is pending.
    Unlocking,
    /// Exactly one selected session is available to the core.
    Open,
    /// New privileged operations are rejected while relock completes.
    Relocking,
}

/// Secret-bearing operation classes prohibited while sealed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultOperation {
    /// Decrypt protected session content.
    Decrypt,
    /// Create a signature with a client-owned key.
    Sign,
    /// Verify or apply admission using secret-bearing state.
    Admit,
    /// Read a mailbox receive capability.
    ReadReceiveCapability,
    /// Exercise acknowledgement authority.
    AcknowledgeDelivery,
    /// Rotate a secret-bearing mailbox authority.
    RotateMailbox,
    /// Read or mutate MLS state.
    MutateMls,
}

/// Platform or application lifecycle events that force immediate sealing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockEvent {
    /// User explicitly selected lock.
    Explicit,
    /// The configured inactivity limit elapsed.
    IdleTimeout,
    /// The operating system reported a locked screen.
    ScreenLocked,
    /// The operating system is suspending the device.
    Sleep,
    /// The user session is ending.
    Logout,
    /// The process is exiting or simulating abrupt teardown.
    ProcessExit,
}

/// Minimal clock boundary used to make lifecycle races deterministic.
pub trait VaultClock {
    /// Returns the current Unix time in whole seconds.
    fn now_unix_seconds(&self) -> u64;
}

/// Manually advanced clock retained only for deterministic conformance tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeterministicClock {
    now_unix_seconds: u64,
}

impl DeterministicClock {
    /// Creates a clock at an explicitly selected test time.
    #[must_use]
    pub const fn new(now_unix_seconds: u64) -> Self {
        Self { now_unix_seconds }
    }

    /// Advances time without wrapping.
    pub fn advance(&mut self, seconds: u64) -> Result<(), VaultError> {
        self.now_unix_seconds = self
            .now_unix_seconds
            .checked_add(seconds)
            .ok_or(VaultError::Rejected)?;
        Ok(())
    }
}

impl VaultClock for DeterministicClock {
    fn now_unix_seconds(&self) -> u64 {
        self.now_unix_seconds
    }
}

/// Unsealed session data key owned only by the vault core.
///
/// This type intentionally implements neither `Clone`, `Debug`, nor `Display`.
pub struct UnsealedSessionKey([u8; SESSION_KEY_BYTES]);

impl UnsealedSessionKey {
    /// Moves provider output into a zeroizing key container.
    pub fn from_provider_bytes(bytes: [u8; SESSION_KEY_BYTES]) -> Result<Self, VaultError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(VaultError::ProviderFailure);
        }
        Ok(Self(bytes))
    }
}

impl Drop for UnsealedSessionKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Provider-neutral platform boundary for unsealing one selected session key.
pub trait SessionKeyProtector {
    /// Provider-private error mapped to the coarse vault boundary.
    type Error: Error;

    /// Reports factual, adapter-specific protection behavior.
    fn capabilities(&self) -> ProtectorCapabilities;

    /// Requires the configured platform protection and returns one session key.
    fn unseal_session_key(
        &mut self,
        session_id: SessionId,
    ) -> Result<UnsealedSessionKey, Self::Error>;
}

/// Failure from the deterministic non-production protector.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("deterministic protector rejected operation")]
pub struct DeterministicProtectorError;

/// Non-production protector for lifecycle conformance tests.
///
/// It retains an unwrapped test key in memory and therefore provides no at-rest
/// protection evidence. It intentionally implements neither `Clone`, `Debug`,
/// nor `Display`.
pub struct DeterministicKeyProtector {
    session_id: SessionId,
    session_key: [u8; SESSION_KEY_BYTES],
    reject: bool,
}

impl DeterministicKeyProtector {
    /// Creates an accepting deterministic protector for one exact session.
    pub fn new(
        session_id: SessionId,
        session_key: [u8; SESSION_KEY_BYTES],
    ) -> Result<Self, VaultError> {
        if session_key.iter().all(|byte| *byte == 0) {
            return Err(VaultError::ProviderFailure);
        }
        Ok(Self {
            session_id,
            session_key,
            reject: false,
        })
    }

    /// Creates a protector that deterministically rejects the next operation.
    #[must_use]
    pub const fn rejecting(session_id: SessionId) -> Self {
        Self {
            session_id,
            session_key: [1; SESSION_KEY_BYTES],
            reject: true,
        }
    }
}

impl SessionKeyProtector for DeterministicKeyProtector {
    type Error = DeterministicProtectorError;

    fn capabilities(&self) -> ProtectorCapabilities {
        ProtectorCapabilities::new(
            KeyStorageProtection::TestOnly,
            DeviceBinding::Unknown,
            UserPresence::None,
            BackupExposure::Unknown,
        )
    }

    fn unseal_session_key(
        &mut self,
        session_id: SessionId,
    ) -> Result<UnsealedSessionKey, Self::Error> {
        if self.reject || session_id != self.session_id {
            return Err(DeterministicProtectorError);
        }
        UnsealedSessionKey::from_provider_bytes(self.session_key)
            .map_err(|_| DeterministicProtectorError)
    }
}

impl Drop for DeterministicKeyProtector {
    fn drop(&mut self) {
        self.session_key.zeroize();
    }
}

/// Linear authority to complete one exact unlock generation.
pub struct UnlockAttempt {
    session_id: SessionId,
    generation: u64,
}

/// Linear authority to complete one exact relock generation.
pub struct RelockAttempt {
    session_id: SessionId,
    generation: u64,
}

enum LifecycleState {
    Sealed,
    Unlocking {
        session_id: SessionId,
        generation: u64,
        expires_at_unix_seconds: u64,
    },
    Open {
        session_id: SessionId,
        generation: u64,
        idle_expires_at_unix_seconds: u64,
        _key: UnsealedSessionKey,
    },
    Relocking {
        session_id: SessionId,
        generation: u64,
    },
}

/// Deterministic sealed-vault lifecycle model.
///
/// This model proves transition and capability-matrix semantics only. It is not
/// encrypted persistence, a platform vault, or a rollback-resistance claim.
pub struct SessionVaultModel<C: VaultClock, P: SessionKeyProtector> {
    policy: VaultPolicy,
    inbox_policy: OpaqueInboxPolicy,
    clock: C,
    protector: P,
    next_generation: u64,
    next_inbox_generation: u64,
    state: LifecycleState,
    inbox: BTreeMap<[u8; 16], OpaqueInboxRecord>,
    inbox_total_encoded_bytes: usize,
}

impl<C: VaultClock, P: SessionKeyProtector> SessionVaultModel<C, P> {
    /// Creates a model in the sealed state.
    #[must_use]
    pub const fn new(
        policy: VaultPolicy,
        inbox_policy: OpaqueInboxPolicy,
        clock: C,
        protector: P,
    ) -> Self {
        Self {
            policy,
            inbox_policy,
            clock,
            protector,
            next_generation: 0,
            next_inbox_generation: 0,
            state: LifecycleState::Sealed,
            inbox: BTreeMap::new(),
            inbox_total_encoded_bytes: 0,
        }
    }

    /// Returns the coarse lifecycle without identifying the selected session.
    #[must_use]
    pub const fn state(&self) -> VaultState {
        match self.state {
            LifecycleState::Sealed => VaultState::Sealed,
            LifecycleState::Unlocking { .. } => VaultState::Unlocking,
            LifecycleState::Open { .. } => VaultState::Open,
            LifecycleState::Relocking { .. } => VaultState::Relocking,
        }
    }

    /// Borrows the injected clock for deterministic event control.
    pub const fn clock_mut(&mut self) -> &mut C {
        &mut self.clock
    }

    /// Starts one bounded unlock attempt from the sealed state.
    pub fn begin_unlock(&mut self, session_id: SessionId) -> Result<UnlockAttempt, VaultError> {
        self.poll();
        if !matches!(self.state, LifecycleState::Sealed) {
            return Err(VaultError::Rejected);
        }
        let generation = self.next_transition_generation()?;
        let expires_at_unix_seconds = self
            .clock
            .now_unix_seconds()
            .checked_add(self.policy.unlock_timeout_seconds)
            .ok_or(VaultError::Rejected)?;
        self.state = LifecycleState::Unlocking {
            session_id,
            generation,
            expires_at_unix_seconds,
        };
        Ok(UnlockAttempt {
            session_id,
            generation,
        })
    }

    /// Completes only the current exact unlock generation.
    pub fn complete_unlock(&mut self, attempt: UnlockAttempt) -> Result<(), VaultError> {
        let now = self.clock.now_unix_seconds();
        let LifecycleState::Unlocking {
            session_id,
            generation,
            expires_at_unix_seconds,
        } = self.state
        else {
            return Err(VaultError::ReservationMismatch);
        };
        if session_id != attempt.session_id || generation != attempt.generation {
            return Err(VaultError::ReservationMismatch);
        }
        self.state = LifecycleState::Sealed;
        if expires_at_unix_seconds <= now {
            return Err(VaultError::Rejected);
        }
        if !self
            .protector
            .capabilities()
            .supports(self.policy.minimum_protection)
        {
            return Err(VaultError::ProviderFailure);
        }
        let key = self
            .protector
            .unseal_session_key(session_id)
            .map_err(|_| VaultError::ProviderFailure)?;
        let completed_at_unix_seconds = self.clock.now_unix_seconds();
        if expires_at_unix_seconds <= completed_at_unix_seconds {
            return Err(VaultError::Rejected);
        }
        let idle_expires_at_unix_seconds = completed_at_unix_seconds
            .checked_add(self.policy.idle_timeout_seconds)
            .ok_or(VaultError::Rejected)?;
        self.state = LifecycleState::Open {
            session_id,
            generation,
            idle_expires_at_unix_seconds,
            _key: key,
        };
        Ok(())
    }

    /// Runs one core-owned operation only for the exact currently open session.
    ///
    /// The callback is never invoked when authorization fails.
    pub fn perform_privileged(
        &mut self,
        session_id: SessionId,
        operation: VaultOperation,
        action: impl FnOnce(),
    ) -> Result<(), VaultError> {
        self.poll();
        let now = self.clock.now_unix_seconds();
        let LifecycleState::Open {
            session_id: selected,
            idle_expires_at_unix_seconds,
            ..
        } = &mut self.state
        else {
            return Err(VaultError::Rejected);
        };
        if *selected != session_id {
            return Err(VaultError::Rejected);
        }
        let refreshed_expiry = now
            .checked_add(self.policy.idle_timeout_seconds)
            .ok_or(VaultError::Rejected)?;
        *idle_expires_at_unix_seconds = refreshed_expiry;
        let _ = operation;
        action();
        Ok(())
    }

    /// Revokes new access and returns one exact relock completion token.
    pub fn begin_relock(&mut self, session_id: SessionId) -> Result<RelockAttempt, VaultError> {
        self.poll();
        let LifecycleState::Open {
            session_id: selected,
            ..
        } = &self.state
        else {
            return Err(VaultError::Rejected);
        };
        if *selected != session_id {
            return Err(VaultError::Rejected);
        }
        let generation = self.next_transition_generation()?;
        self.state = LifecycleState::Relocking {
            session_id,
            generation,
        };
        Ok(RelockAttempt {
            session_id,
            generation,
        })
    }

    /// Completes only the current exact relock generation.
    pub fn complete_relock(&mut self, attempt: RelockAttempt) -> Result<(), VaultError> {
        let LifecycleState::Relocking {
            session_id,
            generation,
        } = self.state
        else {
            return Err(VaultError::ReservationMismatch);
        };
        if session_id != attempt.session_id || generation != attempt.generation {
            return Err(VaultError::ReservationMismatch);
        }
        self.state = LifecycleState::Sealed;
        Ok(())
    }

    /// Immediately drops any unsealed key for a platform or process event.
    pub fn force_lock(&mut self, event: LockEvent) {
        let _ = event;
        self.state = LifecycleState::Sealed;
    }

    /// Applies pending unlock and idle deadlines without running privileged work.
    pub fn poll(&mut self) {
        let now = self.clock.now_unix_seconds();
        let expired = match &self.state {
            LifecycleState::Unlocking {
                expires_at_unix_seconds,
                ..
            } => *expires_at_unix_seconds <= now,
            LifecycleState::Open {
                idle_expires_at_unix_seconds,
                ..
            } => *idle_expires_at_unix_seconds <= now,
            LifecycleState::Sealed | LifecycleState::Relocking { .. } => false,
        };
        if expired {
            self.state = LifecycleState::Sealed;
        }
        self.prune_expired_inbox(now);
    }

    /// Appends one bounded canonical opaque envelope in every vault state.
    ///
    /// This operation never opens the vault, reads a receive capability,
    /// acknowledges remote delivery, or parses the MLS-protected ciphertext.
    pub fn append_opaque(&mut self, encoded: &[u8]) -> Result<InboxAppendOutcome, VaultError> {
        self.poll();
        if encoded.is_empty() || encoded.len() > MAX_ENCODED_OPAQUE_ENVELOPE_BYTES {
            return Err(VaultError::Rejected);
        }
        let envelope =
            OpaqueEnvelope::decode_canonical(encoded).map_err(|_| VaultError::Rejected)?;
        if envelope.envelope_id().iter().all(|byte| *byte == 0) {
            return Err(VaultError::Rejected);
        }
        let now = self.clock.now_unix_seconds();
        let lifetime = envelope
            .expires_at_unix_seconds()
            .checked_sub(now)
            .ok_or(VaultError::Rejected)?;
        if lifetime == 0 || lifetime > self.inbox_policy.maximum_lifetime_seconds {
            return Err(VaultError::Rejected);
        }
        let envelope_id = *envelope.envelope_id();
        if let Some(existing) = self.inbox.get(&envelope_id) {
            return if existing.encoded == encoded {
                Ok(InboxAppendOutcome::AlreadyStored)
            } else {
                Err(VaultError::Rejected)
            };
        }
        if self.inbox.len() >= self.inbox_policy.maximum_envelopes {
            return Err(VaultError::CapacityExceeded);
        }
        let next_total = self
            .inbox_total_encoded_bytes
            .checked_add(encoded.len())
            .ok_or(VaultError::CapacityExceeded)?;
        if next_total > self.inbox_policy.maximum_total_encoded_bytes {
            return Err(VaultError::CapacityExceeded);
        }
        self.next_inbox_generation = self
            .next_inbox_generation
            .checked_add(1)
            .ok_or(VaultError::CapacityExceeded)?;
        self.inbox.insert(
            envelope_id,
            OpaqueInboxRecord {
                encoded: encoded.to_vec(),
                expires_at_unix_seconds: envelope.expires_at_unix_seconds(),
                insertion_generation: self.next_inbox_generation,
            },
        );
        self.inbox_total_encoded_bytes = next_total;
        Ok(InboxAppendOutcome::Stored)
    }

    /// Decodes one retained canonical envelope only for the exact open session.
    pub fn begin_opaque_import(
        &mut self,
        session_id: SessionId,
    ) -> Result<Option<PendingOpaqueImport>, VaultError> {
        self.poll();
        let LifecycleState::Open {
            session_id: selected,
            generation,
            ..
        } = &self.state
        else {
            return Err(VaultError::Rejected);
        };
        if *selected != session_id {
            return Err(VaultError::Rejected);
        }
        let Some((envelope_id, record)) = self.inbox.iter().next() else {
            return Ok(None);
        };
        let envelope =
            OpaqueEnvelope::decode_canonical(&record.encoded).map_err(|_| VaultError::Rejected)?;
        Ok(Some(PendingOpaqueImport {
            session_id,
            open_generation: *generation,
            envelope_id: *envelope_id,
            insertion_generation: record.insertion_generation,
            envelope,
        }))
    }

    /// Removes one exact locally imported envelope while the same vault generation is open.
    ///
    /// Network acknowledgement remains a separate right-specific transport
    /// operation and is deliberately absent from this model.
    pub fn complete_opaque_import(
        &mut self,
        pending: PendingOpaqueImport,
    ) -> Result<(), VaultError> {
        self.poll();
        let LifecycleState::Open {
            session_id,
            generation,
            ..
        } = &self.state
        else {
            return Err(VaultError::ReservationMismatch);
        };
        if *session_id != pending.session_id || *generation != pending.open_generation {
            return Err(VaultError::ReservationMismatch);
        }
        let record = self
            .inbox
            .get(&pending.envelope_id)
            .ok_or(VaultError::ReservationMismatch)?;
        if record.insertion_generation != pending.insertion_generation
            || record.expires_at_unix_seconds <= self.clock.now_unix_seconds()
            || self.inbox_total_encoded_bytes < record.encoded.len()
        {
            return Err(VaultError::ReservationMismatch);
        }
        let encoded_length = record.encoded.len();
        self.inbox
            .remove(&pending.envelope_id)
            .ok_or(VaultError::ReservationMismatch)?;
        self.inbox_total_encoded_bytes -= encoded_length;
        Ok(())
    }

    /// Returns the bounded retained envelope count, including no expired entries after polling.
    #[must_use]
    pub fn inbox_count(&self) -> usize {
        self.inbox.len()
    }

    /// Returns the total canonical encoded bytes retained by the opaque inbox.
    #[must_use]
    pub const fn inbox_total_encoded_bytes(&self) -> usize {
        self.inbox_total_encoded_bytes
    }

    fn next_transition_generation(&mut self) -> Result<u64, VaultError> {
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(VaultError::Rejected)?;
        Ok(self.next_generation)
    }

    fn prune_expired_inbox(&mut self, now_unix_seconds: u64) {
        let expired: Vec<_> = self
            .inbox
            .iter()
            .filter_map(|(envelope_id, record)| {
                (record.expires_at_unix_seconds <= now_unix_seconds).then_some(*envelope_id)
            })
            .collect();
        for envelope_id in expired {
            if let Some(record) = self.inbox.remove(&envelope_id) {
                self.inbox_total_encoded_bytes = self
                    .inbox_total_encoded_bytes
                    .saturating_sub(record.encoded.len());
            }
        }
    }
}
