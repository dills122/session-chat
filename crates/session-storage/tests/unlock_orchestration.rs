use std::cell::Cell;

use session_storage::{
    BackupExposure, DeterministicClock, DeterministicKeyProtector, DeviceBinding,
    KeyStorageProtection, LockEvent, OneShotUnlockCredential, OpaqueInboxPolicy, ProtectionLevel,
    ProtectorCapabilities, SessionId, SessionKeyProtector, SessionVaultModel,
    UnlockCredentialSource, UnlockWorkLimiter, UnsealedSessionKey, UserPresence, VaultError,
    VaultPolicy, VaultState,
};
use thiserror::Error;

const NOW: u64 = 2_000_000_000;

fn session_id(byte: u8) -> SessionId {
    SessionId::new([byte; 32]).expect("nonzero session ID")
}

fn vault(minimum_protection: ProtectionLevel) -> SessionVaultModel<DeterministicClock> {
    SessionVaultModel::new(
        VaultPolicy::new_with_protection(30, 60, minimum_protection).expect("valid vault policy"),
        OpaqueInboxPolicy::new(300, 4, 256 * 1024).expect("valid inbox policy"),
        DeterministicClock::new(NOW),
    )
}

#[test]
fn prepared_result_opens_only_its_exact_live_generation() {
    let selected = session_id(0x11);
    let limiter = UnlockWorkLimiter::new(1).expect("nonzero work limit");
    let mut protector =
        DeterministicKeyProtector::new(selected, [0x21; 32]).expect("test protector");
    let mut first_credential = OneShotUnlockCredential::new(selected, ());
    let first = vault(ProtectionLevel::TestOnly)
        .begin_unlock(selected)
        .expect("independent request fixture");
    let first_completion = first.prepare_with(&limiter, &mut first_credential, &mut protector);

    let mut vault = vault(ProtectionLevel::TestOnly);
    let current = vault
        .begin_unlock(selected)
        .expect("current unlock request");
    assert_eq!(
        vault.complete_unlock(first_completion),
        Err(VaultError::ReservationMismatch)
    );
    assert_eq!(vault.state(), VaultState::Unlocking);

    let mut current_credential = OneShotUnlockCredential::new(selected, ());
    let current_completion =
        current.prepare_with(&limiter, &mut current_credential, &mut protector);
    vault
        .complete_unlock(current_completion)
        .expect("exact current result opens vault");
    assert_eq!(vault.state(), VaultState::Open);
}

#[test]
fn cancellation_discards_a_prepared_key_without_reopening() {
    let selected = session_id(0x12);
    let mut vault = vault(ProtectionLevel::TestOnly);
    let limiter = UnlockWorkLimiter::new(1).expect("nonzero work limit");
    let mut credential = OneShotUnlockCredential::new(selected, ());
    let mut protector =
        DeterministicKeyProtector::new(selected, [0x22; 32]).expect("test protector");
    let request = vault.begin_unlock(selected).expect("begin unlock");
    let completion = request.prepare_with(&limiter, &mut credential, &mut protector);

    vault.force_lock(LockEvent::Explicit);

    assert_eq!(
        vault.complete_unlock(completion),
        Err(VaultError::ReservationMismatch)
    );
    assert_eq!(vault.state(), VaultState::Sealed);
}

#[test]
fn completion_after_deadline_is_discarded() {
    let selected = session_id(0x13);
    let mut vault = vault(ProtectionLevel::TestOnly);
    let limiter = UnlockWorkLimiter::new(1).expect("nonzero work limit");
    let mut credential = OneShotUnlockCredential::new(selected, ());
    let mut protector =
        DeterministicKeyProtector::new(selected, [0x23; 32]).expect("test protector");
    let request = vault.begin_unlock(selected).expect("begin unlock");
    let completion = request.prepare_with(&limiter, &mut credential, &mut protector);
    vault
        .clock_mut()
        .advance(30)
        .expect("advance to exact deadline");

    assert_eq!(vault.complete_unlock(completion), Err(VaultError::Rejected));
    assert_eq!(vault.state(), VaultState::Sealed);
}

#[test]
fn one_shot_credential_is_bound_to_one_session_and_one_acquisition() {
    let selected = session_id(0x14);
    let mut credential = OneShotUnlockCredential::new(selected, [0x41; 8]);

    assert!(credential.acquire(session_id(0x15)).is_err());
    assert_eq!(
        credential.acquire(selected).expect("exact acquisition"),
        [0x41; 8]
    );
    assert!(credential.acquire(selected).is_err());
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("counting protector rejected operation")]
struct CountingProtectorError;

struct CountingProtector<'a> {
    calls: &'a Cell<usize>,
    capabilities: ProtectorCapabilities,
}

impl SessionKeyProtector for CountingProtector<'_> {
    type Credential = ();
    type Error = CountingProtectorError;

    fn capabilities(&self) -> ProtectorCapabilities {
        self.capabilities
    }

    fn unseal_session_key(
        &mut self,
        _session_id: SessionId,
        (): Self::Credential,
    ) -> Result<UnsealedSessionKey, Self::Error> {
        self.calls.set(self.calls.get() + 1);
        UnsealedSessionKey::from_provider_bytes([0x31; 32]).map_err(|_| CountingProtectorError)
    }
}

#[test]
fn work_limit_rejects_before_acquiring_a_credential_or_calling_a_provider() {
    let selected = session_id(0x16);
    let mut vault = vault(ProtectionLevel::TestOnly);
    let limiter = UnlockWorkLimiter::new(1).expect("nonzero work limit");
    let held = limiter.try_reserve().expect("reserve only work slot");
    let mut credential = OneShotUnlockCredential::new(selected, ());
    let calls = Cell::new(0);
    let mut protector = CountingProtector {
        calls: &calls,
        capabilities: ProtectorCapabilities::new(
            KeyStorageProtection::TestOnly,
            DeviceBinding::Unknown,
            UserPresence::None,
            BackupExposure::Unknown,
        ),
    };
    let request = vault.begin_unlock(selected).expect("begin unlock");
    let completion = request.prepare_with(&limiter, &mut credential, &mut protector);

    assert_eq!(
        vault.complete_unlock(completion),
        Err(VaultError::CapacityExceeded)
    );
    assert_eq!(calls.get(), 0);
    assert!(credential.acquire(selected).is_ok());
    assert_eq!(vault.state(), VaultState::Sealed);
    drop(held);
    assert_eq!(limiter.in_flight(), 0);
}

#[test]
fn insufficient_capabilities_fail_before_credential_or_provider_work() {
    let selected = session_id(0x17);
    let mut vault = vault(ProtectionLevel::DeviceBound);
    let limiter = UnlockWorkLimiter::new(1).expect("nonzero work limit");
    let mut credential = OneShotUnlockCredential::new(selected, ());
    let calls = Cell::new(0);
    let mut protector = CountingProtector {
        calls: &calls,
        capabilities: ProtectorCapabilities::new(
            KeyStorageProtection::ApplicationWrapped,
            DeviceBinding::Unknown,
            UserPresence::None,
            BackupExposure::MayBackup,
        ),
    };
    let request = vault.begin_unlock(selected).expect("begin unlock");
    let completion = request.prepare_with(&limiter, &mut credential, &mut protector);

    assert_eq!(
        vault.complete_unlock(completion),
        Err(VaultError::ProviderFailure)
    );
    assert_eq!(calls.get(), 0);
    assert!(credential.acquire(selected).is_ok());
    assert_eq!(vault.state(), VaultState::Sealed);
}

#[test]
fn cancellation_before_work_preserves_the_credential_and_skips_the_provider() {
    let selected = session_id(0x18);
    let mut vault = vault(ProtectionLevel::TestOnly);
    let limiter = UnlockWorkLimiter::new(1).expect("nonzero work limit");
    let mut credential = OneShotUnlockCredential::new(selected, ());
    let calls = Cell::new(0);
    let mut protector = CountingProtector {
        calls: &calls,
        capabilities: ProtectorCapabilities::new(
            KeyStorageProtection::TestOnly,
            DeviceBinding::Unknown,
            UserPresence::None,
            BackupExposure::Unknown,
        ),
    };
    let request = vault.begin_unlock(selected).expect("begin unlock");

    vault.force_lock(LockEvent::Explicit);
    let completion = request.prepare_with(&limiter, &mut credential, &mut protector);

    assert_eq!(calls.get(), 0);
    assert!(credential.acquire(selected).is_ok());
    assert_eq!(limiter.in_flight(), 0);
    assert_eq!(
        vault.complete_unlock(completion),
        Err(VaultError::ReservationMismatch)
    );
    assert_eq!(vault.state(), VaultState::Sealed);
}

#[test]
fn zero_work_limit_is_rejected() {
    assert!(matches!(
        UnlockWorkLimiter::new(0),
        Err(VaultError::InvalidPolicy)
    ));
}
