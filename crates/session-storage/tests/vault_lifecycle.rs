use std::{cell::Cell, rc::Rc};

use session_storage::{
    BackupExposure, DeterministicClock, DeterministicKeyProtector, DeterministicProtectorError,
    DeviceBinding, KeyStorageProtection, LockEvent, OneShotUnlockCredential, OpaqueInboxPolicy,
    ProtectorCapabilities, SessionId, SessionKeyProtector, SessionVaultModel, UnlockWorkLimiter,
    UnsealedSessionKey, UserPresence, VaultClock, VaultError, VaultOperation, VaultPolicy,
    VaultState,
};

const NOW: u64 = 2_000_000_000;

fn session_id(byte: u8) -> SessionId {
    SessionId::new([byte; 32]).expect("nonzero session ID")
}

fn model() -> SessionVaultModel<DeterministicClock> {
    SessionVaultModel::new(
        VaultPolicy::new(30, 60).expect("valid vault policy"),
        OpaqueInboxPolicy::new(300, 4, 256 * 1024).expect("valid inbox policy"),
        DeterministicClock::new(NOW),
    )
}

fn unlock(vault: &mut SessionVaultModel<DeterministicClock>, session_id: SessionId) {
    let limiter = UnlockWorkLimiter::new(1).expect("test work limit");
    let mut credential = OneShotUnlockCredential::new(session_id, ());
    let mut protector = DeterministicKeyProtector::new(session_id, [0x21; 32])
        .expect("valid deterministic protector");
    let attempt = vault
        .begin_unlock(session_id)
        .expect("begin deterministic unlock");
    let completion = attempt.prepare_with(&limiter, &mut credential, &mut protector);
    vault
        .complete_unlock(completion)
        .expect("complete deterministic unlock");
}

#[derive(Clone)]
struct SharedClock(Rc<Cell<u64>>);

impl VaultClock for SharedClock {
    fn now_unix_seconds(&self) -> u64 {
        self.0.get()
    }
}

struct TimeAdvancingProtector {
    clock: SharedClock,
    session_id: SessionId,
}

impl SessionKeyProtector for TimeAdvancingProtector {
    type Credential = ();
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
        (): Self::Credential,
    ) -> Result<UnsealedSessionKey, Self::Error> {
        if session_id != self.session_id {
            return Err(DeterministicProtectorError);
        }
        self.clock.0.set(
            self.clock
                .0
                .get()
                .checked_add(30)
                .expect("test time does not overflow"),
        );
        UnsealedSessionKey::from_provider_bytes([0x31; 32]).map_err(|_| DeterministicProtectorError)
    }
}

#[test]
fn policies_and_identifiers_reject_zero_or_overflowing_values() {
    assert_eq!(SessionId::new([0; 32]), Err(VaultError::Rejected));
    assert_eq!(VaultPolicy::new(0, 1), Err(VaultError::InvalidPolicy));
    assert_eq!(VaultPolicy::new(1, 0), Err(VaultError::InvalidPolicy));
    assert_eq!(
        OpaqueInboxPolicy::new(0, 1, 1),
        Err(VaultError::InvalidPolicy)
    );
    assert_eq!(
        OpaqueInboxPolicy::new(1, 0, 1),
        Err(VaultError::InvalidPolicy)
    );
    assert_eq!(
        OpaqueInboxPolicy::new(1, 1, 0),
        Err(VaultError::InvalidPolicy)
    );
}

#[test]
fn sealed_mode_rejects_every_secret_bearing_operation_before_work_runs() {
    let mut vault = model();
    let session_id = session_id(0x11);

    for operation in [
        VaultOperation::Decrypt,
        VaultOperation::Sign,
        VaultOperation::Admit,
        VaultOperation::ReadReceiveCapability,
        VaultOperation::AcknowledgeDelivery,
        VaultOperation::RotateMailbox,
        VaultOperation::MutateMls,
    ] {
        let calls = Cell::new(0);
        assert_eq!(
            vault.perform_privileged(session_id, operation, || calls.set(calls.get() + 1)),
            Err(VaultError::Rejected)
        );
        assert_eq!(calls.get(), 0, "work ran for {operation:?}");
        assert_eq!(vault.state(), VaultState::Sealed);
    }
}

#[test]
fn exact_unlock_opens_one_session_until_idle_expiry() {
    let mut vault = model();
    let selected = session_id(0x11);

    let attempt = vault.begin_unlock(selected).expect("begin unlock");
    assert_eq!(vault.state(), VaultState::Unlocking);
    assert_eq!(
        vault.perform_privileged(selected, VaultOperation::Decrypt, || {}),
        Err(VaultError::Rejected)
    );
    let limiter = UnlockWorkLimiter::new(1).expect("test work limit");
    let mut credential = OneShotUnlockCredential::new(selected, ());
    let mut protector = DeterministicKeyProtector::new(selected, [0x21; 32])
        .expect("valid deterministic protector");
    let completion = attempt.prepare_with(&limiter, &mut credential, &mut protector);
    vault.complete_unlock(completion).expect("complete unlock");
    assert_eq!(vault.state(), VaultState::Open);

    let calls = Cell::new(0);
    vault
        .perform_privileged(selected, VaultOperation::Decrypt, || {
            calls.set(calls.get() + 1);
        })
        .expect("open selected session authorizes core work");
    assert_eq!(calls.get(), 1);
    assert_eq!(
        vault.perform_privileged(session_id(0x12), VaultOperation::Decrypt, || {}),
        Err(VaultError::Rejected)
    );

    vault
        .clock_mut()
        .advance(60)
        .expect("advance to idle limit");
    assert_eq!(
        vault.perform_privileged(selected, VaultOperation::Decrypt, || {}),
        Err(VaultError::Rejected)
    );
    assert_eq!(vault.state(), VaultState::Sealed);
}

#[test]
fn stale_unlock_completion_cannot_open_a_new_generation() {
    let mut vault = model();
    let selected = session_id(0x11);

    let stale = vault.begin_unlock(selected).expect("begin first unlock");
    vault.clock_mut().advance(30).expect("expire first unlock");
    vault.poll();
    assert_eq!(vault.state(), VaultState::Sealed);

    let current = vault.begin_unlock(selected).expect("begin second unlock");
    let limiter = UnlockWorkLimiter::new(1).expect("test work limit");
    let mut stale_credential = OneShotUnlockCredential::new(selected, ());
    let mut protector = DeterministicKeyProtector::new(selected, [0x21; 32])
        .expect("valid deterministic protector");
    let stale_completion = stale.prepare_with(&limiter, &mut stale_credential, &mut protector);
    assert_eq!(
        vault.complete_unlock(stale_completion),
        Err(VaultError::ReservationMismatch)
    );
    assert_eq!(vault.state(), VaultState::Unlocking);
    let mut current_credential = OneShotUnlockCredential::new(selected, ());
    let current_completion =
        current.prepare_with(&limiter, &mut current_credential, &mut protector);
    vault
        .complete_unlock(current_completion)
        .expect("current generation still opens");
    assert_eq!(vault.state(), VaultState::Open);
}

#[test]
fn unlock_expiring_during_unseal_does_not_open() {
    let selected = session_id(0x11);
    let clock = SharedClock(Rc::new(Cell::new(NOW)));
    let protector = TimeAdvancingProtector {
        clock: clock.clone(),
        session_id: selected,
    };
    let mut vault = SessionVaultModel::new(
        VaultPolicy::new(30, 60).expect("valid vault policy"),
        OpaqueInboxPolicy::new(300, 4, 256 * 1024).expect("valid inbox policy"),
        clock,
    );
    let attempt = vault.begin_unlock(selected).expect("begin unlock");
    let limiter = UnlockWorkLimiter::new(1).expect("test work limit");
    let mut credential = OneShotUnlockCredential::new(selected, ());
    let mut protector = protector;
    let completion = attempt.prepare_with(&limiter, &mut credential, &mut protector);

    assert_eq!(vault.complete_unlock(completion), Err(VaultError::Rejected));
    assert_eq!(vault.state(), VaultState::Sealed);
}

#[test]
fn protector_failure_returns_to_sealed_without_running_work() {
    let selected = session_id(0x11);
    let mut vault = SessionVaultModel::new(
        VaultPolicy::new(30, 60).expect("valid vault policy"),
        OpaqueInboxPolicy::new(300, 4, 256 * 1024).expect("valid inbox policy"),
        DeterministicClock::new(NOW),
    );
    let attempt = vault.begin_unlock(selected).expect("begin unlock");
    let limiter = UnlockWorkLimiter::new(1).expect("test work limit");
    let mut credential = OneShotUnlockCredential::new(selected, ());
    let mut protector = DeterministicKeyProtector::rejecting(selected);
    let completion = attempt.prepare_with(&limiter, &mut credential, &mut protector);

    assert_eq!(
        vault.complete_unlock(completion),
        Err(VaultError::ProviderFailure)
    );
    assert_eq!(vault.state(), VaultState::Sealed);
}

#[test]
fn relock_and_platform_events_revoke_access_and_reject_stale_completion() {
    let mut vault = model();
    let selected = session_id(0x11);
    unlock(&mut vault, selected);

    let stale = vault.begin_relock(selected).expect("begin first relock");
    assert_eq!(vault.state(), VaultState::Relocking);
    assert_eq!(
        vault.perform_privileged(selected, VaultOperation::Sign, || {}),
        Err(VaultError::Rejected)
    );
    vault.force_lock(LockEvent::ScreenLocked);
    assert_eq!(vault.state(), VaultState::Sealed);

    unlock(&mut vault, selected);
    let current = vault.begin_relock(selected).expect("begin current relock");
    assert_eq!(
        vault.complete_relock(stale),
        Err(VaultError::ReservationMismatch)
    );
    assert_eq!(vault.state(), VaultState::Relocking);
    vault
        .complete_relock(current)
        .expect("complete exact relock generation");
    assert_eq!(vault.state(), VaultState::Sealed);

    for event in [
        LockEvent::Explicit,
        LockEvent::IdleTimeout,
        LockEvent::ScreenLocked,
        LockEvent::Sleep,
        LockEvent::Logout,
        LockEvent::ProcessExit,
    ] {
        unlock(&mut vault, selected);
        vault.force_lock(event);
        assert_eq!(vault.state(), VaultState::Sealed);
    }
}
