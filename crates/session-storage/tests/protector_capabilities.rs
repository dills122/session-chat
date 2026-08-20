use session_storage::{
    BackupExposure, DeterministicClock, DeterministicKeyProtector, DeviceBinding,
    KeyStorageProtection, OpaqueInboxPolicy, ProtectionLevel, ProtectorCapabilities, SessionId,
    SessionKeyProtector, SessionVaultModel, UserPresence, VaultError, VaultPolicy, VaultState,
};

fn session_id() -> SessionId {
    SessionId::new([7; 32]).expect("nonzero session")
}

#[test]
fn deterministic_protector_reports_only_test_evidence() {
    let protector = DeterministicKeyProtector::new(session_id(), [8; 32]).expect("test protector");

    assert_eq!(
        protector.capabilities(),
        ProtectorCapabilities::new(
            KeyStorageProtection::TestOnly,
            DeviceBinding::Unknown,
            UserPresence::None,
            BackupExposure::Unknown,
        )
    );
    assert!(protector.capabilities().supports(ProtectionLevel::TestOnly));
    assert!(
        !protector
            .capabilities()
            .supports(ProtectionLevel::DeviceBound)
    );
    assert!(
        !protector
            .capabilities()
            .supports(ProtectionLevel::FreshUserPresence)
    );
}

#[test]
fn stronger_mode_requires_device_only_no_backup_and_fresh_presence_evidence() {
    let user_profile = ProtectorCapabilities::new(
        KeyStorageProtection::OperatingSystem,
        DeviceBinding::UserProfile,
        UserPresence::DeviceUnlock,
        BackupExposure::MayBackup,
    );
    assert!(!user_profile.supports(ProtectionLevel::DeviceBound));

    let device_only = ProtectorCapabilities::new(
        KeyStorageProtection::OperatingSystem,
        DeviceBinding::ThisDeviceOnly,
        UserPresence::DeviceUnlock,
        BackupExposure::Excluded,
    );
    assert!(device_only.supports(ProtectionLevel::DeviceBound));
    assert!(!device_only.supports(ProtectionLevel::FreshUserPresence));

    let fresh = ProtectorCapabilities::new(
        KeyStorageProtection::OperatingSystem,
        DeviceBinding::ThisDeviceOnly,
        UserPresence::FreshPrompt,
        BackupExposure::Excluded,
    );
    assert!(fresh.supports(ProtectionLevel::FreshUserPresence));
}

#[test]
fn vault_policy_records_the_minimum_protector_evidence() {
    assert_eq!(
        VaultPolicy::new(10, 60)
            .expect("test policy")
            .minimum_protection(),
        ProtectionLevel::TestOnly
    );
    assert_eq!(
        VaultPolicy::new_with_protection(10, 60, ProtectionLevel::FreshUserPresence)
            .expect("production-shaped policy")
            .minimum_protection(),
        ProtectionLevel::FreshUserPresence
    );
}

#[test]
fn unlock_fails_closed_before_calling_a_weaker_protector() {
    let selected = session_id();
    let mut vault = SessionVaultModel::new(
        VaultPolicy::new_with_protection(10, 60, ProtectionLevel::FreshUserPresence)
            .expect("production-shaped policy"),
        OpaqueInboxPolicy::new(300, 4, 256 * 1024).expect("inbox policy"),
        DeterministicClock::new(100),
        DeterministicKeyProtector::new(selected, [8; 32]).expect("test protector"),
    );
    let attempt = vault.begin_unlock(selected).expect("begin unlock");

    assert_eq!(
        vault.complete_unlock(attempt),
        Err(VaultError::ProviderFailure)
    );
    assert_eq!(vault.state(), VaultState::Sealed);
}
