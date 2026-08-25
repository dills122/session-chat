use key_protector_passphrase::{
    MAX_PASSPHRASE_BYTES, PortableKeyError, PortablePassphrase, PortablePassphraseKeyProtector,
    PortablePassphraseKeyWrapper, WRAPPED_SESSION_KEY_V1_BYTES, WrappedSessionKeyV1,
};
use session_storage::{
    BackupExposure, DeterministicClock, DeviceBinding, KeyStorageProtection,
    OneShotUnlockCredential, OpaqueInboxPolicy, ProtectionLevel, ProtectorCapabilities, SessionId,
    SessionVaultModel, UnlockCredentialSource, UnlockWorkLimiter, UserPresence, VaultError,
    VaultPolicy, VaultState,
};

fn session_id(byte: u8) -> SessionId {
    SessionId::new([byte; 32]).expect("nonzero session ID")
}

fn passphrase(byte: u8) -> PortablePassphrase {
    PortablePassphrase::new(vec![byte; 32]).expect("bounded passphrase")
}

#[test]
fn passphrase_and_outer_record_are_bounded_before_kdf_work() {
    assert_eq!(
        PortablePassphrase::new(Vec::new()).err(),
        Some(PortableKeyError::Rejected)
    );
    assert!(PortablePassphrase::new(vec![1; MAX_PASSPHRASE_BYTES]).is_ok());
    assert_eq!(
        PortablePassphrase::new(vec![1; MAX_PASSPHRASE_BYTES + 1]).err(),
        Some(PortableKeyError::Rejected)
    );

    for length in 0..WRAPPED_SESSION_KEY_V1_BYTES {
        assert_eq!(
            WrappedSessionKeyV1::decode(&vec![0; length]).err(),
            Some(PortableKeyError::Rejected)
        );
    }
    assert_eq!(
        WrappedSessionKeyV1::decode(&[0; WRAPPED_SESSION_KEY_V1_BYTES + 1]).err(),
        Some(PortableKeyError::Rejected)
    );
}

#[test]
fn portable_capabilities_are_honest_and_backup_capable() {
    let capabilities = PortablePassphraseKeyWrapper::new().capabilities();
    assert_eq!(
        capabilities,
        ProtectorCapabilities::new(
            KeyStorageProtection::ApplicationWrapped,
            DeviceBinding::Unknown,
            UserPresence::None,
            BackupExposure::MayBackup,
        )
    );
    assert!(capabilities.supports(ProtectionLevel::EncryptedAtRest));
    assert!(!capabilities.supports(ProtectionLevel::DeviceBound));
    assert!(!capabilities.supports(ProtectionLevel::FreshUserPresence));
}

#[test]
fn provision_and_unseal_round_trip_binds_the_expected_session() {
    let wrapper = PortablePassphraseKeyWrapper::new();
    let selected = session_id(0x11);
    let provisioned = wrapper
        .provision(selected, passphrase(0x91))
        .expect("provision portable wrapped key");
    let (wrapped, initial_key) = provisioned.into_parts();
    drop(initial_key);

    wrapper
        .unseal(selected, passphrase(0x91), &wrapped)
        .expect("unseal exact session and passphrase");
    assert_eq!(
        wrapper
            .unseal(session_id(0x12), passphrase(0x91), &wrapped)
            .err(),
        Some(PortableKeyError::Rejected)
    );
    assert_eq!(
        wrapper.unseal(selected, passphrase(0x92), &wrapped).err(),
        Some(PortableKeyError::Rejected)
    );
}

#[test]
fn independent_provisioning_uses_fresh_complete_records() {
    let wrapper = PortablePassphraseKeyWrapper::new();
    let first = wrapper
        .provision(session_id(0x21), passphrase(0xa1))
        .expect("first provision");
    let second = wrapper
        .provision(session_id(0x21), passphrase(0xa1))
        .expect("second provision");
    let (first_wrapped, first_key) = first.into_parts();
    let (second_wrapped, second_key) = second.into_parts();
    drop((first_key, second_key));

    assert_ne!(first_wrapped.as_bytes(), second_wrapped.as_bytes());
}

#[test]
fn unknown_headers_truncation_and_trailing_bytes_reject() {
    let wrapper = PortablePassphraseKeyWrapper::new();
    let provisioned = wrapper
        .provision(session_id(0x31), passphrase(0xb1))
        .expect("provision fixture");
    let (wrapped, key) = provisioned.into_parts();
    drop(key);

    for index in 0..26 {
        let mut changed = *wrapped.as_bytes();
        changed[index] ^= 0x80;
        assert_eq!(
            WrappedSessionKeyV1::decode(&changed).err(),
            Some(PortableKeyError::Rejected),
            "changed public header byte {index}"
        );
    }

    let mut trailing = wrapped.as_bytes().to_vec();
    trailing.push(0);
    assert_eq!(
        WrappedSessionKeyV1::decode(&trailing).err(),
        Some(PortableKeyError::Rejected)
    );
}

#[test]
fn salt_nonce_ciphertext_and_tag_tampering_fail_closed() {
    let wrapper = PortablePassphraseKeyWrapper::new();
    let selected = session_id(0x41);
    let provisioned = wrapper
        .provision(selected, passphrase(0xc1))
        .expect("provision fixture");
    let (wrapped, key) = provisioned.into_parts();
    drop(key);

    for index in [26, 41, 42, 53, 54, 85, 86, 101] {
        let mut changed = *wrapped.as_bytes();
        changed[index] ^= 1;
        let decoded = WrappedSessionKeyV1::decode(&changed).expect("structurally valid record");
        assert_eq!(
            wrapper.unseal(selected, passphrase(0xc1), &decoded).err(),
            Some(PortableKeyError::Rejected),
            "tampered byte {index}"
        );
    }
}

#[test]
fn portable_protector_drives_one_exact_encrypted_at_rest_unlock() {
    let selected = session_id(0x51);
    let provisioned = PortablePassphraseKeyWrapper::new()
        .provision(selected, passphrase(0xd1))
        .expect("provision fixture");
    let (wrapped, key) = provisioned.into_parts();
    drop(key);
    let mut protector = PortablePassphraseKeyProtector::new(selected, wrapped);
    let mut credential = OneShotUnlockCredential::new(selected, passphrase(0xd1));
    let limiter = UnlockWorkLimiter::new(1).expect("one KDF at a time");
    let mut vault = SessionVaultModel::new(
        VaultPolicy::new_with_protection(30, 60, ProtectionLevel::EncryptedAtRest)
            .expect("portable policy"),
        OpaqueInboxPolicy::new(300, 4, 256 * 1024).expect("inbox policy"),
        DeterministicClock::new(2_000_000_000),
    );

    let request = vault.begin_unlock(selected).expect("begin unlock");
    let completion = request.prepare_with(&limiter, &mut credential, &mut protector);
    vault
        .complete_unlock(completion)
        .expect("portable result opens exact session");

    assert_eq!(vault.state(), VaultState::Open);
    assert!(credential.acquire(selected).is_err());
    assert_eq!(limiter.in_flight(), 0);
}

#[test]
fn wrong_passphrase_is_consumed_and_returns_only_the_coarse_vault_failure() {
    let selected = session_id(0x52);
    let provisioned = PortablePassphraseKeyWrapper::new()
        .provision(selected, passphrase(0xe1))
        .expect("provision fixture");
    let (wrapped, key) = provisioned.into_parts();
    drop(key);
    let mut protector = PortablePassphraseKeyProtector::new(selected, wrapped);
    let mut credential = OneShotUnlockCredential::new(selected, passphrase(0xe2));
    let limiter = UnlockWorkLimiter::new(1).expect("one KDF at a time");
    let mut vault = SessionVaultModel::new(
        VaultPolicy::new_with_protection(30, 60, ProtectionLevel::EncryptedAtRest)
            .expect("portable policy"),
        OpaqueInboxPolicy::new(300, 4, 256 * 1024).expect("inbox policy"),
        DeterministicClock::new(2_000_000_000),
    );

    let request = vault.begin_unlock(selected).expect("begin unlock");
    let completion = request.prepare_with(&limiter, &mut credential, &mut protector);

    assert_eq!(
        vault.complete_unlock(completion),
        Err(VaultError::ProviderFailure)
    );
    assert_eq!(vault.state(), VaultState::Sealed);
    assert!(credential.acquire(selected).is_err());
    assert_eq!(limiter.in_flight(), 0);
}
