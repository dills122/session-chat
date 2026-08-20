use session_crypto_mls::{
    IncomingMessage, MAX_APPLICATION_BYTES, MAX_MLS_MESSAGE_BYTES, MlsAdapterError, MlsWireMessage,
    SessionCredentialId, SessionGroupId, WelcomeMessage, create_client,
    create_key_package_validator,
};

const NOW: u64 = 1_800_000_000;

fn credential(byte: u8) -> SessionCredentialId {
    SessionCredentialId::new([byte; 32]).expect("nonzero test credential")
}

fn group_id() -> SessionGroupId {
    SessionGroupId::new([0x77; 32]).expect("nonzero test group id")
}

#[test]
fn exact_validated_key_package_reaches_add_welcome_and_two_party_messages()
-> Result<(), MlsAdapterError> {
    let alice = create_client(credential(0x11)).expect("create Alice");
    let bob = create_client(credential(0x22)).expect("create Bob");
    let validator = create_key_package_validator();

    let bob_key_package = bob
        .generate_key_package(NOW)
        .expect("generate Bob KeyPackage");
    let validated = validator
        .validate_key_package(bob_key_package.as_bytes(), NOW)
        .expect("validate Bob KeyPackage");
    let expected_reference = *validated.key_package_reference();

    assert_eq!(validated.credential_identity(), credential(0x22).as_bytes());
    assert_eq!(validated.leaf_signature_key().len(), 32);

    let mut alice_group = alice.create_group(group_id(), NOW).expect("create group");
    let prepared = alice_group
        .prepare_add(validated, NOW)
        .expect("prepare Add");

    assert_eq!(prepared.key_package_reference(), &expected_reference);
    assert_eq!(prepared.epoch_before(), 0);
    assert_eq!(prepared.current_group_epoch(), 0);

    let addition = prepared.apply().expect("apply Add");
    assert_eq!(alice_group.epoch(), 1);
    assert_eq!(alice_group.member_count(), 2);

    let mut trailing_welcome = addition.welcome().as_bytes().to_vec();
    trailing_welcome.push(0);
    assert!(matches!(
        bob.join_group(WelcomeMessage::from_bytes(&trailing_welcome)?, NOW),
        Err(MlsAdapterError::ProtocolRejected)
    ));
    let welcome = WelcomeMessage::from_bytes(addition.welcome().as_bytes())?;
    let mut bob_group = bob.join_group(welcome, NOW).expect("join from Welcome");
    assert_eq!(bob_group.group_id(), group_id().as_bytes());
    assert_eq!(bob_group.epoch(), 1);
    assert_eq!(bob_group.member_count(), 2);

    let ciphertext = alice_group
        .encrypt_application_message(b"hello bob")
        .expect("encrypt application message");
    let ciphertext_bytes = ciphertext.as_bytes().to_vec();
    let mut trailing_ciphertext = ciphertext_bytes.clone();
    trailing_ciphertext.push(0);
    assert_eq!(
        bob_group.process_message(MlsWireMessage::from_bytes(&trailing_ciphertext)?),
        Err(MlsAdapterError::ProtocolRejected)
    );
    let received = bob_group
        .process_message(ciphertext)
        .expect("decrypt application message");
    assert_eq!(
        received,
        IncomingMessage::Application(b"hello bob".to_vec())
    );

    assert_eq!(
        bob_group.process_message(MlsWireMessage::from_bytes(&ciphertext_bytes)?),
        Err(MlsAdapterError::ProtocolRejected)
    );

    Ok(())
}

#[test]
fn malformed_expired_and_oversized_key_packages_fail_before_membership()
-> Result<(), MlsAdapterError> {
    let bob = create_client(credential(0x22))?;
    let validator = create_key_package_validator();
    let key_package = bob.generate_key_package(NOW)?;

    let mut trailing = key_package.as_bytes().to_vec();
    trailing.push(0);
    assert!(matches!(
        validator.validate_key_package(&trailing, NOW),
        Err(MlsAdapterError::MalformedKeyPackage)
    ));
    assert!(matches!(
        validator.validate_key_package(key_package.as_bytes(), NOW + 3_601),
        Err(MlsAdapterError::RejectedKeyPackage)
    ));
    assert!(matches!(
        validator
            .validate_key_package(&vec![0; session_crypto_mls::MAX_KEY_PACKAGE_BYTES + 1], NOW),
        Err(MlsAdapterError::InputTooLarge)
    ));

    Ok(())
}

#[test]
fn abandoned_add_is_releasable_and_duplicate_identity_fails_closed() -> Result<(), MlsAdapterError>
{
    let alice = create_client(credential(0x11))?;
    let duplicate_alice = create_client(credential(0x11))?;
    let validator = create_key_package_validator();
    let key_package = duplicate_alice.generate_key_package(NOW)?;
    let validated = validator.validate_key_package(key_package.as_bytes(), NOW)?;
    let mut group = alice.create_group(group_id(), NOW)?;

    assert!(matches!(
        group.prepare_add(validated, NOW),
        Err(MlsAdapterError::RejectedKeyPackage)
    ));

    let bob = create_client(credential(0x22))?;
    let bob_key_package = bob.generate_key_package(NOW)?;
    let validated = validator.validate_key_package(bob_key_package.as_bytes(), NOW)?;
    let prepared = group.prepare_add(validated, NOW)?;
    assert_eq!(prepared.current_group_epoch(), 0);
    drop(prepared);
    assert_eq!(group.epoch(), 0);
    assert_eq!(group.member_count(), 1);

    let validated = validator.validate_key_package(bob_key_package.as_bytes(), NOW)?;
    assert!(matches!(
        group.prepare_add(validated, NOW + 3_601),
        Err(MlsAdapterError::ProtocolRejected)
    ));
    assert_eq!(group.epoch(), 0);
    let validated = validator.validate_key_package(bob_key_package.as_bytes(), NOW)?;
    group.prepare_add(validated, NOW)?.apply()?;
    assert_eq!(group.member_count(), 2);

    let carol = create_client(credential(0x33))?;
    let carol_key_package = carol.generate_key_package(NOW)?;
    let carol = validator.validate_key_package(carol_key_package.as_bytes(), NOW)?;
    assert!(matches!(
        group.prepare_add(carol, NOW),
        Err(MlsAdapterError::GroupFull)
    ));

    Ok(())
}

#[test]
fn removal_advances_the_epoch_and_blocks_future_messages() -> Result<(), MlsAdapterError> {
    let alice = create_client(credential(0x11))?;
    let bob = create_client(credential(0x22))?;
    let validator = create_key_package_validator();
    let bob_key_package = bob.generate_key_package(NOW)?;
    let bob_admission = validator.validate_key_package(bob_key_package.as_bytes(), NOW)?;
    let mut alice_group = alice.create_group(group_id(), NOW)?;
    let addition = alice_group.prepare_add(bob_admission, NOW)?.apply()?;
    let mut bob_group = bob.join_group(addition.into_welcome(), NOW)?;

    let removal = alice_group.prepare_remove_peer(NOW)?.apply()?;
    assert_eq!(alice_group.epoch(), 2);
    assert_eq!(alice_group.member_count(), 1);
    let removal_bytes = removal.commit().as_bytes().to_vec();
    assert_eq!(
        bob_group.process_message(removal.into_commit())?,
        IncomingMessage::Removed
    );

    let after_removal = alice_group.encrypt_application_message(b"after removal")?;
    assert_eq!(
        bob_group.process_message(after_removal),
        Err(MlsAdapterError::ProtocolRejected)
    );
    assert_eq!(
        bob_group.process_message(MlsWireMessage::from_bytes(&removal_bytes)?),
        Err(MlsAdapterError::ProtocolRejected)
    );

    Ok(())
}

#[test]
fn update_and_reordered_or_temporarily_lost_messages_recover_safely() -> Result<(), MlsAdapterError>
{
    let alice = create_client(credential(0x11))?;
    let bob = create_client(credential(0x22))?;
    let validator = create_key_package_validator();
    let bob_key_package = bob.generate_key_package(NOW)?;
    let bob_admission = validator.validate_key_package(bob_key_package.as_bytes(), NOW)?;
    let mut alice_group = alice.create_group(group_id(), NOW)?;
    let addition = alice_group.prepare_add(bob_admission, NOW)?.apply()?;
    let mut bob_group = bob.join_group(addition.into_welcome(), NOW)?;

    let first = alice_group.encrypt_application_message(b"first")?;
    let first_bytes = first.as_bytes().to_vec();
    let second = alice_group.encrypt_application_message(b"second")?;
    assert_eq!(
        bob_group.process_message(second)?,
        IncomingMessage::Application(b"second".to_vec())
    );
    assert_eq!(
        bob_group.process_message(first)?,
        IncomingMessage::Application(b"first".to_vec())
    );
    assert_eq!(
        bob_group.process_message(MlsWireMessage::from_bytes(&first_bytes)?),
        Err(MlsAdapterError::ProtocolRejected)
    );

    let update = alice_group.prepare_epoch_update(NOW)?.apply()?;
    assert_eq!(alice_group.epoch(), 2);
    let update_bytes = update.commit().as_bytes().to_vec();
    let mut trailing_update = update_bytes.clone();
    trailing_update.push(0);
    assert_eq!(
        bob_group.process_message(MlsWireMessage::from_bytes(&trailing_update)?),
        Err(MlsAdapterError::ProtocolRejected)
    );
    let future_epoch_message = alice_group.encrypt_application_message(b"future epoch")?;
    assert_eq!(
        bob_group.process_message(future_epoch_message),
        Err(MlsAdapterError::ProtocolRejected)
    );
    assert_eq!(
        bob_group.process_message(update.into_commit())?,
        IncomingMessage::EpochAdvanced
    );
    assert_eq!(bob_group.epoch(), 2);
    assert_eq!(
        bob_group.process_message(MlsWireMessage::from_bytes(&update_bytes)?),
        Err(MlsAdapterError::ProtocolRejected)
    );
    assert_eq!(
        bob_group.process_message(alice_group.encrypt_application_message(b"recovered")?)?,
        IncomingMessage::Application(b"recovered".to_vec())
    );

    Ok(())
}

#[test]
fn application_and_wire_bounds_fail_closed() -> Result<(), MlsAdapterError> {
    let alice = create_client(credential(0x11))?;
    let mut group = alice.create_group(group_id(), NOW)?;

    assert!(matches!(
        group.encrypt_application_message(&vec![0; MAX_APPLICATION_BYTES + 1]),
        Err(MlsAdapterError::InputTooLarge)
    ));
    assert!(matches!(
        MlsWireMessage::from_bytes(&vec![0; MAX_MLS_MESSAGE_BYTES + 1]),
        Err(MlsAdapterError::InputTooLarge)
    ));
    assert!(matches!(
        WelcomeMessage::from_bytes(&vec![0; MAX_MLS_MESSAGE_BYTES + 1]),
        Err(MlsAdapterError::InputTooLarge)
    ));
    assert_eq!(
        group.process_message(MlsWireMessage::from_bytes(&[0])?),
        Err(MlsAdapterError::ProtocolRejected)
    );

    Ok(())
}

#[test]
fn otherwise_valid_key_package_with_leaf_extension_is_rejected() -> Result<(), MlsAdapterError> {
    use mls_rs::{
        CipherSuite, CipherSuiteProvider, Client, CryptoProvider, Extension, ExtensionList,
        ProtocolVersion,
        extension::ExtensionType,
        identity::{
            SigningIdentity,
            basic::{BasicCredential, BasicIdentityProvider},
        },
    };
    use mls_rs_crypto_awslc::AwsLcCryptoProvider;

    let crypto = AwsLcCryptoProvider::default();
    let suite = CipherSuite::CURVE25519_AES128;
    let provider = crypto
        .cipher_suite_provider(suite)
        .expect("selected ciphersuite");
    let (secret, public) = provider.signature_key_generate().expect("signature key");
    let identity = SigningIdentity::new(
        BasicCredential::new(credential(0x22).as_bytes().to_vec()).into_credential(),
        public,
    );
    let extension_type = ExtensionType::from(0xF001);
    let client = Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto)
        .protocol_version(ProtocolVersion::MLS_10)
        .extension_type(extension_type)
        .signing_identity(identity, secret, suite)
        .build();
    let message = client
        .generate_key_package_message(
            ExtensionList::new(),
            ExtensionList::from(vec![Extension::new(extension_type, vec![1])]),
            Some(NOW.into()),
        )
        .expect("otherwise valid extended KeyPackage");
    let bytes = message.to_bytes().expect("serialize KeyPackage");

    assert!(matches!(
        create_key_package_validator().validate_key_package(&bytes, NOW),
        Err(MlsAdapterError::RejectedKeyPackage)
    ));

    Ok(())
}
