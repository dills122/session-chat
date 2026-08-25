use session_crypto::{
    ApplicationMessage, MAX_APPLICATION_MESSAGE_BYTES, MessageEvent, MessageSession,
    MessageSessionError,
};
use session_crypto_mls::{
    IncomingMessage, MAX_APPLICATION_BYTES, MAX_MLS_MESSAGE_BYTES, MlsAdapterError, MlsWireMessage,
    SessionGroupId, WelcomeMessage, create_client, create_key_package_validator,
};

const NOW: u64 = 1_800_000_000;

fn group_id() -> SessionGroupId {
    SessionGroupId::new([0x77; 32]).expect("nonzero test group id")
}

#[test]
fn clients_generate_fresh_nonzero_session_credential_identities() -> Result<(), MlsAdapterError> {
    let alice = create_client()?;
    let bob = create_client()?;

    assert!(
        alice
            .credential_identity()
            .as_bytes()
            .iter()
            .any(|byte| *byte != 0)
    );
    assert_ne!(
        alice.credential_identity().as_bytes(),
        bob.credential_identity().as_bytes()
    );

    Ok(())
}

#[test]
fn exact_validated_key_package_reaches_add_welcome_and_two_party_messages()
-> Result<(), MlsAdapterError> {
    let alice = create_client().expect("create Alice");
    let bob = create_client().expect("create Bob");
    let validator = create_key_package_validator();

    let bob_key_package = bob
        .generate_key_package(NOW)
        .expect("generate Bob KeyPackage");
    let validated = validator
        .validate_key_package(bob_key_package.as_bytes(), NOW)
        .expect("validate Bob KeyPackage");
    let expected_reference = *validated.key_package_reference();

    assert_eq!(
        validated.credential_identity(),
        bob.credential_identity().as_bytes()
    );
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
    assert_eq!(addition.key_package_reference(), &expected_reference);
    assert!(!addition.commit().as_bytes().is_empty());

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
fn application_messages_use_the_provider_neutral_session_interface()
-> Result<(), Box<dyn std::error::Error>> {
    let alice = create_client()?;
    let bob = create_client()?;
    let validator = create_key_package_validator();
    let bob_key_package = bob.generate_key_package(NOW)?;
    let validated = validator.validate_key_package(bob_key_package.as_bytes(), NOW)?;
    let mut alice_group = alice.create_group(group_id(), NOW)?;
    let addition = alice_group.prepare_add(validated, NOW)?.apply()?;
    let bob_group = bob.join_group(addition.into_welcome(), NOW)?;

    let mut alice_session: Box<dyn MessageSession> = Box::new(alice_group);
    let mut bob_session: Box<dyn MessageSession> = Box::new(bob_group);

    let protected = alice_session.protect_application_message(b"provider-neutral hello")?;
    assert_eq!(
        bob_session.process_protected_message(protected)?,
        MessageEvent::Application(ApplicationMessage::from_bytes(b"provider-neutral hello")?)
    );
    assert_eq!(alice_session.epoch(), 1);
    assert_eq!(bob_session.member_count(), 2);
    assert_eq!(
        alice_session.protect_application_message(&vec![0; MAX_APPLICATION_MESSAGE_BYTES + 1]),
        Err(MessageSessionError::InputTooLarge)
    );

    Ok(())
}

#[test]
fn malformed_expired_and_oversized_key_packages_fail_before_membership()
-> Result<(), MlsAdapterError> {
    let bob = create_client()?;
    let validator = create_key_package_validator();
    let key_package = bob.generate_key_package(NOW)?;

    assert!(matches!(
        validator.validate_key_package(&[], NOW),
        Err(MlsAdapterError::MalformedKeyPackage)
    ));
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
fn abandoned_add_is_releasable_and_expired_add_fails_closed() -> Result<(), MlsAdapterError> {
    let alice = create_client()?;
    let validator = create_key_package_validator();
    let mut group = alice.create_group(group_id(), NOW)?;

    let bob = create_client()?;
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

    let carol = create_client()?;
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
    let alice = create_client()?;
    let bob = create_client()?;
    let validator = create_key_package_validator();
    let bob_key_package = bob.generate_key_package(NOW)?;
    let bob_admission = validator.validate_key_package(bob_key_package.as_bytes(), NOW)?;
    let mut alice_group = alice.create_group(group_id(), NOW)?;
    assert!(matches!(
        alice_group.prepare_remove_peer(NOW),
        Err(MlsAdapterError::ProtocolRejected)
    ));
    let addition = alice_group.prepare_add(bob_admission, NOW)?.apply()?;
    let mut bob_group = bob.join_group(addition.into_welcome(), NOW)?;

    let removal = alice_group.prepare_remove_peer(NOW)?;
    assert_eq!(removal.epoch_before(), 1);
    assert_eq!(removal.current_group_epoch(), 1);
    let removal = removal.apply()?;
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
    let alice = create_client()?;
    let bob = create_client()?;
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

    let abandoned_update = alice_group.prepare_epoch_update(NOW)?;
    assert_eq!(abandoned_update.epoch_before(), 1);
    drop(abandoned_update);
    assert_eq!(alice_group.epoch(), 1);

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
    let alice = create_client()?;
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
        BasicCredential::new(vec![0x22; 32]).into_credential(),
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
