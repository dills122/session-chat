use session_crypto_mls::{
    IncomingMessage, MlsAdapterError, MlsWireMessage, SessionCredentialId, SessionGroupId,
    create_client, create_key_package_validator,
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

    let mut bob_group = bob
        .join_group(addition.into_welcome(), NOW)
        .expect("join from Welcome");
    assert_eq!(bob_group.group_id(), group_id().as_bytes());
    assert_eq!(bob_group.epoch(), 1);
    assert_eq!(bob_group.member_count(), 2);

    let ciphertext = alice_group
        .encrypt_application_message(b"hello bob")
        .expect("encrypt application message");
    let ciphertext_bytes = ciphertext.as_bytes().to_vec();
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
