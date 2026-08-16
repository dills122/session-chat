use ed25519_dalek::{Signer, SigningKey};
use minicbor::Encoder;
use session_protocol::{
    AdmissionMode, CapabilityInvitationClaims, InvitationUsePolicy, MAX_SIGNED_INVITATION_BYTES,
    SecretCapability, SignatureSuite, SignedCapabilityInvitation, WireError, WireObjectType,
};

const INVITATION_ID: [u8; 16] = [0x11; 16];
const JOIN_CHALLENGE: [u8; 32] = [0x22; 32];
const CAPABILITY: [u8; 32] = [0x33; 32];
const ISSUED_AT: u64 = 1_700_000_000;
const EXPIRES_AT: u64 = ISSUED_AT + 3_600;

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0xa5; 32])
}

fn claims() -> CapabilityInvitationClaims {
    CapabilityInvitationClaims::new(
        INVITATION_ID,
        ISSUED_AT,
        EXPIRES_AT,
        JOIN_CHALLENGE,
        SecretCapability::new(CAPABILITY).expect("the fixture capability is nonzero"),
    )
    .expect("the fixture claims are structurally valid")
}

fn invitation() -> SignedCapabilityInvitation {
    SignedCapabilityInvitation::sign(claims(), &signing_key()).expect("fixture signing succeeds")
}

fn encoded_invitation() -> Vec<u8> {
    invitation()
        .encode_canonical()
        .expect("fixture encoding succeeds")
}

fn decode_hex(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2));
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("fixture is valid hex"))
        .collect()
}

#[test]
fn emits_the_committed_signed_invitation_fixture() {
    let expected = decode_hex(
        "8c01020150111111111111111111111111111111111a6553f1001a6553ff1001015820222222222222222222222222222222222222222222222222222222222222222258203333333333333333333333333333333333333333333333333333333333333333582029e5833a915a6429a4e3a7948475c338ef436eb82be89c92f059704403db9d555840f5da78f19bbfd2c7b71133965386ff44a7c0918af9ce72e766d6a71ffee13049a0de2d1aa7be380a092d21cd6f0a1099717758429dde204cee722da697728905",
    );

    let actual = encoded_invitation();
    assert_eq!(actual.len(), expected.len());
    assert_eq!(actual, expected);
}

#[test]
fn authenticates_and_exposes_the_capability_invitation_contract() {
    let encoded = encoded_invitation();
    assert!(encoded.len() <= MAX_SIGNED_INVITATION_BYTES);

    let decoded = SignedCapabilityInvitation::decode_and_verify(&encoded)
        .expect("the signed fixture authenticates");

    assert_eq!(
        decoded.object_type(),
        WireObjectType::SignedCapabilityInvitation
    );
    assert_eq!(decoded.signature_suite(), SignatureSuite::Ed25519);
    assert_eq!(decoded.admission_mode(), AdmissionMode::SecretCapability);
    assert_eq!(decoded.use_policy(), InvitationUsePolicy::SingleUse);
    assert_eq!(decoded.invitation_id(), &INVITATION_ID);
    assert_eq!(decoded.issued_at_unix_seconds(), ISSUED_AT);
    assert_eq!(decoded.expires_at_unix_seconds(), EXPIRES_AT);
    assert_eq!(decoded.join_challenge(), &JOIN_CHALLENGE);
    assert_eq!(decoded.capability().expose_secret(), &CAPABILITY);
    assert_eq!(
        decoded.inviter_verifying_key(),
        &signing_key().verifying_key().to_bytes()
    );
}

#[test]
fn rejects_tampering_with_every_secret_or_binding_field() {
    let encoded = encoded_invitation();
    let tamper_offsets = [
        5,                 // invitation id
        25,                // issued at
        30,                // expires at
        35,                // join challenge
        69,                // capability
        103,               // verifying key
        encoded.len() - 1, // signature
    ];

    for offset in tamper_offsets {
        let mut tampered = encoded.clone();
        tampered[offset] ^= 0x01;

        assert!(
            SignedCapabilityInvitation::decode_and_verify(&tampered).is_err(),
            "tampering at byte {offset} must fail"
        );
    }
}

#[test]
fn rejects_a_signature_without_the_invitation_domain_prefix() {
    let valid = invitation();
    let mut unsigned = Encoder::new(Vec::new());
    unsigned
        .array(11)
        .and_then(|encoder| encoder.u16(1))
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.u16(1))
        .and_then(|encoder| encoder.bytes(valid.invitation_id()))
        .and_then(|encoder| encoder.u64(valid.issued_at_unix_seconds()))
        .and_then(|encoder| encoder.u64(valid.expires_at_unix_seconds()))
        .and_then(|encoder| encoder.u16(1))
        .and_then(|encoder| encoder.u16(1))
        .and_then(|encoder| encoder.bytes(valid.join_challenge()))
        .and_then(|encoder| encoder.bytes(valid.capability().expose_secret()))
        .and_then(|encoder| encoder.bytes(valid.inviter_verifying_key()))
        .expect("test-only unsigned payload encodes");

    let wrong_signature = signing_key().sign(&unsigned.into_writer()).to_bytes();
    let mut encoded = valid.encode_canonical().expect("fixture encodes");
    let signature_start = encoded.len() - wrong_signature.len();
    encoded[signature_start..].copy_from_slice(&wrong_signature);

    assert_eq!(
        SignedCapabilityInvitation::decode_and_verify(&encoded).err(),
        Some(WireError::InvalidSignature)
    );
}

#[test]
fn rejects_unknown_signature_admission_and_use_identifiers() {
    let encoded = encoded_invitation();
    let cases = [
        (3, WireError::UnsupportedSignatureSuite(7)),
        (31, WireError::UnsupportedAdmissionMode(7)),
        (32, WireError::UnsupportedInvitationUsePolicy(7)),
    ];

    for (offset, expected) in cases {
        let mut unknown = encoded.clone();
        unknown[offset] = 7;

        assert_eq!(
            SignedCapabilityInvitation::decode_and_verify(&unknown).err(),
            Some(expected)
        );
    }
}

#[test]
fn rejects_malformed_non_deterministic_and_oversized_invitation_bytes() {
    let encoded = encoded_invitation();

    let mut wrong_field_count = encoded.clone();
    wrong_field_count[0] = 0x8b;
    assert_eq!(
        SignedCapabilityInvitation::decode_and_verify(&wrong_field_count).err(),
        Some(WireError::Malformed)
    );

    let mut non_deterministic_version = encoded.clone();
    non_deterministic_version.splice(1..2, [0x18, 0x01]);
    assert_eq!(
        SignedCapabilityInvitation::decode_and_verify(&non_deterministic_version).err(),
        Some(WireError::NonDeterministicEncoding)
    );

    let mut indefinite_array = encoded.clone();
    indefinite_array[0] = 0x9f;
    indefinite_array.push(0xff);
    assert_eq!(
        SignedCapabilityInvitation::decode_and_verify(&indefinite_array).err(),
        Some(WireError::Malformed)
    );

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        SignedCapabilityInvitation::decode_and_verify(&trailing).err(),
        Some(WireError::TrailingData)
    );

    let oversized = vec![0; MAX_SIGNED_INVITATION_BYTES + 1];
    assert_eq!(
        SignedCapabilityInvitation::decode_and_verify(&oversized).err(),
        Some(WireError::WireObjectTooLarge {
            actual: MAX_SIGNED_INVITATION_BYTES + 1,
            maximum: MAX_SIGNED_INVITATION_BYTES,
        })
    );
}

#[test]
fn rejects_invalid_fixed_lengths_and_verifying_keys() {
    let encoded = encoded_invitation();

    let mut short_id = encoded.clone();
    short_id[4] = 0x4f;
    assert_eq!(
        SignedCapabilityInvitation::decode_and_verify(&short_id).err(),
        Some(WireError::InvalidInvitationIdLength(15))
    );

    let mut short_challenge = encoded.clone();
    short_challenge[33] = 0x4f;
    assert_eq!(
        SignedCapabilityInvitation::decode_and_verify(&short_challenge).err(),
        Some(WireError::InvalidJoinChallengeLength(15))
    );

    let mut invalid_key = encoded.clone();
    invalid_key[103..135].fill(0xff);
    assert!(matches!(
        SignedCapabilityInvitation::decode_and_verify(&invalid_key),
        Err(WireError::InvalidVerifyingKey | WireError::InvalidSignature)
    ));
}

#[test]
fn rejects_zero_identifiers_challenges_capabilities_and_time_reversal() {
    assert_eq!(
        CapabilityInvitationClaims::new(
            [0; 16],
            ISSUED_AT,
            EXPIRES_AT,
            JOIN_CHALLENGE,
            SecretCapability::new(CAPABILITY).expect("fixture is nonzero"),
        )
        .err(),
        Some(WireError::ZeroInvitationId)
    );

    assert_eq!(
        CapabilityInvitationClaims::new(
            INVITATION_ID,
            ISSUED_AT,
            EXPIRES_AT,
            [0; 32],
            SecretCapability::new(CAPABILITY).expect("fixture is nonzero"),
        )
        .err(),
        Some(WireError::ZeroJoinChallenge)
    );

    assert_eq!(
        SecretCapability::new([0; 32]).err(),
        Some(WireError::ZeroSecretCapability)
    );

    assert_eq!(
        CapabilityInvitationClaims::new(
            INVITATION_ID,
            EXPIRES_AT,
            ISSUED_AT,
            JOIN_CHALLENGE,
            SecretCapability::new(CAPABILITY).expect("fixture is nonzero"),
        )
        .err(),
        Some(WireError::InvalidInvitationTimeRange {
            issued_at: EXPIRES_AT,
            expires_at: ISSUED_AT,
        })
    );
}
