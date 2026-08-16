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
fn rejects_unknown_versions_and_object_types() {
    let encoded = encoded_invitation();
    let cases = [
        (1, 7, WireError::UnsupportedVersion(7)),
        (2, 7, WireError::UnsupportedObjectType(7)),
        (
            2,
            WireObjectType::OpaqueEnvelope as u8,
            WireError::UnsupportedObjectType(WireObjectType::OpaqueEnvelope as u16),
        ),
    ];

    for (offset, value, expected) in cases {
        let mut unsupported = encoded.clone();
        unsupported[offset] = value;
        assert_eq!(
            SignedCapabilityInvitation::decode_and_verify(&unsupported).err(),
            Some(expected),
            "field at byte {offset} must be allowlisted"
        );
    }
}

#[test]
fn rejects_wrong_cbor_types_for_every_invitation_field() {
    let encoded = encoded_invitation();
    let field_offsets = [1, 2, 3, 4, 21, 26, 31, 32, 33, 67, 101, 135];

    for offset in field_offsets {
        let mut wrong_type = encoded.clone();
        wrong_type[offset] = if matches!(offset, 1 | 2 | 3 | 21 | 26 | 31 | 32) {
            0x40 // empty byte string where an integer is required
        } else {
            0x00 // integer where a byte string is required
        };

        assert_eq!(
            SignedCapabilityInvitation::decode_and_verify(&wrong_type).err(),
            Some(WireError::Malformed),
            "wrong CBOR type at byte {offset} must fail before authentication"
        );
    }
}

#[test]
fn rejects_indefinite_byte_strings_for_every_byte_field() {
    let encoded = encoded_invitation();

    for offset in [4, 33, 67, 101, 135] {
        let mut indefinite = encoded.clone();
        indefinite[offset] = 0x5f;
        assert_eq!(
            SignedCapabilityInvitation::decode_and_verify(&indefinite).err(),
            Some(WireError::Malformed),
            "indefinite byte string at byte {offset} is outside the profile"
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
    let cases = [
        (4, 0x4f, WireError::InvalidInvitationIdLength(15)),
        (4, 0x51, WireError::InvalidInvitationIdLength(17)),
        (34, 31, WireError::InvalidJoinChallengeLength(31)),
        (34, 33, WireError::InvalidJoinChallengeLength(33)),
        (68, 31, WireError::InvalidSecretCapabilityLength(31)),
        (68, 33, WireError::InvalidSecretCapabilityLength(33)),
        (102, 31, WireError::InvalidVerifyingKeyLength(31)),
        (102, 33, WireError::InvalidVerifyingKeyLength(33)),
        (136, 63, WireError::InvalidSignatureLength(63)),
    ];

    for (offset, value, expected) in cases {
        let mut invalid_length = encoded.clone();
        invalid_length[offset] = value;
        assert_eq!(
            SignedCapabilityInvitation::decode_and_verify(&invalid_length).err(),
            Some(expected),
            "fixed-size field at byte {offset} must reject length {value}"
        );
    }

    let mut long_signature = encoded.clone();
    long_signature[136] = 65;
    long_signature.push(0);
    assert_eq!(
        SignedCapabilityInvitation::decode_and_verify(&long_signature).err(),
        Some(WireError::InvalidSignatureLength(65))
    );

    let weak_keys = [
        [0; 32],
        {
            let mut identity = [0; 32];
            identity[0] = 1;
            identity
        },
        [0xff; 32],
    ];
    for weak_key in weak_keys {
        let mut encoded_with_weak_key = encoded.clone();
        encoded_with_weak_key[103..135].copy_from_slice(&weak_key);
        assert!(matches!(
            SignedCapabilityInvitation::decode_and_verify(&encoded_with_weak_key),
            Err(WireError::InvalidVerifyingKey | WireError::InvalidSignature)
        ));
    }
}

#[test]
fn rejects_zero_secret_and_binding_fields_after_decoding() {
    let encoded = encoded_invitation();
    let cases = [
        (5..21, WireError::ZeroInvitationId),
        (35..67, WireError::ZeroJoinChallenge),
        (69..101, WireError::ZeroSecretCapability),
    ];

    for (range, expected) in cases {
        let mut zeroed = encoded.clone();
        zeroed[range].fill(0);
        assert_eq!(
            SignedCapabilityInvitation::decode_and_verify(&zeroed).err(),
            Some(expected)
        );
    }
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
