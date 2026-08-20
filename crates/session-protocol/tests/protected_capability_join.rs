use ed25519_dalek::SigningKey;
use minicbor::Decoder;
use session_protocol::{
    AdmissionMode, AdmissionProofVersion, ApplicationProtocolVersion, CapabilityInvitationClaims,
    CapabilityInvitationV2Claims, CapabilityJoinRequest, CredentialType, DepositCapability,
    InvitationEncryptionSuite, InvitationJoinBinding, InvitationUsePolicy, JoinRequestBinding,
    JoinRequestSchemaVersion, LocalWelcomeDepositEndpoint, MAX_CAPABILITY_JOIN_REQUEST_BYTES,
    MAX_JOIN_KEY_PACKAGE_BYTES, MAX_LOCAL_WELCOME_ENDPOINT_BYTES,
    MAX_PROTECTED_JOIN_CIPHERTEXT_BYTES, MAX_PROTECTED_JOIN_REQUEST_BYTES,
    MAX_SIGNED_INVITATION_BYTES, MlsCiphersuite, MlsKeyPackageBinding, MlsProtocolVersion,
    NestedObjectType, ProtectedJoinRequest, SecretCapability, SignatureSuite,
    SignedCapabilityInvitation, SignedCapabilityInvitationV2, TransportProfile, WireError,
    WireObjectType,
};

const INVITATION_ID: [u8; 16] = [0x11; 16];
const JOIN_CHALLENGE: [u8; 32] = [0x22; 32];
const CAPABILITY: [u8; 32] = [0x33; 32];
const INVITATION_KEY_ID: [u8; 16] = [0x44; 16];
const HPKE_PUBLIC_KEY: [u8; 32] = [0x55; 32];
const ISSUED_AT: u64 = 1_700_000_000;
const EXPIRES_AT: u64 = ISSUED_AT + 3_600;
const TRANSPORT_INSTANCE_ID: [u8; 16] = [0x66; 16];
const MAILBOX_ID: [u8; 16] = [0x77; 16];
const DEPOSIT_CAPABILITY: [u8; 32] = [0x88; 32];
const JOIN_REQUEST_ID: [u8; 16] = [0x99; 16];
const REQUEST_NONCE: [u8; 32] = [0xaa; 32];
const KEY_PACKAGE_REFERENCE: [u8; 32] = [0xbb; 32];
const CREDENTIAL_IDENTITY: [u8; 32] = [0xcc; 32];
const HPKE_ENCAPSULATED_KEY: [u8; 32] = [0xee; 32];
const HPKE_CIPHERTEXT: &[u8] = b"authenticated ciphertext";
const INVITATION_V2_HEX: &str = "920202010101010150111111111111111111111111111111111a6553f1001a6553ff1001015820222222222222222222222222222222222222222222222222222222222222222258203333333333333333333333333333333333333333333333333333333333333333582029e5833a915a6429a4e3a7948475c338ef436eb82be89c92f059704403db9d555044444444444444444444444444444444582055555555555555555555555555555555555555555555555555555555555555555840caad4a978ce0ec0fd8f44b7fc0a8624b86424674a0fd8cb45da59f08e6e7be73e7a21da3758d37765c1a4395c5e44e8fd2265ff83dc633ab837bad7e3304f307";
const ENDPOINT_HEX: &str = "8701050150666666666666666666666666666666665077777777777777777777777777777777582088888888888888888888888888888888888888888888888888888888888888881a6553ff10";
const INNER_HEX: &str = "950104015011111111111111111111111111111111582022222222222222222222222222222222222222222222222222222222222222225044444444444444444444444444444444582029e5833a915a6429a4e3a7948475c338ef436eb82be89c92f059704403db9d5550999999999999999999999999999999991a6553f1011a6553ff105820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01015820bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb4b6b65792d7061636b616765015820cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc5820805440ee48051fc82ea64d905acabff0d21780f7fcaba6900e0e41387b1d4a5701018701050150666666666666666666666666666666665077777777777777777777777777777777582088888888888888888888888888888888888888888888888888888888888888881a6553ff10";
const OUTER_HEX: &str = "87010301501111111111111111111111111111111150444444444444444444444444444444445820eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee581861757468656e746963617465642063697068657274657874";
const AAD_HEX: &str = "86010301501111111111111111111111111111111150444444444444444444444444444444445820eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

type DecodeError = fn(&[u8]) -> Option<WireError>;

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0xa5; 32])
}

fn leaf_signature_key() -> [u8; 32] {
    SigningKey::from_bytes(&[0xb6; 32])
        .verifying_key()
        .to_bytes()
}

fn decode_hex(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2));
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("fixture is valid hex"))
        .collect()
}

fn top_level_field_offsets(bytes: &[u8]) -> Vec<usize> {
    let mut decoder = Decoder::new(bytes);
    let fields = decoder
        .array()
        .expect("fixture array header decodes")
        .expect("fixture uses a definite array");
    (0..fields)
        .map(|_| {
            let offset = decoder.position();
            decoder.skip().expect("fixture field skips");
            offset
        })
        .collect()
}

fn shorten_byte_string(bytes: &mut [u8], field_offset: usize) {
    match bytes[field_offset] {
        0x41..=0x57 => bytes[field_offset] -= 1,
        0x58 => bytes[field_offset + 1] -= 1,
        marker => panic!("fixture field at {field_offset} has unexpected marker {marker:#x}"),
    }
}

fn field_payload_offset(bytes: &[u8], field_offset: usize) -> usize {
    match bytes[field_offset] {
        0x40..=0x57 => field_offset + 1,
        0x58 => field_offset + 2,
        0x1a | 0x1b => field_offset + 1,
        _ => field_offset,
    }
}

fn base_claims() -> CapabilityInvitationClaims {
    CapabilityInvitationClaims::new(
        INVITATION_ID,
        ISSUED_AT,
        EXPIRES_AT,
        JOIN_CHALLENGE,
        SecretCapability::new(CAPABILITY).expect("the fixture capability is nonzero"),
    )
    .expect("the fixture claims are structurally valid")
}

fn invitation_v2() -> SignedCapabilityInvitationV2 {
    let claims =
        CapabilityInvitationV2Claims::new(base_claims(), INVITATION_KEY_ID, HPKE_PUBLIC_KEY)
            .expect("the v2 claims are structurally valid");
    SignedCapabilityInvitationV2::sign(claims, &signing_key()).expect("fixture signing succeeds")
}

fn response_endpoint() -> LocalWelcomeDepositEndpoint {
    LocalWelcomeDepositEndpoint::new(
        TRANSPORT_INSTANCE_ID,
        MAILBOX_ID,
        DepositCapability::new(DEPOSIT_CAPABILITY)
            .expect("the fixture deposit capability is nonzero"),
        EXPIRES_AT,
    )
    .expect("the response endpoint is structurally valid")
}

fn capability_join_request() -> CapabilityJoinRequest {
    let invitation = InvitationJoinBinding::new(
        INVITATION_ID,
        JOIN_CHALLENGE,
        INVITATION_KEY_ID,
        signing_key().verifying_key().to_bytes(),
    )
    .expect("the invitation binding is structurally valid");
    let request =
        JoinRequestBinding::new(JOIN_REQUEST_ID, ISSUED_AT + 1, EXPIRES_AT, REQUEST_NONCE)
            .expect("the request binding is structurally valid");
    let mls = MlsKeyPackageBinding::new(
        KEY_PACKAGE_REFERENCE,
        b"key-package".to_vec(),
        CREDENTIAL_IDENTITY,
        leaf_signature_key(),
    )
    .expect("the MLS binding is structurally valid");

    CapabilityJoinRequest::new(invitation, request, mls, response_endpoint())
        .expect("the full inner request is structurally valid")
}

#[test]
fn round_trips_and_authenticates_the_signed_invitation_v2_contract() {
    let encoded = invitation_v2()
        .encode_canonical()
        .expect("fixture encoding succeeds");
    let decoded = SignedCapabilityInvitationV2::decode_and_verify(&encoded)
        .expect("the signed fixture authenticates");
    assert_eq!(encoded, decode_hex(INVITATION_V2_HEX));

    assert_eq!(decoded.schema_version(), 2);
    assert_eq!(
        decoded.object_type(),
        WireObjectType::SignedCapabilityInvitation
    );
    assert_eq!(decoded.signature_suite(), SignatureSuite::Ed25519);
    assert_eq!(
        decoded.invitation_encryption_suite(),
        InvitationEncryptionSuite::X25519HkdfSha256Aes128GcmPsk
    );
    assert_eq!(decoded.join_request_schema(), JoinRequestSchemaVersion::V1);
    assert_eq!(
        decoded.application_protocol_version(),
        ApplicationProtocolVersion::V1
    );
    assert_eq!(decoded.transport_profile(), TransportProfile::LocalMemory);
    assert_eq!(decoded.admission_mode(), AdmissionMode::SecretCapability);
    assert_eq!(decoded.use_policy(), InvitationUsePolicy::SingleUse);
    assert_eq!(decoded.invitation_id(), &INVITATION_ID);
    assert_eq!(decoded.issued_at_unix_seconds(), ISSUED_AT);
    assert_eq!(decoded.expires_at_unix_seconds(), EXPIRES_AT);
    assert_eq!(decoded.join_challenge(), &JOIN_CHALLENGE);
    assert_eq!(decoded.capability().expose_secret(), &CAPABILITY);
    assert_eq!(decoded.invitation_key_id(), &INVITATION_KEY_ID);
    assert_eq!(decoded.hpke_recipient_public_key(), &HPKE_PUBLIC_KEY);
    assert_eq!(
        decoded.inviter_verifying_key(),
        &signing_key().verifying_key().to_bytes()
    );
}

#[test]
fn invitation_versions_are_domain_and_layout_separated() {
    let encoded_v2 = invitation_v2()
        .encode_canonical()
        .expect("fixture encoding succeeds");
    assert_eq!(
        SignedCapabilityInvitation::decode_and_verify(&encoded_v2).err(),
        Some(WireError::Malformed)
    );

    let encoded_v1 = SignedCapabilityInvitation::sign(base_claims(), &signing_key())
        .expect("v1 signing succeeds")
        .encode_canonical()
        .expect("v1 encoding succeeds");
    assert_eq!(
        SignedCapabilityInvitationV2::decode_and_verify(&encoded_v1).err(),
        Some(WireError::Malformed)
    );
}

#[test]
fn tampering_with_any_v2_secret_or_generation_binding_fails_verification() {
    let encoded = decode_hex(INVITATION_V2_HEX);
    let offsets = top_level_field_offsets(&encoded);

    for field in [7, 8, 9, 12, 13, 14, 15, 16, 17] {
        let mut tampered = encoded.clone();
        let offset = field_payload_offset(&tampered, offsets[field]);
        tampered[offset] ^= 1;
        assert!(
            SignedCapabilityInvitationV2::decode_and_verify(&tampered).is_err(),
            "tampering with invitation-v2 field {field} must fail"
        );
    }
}

#[test]
fn rejects_zero_v2_encryption_identifiers_and_public_keys() {
    assert_eq!(
        CapabilityInvitationV2Claims::new(base_claims(), [0; 16], HPKE_PUBLIC_KEY).err(),
        Some(WireError::ZeroInvitationKeyId)
    );
    assert_eq!(
        CapabilityInvitationV2Claims::new(base_claims(), INVITATION_KEY_ID, [0; 32]).err(),
        Some(WireError::ZeroHpkePublicKey)
    );
}

#[test]
fn round_trips_the_right_specific_local_welcome_endpoint() {
    let encoded = response_endpoint()
        .encode_canonical()
        .expect("endpoint encoding succeeds");
    let decoded = LocalWelcomeDepositEndpoint::decode_canonical(&encoded)
        .expect("endpoint decoding succeeds");
    assert_eq!(encoded, decode_hex(ENDPOINT_HEX));

    assert_eq!(decoded.schema_version(), 1);
    assert_eq!(
        decoded.object_type(),
        NestedObjectType::LocalWelcomeDepositEndpoint
    );
    assert_eq!(decoded.transport_profile(), TransportProfile::LocalMemory);
    assert_eq!(decoded.transport_instance_id(), &TRANSPORT_INSTANCE_ID);
    assert_eq!(decoded.mailbox_id(), &MAILBOX_ID);
    assert_eq!(
        decoded.deposit_capability().expose_secret(),
        &DEPOSIT_CAPABILITY
    );
    assert_eq!(decoded.expires_at_unix_seconds(), EXPIRES_AT);
}

#[test]
fn round_trips_the_complete_inner_capability_join_request() {
    let encoded = capability_join_request()
        .encode_canonical()
        .expect("inner request encoding succeeds");
    let decoded =
        CapabilityJoinRequest::decode_canonical(&encoded).expect("inner request decoding succeeds");
    assert_eq!(encoded, decode_hex(INNER_HEX));

    assert_eq!(decoded.schema_version(), 1);
    assert_eq!(
        decoded.object_type(),
        NestedObjectType::CapabilityJoinRequest
    );
    assert_eq!(
        decoded.admission_proof_version(),
        AdmissionProofVersion::HpkePskCapability
    );
    assert_eq!(decoded.invitation_id(), &INVITATION_ID);
    assert_eq!(decoded.join_challenge(), &JOIN_CHALLENGE);
    assert_eq!(decoded.invitation_key_id(), &INVITATION_KEY_ID);
    assert_eq!(
        decoded.intended_verifier(),
        &signing_key().verifying_key().to_bytes()
    );
    assert_eq!(decoded.join_request_id(), &JOIN_REQUEST_ID);
    assert_eq!(decoded.issued_at_unix_seconds(), ISSUED_AT + 1);
    assert_eq!(decoded.expires_at_unix_seconds(), EXPIRES_AT);
    assert_eq!(decoded.request_nonce(), &REQUEST_NONCE);
    assert_eq!(decoded.mls_protocol_version(), MlsProtocolVersion::Mls10);
    assert_eq!(decoded.mls_ciphersuite(), MlsCiphersuite::Suite1);
    assert_eq!(decoded.key_package_reference(), &KEY_PACKAGE_REFERENCE);
    assert_eq!(decoded.key_package(), b"key-package");
    assert_eq!(decoded.credential_type(), CredentialType::Basic);
    assert_eq!(decoded.credential_identity(), &CREDENTIAL_IDENTITY);
    assert_eq!(decoded.leaf_signature_key(), &leaf_signature_key());
    assert_eq!(
        decoded.application_protocol_version(),
        ApplicationProtocolVersion::V1
    );
    assert_eq!(decoded.transport_profile(), TransportProfile::LocalMemory);
    assert_eq!(decoded.response_endpoint().mailbox_id(), &MAILBOX_ID);
}

#[test]
fn rejects_response_endpoints_that_outlive_the_inner_request() {
    let invitation = InvitationJoinBinding::new(
        INVITATION_ID,
        JOIN_CHALLENGE,
        INVITATION_KEY_ID,
        signing_key().verifying_key().to_bytes(),
    )
    .expect("the invitation binding is structurally valid");
    let request = JoinRequestBinding::new(
        JOIN_REQUEST_ID,
        ISSUED_AT + 1,
        EXPIRES_AT - 1,
        REQUEST_NONCE,
    )
    .expect("the request binding is structurally valid");
    let mls = MlsKeyPackageBinding::new(
        KEY_PACKAGE_REFERENCE,
        b"key-package".to_vec(),
        CREDENTIAL_IDENTITY,
        leaf_signature_key(),
    )
    .expect("the MLS binding is structurally valid");

    assert_eq!(
        CapabilityJoinRequest::new(invitation, request, mls, response_endpoint()).err(),
        Some(WireError::ResponseEndpointOutlivesRequest)
    );
}

#[test]
fn round_trips_the_protected_join_request_and_derives_exact_aad() {
    let protected = ProtectedJoinRequest::new(
        INVITATION_ID,
        INVITATION_KEY_ID,
        HPKE_ENCAPSULATED_KEY,
        HPKE_CIPHERTEXT.to_vec(),
    )
    .expect("the protected request is structurally valid");
    let encoded = protected
        .encode_canonical()
        .expect("outer request encoding succeeds");
    let decoded =
        ProtectedJoinRequest::decode_canonical(&encoded).expect("outer request decoding succeeds");
    assert_eq!(encoded, decode_hex(OUTER_HEX));

    assert_eq!(decoded.schema_version(), 1);
    assert_eq!(decoded.object_type(), WireObjectType::ProtectedJoinRequest);
    assert_eq!(
        decoded.invitation_encryption_suite(),
        InvitationEncryptionSuite::X25519HkdfSha256Aes128GcmPsk
    );
    assert_eq!(decoded.invitation_id(), &INVITATION_ID);
    assert_eq!(decoded.invitation_key_id(), &INVITATION_KEY_ID);
    assert_eq!(decoded.encapsulated_key(), &HPKE_ENCAPSULATED_KEY);
    assert_eq!(decoded.ciphertext(), HPKE_CIPHERTEXT);
    assert_eq!(
        decoded.aad_canonical().expect("AAD encoding succeeds"),
        decode_hex(AAD_HEX)
    );
}

#[test]
fn rejects_invalid_protected_join_request_fields_before_encoding() {
    assert_eq!(
        ProtectedJoinRequest::new(
            INVITATION_ID,
            INVITATION_KEY_ID,
            HPKE_ENCAPSULATED_KEY,
            Vec::new(),
        )
        .err(),
        Some(WireError::EmptyProtectedJoinCiphertext)
    );
    assert_eq!(
        ProtectedJoinRequest::new(
            [0; 16],
            INVITATION_KEY_ID,
            HPKE_ENCAPSULATED_KEY,
            HPKE_CIPHERTEXT.to_vec(),
        )
        .err(),
        Some(WireError::ZeroInvitationId)
    );
    assert_eq!(
        ProtectedJoinRequest::new(
            INVITATION_ID,
            INVITATION_KEY_ID,
            HPKE_ENCAPSULATED_KEY,
            vec![0; MAX_PROTECTED_JOIN_CIPHERTEXT_BYTES + 1],
        )
        .err(),
        Some(WireError::ProtectedJoinCiphertextTooLarge {
            actual: MAX_PROTECTED_JOIN_CIPHERTEXT_BYTES + 1,
            maximum: MAX_PROTECTED_JOIN_CIPHERTEXT_BYTES,
        })
    );
}

#[test]
fn rejects_unknown_identifiers_in_every_closed_new_schema() {
    let mut invitation = decode_hex(INVITATION_V2_HEX);
    let invitation_offsets = top_level_field_offsets(&invitation);
    let invitation_cases = [
        (2, WireError::UnsupportedSignatureSuite(7)),
        (3, WireError::UnsupportedInvitationEncryptionSuite(7)),
        (4, WireError::UnsupportedJoinRequestSchema(7)),
        (5, WireError::UnsupportedApplicationProtocolVersion(7)),
        (6, WireError::UnsupportedTransportProfile(7)),
        (10, WireError::UnsupportedAdmissionMode(7)),
        (11, WireError::UnsupportedInvitationUsePolicy(7)),
    ];
    for (field, expected) in invitation_cases {
        invitation[invitation_offsets[field]] = 7;
        assert_eq!(
            SignedCapabilityInvitationV2::decode_and_verify(&invitation).err(),
            Some(expected)
        );
        invitation = decode_hex(INVITATION_V2_HEX);
    }

    let mut endpoint = decode_hex(ENDPOINT_HEX);
    let endpoint_offsets = top_level_field_offsets(&endpoint);
    endpoint[endpoint_offsets[2]] = 7;
    assert_eq!(
        LocalWelcomeDepositEndpoint::decode_canonical(&endpoint).err(),
        Some(WireError::UnsupportedTransportProfile(7))
    );

    let mut inner = decode_hex(INNER_HEX);
    let inner_offsets = top_level_field_offsets(&inner);
    let inner_cases = [
        (2, WireError::UnsupportedAdmissionProofVersion(7)),
        (11, WireError::UnsupportedMlsProtocolVersion(7)),
        (12, WireError::UnsupportedMlsCiphersuite(7)),
        (15, WireError::UnsupportedCredentialType(7)),
        (18, WireError::UnsupportedApplicationProtocolVersion(7)),
        (19, WireError::UnsupportedTransportProfile(7)),
    ];
    for (field, expected) in inner_cases {
        inner[inner_offsets[field]] = 7;
        assert_eq!(
            CapabilityJoinRequest::decode_canonical(&inner).err(),
            Some(expected)
        );
        inner = decode_hex(INNER_HEX);
    }

    let mut outer = decode_hex(OUTER_HEX);
    let outer_offsets = top_level_field_offsets(&outer);
    outer[outer_offsets[2]] = 7;
    assert_eq!(
        ProtectedJoinRequest::decode_canonical(&outer).err(),
        Some(WireError::UnsupportedInvitationEncryptionSuite(7))
    );
}

#[test]
fn rejects_noncanonical_container_forms_for_every_new_schema() {
    let fixtures: [(&str, DecodeError); 4] = [
        (INVITATION_V2_HEX, |bytes| {
            SignedCapabilityInvitationV2::decode_and_verify(bytes).err()
        }),
        (ENDPOINT_HEX, |bytes| {
            LocalWelcomeDepositEndpoint::decode_canonical(bytes).err()
        }),
        (INNER_HEX, |bytes| {
            CapabilityJoinRequest::decode_canonical(bytes).err()
        }),
        (OUTER_HEX, |bytes| {
            ProtectedJoinRequest::decode_canonical(bytes).err()
        }),
    ];

    for (hex, decode_error) in fixtures {
        let canonical = decode_hex(hex);

        let mut missing_field = canonical.clone();
        missing_field[0] -= 1;
        assert_eq!(decode_error(&missing_field), Some(WireError::Malformed));

        let mut extra_field = canonical.clone();
        extra_field[0] += 1;
        assert_eq!(decode_error(&extra_field), Some(WireError::Malformed));

        let mut wrong_type = canonical.clone();
        wrong_type[1] = 0x40;
        assert_eq!(decode_error(&wrong_type), Some(WireError::Malformed));

        let mut nonpreferred_version = canonical.clone();
        nonpreferred_version.splice(1..2, [0x18, canonical[1]]);
        assert_eq!(
            decode_error(&nonpreferred_version),
            Some(WireError::NonDeterministicEncoding)
        );

        let mut trailing = canonical.clone();
        trailing.push(0);
        assert_eq!(decode_error(&trailing), Some(WireError::TrailingData));

        let mut indefinite = canonical;
        indefinite[0] = 0x9f;
        indefinite.push(0xff);
        assert_eq!(decode_error(&indefinite), Some(WireError::Malformed));
    }
}

#[test]
fn rejects_wrong_fixed_lengths_and_reserved_zero_values() {
    let mut endpoint = decode_hex(ENDPOINT_HEX);
    let endpoint_offsets = top_level_field_offsets(&endpoint);
    shorten_byte_string(&mut endpoint, endpoint_offsets[3]);
    assert_eq!(
        LocalWelcomeDepositEndpoint::decode_canonical(&endpoint).err(),
        Some(WireError::InvalidTransportInstanceIdLength(15))
    );

    let mut inner = decode_hex(INNER_HEX);
    let inner_offsets = top_level_field_offsets(&inner);
    shorten_byte_string(&mut inner, inner_offsets[10]);
    assert_eq!(
        CapabilityJoinRequest::decode_canonical(&inner).err(),
        Some(WireError::InvalidRequestNonceLength(31))
    );

    let mut outer = decode_hex(OUTER_HEX);
    let outer_offsets = top_level_field_offsets(&outer);
    shorten_byte_string(&mut outer, outer_offsets[5]);
    assert_eq!(
        ProtectedJoinRequest::decode_canonical(&outer).err(),
        Some(WireError::InvalidHpkeEncapsulatedKeyLength(31))
    );

    assert_eq!(
        DepositCapability::new([0; 32]).err(),
        Some(WireError::ZeroDepositCapability)
    );
    assert_eq!(
        JoinRequestBinding::new(JOIN_REQUEST_ID, EXPIRES_AT, ISSUED_AT, REQUEST_NONCE).err(),
        Some(WireError::InvalidJoinRequestTimeRange {
            issued_at: EXPIRES_AT,
            expires_at: ISSUED_AT,
        })
    );
    let mut weak_leaf_key = [0; 32];
    weak_leaf_key[0] = 1;
    assert_eq!(
        InvitationJoinBinding::new(
            INVITATION_ID,
            JOIN_CHALLENGE,
            INVITATION_KEY_ID,
            weak_leaf_key,
        )
        .err(),
        Some(WireError::InvalidVerifyingKey)
    );
    assert_eq!(
        MlsKeyPackageBinding::new(
            KEY_PACKAGE_REFERENCE,
            b"key-package".to_vec(),
            CREDENTIAL_IDENTITY,
            weak_leaf_key,
        )
        .err(),
        Some(WireError::InvalidLeafSignatureKey)
    );
}

#[test]
fn prebounds_every_new_object_and_accepts_the_outer_exact_limit() {
    let oversized_cases: [(usize, DecodeError); 4] = [
        (MAX_SIGNED_INVITATION_BYTES, |bytes| {
            SignedCapabilityInvitationV2::decode_and_verify(bytes).err()
        }),
        (MAX_LOCAL_WELCOME_ENDPOINT_BYTES, |bytes| {
            LocalWelcomeDepositEndpoint::decode_canonical(bytes).err()
        }),
        (MAX_CAPABILITY_JOIN_REQUEST_BYTES, |bytes| {
            CapabilityJoinRequest::decode_canonical(bytes).err()
        }),
        (MAX_PROTECTED_JOIN_REQUEST_BYTES, |bytes| {
            ProtectedJoinRequest::decode_canonical(bytes).err()
        }),
    ];
    for (maximum, decode_error) in oversized_cases {
        let oversized = vec![0; maximum + 1];
        assert_eq!(
            decode_error(&oversized),
            Some(WireError::WireObjectTooLarge {
                actual: maximum + 1,
                maximum,
            })
        );
    }

    assert_eq!(
        MlsKeyPackageBinding::new(
            KEY_PACKAGE_REFERENCE,
            vec![0; MAX_JOIN_KEY_PACKAGE_BYTES + 1],
            CREDENTIAL_IDENTITY,
            leaf_signature_key(),
        )
        .err(),
        Some(WireError::KeyPackageTooLarge {
            actual: MAX_JOIN_KEY_PACKAGE_BYTES + 1,
            maximum: MAX_JOIN_KEY_PACKAGE_BYTES,
        })
    );

    let boundary = ProtectedJoinRequest::new(
        INVITATION_ID,
        INVITATION_KEY_ID,
        HPKE_ENCAPSULATED_KEY,
        vec![0; MAX_PROTECTED_JOIN_CIPHERTEXT_BYTES],
    )
    .expect("the exact ciphertext boundary is accepted");
    let encoded = boundary.encode_canonical().expect("the boundary encodes");
    assert_eq!(encoded.len(), MAX_PROTECTED_JOIN_REQUEST_BYTES);
    assert_eq!(
        ProtectedJoinRequest::decode_canonical(&encoded)
            .expect("the exact outer boundary decodes")
            .ciphertext()
            .len(),
        MAX_PROTECTED_JOIN_CIPHERTEXT_BYTES
    );
}
