use ed25519_dalek::SigningKey;
use session_crypto_hpke::{
    AwsLcInvitationJoinProtector, InvitationHpkePrivateKey, InvitationJoinProtector,
    JoinProtectionError,
};
use session_protocol::{
    CapabilityInvitationClaims, CapabilityInvitationV2Claims, CapabilityJoinRequest,
    DepositCapability, InvitationJoinBinding, JoinRequestBinding, LocalWelcomeDepositEndpoint,
    MlsKeyPackageBinding, ProtectedJoinRequest, SecretCapability, SignedCapabilityInvitationV2,
};

const INVITATION_ID: [u8; 16] = [0x11; 16];
const JOIN_CHALLENGE: [u8; 32] = [0x22; 32];
const CAPABILITY: [u8; 32] = [0x33; 32];
const INVITATION_KEY_ID: [u8; 16] = [0x44; 16];
const ISSUED_AT: u64 = 1_700_000_000;
const EXPIRES_AT: u64 = ISSUED_AT + 3_600;

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0xa5; 32])
}

fn invitation(recipient_public_key: [u8; 32]) -> SignedCapabilityInvitationV2 {
    invitation_for(
        recipient_public_key,
        INVITATION_ID,
        JOIN_CHALLENGE,
        CAPABILITY,
        INVITATION_KEY_ID,
        ISSUED_AT,
        EXPIRES_AT,
        [0xa5; 32],
    )
}

#[allow(clippy::too_many_arguments)]
fn invitation_for(
    recipient_public_key: [u8; 32],
    invitation_id: [u8; 16],
    join_challenge: [u8; 32],
    capability: [u8; 32],
    invitation_key_id: [u8; 16],
    issued_at: u64,
    expires_at: u64,
    signing_seed: [u8; 32],
) -> SignedCapabilityInvitationV2 {
    let base = CapabilityInvitationClaims::new(
        invitation_id,
        issued_at,
        expires_at,
        join_challenge,
        SecretCapability::new(capability).expect("fixture capability is nonzero"),
    )
    .expect("fixture invitation claims are valid");
    let claims = CapabilityInvitationV2Claims::new(base, invitation_key_id, recipient_public_key)
        .expect("fixture v2 claims are valid");
    SignedCapabilityInvitationV2::sign(claims, &SigningKey::from_bytes(&signing_seed))
        .expect("fixture signing succeeds")
}

fn request() -> CapabilityJoinRequest {
    request_for(
        INVITATION_ID,
        JOIN_CHALLENGE,
        INVITATION_KEY_ID,
        signing_key().verifying_key().to_bytes(),
        ISSUED_AT + 1,
        EXPIRES_AT,
    )
}

fn request_for(
    invitation_id: [u8; 16],
    join_challenge: [u8; 32],
    invitation_key_id: [u8; 16],
    intended_verifier: [u8; 32],
    issued_at: u64,
    expires_at: u64,
) -> CapabilityJoinRequest {
    let invitation = InvitationJoinBinding::new(
        invitation_id,
        join_challenge,
        invitation_key_id,
        intended_verifier,
    )
    .expect("fixture invitation binding is valid");
    let request = JoinRequestBinding::new([0x55; 16], issued_at, expires_at, [0x66; 32])
        .expect("fixture request binding is valid");
    let mls = MlsKeyPackageBinding::new(
        [0x77; 32],
        b"key-package".to_vec(),
        [0x88; 32],
        SigningKey::from_bytes(&[0xb6; 32])
            .verifying_key()
            .to_bytes(),
    )
    .expect("fixture MLS binding is valid");
    let endpoint = LocalWelcomeDepositEndpoint::new(
        [0x99; 16],
        [0xaa; 16],
        DepositCapability::new([0xbb; 32]).expect("fixture deposit capability is nonzero"),
        expires_at,
    )
    .expect("fixture endpoint is valid");

    CapabilityJoinRequest::new(invitation, request, mls, endpoint)
        .expect("fixture inner request is valid")
}

fn assert_rejected<T>(result: Result<T, JoinProtectionError>) {
    assert!(matches!(result, Err(JoinProtectionError::Rejected)));
}

#[test]
fn generated_key_seals_and_opens_one_exact_capability_request() {
    let implementation = AwsLcInvitationJoinProtector::new();
    let protector: &dyn InvitationJoinProtector = &implementation;
    let generated = protector
        .generate_invitation_key()
        .expect("provider key generation succeeds");
    let signed = invitation(*generated.public_key());
    let private_key = generated.into_private_key();
    let request = request();
    let expected = request.encode_canonical().expect("fixture request encodes");

    let protected = protector
        .seal_capability_request(&signed, &request)
        .expect("bounded request seals");
    let opened = protector
        .open_capability_request(&private_key, &signed, &protected)
        .expect("matching request opens");

    assert_eq!(
        opened
            .request()
            .encode_canonical()
            .expect("opened request encodes"),
        expected
    );
    assert_eq!(protected.invitation_id(), signed.invitation_id());
    assert_eq!(protected.invitation_key_id(), signed.invitation_key_id());
    assert_eq!(opened.invitation_signature(), signed.signature());
}

#[test]
fn provider_generates_every_secret_and_identifier_for_invitation_v2() {
    let implementation = AwsLcInvitationJoinProtector::new();
    let protector: &dyn InvitationJoinProtector = &implementation;
    let first = protector
        .generate_capability_invitation(ISSUED_AT, EXPIRES_AT)
        .expect("complete invitation generation succeeds");
    let second = protector
        .generate_capability_invitation(ISSUED_AT, EXPIRES_AT)
        .expect("second complete invitation generation succeeds");
    let first_invitation = first.invitation();
    let second_invitation = second.invitation();

    assert_ne!(first_invitation.invitation_id(), &[0; 16]);
    assert_ne!(first_invitation.join_challenge(), &[0; 32]);
    assert_ne!(first_invitation.capability().expose_secret(), &[0; 32]);
    assert_ne!(first_invitation.invitation_key_id(), &[0; 16]);
    assert_ne!(first_invitation.hpke_recipient_public_key(), &[0; 32]);
    assert_ne!(first_invitation.inviter_verifying_key(), &[0; 32]);
    assert_ne!(
        first_invitation.invitation_id(),
        second_invitation.invitation_id()
    );
    assert_ne!(
        first_invitation.join_challenge(),
        second_invitation.join_challenge()
    );
    assert_ne!(
        first_invitation.capability().expose_secret(),
        second_invitation.capability().expose_secret()
    );
    assert_ne!(
        first_invitation.invitation_key_id(),
        second_invitation.invitation_key_id()
    );
    assert_ne!(
        first_invitation.hpke_recipient_public_key(),
        second_invitation.hpke_recipient_public_key()
    );
    assert_ne!(
        first_invitation.inviter_verifying_key(),
        second_invitation.inviter_verifying_key()
    );

    let encoded = first_invitation
        .encode_canonical()
        .expect("generated invitation encodes");
    SignedCapabilityInvitationV2::decode_and_verify(&encoded)
        .expect("generated invitation authenticates");
    let request = request_for(
        *first_invitation.invitation_id(),
        *first_invitation.join_challenge(),
        *first_invitation.invitation_key_id(),
        *first_invitation.inviter_verifying_key(),
        ISSUED_AT + 1,
        EXPIRES_AT,
    );
    let protected = protector
        .seal_capability_request(first_invitation, &request)
        .expect("generated context seals");
    protector
        .open_capability_request(first.private_key(), first_invitation, &protected)
        .expect("generated private key opens its context");
}

#[test]
fn complete_invitation_generation_rejects_an_invalid_time_range() {
    let protector = AwsLcInvitationJoinProtector::new();

    assert_rejected(protector.generate_capability_invitation(EXPIRES_AT, ISSUED_AT));
    assert_rejected(protector.generate_capability_invitation(ISSUED_AT, ISSUED_AT));
}

#[test]
fn sealing_rejects_every_cross_context_inner_binding() {
    let protector = AwsLcInvitationJoinProtector::new();
    let generated = protector
        .generate_invitation_key()
        .expect("provider key generation succeeds");
    let signed = invitation(*generated.public_key());
    let verifier = signing_key().verifying_key().to_bytes();

    for mismatched in [
        request_for(
            [0x12; 16],
            JOIN_CHALLENGE,
            INVITATION_KEY_ID,
            verifier,
            ISSUED_AT + 1,
            EXPIRES_AT,
        ),
        request_for(
            INVITATION_ID,
            [0x23; 32],
            INVITATION_KEY_ID,
            verifier,
            ISSUED_AT + 1,
            EXPIRES_AT,
        ),
        request_for(
            INVITATION_ID,
            JOIN_CHALLENGE,
            [0x45; 16],
            verifier,
            ISSUED_AT + 1,
            EXPIRES_AT,
        ),
        request_for(
            INVITATION_ID,
            JOIN_CHALLENGE,
            INVITATION_KEY_ID,
            SigningKey::from_bytes(&[0xc7; 32])
                .verifying_key()
                .to_bytes(),
            ISSUED_AT + 1,
            EXPIRES_AT,
        ),
        request_for(
            INVITATION_ID,
            JOIN_CHALLENGE,
            INVITATION_KEY_ID,
            verifier,
            ISSUED_AT - 1,
            EXPIRES_AT,
        ),
        request_for(
            INVITATION_ID,
            JOIN_CHALLENGE,
            INVITATION_KEY_ID,
            verifier,
            ISSUED_AT + 1,
            EXPIRES_AT + 1,
        ),
    ] {
        assert_rejected(protector.seal_capability_request(&signed, &mismatched));
    }
}

#[test]
fn opening_rejects_wrong_key_and_tampered_wire_fields() {
    let protector = AwsLcInvitationJoinProtector::new();
    let generated = protector
        .generate_invitation_key()
        .expect("provider key generation succeeds");
    let signed = invitation(*generated.public_key());
    let private_key = generated.into_private_key();
    let request = request();
    let protected = protector
        .seal_capability_request(&signed, &request)
        .expect("bounded request seals");
    let wrong_private_key = protector
        .generate_invitation_key()
        .expect("second provider key generation succeeds")
        .into_private_key();

    assert_rejected(protector.open_capability_request(&wrong_private_key, &signed, &protected));

    let mut tampered_encapsulation = *protected.encapsulated_key();
    tampered_encapsulation[0] ^= 1;
    let tampered_encapsulation = ProtectedJoinRequest::new(
        *protected.invitation_id(),
        *protected.invitation_key_id(),
        tampered_encapsulation,
        protected.ciphertext().to_vec(),
    )
    .expect("tampered fixed-size envelope remains structurally valid");
    assert_rejected(protector.open_capability_request(
        &private_key,
        &signed,
        &tampered_encapsulation,
    ));

    let mut tampered_ciphertext = protected.ciphertext().to_vec();
    tampered_ciphertext[0] ^= 1;
    let tampered_ciphertext = ProtectedJoinRequest::new(
        *protected.invitation_id(),
        *protected.invitation_key_id(),
        *protected.encapsulated_key(),
        tampered_ciphertext,
    )
    .expect("tampered ciphertext remains structurally valid");
    assert_rejected(protector.open_capability_request(&private_key, &signed, &tampered_ciphertext));

    for tampered_outer in [
        ProtectedJoinRequest::new(
            [0x12; 16],
            *protected.invitation_key_id(),
            *protected.encapsulated_key(),
            protected.ciphertext().to_vec(),
        )
        .expect("alternate invitation id is structurally valid"),
        ProtectedJoinRequest::new(
            *protected.invitation_id(),
            [0x45; 16],
            *protected.encapsulated_key(),
            protected.ciphertext().to_vec(),
        )
        .expect("alternate key id is structurally valid"),
    ] {
        assert_rejected(protector.open_capability_request(&private_key, &signed, &tampered_outer));
    }
}

#[test]
fn opening_rejects_every_changed_signed_hpke_context() {
    let protector = AwsLcInvitationJoinProtector::new();
    let generated = protector
        .generate_invitation_key()
        .expect("provider key generation succeeds");
    let recipient_public_key = *generated.public_key();
    let signed = invitation(recipient_public_key);
    let private_key = generated.into_private_key();
    let protected = protector
        .seal_capability_request(&signed, &request())
        .expect("bounded request seals");

    for changed_invitation in [
        invitation_for(
            recipient_public_key,
            INVITATION_ID,
            [0x23; 32],
            CAPABILITY,
            INVITATION_KEY_ID,
            ISSUED_AT,
            EXPIRES_AT,
            [0xa5; 32],
        ),
        invitation_for(
            recipient_public_key,
            INVITATION_ID,
            JOIN_CHALLENGE,
            [0x34; 32],
            INVITATION_KEY_ID,
            ISSUED_AT,
            EXPIRES_AT,
            [0xa5; 32],
        ),
        invitation_for(
            recipient_public_key,
            INVITATION_ID,
            JOIN_CHALLENGE,
            CAPABILITY,
            INVITATION_KEY_ID,
            ISSUED_AT,
            EXPIRES_AT,
            [0xa6; 32],
        ),
    ] {
        assert_rejected(protector.open_capability_request(
            &private_key,
            &changed_invitation,
            &protected,
        ));
    }
}

#[test]
fn public_failures_are_coarse_and_do_not_echo_capability_material() {
    assert_eq!(
        JoinProtectionError::Rejected.to_string(),
        "join-protection operation rejected"
    );
    assert_eq!(format!("{:?}", JoinProtectionError::Rejected), "Rejected");
    assert!(!JoinProtectionError::Rejected.to_string().contains("3333"));
}

#[test]
fn restored_zero_private_key_and_low_order_encapsulation_fail_closed() {
    assert!(matches!(
        InvitationHpkePrivateKey::from_bytes([0; 32]),
        Err(JoinProtectionError::Rejected)
    ));

    let protector = AwsLcInvitationJoinProtector::new();
    let generated = protector
        .generate_invitation_key()
        .expect("provider key generation succeeds");
    let signed = invitation(*generated.public_key());
    let private_key = generated.into_private_key();
    let protected = protector
        .seal_capability_request(&signed, &request())
        .expect("bounded request seals");
    let low_order = ProtectedJoinRequest::new(
        *protected.invitation_id(),
        *protected.invitation_key_id(),
        [0; 32],
        protected.ciphertext().to_vec(),
    )
    .expect("outer framing treats the encapsulation as provider-owned bytes");

    assert_rejected(protector.open_capability_request(&private_key, &signed, &low_order));
}
