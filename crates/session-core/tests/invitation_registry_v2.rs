use ed25519_dalek::SigningKey;
use session_core::{
    InvitationLifecycle, InvitationLifecycleError, InvitationPolicy, InvitationRegistry,
};
use session_crypto_hpke::{AwsLcInvitationJoinProtector, InvitationJoinProtector};
use session_protocol::{
    CapabilityInvitationClaims, CapabilityInvitationV2Claims, SecretCapability,
    SignedCapabilityInvitationV2,
};

const NOW: u64 = 1_700_000_000;

fn registry(capacity: usize) -> InvitationRegistry {
    InvitationRegistry::new(
        InvitationPolicy::new(3_600, 30, capacity).expect("valid invitation policy"),
    )
}

fn remote_v2(
    invitation_id: [u8; 16],
    issued_at: u64,
    expires_at: u64,
) -> SignedCapabilityInvitationV2 {
    let protector = AwsLcInvitationJoinProtector::new();
    let hpke = protector
        .generate_invitation_key()
        .expect("generate remote HPKE key");
    let base = CapabilityInvitationClaims::new(
        invitation_id,
        issued_at,
        expires_at,
        [0x22; 32],
        SecretCapability::new([0x33; 32]).expect("nonzero capability"),
    )
    .expect("valid base claims");
    let claims = CapabilityInvitationV2Claims::new(base, [0x44; 16], *hpke.public_key())
        .expect("valid v2 claims");
    SignedCapabilityInvitationV2::sign(claims, &SigningKey::from_bytes(&[0xa5; 32]))
        .expect("sign remote invitation")
}

#[test]
fn generated_v2_invitation_uses_the_existing_reserve_release_consume_lifecycle() {
    let protector = AwsLcInvitationJoinProtector::new();
    let generated = protector
        .generate_capability_invitation(NOW, NOW + 300)
        .expect("generate complete invitation");
    let invitation_id = *generated.invitation().invitation_id();
    let mut registry = registry(2);
    let issued = registry
        .issue_v2(generated, NOW)
        .expect("generated invitation enters local state");
    let encoded = issued
        .encode_canonical()
        .expect("issued invitation encodes");
    let validated = registry
        .validate_descriptor_v2(&encoded, NOW)
        .expect("issued descriptor validates read-only");

    let first = registry
        .reserve_v2_after_admission(&validated, [0x51; 16], NOW)
        .expect("verified request reserves v2 invitation");
    assert_eq!(
        registry.lifecycle(&invitation_id),
        Some(InvitationLifecycle::Reserved)
    );
    registry.release(first, NOW).expect("rejection releases v2");

    let second = registry
        .reserve_v2_after_admission(&validated, [0x52; 16], NOW)
        .expect("later request reserves released invitation");
    registry
        .consume_after_membership(second, NOW)
        .expect("successful membership consumes v2 invitation");
    assert_eq!(
        registry.lifecycle(&invitation_id),
        Some(InvitationLifecycle::Consumed)
    );
    let _ = issued.private_key();
}

#[test]
fn remote_v2_validation_is_read_only_and_cannot_create_local_state() {
    let remote = remote_v2([0x61; 16], NOW, NOW + 300)
        .encode_canonical()
        .expect("remote descriptor encodes");
    let mut registry = registry(1);
    let validated = registry
        .validate_descriptor_v2(&remote, NOW)
        .expect("remote descriptor authenticates");

    assert_eq!(registry.record_count(), 0);
    assert_eq!(
        registry
            .reserve_v2_after_admission(&validated, [0x62; 16], NOW)
            .err(),
        Some(InvitationLifecycleError::UnknownInvitation)
    );
    assert_eq!(registry.record_count(), 0);
}

#[test]
fn v1_and_v2_share_capacity_and_invalid_v2_time_never_mutates_state() {
    let protector = AwsLcInvitationJoinProtector::new();
    let overlong = protector
        .generate_capability_invitation(NOW, NOW + 3_601)
        .expect("structurally valid invitation");
    let mut registry = registry(1);

    assert_eq!(
        registry.issue_v2(overlong, NOW).err(),
        Some(InvitationLifecycleError::LifetimeExceedsPolicy {
            actual_seconds: 3_601,
            maximum_seconds: 3_600,
        })
    );
    assert_eq!(registry.record_count(), 0);

    let generated = protector
        .generate_capability_invitation(NOW, NOW + 1)
        .expect("generate short-lived invitation");
    registry
        .issue_v2(generated, NOW)
        .expect("v2 consumes shared capacity");
    let v1_claims = CapabilityInvitationClaims::new(
        [0x71; 16],
        NOW,
        NOW + 300,
        [0x72; 32],
        SecretCapability::new([0x73; 32]).expect("nonzero capability"),
    )
    .expect("valid v1 claims");
    assert_eq!(
        registry
            .issue(v1_claims, &SigningKey::from_bytes(&[0xa7; 32]), NOW)
            .err(),
        Some(InvitationLifecycleError::CapacityExceeded { maximum: 1 })
    );
}

#[test]
fn stale_v2_reservation_cannot_mutate_v1_reissue_with_the_same_ids() {
    let protector = AwsLcInvitationJoinProtector::new();
    let generated = protector
        .generate_capability_invitation(NOW, NOW + 1)
        .expect("generate short-lived v2 invitation");
    let invitation_id = *generated.invitation().invitation_id();
    let encoded_v2 = generated
        .invitation()
        .encode_canonical()
        .expect("v2 descriptor encodes");
    let join_request_id = [0x81; 16];
    let mut registry = registry(1);
    registry
        .issue_v2(generated, NOW)
        .expect("v2 invitation enters local state");
    let validated_v2 = registry
        .validate_descriptor_v2(&encoded_v2, NOW)
        .expect("v2 descriptor validates");
    let stale_v2 = registry
        .reserve_v2_after_admission(&validated_v2, join_request_id, NOW)
        .expect("v2 reservation succeeds");

    let v1_claims = CapabilityInvitationClaims::new(
        invitation_id,
        NOW + 1,
        NOW + 301,
        [0x82; 32],
        SecretCapability::new([0x83; 32]).expect("nonzero capability"),
    )
    .expect("valid v1 claims");
    let issued_v1 = registry
        .issue(v1_claims, &SigningKey::from_bytes(&[0xa8; 32]), NOW + 1)
        .expect("expired v2 can be replaced by v1");
    let encoded_v1 = issued_v1.encode_canonical().expect("v1 descriptor encodes");
    let validated_v1 = registry
        .validate_descriptor(&encoded_v1, NOW + 1)
        .expect("v1 descriptor validates");
    let current_v1 = registry
        .reserve_after_admission(&validated_v1, join_request_id, NOW + 1)
        .expect("v1 reservation with reused request ID succeeds");

    assert_eq!(
        registry.release(stale_v2, NOW + 1),
        Err(InvitationLifecycleError::ReservationMismatch)
    );
    assert_eq!(
        registry.lifecycle(&invitation_id),
        Some(InvitationLifecycle::Reserved)
    );
    registry
        .consume_after_membership(current_v1, NOW + 1)
        .expect("current v1 reservation remains authoritative");
}
