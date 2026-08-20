use admission_capability::{
    CapabilityAdmissionError, CapabilityAdmissionPolicy, CapabilityAdmissionVerifier,
    CapabilityApprovalOutcome, ManualApprovalDecision,
};
use session_core::{
    InvitationLifecycle, InvitationPolicy, InvitationRegistry, ValidatedCapabilityInvitationV2,
};
use session_crypto_hpke::{AwsLcInvitationJoinProtector, InvitationJoinProtector};
use session_crypto_mls::{
    KeyPackageReference, SessionGroupId, create_client, create_key_package_validator,
};
use session_protocol::{
    CapabilityJoinRequest, DepositCapability, InvitationJoinBinding, JoinRequestBinding,
    LocalWelcomeDepositEndpoint, MlsKeyPackageBinding,
};

const NOW: u64 = 1_700_000_000;
const REQUEST_ID: [u8; 16] = [0x41; 16];
const NONCE: [u8; 32] = [0x51; 32];

struct ApprovalFixture {
    registry: InvitationRegistry,
    validated: ValidatedCapabilityInvitationV2,
    opened: session_crypto_hpke::OpenedCapabilityJoinRequest,
    invitation_id: [u8; 16],
    key_package_reference: KeyPackageReference,
}

fn approval_fixture() -> ApprovalFixture {
    let protector = AwsLcInvitationJoinProtector::new();
    let generated = protector
        .generate_capability_invitation(NOW, NOW + 300)
        .expect("generate complete invitation");
    let invitation_id = *generated.invitation().invitation_id();
    let mut registry = InvitationRegistry::new(
        InvitationPolicy::new(3_600, 5, 8).expect("valid invitation policy"),
    );
    let issued = registry
        .issue_v2(generated, NOW)
        .expect("issue provider-generated invitation");
    let encoded = issued.encode_canonical().expect("encode issued invitation");
    let validated = registry
        .validate_descriptor_v2(&encoded, NOW)
        .expect("validate issued descriptor read-only");

    let joiner = create_client().expect("create joiner");
    let key_package = joiner
        .generate_key_package(NOW)
        .expect("generate KeyPackage");
    let exact = create_key_package_validator()
        .validate_key_package(key_package.as_bytes(), NOW)
        .expect("validate KeyPackage");
    let invitation_binding = InvitationJoinBinding::new(
        invitation_id,
        *issued.invitation().join_challenge(),
        *issued.invitation().invitation_key_id(),
        *issued.invitation().inviter_verifying_key(),
    )
    .expect("bind exact invitation generation");
    let request_binding =
        JoinRequestBinding::new(REQUEST_ID, NOW, NOW + 120, NONCE).expect("bind request lifetime");
    let mls_binding = MlsKeyPackageBinding::new(
        *exact.key_package_reference(),
        key_package.as_bytes().to_vec(),
        *exact.credential_identity(),
        *exact.leaf_signature_key(),
    )
    .expect("bind exact KeyPackage");
    let response_endpoint = LocalWelcomeDepositEndpoint::new(
        [0x61; 16],
        [0x71; 16],
        DepositCapability::new([0x81; 32]).expect("nonzero deposit capability"),
        NOW + 120,
    )
    .expect("create response endpoint");
    let request = CapabilityJoinRequest::new(
        invitation_binding,
        request_binding,
        mls_binding,
        response_endpoint,
    )
    .expect("create exact request");
    let protected = protector
        .seal_capability_request(issued.invitation(), &request)
        .expect("seal request");
    let opened = protector
        .open_capability_request(issued.private_key(), issued.invitation(), &protected)
        .expect("open request");

    ApprovalFixture {
        registry,
        validated,
        opened,
        invitation_id,
        key_package_reference: *exact.key_package_reference(),
    }
}

fn verifier() -> CapabilityAdmissionVerifier {
    CapabilityAdmissionVerifier::new(
        CapabilityAdmissionPolicy::new(3_600, 5, 8).expect("valid admission policy"),
    )
}

fn group_id() -> SessionGroupId {
    SessionGroupId::new([0x91; 32]).expect("nonzero group ID")
}

#[test]
fn explicit_rejection_releases_invitation_and_replay_reservations() {
    let mut fixture = approval_fixture();
    let mut verifier = verifier();
    let verified = verifier
        .verify_and_reserve(fixture.opened, NOW)
        .expect("automated verification succeeds");
    let pending = verifier
        .reserve_v2_for_approval(&mut fixture.registry, &fixture.validated, verified, NOW)
        .expect("exact local invitation is reserved");

    assert_eq!(
        fixture.registry.lifecycle(&fixture.invitation_id),
        Some(InvitationLifecycle::Reserved)
    );
    assert_eq!(verifier.pending_count(), 1);
    assert!(matches!(
        verifier
            .decide_v2(
                &mut fixture.registry,
                pending,
                ManualApprovalDecision::Reject,
                NOW,
            )
            .expect("reject both reservations"),
        CapabilityApprovalOutcome::Rejected
    ));
    assert_eq!(
        fixture.registry.lifecycle(&fixture.invitation_id),
        Some(InvitationLifecycle::Available)
    );
    assert_eq!(verifier.pending_count(), 0);
}

#[test]
fn a_different_validated_invitation_cannot_capture_verified_admission() {
    let source = approval_fixture();
    let mut other = approval_fixture();
    let mut verifier = verifier();
    let verified = verifier
        .verify_and_reserve(source.opened, NOW)
        .expect("source admission verifies");

    assert!(
        verifier
            .reserve_v2_for_approval(&mut other.registry, &other.validated, verified, NOW)
            .is_err()
    );
    assert_eq!(verifier.pending_count(), 0);
    assert_eq!(
        other.registry.lifecycle(&other.invitation_id),
        Some(InvitationLifecycle::Available)
    );
}

#[test]
fn a_foreign_verifier_cannot_mutate_invitation_state() {
    let mut fixture = approval_fixture();
    let mut owner = verifier();
    let verified = owner
        .verify_and_reserve(fixture.opened, NOW)
        .expect("owner reserves replay state");
    let mut foreign = verifier();

    assert!(matches!(
        foreign.reserve_v2_for_approval(&mut fixture.registry, &fixture.validated, verified, NOW,),
        Err(CapabilityAdmissionError::ReservationMismatch)
    ));
    assert_eq!(owner.pending_count(), 1);
    assert_eq!(foreign.pending_count(), 0);
    assert_eq!(
        fixture.registry.lifecycle(&fixture.invitation_id),
        Some(InvitationLifecycle::Available)
    );
}

#[test]
fn a_foreign_verifier_cannot_release_a_pending_approval() {
    let mut fixture = approval_fixture();
    let mut owner = verifier();
    let verified = owner
        .verify_and_reserve(fixture.opened, NOW)
        .expect("owner reserves replay state");
    let pending = owner
        .reserve_v2_for_approval(&mut fixture.registry, &fixture.validated, verified, NOW)
        .expect("owner reserves invitation state");
    let mut foreign = verifier();

    assert!(matches!(
        foreign.decide_v2(
            &mut fixture.registry,
            pending,
            ManualApprovalDecision::Reject,
            NOW,
        ),
        Err(CapabilityAdmissionError::ReservationMismatch)
    ));
    assert_eq!(owner.pending_count(), 1);
    assert_eq!(foreign.pending_count(), 0);
    assert_eq!(
        fixture.registry.lifecycle(&fixture.invitation_id),
        Some(InvitationLifecycle::Reserved)
    );
}

#[test]
fn request_expiry_before_prepare_releases_both_state_machines() {
    let mut fixture = approval_fixture();
    let mut verifier = verifier();
    let verified = verifier
        .verify_and_reserve(fixture.opened, NOW)
        .expect("automated verification succeeds");
    let pending = verifier
        .reserve_v2_for_approval(&mut fixture.registry, &fixture.validated, verified, NOW)
        .expect("reserve invitation");
    let CapabilityApprovalOutcome::Approved(approved) = verifier
        .decide_v2(
            &mut fixture.registry,
            pending,
            ManualApprovalDecision::Approve,
            NOW,
        )
        .expect("record approval")
    else {
        panic!("approval must produce the one-shot approved value");
    };
    let inviter = create_client().expect("create inviter");
    let mut group = inviter.create_group(group_id(), NOW).expect("create group");

    assert!(
        verifier
            .prepare_approved_add(&mut fixture.registry, approved, &mut group, NOW + 120)
            .is_err()
    );
    assert_eq!(group.epoch(), 0);
    assert_eq!(group.member_count(), 1);
    assert_eq!(verifier.pending_count(), 0);
    assert_eq!(
        fixture.registry.lifecycle(&fixture.invitation_id),
        Some(InvitationLifecycle::Available)
    );
}

#[test]
fn failed_mls_prepare_releases_invitation_and_replay_state() {
    let mut fixture = approval_fixture();
    let mut verifier = verifier();
    let verified = verifier
        .verify_and_reserve(fixture.opened, NOW)
        .expect("automated verification succeeds");
    let pending = verifier
        .reserve_v2_for_approval(&mut fixture.registry, &fixture.validated, verified, NOW)
        .expect("reserve invitation");
    let CapabilityApprovalOutcome::Approved(approved) = verifier
        .decide_v2(
            &mut fixture.registry,
            pending,
            ManualApprovalDecision::Approve,
            NOW,
        )
        .expect("record approval")
    else {
        panic!("approval must produce the one-shot approved value");
    };
    let inviter = create_client().expect("create inviter");
    let existing_peer = create_client().expect("create existing peer");
    let existing_key_package = existing_peer
        .generate_key_package(NOW)
        .expect("generate existing peer KeyPackage");
    let existing = create_key_package_validator()
        .validate_key_package(existing_key_package.as_bytes(), NOW)
        .expect("validate existing peer");
    let mut group = inviter.create_group(group_id(), NOW).expect("create group");
    group
        .prepare_add(existing, NOW)
        .expect("prepare existing peer")
        .apply()
        .expect("fill Phase 1 group");

    assert!(
        verifier
            .prepare_approved_add(&mut fixture.registry, approved, &mut group, NOW)
            .is_err()
    );
    assert_eq!(group.epoch(), 1);
    assert_eq!(group.member_count(), 2);
    assert_eq!(verifier.pending_count(), 0);
    assert_eq!(
        fixture.registry.lifecycle(&fixture.invitation_id),
        Some(InvitationLifecycle::Available)
    );
}

#[test]
fn abandoning_approved_prepare_releases_both_state_machines() {
    let mut fixture = approval_fixture();
    let mut verifier = verifier();
    let verified = verifier
        .verify_and_reserve(fixture.opened, NOW)
        .expect("automated verification succeeds");
    let pending = verifier
        .reserve_v2_for_approval(&mut fixture.registry, &fixture.validated, verified, NOW)
        .expect("reserve invitation");
    let CapabilityApprovalOutcome::Approved(approved) = verifier
        .decide_v2(
            &mut fixture.registry,
            pending,
            ManualApprovalDecision::Approve,
            NOW,
        )
        .expect("record simulated approval")
    else {
        panic!("approval must produce the one-shot approved value");
    };
    let inviter = create_client().expect("create inviter");
    let mut group = inviter.create_group(group_id(), NOW).expect("create group");

    drop(
        verifier
            .prepare_approved_add(&mut fixture.registry, approved, &mut group, NOW)
            .expect("prepare approved Add"),
    );

    assert_eq!(group.epoch(), 0);
    assert_eq!(group.member_count(), 1);
    assert_eq!(verifier.pending_count(), 0);
    assert_eq!(
        fixture.registry.lifecycle(&fixture.invitation_id),
        Some(InvitationLifecycle::Available)
    );
}

#[test]
fn delayed_apply_rechecks_request_time_before_mls_mutation() {
    let mut fixture = approval_fixture();
    let mut verifier = verifier();
    let verified = verifier
        .verify_and_reserve(fixture.opened, NOW)
        .expect("automated verification succeeds");
    let pending = verifier
        .reserve_v2_for_approval(&mut fixture.registry, &fixture.validated, verified, NOW)
        .expect("reserve invitation");
    let CapabilityApprovalOutcome::Approved(approved) = verifier
        .decide_v2(
            &mut fixture.registry,
            pending,
            ManualApprovalDecision::Approve,
            NOW,
        )
        .expect("record simulated approval")
    else {
        panic!("approval must produce the one-shot approved value");
    };
    let inviter = create_client().expect("create inviter");
    let mut group = inviter.create_group(group_id(), NOW).expect("create group");
    let prepared = verifier
        .prepare_approved_add(&mut fixture.registry, approved, &mut group, NOW)
        .expect("prepare approved Add");

    assert!(prepared.apply(NOW + 120).is_err());

    assert_eq!(group.epoch(), 0);
    assert_eq!(group.member_count(), 1);
    assert_eq!(verifier.pending_count(), 0);
    assert_eq!(
        fixture.registry.lifecycle(&fixture.invitation_id),
        Some(InvitationLifecycle::Available)
    );
}

#[test]
fn only_approved_exact_value_applies_mls_and_consumes_invitation() {
    let mut fixture = approval_fixture();
    let mut verifier = verifier();
    let verified = verifier
        .verify_and_reserve(fixture.opened, NOW)
        .expect("automated verification succeeds");
    let pending = verifier
        .reserve_v2_for_approval(&mut fixture.registry, &fixture.validated, verified, NOW)
        .expect("reserve invitation");
    let CapabilityApprovalOutcome::Approved(approved) = verifier
        .decide_v2(
            &mut fixture.registry,
            pending,
            ManualApprovalDecision::Approve,
            NOW,
        )
        .expect("record simulated approval")
    else {
        panic!("approval must produce the one-shot approved value");
    };
    let inviter = create_client().expect("create inviter");
    let mut group = inviter.create_group(group_id(), NOW).expect("create group");

    let prepared = verifier
        .prepare_approved_add(&mut fixture.registry, approved, &mut group, NOW)
        .expect("prepare approved exact Add");
    assert_eq!(
        prepared.key_package_reference(),
        &fixture.key_package_reference
    );
    let committed = prepared.apply(NOW).expect("apply in-memory join");

    assert_eq!(
        committed.key_package_reference(),
        &fixture.key_package_reference
    );
    assert_eq!(group.epoch(), 1);
    assert_eq!(group.member_count(), 2);
    assert_eq!(verifier.pending_count(), 1);
    assert_eq!(
        fixture.registry.lifecycle(&fixture.invitation_id),
        Some(InvitationLifecycle::Consumed)
    );
}
