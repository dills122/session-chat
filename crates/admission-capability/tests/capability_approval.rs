use admission_capability::{
    CapabilityAdmissionError, CapabilityAdmissionPolicy, CapabilityAdmissionVerifier,
    CapabilityApprovalOutcome, ManualApprovalDecision,
};
use session_admission::{AdmissionMethod, PendingAdmission};
use session_core::{
    InvitationLifecycle, InvitationPolicy, InvitationRegistry, ValidatedCapabilityInvitationV2,
};
use session_crypto_hpke::{AwsLcInvitationJoinProtector, InvitationJoinProtector};
use session_crypto_mls::{
    KeyPackageReference, SessionGroupId, create_client, create_key_package_validator,
};
use session_protocol::{
    CapabilityJoinRequest, DepositCapability, InvitationJoinBinding, JoinRequestBinding,
    LocalWelcomeDepositEndpoint, MlsKeyPackageBinding, OpaqueEnvelope,
};
use session_transport::{LocalMailboxPolicy, LocalMemoryWelcomeTransport, LocalTransportError};

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
    let response_endpoint = LocalWelcomeDepositEndpoint::new(
        [0x61; 16],
        [0x71; 16],
        DepositCapability::new([0x81; 32]).expect("nonzero deposit capability"),
        NOW + 120,
    )
    .expect("create response endpoint");
    approval_fixture_with_endpoint(response_endpoint)
}

fn approval_fixture_with_endpoint(
    response_endpoint: LocalWelcomeDepositEndpoint,
) -> ApprovalFixture {
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
fn pending_capability_exposes_exact_non_authorizing_approval_context() {
    let mut fixture = approval_fixture();
    let mut verifier = verifier();
    let verified = verifier
        .verify_and_reserve(fixture.opened, NOW)
        .expect("automated verification succeeds");
    let pending = verifier
        .reserve_v2_for_approval(&mut fixture.registry, &fixture.validated, verified, NOW)
        .expect("exact local invitation is reserved");

    let context = pending.approval_context();
    assert_eq!(pending.invitation_id(), &fixture.invitation_id);
    assert_eq!(pending.join_request_id(), &REQUEST_ID);
    assert_eq!(context.method(), AdmissionMethod::SecretCapability);
    assert_eq!(context.invitation_id(), &fixture.invitation_id);
    assert_eq!(context.join_request_id(), &REQUEST_ID);
    assert_eq!(
        context.key_package_reference(),
        &fixture.key_package_reference
    );
    assert_eq!(context.expires_at_unix_seconds(), NOW + 120);
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
    assert_eq!(
        approved.key_package_reference(),
        &fixture.key_package_reference
    );
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
fn endpoint_expiry_at_approval_decision_releases_both_state_machines() {
    let response_endpoint = LocalWelcomeDepositEndpoint::new(
        [0x64; 16],
        [0x74; 16],
        DepositCapability::new([0x84; 32]).expect("nonzero deposit capability"),
        NOW + 60,
    )
    .expect("create shorter-lived endpoint");
    let mut fixture = approval_fixture_with_endpoint(response_endpoint);
    let mut verifier = verifier();
    let verified = verifier
        .verify_and_reserve(fixture.opened, NOW)
        .expect("automated verification succeeds");
    let pending = verifier
        .reserve_v2_for_approval(&mut fixture.registry, &fixture.validated, verified, NOW)
        .expect("reserve invitation");

    assert!(matches!(
        verifier.decide_v2(
            &mut fixture.registry,
            pending,
            ManualApprovalDecision::Approve,
            NOW + 60,
        ),
        Err(CapabilityAdmissionError::Rejected)
    ));
    assert_eq!(verifier.pending_count(), 0);
    assert_eq!(
        fixture.registry.lifecycle(&fixture.invitation_id),
        Some(InvitationLifecycle::Available)
    );
}

#[test]
fn foreign_verifier_cannot_prepare_an_approved_exact_add() {
    let mut fixture = approval_fixture();
    let mut owner = verifier();
    let verified = owner
        .verify_and_reserve(fixture.opened, NOW)
        .expect("automated verification succeeds");
    let pending = owner
        .reserve_v2_for_approval(&mut fixture.registry, &fixture.validated, verified, NOW)
        .expect("reserve invitation");
    let CapabilityApprovalOutcome::Approved(approved) = owner
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
    let mut foreign = verifier();

    assert!(matches!(
        foreign.prepare_approved_add(&mut fixture.registry, approved, &mut group, NOW),
        Err(CapabilityAdmissionError::ReservationMismatch)
    ));
    assert_eq!(group.epoch(), 0);
    assert_eq!(group.member_count(), 1);
    assert_eq!(owner.pending_count(), 1);
    assert_eq!(foreign.pending_count(), 0);
    assert_eq!(
        fixture.registry.lifecycle(&fixture.invitation_id),
        Some(InvitationLifecycle::Reserved)
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
fn expired_response_endpoint_is_rejected_before_replay_reservation() {
    let response_endpoint = LocalWelcomeDepositEndpoint::new(
        [0x62; 16],
        [0x72; 16],
        DepositCapability::new([0x82; 32]).expect("nonzero deposit capability"),
        NOW,
    )
    .expect("create structurally valid expired endpoint");
    let fixture = approval_fixture_with_endpoint(response_endpoint);
    let mut verifier = verifier();

    assert!(verifier.verify_and_reserve(fixture.opened, NOW).is_err());
    assert_eq!(verifier.pending_count(), 0);
    assert_eq!(
        fixture.registry.lifecycle(&fixture.invitation_id),
        Some(InvitationLifecycle::Available)
    );
}

#[test]
fn delayed_apply_rechecks_response_endpoint_before_mls_mutation() {
    let response_endpoint = LocalWelcomeDepositEndpoint::new(
        [0x63; 16],
        [0x73; 16],
        DepositCapability::new([0x83; 32]).expect("nonzero deposit capability"),
        NOW + 60,
    )
    .expect("create shorter-lived endpoint");
    let mut fixture = approval_fixture_with_endpoint(response_endpoint);
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
        .expect("prepare while endpoint is live");

    assert!(prepared.apply(NOW + 60).is_err());
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
    assert!(!committed.commit().as_bytes().is_empty());
    assert_eq!(group.epoch(), 1);
    assert_eq!(group.member_count(), 2);
    assert_eq!(verifier.pending_count(), 1);
    assert_eq!(
        fixture.registry.lifecycle(&fixture.invitation_id),
        Some(InvitationLifecycle::Consumed)
    );
}

#[test]
fn durability_pending_join_defers_invitation_consumption_until_commit_is_confirmed() {
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

    let durability_pending = verifier
        .prepare_approved_add(&mut fixture.registry, approved, &mut group, NOW)
        .expect("prepare approved Add")
        .apply_awaiting_durability(NOW)
        .expect("apply MLS while durability remains unresolved");

    assert_eq!(
        durability_pending.key_package_reference(),
        &fixture.key_package_reference
    );
    assert!(!durability_pending.commit().as_bytes().is_empty());
    assert!(!durability_pending.welcome().as_bytes().is_empty());
    assert_eq!(
        durability_pending
            .response_endpoint()
            .expires_at_unix_seconds(),
        NOW + 120
    );
    assert_eq!(group.epoch(), 1);
    assert_eq!(group.member_count(), 2);
    assert_eq!(
        durability_pending.invitation_lifecycle(),
        Some(InvitationLifecycle::Reserved)
    );
    let committed = durability_pending
        .finalize_committed()
        .expect("confirmed durable commit consumes the in-memory shadow");

    assert_eq!(
        committed.key_package_reference(),
        &fixture.key_package_reference
    );
    assert_eq!(verifier.pending_count(), 1);
    assert_eq!(
        fixture.registry.lifecycle(&fixture.invitation_id),
        Some(InvitationLifecycle::Consumed)
    );
}

#[test]
fn proven_uncommitted_durable_join_releases_admission_reservations() {
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

    verifier
        .prepare_approved_add(&mut fixture.registry, approved, &mut group, NOW)
        .expect("prepare approved Add")
        .apply_awaiting_durability(NOW)
        .expect("apply transient MLS state")
        .release_proven_uncommitted()
        .expect("known rollback releases both reservations");

    assert_eq!(group.epoch(), 1);
    assert_eq!(group.member_count(), 2);
    assert_eq!(verifier.pending_count(), 0);
    assert_eq!(
        fixture.registry.lifecycle(&fixture.invitation_id),
        Some(InvitationLifecycle::Available)
    );
}

#[test]
fn abandoning_ambiguous_durable_join_preserves_reservations_fail_closed() {
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

    drop(
        verifier
            .prepare_approved_add(&mut fixture.registry, approved, &mut group, NOW)
            .expect("prepare approved Add")
            .apply_awaiting_durability(NOW)
            .expect("apply MLS with ambiguous durability"),
    );

    assert_eq!(verifier.pending_count(), 1);
    assert_eq!(
        fixture.registry.lifecycle(&fixture.invitation_id),
        Some(InvitationLifecycle::Reserved)
    );
}

#[test]
fn approved_join_returns_only_the_deposit_endpoint_for_local_welcome_delivery() {
    let mut transport = LocalMemoryWelcomeTransport::new(
        LocalMailboxPolicy::new(300, 1).expect("valid mailbox policy"),
    )
    .expect("create local transport");
    let (deposit, receive, acknowledgement) = transport
        .create_welcome_mailbox(NOW + 120, NOW)
        .expect("create right-specific mailbox")
        .into_parts();
    let mut fixture = approval_fixture_with_endpoint(deposit);
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

    let committed = verifier
        .prepare_approved_add(&mut fixture.registry, approved, &mut group, NOW)
        .expect("prepare approved exact Add")
        .apply(NOW)
        .expect("apply in-memory join");
    let envelope = OpaqueEnvelope::new(
        [0xa1; 16],
        NOW + 60,
        committed.welcome().as_bytes().to_vec(),
    )
    .expect("MLS Welcome fits the bounded envelope");
    let delivery_id = transport
        .deposit(committed.response_endpoint(), envelope.clone(), NOW)
        .expect("deposit through the returned sender-only endpoint");
    let received = transport
        .receive(&receive, NOW)
        .expect("receive with joiner-only authority")
        .expect("Welcome is retained");

    assert_eq!(received.delivery_id(), &delivery_id);
    assert_eq!(received.envelope(), &envelope);
    assert_eq!(group.epoch(), 1);
    assert_eq!(group.member_count(), 2);
    assert_eq!(
        fixture.registry.lifecycle(&fixture.invitation_id),
        Some(InvitationLifecycle::Consumed)
    );

    transport
        .acknowledge(&acknowledgement, delivery_id, NOW)
        .expect("joiner acknowledgement deletes the Welcome");
    assert!(
        transport
            .receive(&receive, NOW)
            .expect("mailbox remains readable")
            .is_none()
    );
    assert_eq!(
        transport.deposit(committed.response_endpoint(), envelope, NOW + 120),
        Err(LocalTransportError::Rejected)
    );
    assert_eq!(group.epoch(), 1);
    assert_eq!(group.member_count(), 2);
    assert_eq!(
        fixture.registry.lifecycle(&fixture.invitation_id),
        Some(InvitationLifecycle::Consumed)
    );
}
