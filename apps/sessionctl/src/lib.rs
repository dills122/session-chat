#![forbid(unsafe_code)]

//! Headless Phase 1 composition and conformance flow.

use admission_capability::{
    CapabilityAdmissionPolicy, CapabilityAdmissionVerifier, CapabilityApprovalOutcome,
    ManualApprovalDecision,
};
use aws_lc_rs::rand;
use session_admission::{AdmissionMethod, PendingAdmission};
use session_core::{InvitationLifecycle, InvitationPolicy, InvitationRegistry};
use session_crypto::{MessageEvent, MessageSession, ProtectedMessage};
use session_crypto_hpke::{AwsLcInvitationJoinProtector, InvitationJoinProtector};
use session_crypto_mls::{
    SessionGroupId, WelcomeMessage, create_client, create_key_package_validator,
};
use session_protocol::{
    CapabilityJoinRequest, InvitationJoinBinding, JoinRequestBinding, MlsKeyPackageBinding,
    OpaqueEnvelope,
};
use session_transport::{EnvelopeTransport, LocalMailboxPolicy, LocalMemoryWelcomeTransport};
use thiserror::Error;
use transport_memory::{
    DeliveryAction, DeterministicMemoryTransport, MemoryAcknowledgementCapability,
    MemoryDepositEndpoint, MemoryMailboxPolicy, MemoryReceiveCapability,
};

const NOW: u64 = 1_900_000_000;
const MAILBOX_EXPIRES_AT: u64 = NOW + 240;
const REQUEST_EXPIRES_AT: u64 = NOW + 120;
const INVITATION_EXPIRES_AT: u64 = NOW + 300;

/// Coarse failure from the headless protocol-conformance flow.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SessionCtlError {
    /// One named protocol stage rejected its input or contradicted the expected state.
    #[error("headless Phase 1 flow failed at {0}")]
    Stage(&'static str),
}

/// Real orchestration boundaries at which a conformance runner may stop the flow.
///
/// A fault point carries no provider error, protocol object, identifier, or
/// secret-bearing value. Production execution uses a plan that never fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhaseOneFaultPoint {
    /// Fail after invitation key and capability generation.
    InvitationGeneration,
    /// Fail after inviter-owned invitation issuance.
    InvitationIssue,
    /// Fail after canonical invitation encoding.
    InvitationEncoding,
    /// Fail after read-only invitation validation.
    InvitationValidation,
    /// Fail after constructing the local Welcome transport.
    WelcomeTransport,
    /// Fail after creating the right-specific Welcome mailbox.
    WelcomeMailbox,
    /// Fail after creating Alice's MLS client.
    AliceClient,
    /// Fail after creating Bob's MLS client.
    BobClient,
    /// Fail after Bob generates an exact KeyPackage.
    BobKeyPackage,
    /// Fail after provider validation of Bob's KeyPackage.
    KeyPackageValidation,
    /// Fail after protecting the capability join request.
    JoinRequestProtection,
    /// Fail after opening the capability join request.
    JoinRequestOpening,
    /// Fail after automated admission verification and replay reservation.
    AdmissionVerification,
    /// Fail after binding admission to inviter-owned invitation state.
    ApprovalReservation,
    /// Stop while the exact request is reserved and awaiting approval.
    ApprovalDecision,
    /// Fail after creating Alice's initial MLS group.
    AliceGroup,
    /// Fail after preparing the approved MLS Add.
    MembershipPreparation,
    /// Abandon the prepared MLS Add before applying its pending Commit.
    MembershipApply,
    /// Stop after membership commits but before depositing the Welcome.
    WelcomeDeposit,
    /// Fail after receiving the encrypted Welcome envelope.
    WelcomeReceive,
    /// Fail after framing the encrypted MLS Welcome.
    WelcomeFraming,
    /// Fail after Bob joins the MLS group.
    BobJoin,
    /// Fail after acknowledging the Welcome delivery.
    WelcomeAcknowledgement,
    /// Fail after constructing the deterministic application transport.
    MessageTransport,
    /// Fail after creating Alice's application-message mailbox.
    AliceMessageMailbox,
    /// Fail after creating Bob's application-message mailbox.
    BobMessageMailbox,
    /// Fail after Alice protects the first application message.
    AliceMessageProtection,
    /// Drop the first accepted application-message delivery.
    FirstApplicationDelivery,
    /// Fail after Bob processes Alice's application message.
    BobMessageProcessing,
    /// Fail after Bob protects the reply application message.
    BobMessageProtection,
    /// Fail after the reply delivery is acknowledged.
    SecondApplicationDelivery,
    /// Fail after Alice processes Bob's application message.
    AliceMessageProcessing,
    /// Fail after preparing Alice's path update.
    PathUpdatePreparation,
    /// Fail after applying Alice's path update.
    PathUpdateApply,
    /// Fail after the path-update delivery is acknowledged.
    PathUpdateDelivery,
    /// Fail after Bob processes the path update.
    PathUpdateProcessing,
    /// Fail after preparing Bob's removal.
    RemovalPreparation,
    /// Fail after applying Bob's removal.
    RemovalApply,
    /// Fail after the removal delivery is acknowledged.
    RemovalDelivery,
    /// Fail after Bob processes his removal.
    RemovalProcessing,
    /// Fail after Alice protects a post-removal message.
    PostRemovalProtection,
    /// Fail after the post-removal delivery is acknowledged.
    PostRemovalDelivery,
}

/// Secret-free cleanup evidence emitted to an injected conformance plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhaseOneObservation {
    /// Rejection released both the invitation and replay reservations.
    ApprovalReservationsReleased,
    /// Dropping the prepared Add released reservations and left MLS unchanged.
    PreparedMembershipReleased,
    /// A post-commit delivery failure did not roll membership back.
    CommittedMembershipRetained,
    /// The deterministic transport accepted but did not expose the dropped delivery.
    DroppedDeliveryObserved,
    /// All orchestration-owned values have left scope after success or failure.
    OrchestrationQuiescent,
}

/// Injected conformance controls for the headless orchestration boundary.
///
/// Implementations can select a failure milestone and retain only the
/// secret-free observations emitted by the flow. They never receive protocol
/// bytes, capabilities, identifiers, plaintext, or provider errors.
pub trait PhaseOneFaultPlan {
    /// Returns whether this run should fail at one exact operation boundary.
    fn fail_at(&mut self, point: PhaseOneFaultPoint) -> bool;

    /// Receives a coarse cleanup observation.
    fn observe(&mut self, _observation: PhaseOneObservation) {}
}

struct NoFaults;

impl PhaseOneFaultPlan for NoFaults {
    fn fail_at(&mut self, _point: PhaseOneFaultPoint) -> bool {
        false
    }
}

/// Non-sensitive milestones observed during one complete headless flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhaseOneReport {
    admission_approved: bool,
    welcome_delivered: bool,
    joined_epoch: u64,
    application_messages_received: usize,
    updated_epoch: u64,
    removed: bool,
    post_removal_rejected: bool,
}

impl PhaseOneReport {
    /// Reports that an exact verified request received an explicit approval.
    #[must_use]
    pub const fn admission_approved(&self) -> bool {
        self.admission_approved
    }

    /// Reports that the one-shot Welcome traversed its right-specific mailbox.
    #[must_use]
    pub const fn welcome_delivered(&self) -> bool {
        self.welcome_delivered
    }

    /// Returns the MLS epoch held by both clients immediately after joining.
    #[must_use]
    pub const fn joined_epoch(&self) -> u64 {
        self.joined_epoch
    }

    /// Returns the number of bidirectional application messages authenticated.
    #[must_use]
    pub const fn application_messages_received(&self) -> usize {
        self.application_messages_received
    }

    /// Returns the epoch held by both clients after the path update.
    #[must_use]
    pub const fn updated_epoch(&self) -> u64 {
        self.updated_epoch
    }

    /// Reports that Bob authenticated the Commit removing him.
    #[must_use]
    pub const fn removed(&self) -> bool {
        self.removed
    }

    /// Reports that Bob rejected an otherwise valid message created after removal.
    #[must_use]
    pub const fn post_removal_rejected(&self) -> bool {
        self.post_removal_rejected
    }
}

/// Runs the in-memory, two-client Phase 1 protocol-conformance scenario.
///
/// This composes reviewed local adapters; it is not a network, durability,
/// anonymity, or production-hosting claim.
pub fn run_phase_one_demo() -> Result<PhaseOneReport, SessionCtlError> {
    run_phase_one_demo_with_faults(&mut NoFaults)
}

/// Runs the Phase 1 scenario with explicit, secret-free conformance controls.
///
/// The injected plan can stop only at named operation boundaries. The normal
/// [`run_phase_one_demo`] path injects no failures and remains unchanged.
pub fn run_phase_one_demo_with_faults(
    faults: &mut impl PhaseOneFaultPlan,
) -> Result<PhaseOneReport, SessionCtlError> {
    let result = run_phase_one_flow(faults);
    faults.observe(PhaseOneObservation::OrchestrationQuiescent);
    result
}

fn run_phase_one_flow(
    faults: &mut impl PhaseOneFaultPlan,
) -> Result<PhaseOneReport, SessionCtlError> {
    let protector = AwsLcInvitationJoinProtector::new();
    let generated = operation_result(
        faults,
        PhaseOneFaultPoint::InvitationGeneration,
        protector.generate_capability_invitation(NOW, INVITATION_EXPIRES_AT),
        "invitation generation",
    )?;
    let mut invitation_registry =
        InvitationRegistry::new(InvitationPolicy::new(3_600, 5, 8).at_stage("invitation policy")?);
    let issued = operation_result(
        faults,
        PhaseOneFaultPoint::InvitationIssue,
        invitation_registry.issue_v2(generated, NOW),
        "invitation issue",
    )?;
    let encoded_invitation = operation_result(
        faults,
        PhaseOneFaultPoint::InvitationEncoding,
        issued.encode_canonical(),
        "invitation encoding",
    )?;
    let validated_invitation = operation_result(
        faults,
        PhaseOneFaultPoint::InvitationValidation,
        invitation_registry.validate_descriptor_v2(&encoded_invitation, NOW),
        "invitation validation",
    )?;

    let welcome_policy = LocalMailboxPolicy::new(300, 1).at_stage("Welcome mailbox policy")?;
    let mut welcome_transport = operation_result(
        faults,
        PhaseOneFaultPoint::WelcomeTransport,
        LocalMemoryWelcomeTransport::new(welcome_policy),
        "Welcome transport",
    )?;
    let welcome_mailbox = operation_result(
        faults,
        PhaseOneFaultPoint::WelcomeMailbox,
        welcome_transport.create_welcome_mailbox(REQUEST_EXPIRES_AT, NOW),
        "Welcome mailbox",
    )?;
    let (welcome_deposit, welcome_receive, welcome_acknowledgement) = welcome_mailbox.into_parts();

    let alice = operation_result(
        faults,
        PhaseOneFaultPoint::AliceClient,
        create_client(),
        "Alice client",
    )?;
    let bob = operation_result(
        faults,
        PhaseOneFaultPoint::BobClient,
        create_client(),
        "Bob client",
    )?;
    let bob_key_package = operation_result(
        faults,
        PhaseOneFaultPoint::BobKeyPackage,
        bob.generate_key_package(NOW),
        "Bob KeyPackage",
    )?;
    let validated_key_package = operation_result(
        faults,
        PhaseOneFaultPoint::KeyPackageValidation,
        create_key_package_validator().validate_key_package(bob_key_package.as_bytes(), NOW),
        "KeyPackage validation",
    )?;
    let expected_key_package_reference = *validated_key_package.key_package_reference();

    let invitation_binding = InvitationJoinBinding::new(
        *issued.invitation().invitation_id(),
        *issued.invitation().join_challenge(),
        *issued.invitation().invitation_key_id(),
        *issued.invitation().inviter_verifying_key(),
    )
    .at_stage("invitation binding")?;
    let request_binding = JoinRequestBinding::new(
        random_nonzero()?,
        NOW,
        REQUEST_EXPIRES_AT,
        random_nonzero()?,
    )
    .at_stage("request binding")?;
    let mls_binding = MlsKeyPackageBinding::new(
        expected_key_package_reference,
        bob_key_package.as_bytes().to_vec(),
        *validated_key_package.credential_identity(),
        *validated_key_package.leaf_signature_key(),
    )
    .at_stage("MLS binding")?;
    let request = CapabilityJoinRequest::new(
        invitation_binding,
        request_binding,
        mls_binding,
        welcome_deposit,
    )
    .at_stage("join request")?;
    let protected_request = operation_result(
        faults,
        PhaseOneFaultPoint::JoinRequestProtection,
        protector.seal_capability_request(issued.invitation(), &request),
        "join request protection",
    )?;
    let opened_request = operation_result(
        faults,
        PhaseOneFaultPoint::JoinRequestOpening,
        protector.open_capability_request(
            issued.private_key(),
            issued.invitation(),
            &protected_request,
        ),
        "join request opening",
    )?;

    let mut admission = CapabilityAdmissionVerifier::new(
        CapabilityAdmissionPolicy::new(3_600, 5, 8).at_stage("admission policy")?,
    );
    let verified = operation_result(
        faults,
        PhaseOneFaultPoint::AdmissionVerification,
        admission.verify_and_reserve(opened_request, NOW),
        "admission verification",
    )?;
    let pending = operation_result(
        faults,
        PhaseOneFaultPoint::ApprovalReservation,
        admission.reserve_v2_for_approval(
            &mut invitation_registry,
            &validated_invitation,
            verified,
            NOW,
        ),
        "approval reservation",
    )?;
    let approval_context = pending.approval_context();
    if approval_context.method() != AdmissionMethod::SecretCapability
        || approval_context.key_package_reference() != &expected_key_package_reference
    {
        return Err(stage("approval context"));
    }
    if faults.fail_at(PhaseOneFaultPoint::ApprovalDecision) {
        let invitation_id = *issued.invitation().invitation_id();
        let outcome = admission
            .decide_v2(
                &mut invitation_registry,
                pending,
                ManualApprovalDecision::Reject,
                NOW,
            )
            .at_stage("approval cleanup")?;
        if !matches!(outcome, CapabilityApprovalOutcome::Rejected)
            || admission.pending_count() != 0
            || invitation_registry.lifecycle(&invitation_id) != Some(InvitationLifecycle::Available)
        {
            return Err(stage("approval cleanup"));
        }
        faults.observe(PhaseOneObservation::ApprovalReservationsReleased);
        return Err(stage("approval decision"));
    }
    let CapabilityApprovalOutcome::Approved(approved) = admission
        .decide_v2(
            &mut invitation_registry,
            pending,
            ManualApprovalDecision::Approve,
            NOW,
        )
        .at_stage("approval decision")?
    else {
        return Err(stage("approval decision"));
    };

    let mut alice_group = operation_result(
        faults,
        PhaseOneFaultPoint::AliceGroup,
        alice.create_group(
            SessionGroupId::new(random_nonzero()?).at_stage("group ID")?,
            NOW,
        ),
        "Alice group",
    )?;
    let prepared_join = operation_result(
        faults,
        PhaseOneFaultPoint::MembershipPreparation,
        admission.prepare_approved_add(&mut invitation_registry, approved, &mut alice_group, NOW),
        "MLS Add preparation",
    )?;
    if faults.fail_at(PhaseOneFaultPoint::MembershipApply) {
        let invitation_id = *issued.invitation().invitation_id();
        drop(prepared_join);
        if admission.pending_count() != 0
            || invitation_registry.lifecycle(&invitation_id) != Some(InvitationLifecycle::Available)
            || alice_group.epoch() != 0
            || alice_group.member_count() != 1
        {
            return Err(stage("MLS Add cleanup"));
        }
        faults.observe(PhaseOneObservation::PreparedMembershipReleased);
        return Err(stage("MLS Add apply"));
    }
    let committed_join = prepared_join.apply(NOW).at_stage("MLS Add apply")?;
    if committed_join.key_package_reference() != &expected_key_package_reference {
        return Err(stage("Welcome ownership"));
    }
    let (addition, response_endpoint) = committed_join.into_parts();
    if faults.fail_at(PhaseOneFaultPoint::WelcomeDeposit) {
        let invitation_id = *issued.invitation().invitation_id();
        let mailbox_empty = welcome_transport
            .receive(&welcome_receive, NOW)
            .at_stage("Welcome cleanup")?
            .is_none();
        if invitation_registry.lifecycle(&invitation_id) != Some(InvitationLifecycle::Consumed)
            || alice_group.epoch() != 1
            || alice_group.member_count() != 2
            || !mailbox_empty
        {
            return Err(stage("Welcome cleanup"));
        }
        faults.observe(PhaseOneObservation::CommittedMembershipRetained);
        return Err(stage("Welcome deposit"));
    }
    let welcome_envelope = OpaqueEnvelope::new(
        random_nonzero()?,
        REQUEST_EXPIRES_AT,
        addition.welcome().as_bytes().to_vec(),
    )
    .at_stage("Welcome envelope")?;
    let welcome_delivery = welcome_transport
        .deposit(&response_endpoint, welcome_envelope, NOW)
        .at_stage("Welcome deposit")?;
    let received_welcome = operation_result(
        faults,
        PhaseOneFaultPoint::WelcomeReceive,
        welcome_transport.receive(&welcome_receive, NOW),
        "Welcome receive",
    )?
    .ok_or_else(|| stage("Welcome receive"))?;
    if received_welcome.delivery_id() != &welcome_delivery {
        return Err(stage("Welcome delivery identity"));
    }
    let welcome = operation_result(
        faults,
        PhaseOneFaultPoint::WelcomeFraming,
        WelcomeMessage::from_bytes(received_welcome.envelope().ciphertext()),
        "Welcome framing",
    )?;
    let mut bob_group = operation_result(
        faults,
        PhaseOneFaultPoint::BobJoin,
        bob.join_group(welcome, NOW),
        "Bob join",
    )?;
    operation_result(
        faults,
        PhaseOneFaultPoint::WelcomeAcknowledgement,
        welcome_transport.acknowledge(&welcome_acknowledgement, welcome_delivery, NOW),
        "Welcome acknowledgement",
    )?;
    if alice_group.epoch() != 1 || bob_group.epoch() != 1 {
        return Err(stage("joined epoch"));
    }

    let message_policy =
        MemoryMailboxPolicy::new(300, 2, 8, 3).at_stage("message mailbox policy")?;
    let mut message_transport = operation_result(
        faults,
        PhaseOneFaultPoint::MessageTransport,
        DeterministicMemoryTransport::new(message_policy),
        "message transport",
    )?;
    let alice_mailbox = operation_result(
        faults,
        PhaseOneFaultPoint::AliceMessageMailbox,
        message_transport.create_mailbox(MAILBOX_EXPIRES_AT, NOW),
        "Alice message mailbox",
    )?;
    let (to_alice, alice_receive, alice_acknowledgement) = alice_mailbox.into_parts();
    let bob_mailbox = operation_result(
        faults,
        PhaseOneFaultPoint::BobMessageMailbox,
        message_transport.create_mailbox(MAILBOX_EXPIRES_AT, NOW),
        "Bob message mailbox",
    )?;
    let (to_bob, bob_receive, bob_acknowledgement) = bob_mailbox.into_parts();

    let alice_plaintext = b"hello from Alice";
    let protected = operation_result(
        faults,
        PhaseOneFaultPoint::AliceMessageProtection,
        alice_group.protect_application_message(alice_plaintext),
        "Alice message protection",
    )?;
    let drop_first_delivery = faults.fail_at(PhaseOneFaultPoint::FirstApplicationDelivery);
    if drop_first_delivery {
        message_transport
            .queue_action(DeliveryAction::Drop)
            .at_stage("message fault plan")?;
    }
    let delivery_result = deliver_message(
        &mut message_transport,
        &to_bob,
        &bob_receive,
        &bob_acknowledgement,
        protected,
    );
    if drop_first_delivery {
        let snapshot = message_transport.conformance_snapshot();
        if delivery_result != Err(stage("message receive"))
            || snapshot.live_envelopes() != 1
            || snapshot.visible_copies() != 0
            || snapshot.held_copies() != 0
            || snapshot.queued_delivery_actions() != 0
        {
            return Err(stage("message delivery cleanup"));
        }
        faults.observe(PhaseOneObservation::DroppedDeliveryObserved);
        return Err(stage("message receive"));
    }
    let delivered = delivery_result?;
    assert_application(
        operation_result(
            faults,
            PhaseOneFaultPoint::BobMessageProcessing,
            bob_group.process_protected_message(delivered),
            "Bob message processing",
        )?,
        alice_plaintext,
    )?;

    let bob_plaintext = b"hello from Bob";
    let protected = operation_result(
        faults,
        PhaseOneFaultPoint::BobMessageProtection,
        bob_group.protect_application_message(bob_plaintext),
        "Bob message protection",
    )?;
    let delivered = deliver_message(
        &mut message_transport,
        &to_alice,
        &alice_receive,
        &alice_acknowledgement,
        protected,
    )?;
    fail_after_operation(
        faults,
        PhaseOneFaultPoint::SecondApplicationDelivery,
        "message delivery",
    )?;
    assert_application(
        operation_result(
            faults,
            PhaseOneFaultPoint::AliceMessageProcessing,
            alice_group.process_protected_message(delivered),
            "Alice message processing",
        )?,
        bob_plaintext,
    )?;

    let prepared_update = operation_result(
        faults,
        PhaseOneFaultPoint::PathUpdatePreparation,
        alice_group.prepare_epoch_update(NOW),
        "path update preparation",
    )?;
    let update = operation_result(
        faults,
        PhaseOneFaultPoint::PathUpdateApply,
        prepared_update.apply(),
        "path update apply",
    )?
    .into_commit();
    let delivered_update = deliver_message(
        &mut message_transport,
        &to_bob,
        &bob_receive,
        &bob_acknowledgement,
        ProtectedMessage::from_bytes(update.as_bytes()).at_stage("path update framing")?,
    )?;
    fail_after_operation(
        faults,
        PhaseOneFaultPoint::PathUpdateDelivery,
        "path update delivery",
    )?;
    if operation_result(
        faults,
        PhaseOneFaultPoint::PathUpdateProcessing,
        bob_group.process_protected_message(delivered_update),
        "path update processing",
    )? != MessageEvent::EpochAdvanced
        || alice_group.epoch() != 2
        || bob_group.epoch() != 2
    {
        return Err(stage("path update outcome"));
    }

    let prepared_removal = operation_result(
        faults,
        PhaseOneFaultPoint::RemovalPreparation,
        alice_group.prepare_remove_peer(NOW),
        "removal preparation",
    )?;
    let removal = operation_result(
        faults,
        PhaseOneFaultPoint::RemovalApply,
        prepared_removal.apply(),
        "removal apply",
    )?
    .into_commit();
    let delivered_removal = deliver_message(
        &mut message_transport,
        &to_bob,
        &bob_receive,
        &bob_acknowledgement,
        ProtectedMessage::from_bytes(removal.as_bytes()).at_stage("removal framing")?,
    )?;
    fail_after_operation(
        faults,
        PhaseOneFaultPoint::RemovalDelivery,
        "removal delivery",
    )?;
    let removed = operation_result(
        faults,
        PhaseOneFaultPoint::RemovalProcessing,
        bob_group.process_protected_message(delivered_removal),
        "removal processing",
    )? == MessageEvent::Removed;
    if !removed || alice_group.epoch() != 3 || alice_group.member_count() != 1 {
        return Err(stage("removal outcome"));
    }

    let after_removal = operation_result(
        faults,
        PhaseOneFaultPoint::PostRemovalProtection,
        alice_group.protect_application_message(b"message after removal"),
        "post-removal protection",
    )?;
    let delivered_after_removal = deliver_message(
        &mut message_transport,
        &to_bob,
        &bob_receive,
        &bob_acknowledgement,
        after_removal,
    )?;
    fail_after_operation(
        faults,
        PhaseOneFaultPoint::PostRemovalDelivery,
        "post-removal delivery",
    )?;
    let post_removal_rejected = bob_group
        .process_protected_message(delivered_after_removal)
        .is_err();
    if !post_removal_rejected {
        return Err(stage("post-removal rejection"));
    }

    Ok(PhaseOneReport {
        admission_approved: true,
        welcome_delivered: true,
        joined_epoch: 1,
        application_messages_received: 2,
        updated_epoch: 2,
        removed,
        post_removal_rejected,
    })
}

fn deliver_message(
    transport: &mut DeterministicMemoryTransport,
    endpoint: &MemoryDepositEndpoint,
    receive: &MemoryReceiveCapability,
    acknowledgement: &MemoryAcknowledgementCapability,
    message: ProtectedMessage,
) -> Result<ProtectedMessage, SessionCtlError> {
    let envelope = OpaqueEnvelope::new(random_nonzero()?, REQUEST_EXPIRES_AT, message.into_bytes())
        .at_stage("message envelope")?;
    let delivery_id = transport
        .deposit(endpoint, envelope, NOW)
        .at_stage("message deposit")?;
    let received = transport
        .receive(receive, NOW)
        .at_stage("message receive")?
        .ok_or_else(|| stage("message receive"))?;
    if received.delivery_id() != &delivery_id {
        return Err(stage("message delivery identity"));
    }
    let protected = ProtectedMessage::from_bytes(received.envelope().ciphertext())
        .at_stage("message framing")?;
    transport
        .acknowledge(acknowledgement, delivery_id, NOW)
        .at_stage("message acknowledgement")?;
    Ok(protected)
}

fn assert_application(event: MessageEvent, expected: &[u8]) -> Result<(), SessionCtlError> {
    let MessageEvent::Application(application) = event else {
        return Err(stage("application event"));
    };
    if application.as_bytes() != expected {
        return Err(stage("application content"));
    }
    Ok(())
}

fn random_nonzero<const N: usize>() -> Result<[u8; N], SessionCtlError> {
    let mut bytes = [0; N];
    rand::fill(&mut bytes).at_stage("random provider")?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(stage("random provider"));
    }
    Ok(bytes)
}

fn operation_result<T, E>(
    faults: &mut impl PhaseOneFaultPlan,
    point: PhaseOneFaultPoint,
    result: Result<T, E>,
    name: &'static str,
) -> Result<T, SessionCtlError> {
    if faults.fail_at(point) {
        return Err(stage(name));
    }
    result.at_stage(name)
}

fn fail_after_operation(
    faults: &mut impl PhaseOneFaultPlan,
    point: PhaseOneFaultPoint,
    name: &'static str,
) -> Result<(), SessionCtlError> {
    if faults.fail_at(point) {
        return Err(stage(name));
    }
    Ok(())
}

const fn stage(name: &'static str) -> SessionCtlError {
    SessionCtlError::Stage(name)
}

trait StageResult<T> {
    fn at_stage(self, name: &'static str) -> Result<T, SessionCtlError>;
}

impl<T, E> StageResult<T> for Result<T, E> {
    fn at_stage(self, name: &'static str) -> Result<T, SessionCtlError> {
        self.map_err(|_| stage(name))
    }
}
