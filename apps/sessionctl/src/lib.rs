#![forbid(unsafe_code)]

//! Headless Phase 1 composition and conformance flow.

mod l1_process;

pub use l1_process::{L1ProcessReport, run_l1_process_demo, run_l1_process_internal_role};

use std::{
    fmt::Write as _,
    path::PathBuf,
    time::{Duration, Instant},
};

use admission_capability::{
    CapabilityAdmissionPolicy, CapabilityAdmissionVerifier, CapabilityApprovalOutcome,
    ManualApprovalDecision,
};
use aws_lc_rs::{
    digest::{SHA256, digest},
    rand,
};
use session_admission::{AdmissionMethod, ApprovalContext, PendingAdmission};
use session_core::{InvitationLifecycle, InvitationPolicy, InvitationRegistry};
use session_crypto::{MessageEvent, MessageSession, ProtectedMessage};
use session_crypto_hpke::{AwsLcInvitationJoinProtector, InvitationJoinProtector};
use session_crypto_mls::{
    SessionGroupId, WelcomeMessage, create_client, create_durable_client_with_storage,
    create_key_package_validator, load_durable_client_with_storage,
};
use session_protocol::{
    CapabilityJoinRequest, InvitationJoinBinding, JoinRequestBinding, MlsKeyPackageBinding,
    OpaqueEnvelope,
};
use session_transport::{
    BlockingFutureSupervisor, CoordinatorOutcome, CoordinatorPolicy, EnvelopeTransport,
    LocalMailboxPolicy, LocalMemoryWelcomeTransport, LocalV1DepositEndpointResolver,
    ThreadDispatchControl, WelcomeDeliveryCoordinator,
};
use storage_sqlcipher::{
    InvitationState, InviterJoinTransaction, PersistenceFault, SqlCipherStorage, VaultKey,
    WelcomeOutboxState,
};
use thiserror::Error;
use transport_memory::{
    DeliveryAction, DeterministicMemoryTransport, MemoryAcknowledgementCapability,
    MemoryDepositEndpoint, MemoryMailboxPolicy, MemoryReceiveCapability,
};
use zeroize::Zeroizing;

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
    /// Fail after creating the disposable encrypted owner store.
    DurableStore,
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
    /// Fail after persisting the exact inviter-owned reservation.
    DurableReservation,
    /// Stop while the exact request is reserved and awaiting approval.
    ApprovalDecision,
    /// Fail after creating Alice's initial MLS group.
    AliceGroup,
    /// Fail after preparing the approved MLS Add.
    MembershipPreparation,
    /// Abandon the prepared MLS Add before applying its pending Commit.
    MembershipApply,
    /// Inject a proven pre-commit SQL rollback after applying transient MLS state.
    MembershipPersistence,
    /// Inject an ambiguous response after the SQL membership commit succeeds.
    MembershipCommitResponse,
    /// Stop after membership commits but before depositing the Welcome.
    WelcomeDeposit,
    /// Fail after reopening the SQLCipher owner for delivery coordination.
    DurableStoreReopen,
    /// Fail after the durable coordinator records adapter acceptance.
    WelcomeCoordinator,
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
    /// A proven SQL rollback released admission reservations fail-closed.
    DurableRollbackReleased,
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

    /// Encodes one bounded, versioned, secret-free scenario result.
    ///
    /// This is intentionally smaller than the future independent-process
    /// evidence manifest: it records the current single-process topology and
    /// coarse protocol outcomes, but no identifiers, paths, capabilities,
    /// ciphertext, plaintext, or environment metadata.
    #[must_use]
    pub fn encode_scenario_evidence_v1(&self) -> String {
        format!(
            concat!(
                "version=1\n",
                "scenario=E2E-JOIN-001\n",
                "topology=single-process-sqlcipher-local-v1\n",
                "result=pass\n",
                "admission={}\n",
                "welcome={}\n",
                "joined_epoch={}\n",
                "messages={}\n",
                "updated_epoch={}\n",
                "removal={}\n",
                "post_removal={}\n"
            ),
            if self.admission_approved {
                "approved"
            } else {
                "rejected"
            },
            if self.welcome_delivered {
                "delivered"
            } else {
                "not_delivered"
            },
            self.joined_epoch,
            self.application_messages_received,
            self.updated_epoch,
            if self.removed {
                "enforced"
            } else {
                "not_enforced"
            },
            if self.post_removal_rejected {
                "rejected"
            } else {
                "accepted"
            },
        )
    }
}

/// Runs the durable-component, single-process two-client Phase 1 scenario.
///
/// This composes the SQLCipher laboratory and reviewed local adapters; it is
/// not a full client-restart, network, anonymity, or production-hosting claim.
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
    let database = TempDatabase::new()?;
    let database_key = Zeroizing::new(random_nonzero()?);
    let storage = operation_result(
        faults,
        PhaseOneFaultPoint::DurableStore,
        SqlCipherStorage::create(
            database.path(),
            VaultKey::new(*database_key).at_stage("durable store key")?,
        ),
        "durable store",
    )?;
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
    let alice_group_id = SessionGroupId::new(random_nonzero()?).at_stage("Alice group ID")?;

    let alice = operation_result(
        faults,
        PhaseOneFaultPoint::AliceClient,
        create_durable_client_with_storage(
            alice_group_id,
            storage.clone(),
            storage.clone(),
            storage.clone(),
        ),
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
    let join_request_id = random_nonzero()?;
    let request_binding =
        JoinRequestBinding::new(join_request_id, NOW, REQUEST_EXPIRES_AT, random_nonzero()?)
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
    let protected_request_bytes = protected_request
        .encode_canonical()
        .at_stage("join request encoding")?;
    let request_fingerprint = digest(&SHA256, &protected_request_bytes)
        .as_ref()
        .try_into()
        .map_err(|_| stage("join request fingerprint"))?;
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
    operation_result(
        faults,
        PhaseOneFaultPoint::DurableReservation,
        storage.seed_reservation(
            *issued.invitation().invitation_id(),
            *issued.invitation().signature(),
            join_request_id,
            INVITATION_EXPIRES_AT,
            NOW,
        ),
        "durable reservation",
    )?;
    let approval_record = encode_approval_record(approval_context);
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
        alice.create_group(alice_group_id, NOW),
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
    let durability_pending = prepared_join
        .apply_awaiting_durability(NOW)
        .at_stage("MLS Add apply")?;
    if durability_pending.key_package_reference() != &expected_key_package_reference {
        return Err(stage("Welcome ownership"));
    }
    let welcome_envelope = OpaqueEnvelope::new(
        random_nonzero()?,
        REQUEST_EXPIRES_AT,
        durability_pending.welcome().as_bytes().to_vec(),
    )
    .at_stage("Welcome envelope")?;
    let canonical_welcome_envelope = welcome_envelope
        .encode_canonical()
        .at_stage("Welcome envelope encoding")?;
    let transaction_id = random_nonzero()?;
    let inviter_transaction = InviterJoinTransaction::new(
        transaction_id,
        *issued.invitation().invitation_id(),
        *issued.invitation().signature(),
        join_request_id,
        request_fingerprint,
        *alice_group.group_id(),
        0,
        1,
        approval_record,
        canonical_welcome_envelope.clone(),
        durability_pending
            .response_endpoint()
            .encode_canonical()
            .at_stage("Welcome endpoint encoding")?,
        REQUEST_EXPIRES_AT,
    )
    .at_stage("inviter transaction")?;
    let inject_rollback = faults.fail_at(PhaseOneFaultPoint::MembershipPersistence);
    let inject_ambiguous_response = faults.fail_at(PhaseOneFaultPoint::MembershipCommitResponse);
    storage
        .stage_inviter(
            inviter_transaction,
            NOW,
            if inject_rollback {
                PersistenceFault::BeforeCommit
            } else if inject_ambiguous_response {
                PersistenceFault::AfterCommit
            } else {
                PersistenceFault::None
            },
        )
        .at_stage("membership persistence staging")?;
    let write_result = alice_group.write_to_storage();
    let recovered = storage
        .recover_inviter(&transaction_id)
        .at_stage("membership recovery")?;
    if inject_rollback {
        durability_pending
            .release_proven_uncommitted()
            .at_stage("membership rollback cleanup")?;
        if write_result.is_ok()
            || recovered.is_some()
            || storage
                .invitation_state(issued.invitation().invitation_id())
                .at_stage("durable invitation cleanup")?
                != Some(InvitationState::Reserved)
            || invitation_registry.lifecycle(issued.invitation().invitation_id())
                != Some(InvitationLifecycle::Available)
            || alice_group.epoch() != 1
            || alice_group.member_count() != 2
        {
            return Err(stage("membership rollback cleanup"));
        }
        faults.observe(PhaseOneObservation::DurableRollbackReleased);
        return Err(stage("membership persistence"));
    }
    if write_result.is_ok() == inject_ambiguous_response
        || recovered.is_none_or(|recovery| {
            recovery.epoch_after != 1
                || recovery.outbox_state != WelcomeOutboxState::Pending
                || recovery.delivery_attempts != 0
        })
    {
        return Err(stage("membership recovery"));
    }
    let committed_join = durability_pending
        .finalize_committed()
        .at_stage("membership finalization")?;
    if committed_join.key_package_reference() != &expected_key_package_reference
        || storage
            .invitation_state(issued.invitation().invitation_id())
            .at_stage("durable invitation state")?
            != Some(InvitationState::Consumed)
    {
        return Err(stage("membership finalization"));
    }
    if inject_ambiguous_response {
        faults.observe(PhaseOneObservation::CommittedMembershipRetained);
        return Err(stage("membership commit response"));
    }
    if faults.fail_at(PhaseOneFaultPoint::WelcomeDeposit) {
        let invitation_id = *issued.invitation().invitation_id();
        let mailbox_empty = welcome_transport
            .receive(&welcome_receive, NOW)
            .at_stage("Welcome cleanup")?
            .is_none();
        let outbox_pending = storage
            .recover_inviter(&transaction_id)
            .at_stage("Welcome cleanup")?
            .is_some_and(|recovery| recovery.outbox_state == WelcomeOutboxState::Pending);
        if invitation_registry.lifecycle(&invitation_id) != Some(InvitationLifecycle::Consumed)
            || alice_group.epoch() != 1
            || alice_group.member_count() != 2
            || !mailbox_empty
            || !outbox_pending
        {
            return Err(stage("Welcome cleanup"));
        }
        faults.observe(PhaseOneObservation::CommittedMembershipRetained);
        return Err(stage("Welcome deposit"));
    }
    drop(committed_join);
    if alice_group.group_id() != alice_group_id.as_bytes() {
        return Err(stage("Alice group ID"));
    }
    drop(alice_group);
    drop(alice);
    drop(storage);
    let mut delivery_store = operation_result(
        faults,
        PhaseOneFaultPoint::DurableStoreReopen,
        SqlCipherStorage::open(
            database.path(),
            VaultKey::new(*database_key).at_stage("durable reopen key")?,
        ),
        "durable store reopen",
    )?;
    let reloaded_alice = load_durable_client_with_storage(
        alice_group_id,
        delivery_store.clone(),
        delivery_store.clone(),
        delivery_store.clone(),
    )
    .at_stage("Alice identity reload")?;
    let mut alice_group = reloaded_alice
        .load_group(alice_group_id)
        .at_stage("Alice group reload")?;
    let coordinator = WelcomeDeliveryCoordinator::new(
        CoordinatorPolicy::new(Duration::from_secs(1), 30, 64 * 1024)
            .at_stage("Welcome coordinator policy")?,
    );
    let (dispatch_control, _cancellation) = ThreadDispatchControl::new();
    let coordinator_outcome = BlockingFutureSupervisor::run(
        coordinator.run_once(
            &mut delivery_store,
            &mut LocalV1DepositEndpointResolver,
            &mut welcome_transport,
            &dispatch_control,
        ),
        &dispatch_control,
        Instant::now() + Duration::from_secs(2),
    )
    .at_stage("Welcome supervision")?
    .at_stage("Welcome coordinator")?;
    if coordinator_outcome != CoordinatorOutcome::Accepted {
        return Err(stage("Welcome coordinator"));
    }
    fail_after_operation(
        faults,
        PhaseOneFaultPoint::WelcomeCoordinator,
        "Welcome coordinator",
    )?;
    let received_welcome = operation_result(
        faults,
        PhaseOneFaultPoint::WelcomeReceive,
        welcome_transport.receive(&welcome_receive, NOW),
        "Welcome receive",
    )?
    .ok_or_else(|| stage("Welcome receive"))?;
    if received_welcome
        .envelope()
        .encode_canonical()
        .at_stage("Welcome receive encoding")?
        != canonical_welcome_envelope
        || delivery_store
            .recover_inviter(&transaction_id)
            .at_stage("Welcome delivery recovery")?
            .is_none_or(|recovery| recovery.outbox_state != WelcomeOutboxState::Delivered)
    {
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
        welcome_transport.acknowledge(
            &welcome_acknowledgement,
            *received_welcome.delivery_id(),
            NOW,
        ),
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

struct TempDatabase(PathBuf);

impl TempDatabase {
    fn new() -> Result<Self, SessionCtlError> {
        let identifier: [u8; 16] = random_nonzero()?;
        let mut name = String::from("session-chat-sessionctl-");
        for byte in identifier {
            write!(&mut name, "{byte:02x}").map_err(|_| stage("durable store path"))?;
        }
        name.push_str(".sqlite3");
        Ok(Self(std::env::temp_dir().join(name)))
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDatabase {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.0.with_extension("sqlite3-journal"));
    }
}

fn encode_approval_record(context: ApprovalContext) -> Vec<u8> {
    let mut record = Vec::with_capacity(73);
    record.push(match context.method() {
        AdmissionMethod::SecretCapability => 1,
    });
    record.extend_from_slice(context.invitation_id());
    record.extend_from_slice(context.join_request_id());
    record.extend_from_slice(context.key_package_reference());
    record.extend_from_slice(&context.expires_at_unix_seconds().to_be_bytes());
    record
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
