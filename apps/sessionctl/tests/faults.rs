use sessionctl::{
    PhaseOneFaultPlan, PhaseOneFaultPoint, PhaseOneObservation, SessionCtlError,
    run_phase_one_demo_with_faults,
};

#[derive(Default)]
struct RecordingFaultPlan {
    fault: Option<PhaseOneFaultPoint>,
    observations: Vec<PhaseOneObservation>,
}

impl RecordingFaultPlan {
    fn at(fault: PhaseOneFaultPoint) -> Self {
        Self {
            fault: Some(fault),
            observations: Vec::new(),
        }
    }
}

impl PhaseOneFaultPlan for RecordingFaultPlan {
    fn fail_at(&mut self, point: PhaseOneFaultPoint) -> bool {
        self.fault == Some(point)
    }

    fn observe(&mut self, observation: PhaseOneObservation) {
        self.observations.push(observation);
    }
}

fn assert_coarse_failure(
    fault: PhaseOneFaultPoint,
    expected_stage: &'static str,
    expected_observation: PhaseOneObservation,
) {
    let mut plan = RecordingFaultPlan::at(fault);
    let error = run_phase_one_demo_with_faults(&mut plan).expect_err("injected fault must fail");

    assert_eq!(error, SessionCtlError::Stage(expected_stage));
    assert!(plan.observations.contains(&expected_observation));
    assert_eq!(
        plan.observations.last(),
        Some(&PhaseOneObservation::OrchestrationQuiescent)
    );

    let diagnostic = error.to_string();
    assert_eq!(
        diagnostic,
        format!("headless Phase 1 flow failed at {expected_stage}")
    );
    for forbidden in [
        "hello from Alice",
        "hello from Bob",
        "message after removal",
        "ciphertext",
        "credential",
        "key_package",
        "plaintext",
        "secret",
        "token",
    ] {
        assert!(!diagnostic.contains(forbidden));
    }
}

#[test]
fn approval_fault_releases_invitation_and_replay_reservations() {
    assert_coarse_failure(
        PhaseOneFaultPoint::ApprovalDecision,
        "approval decision",
        PhaseOneObservation::ApprovalReservationsReleased,
    );
}

#[test]
fn membership_apply_fault_abandons_pending_add_and_reservations() {
    assert_coarse_failure(
        PhaseOneFaultPoint::MembershipApply,
        "MLS Add apply",
        PhaseOneObservation::PreparedMembershipReleased,
    );
}

#[test]
fn membership_persistence_fault_releases_only_after_proven_sql_rollback() {
    assert_coarse_failure(
        PhaseOneFaultPoint::MembershipPersistence,
        "membership persistence",
        PhaseOneObservation::DurableRollbackReleased,
    );
}

#[test]
fn ambiguous_membership_commit_response_recovers_committed_state() {
    assert_coarse_failure(
        PhaseOneFaultPoint::MembershipCommitResponse,
        "membership commit response",
        PhaseOneObservation::CommittedMembershipRetained,
    );
}

#[test]
fn welcome_fault_does_not_roll_back_committed_membership() {
    assert_coarse_failure(
        PhaseOneFaultPoint::WelcomeDeposit,
        "Welcome deposit",
        PhaseOneObservation::CommittedMembershipRetained,
    );
}

#[test]
fn dropped_application_delivery_fails_closed_and_quiesces() {
    assert_coarse_failure(
        PhaseOneFaultPoint::FirstApplicationDelivery,
        "message receive",
        PhaseOneObservation::DroppedDeliveryObserved,
    );
}

#[test]
fn operation_boundary_faults_map_to_coarse_secret_free_stages() {
    for (fault, expected_stage) in [
        (PhaseOneFaultPoint::DurableStore, "durable store"),
        (
            PhaseOneFaultPoint::InvitationGeneration,
            "invitation generation",
        ),
        (PhaseOneFaultPoint::InvitationIssue, "invitation issue"),
        (
            PhaseOneFaultPoint::InvitationEncoding,
            "invitation encoding",
        ),
        (
            PhaseOneFaultPoint::InvitationValidation,
            "invitation validation",
        ),
        (PhaseOneFaultPoint::WelcomeTransport, "Welcome transport"),
        (PhaseOneFaultPoint::WelcomeMailbox, "Welcome mailbox"),
        (PhaseOneFaultPoint::AliceClient, "Alice client"),
        (PhaseOneFaultPoint::BobClient, "Bob client"),
        (PhaseOneFaultPoint::BobKeyPackage, "Bob KeyPackage"),
        (
            PhaseOneFaultPoint::KeyPackageValidation,
            "KeyPackage validation",
        ),
        (
            PhaseOneFaultPoint::JoinRequestProtection,
            "join request protection",
        ),
        (
            PhaseOneFaultPoint::JoinRequestOpening,
            "join request opening",
        ),
        (
            PhaseOneFaultPoint::AdmissionVerification,
            "admission verification",
        ),
        (
            PhaseOneFaultPoint::ApprovalReservation,
            "approval reservation",
        ),
        (
            PhaseOneFaultPoint::DurableReservation,
            "durable reservation",
        ),
        (PhaseOneFaultPoint::AliceGroup, "Alice group"),
        (
            PhaseOneFaultPoint::MembershipPreparation,
            "MLS Add preparation",
        ),
        (PhaseOneFaultPoint::WelcomeReceive, "Welcome receive"),
        (PhaseOneFaultPoint::WelcomeFraming, "Welcome framing"),
        (
            PhaseOneFaultPoint::DurableStoreReopen,
            "durable store reopen",
        ),
        (
            PhaseOneFaultPoint::WelcomeCoordinator,
            "Welcome coordinator",
        ),
        (PhaseOneFaultPoint::BobJoin, "Bob join"),
        (
            PhaseOneFaultPoint::WelcomeAcknowledgement,
            "Welcome acknowledgement",
        ),
        (PhaseOneFaultPoint::MessageTransport, "message transport"),
        (
            PhaseOneFaultPoint::AliceMessageMailbox,
            "Alice message mailbox",
        ),
        (PhaseOneFaultPoint::BobMessageMailbox, "Bob message mailbox"),
        (
            PhaseOneFaultPoint::AliceMessageProtection,
            "Alice message protection",
        ),
        (
            PhaseOneFaultPoint::BobMessageProcessing,
            "Bob message processing",
        ),
        (
            PhaseOneFaultPoint::BobMessageProtection,
            "Bob message protection",
        ),
        (
            PhaseOneFaultPoint::SecondApplicationDelivery,
            "message delivery",
        ),
        (
            PhaseOneFaultPoint::AliceMessageProcessing,
            "Alice message processing",
        ),
        (
            PhaseOneFaultPoint::PathUpdatePreparation,
            "path update preparation",
        ),
        (PhaseOneFaultPoint::PathUpdateApply, "path update apply"),
        (
            PhaseOneFaultPoint::PathUpdateDelivery,
            "path update delivery",
        ),
        (
            PhaseOneFaultPoint::PathUpdateProcessing,
            "path update processing",
        ),
        (
            PhaseOneFaultPoint::RemovalPreparation,
            "removal preparation",
        ),
        (PhaseOneFaultPoint::RemovalApply, "removal apply"),
        (PhaseOneFaultPoint::RemovalDelivery, "removal delivery"),
        (PhaseOneFaultPoint::RemovalProcessing, "removal processing"),
        (
            PhaseOneFaultPoint::PostRemovalProtection,
            "post-removal protection",
        ),
        (
            PhaseOneFaultPoint::PostRemovalDelivery,
            "post-removal delivery",
        ),
    ] {
        let mut plan = RecordingFaultPlan::at(fault);
        let error = run_phase_one_demo_with_faults(&mut plan)
            .expect_err("operation-boundary fault must fail closed");

        assert_eq!(error, SessionCtlError::Stage(expected_stage), "{fault:?}");
        assert_eq!(
            plan.observations,
            [PhaseOneObservation::OrchestrationQuiescent],
            "{fault:?}"
        );
        assert!(!error.to_string().contains("hello from"), "{fault:?}");
    }
}
