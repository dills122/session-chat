use std::collections::BTreeMap;

use session_transport::LifecycleConformanceCaseV1 as Case;

const EVIDENCE: &[(Case, &str)] = &[
    (
        Case::IssueFreshGeneration,
        "lifecycle_provider::issues_and_rotates",
    ),
    (
        Case::PersistBeforeAcknowledge,
        "cursor_provider::owner_commit_before_ack",
    ),
    (Case::CursorAdvance, "cursor_provider::restart_resume"),
    (
        Case::CursorlessCheckpointAdvance,
        "receive_owner::cursorless_successor",
    ),
    (Case::LoadCommittedCheckpoint, "receive_owner::restart_load"),
    (
        Case::CursorOverlapDeduplicated,
        "receive_owner::overlap_duplicate",
    ),
    (Case::RestartResume, "cursor_provider::restart_resume"),
    (
        Case::RecoverCommittedAcknowledgement,
        "receive_owner::recover_ack",
    ),
    (
        Case::RecoverAcknowledgementAfterLeaseCrash,
        "receive_owner::restart_recover_ack",
    ),
    (Case::AcceptAcknowledgement, "receive_owner::accept_ack"),
    (
        Case::ReleaseAmbiguousAcknowledgement,
        "receive_owner::release_recover_ack",
    ),
    (
        Case::ExplicitResynchronization,
        "receive_owner::explicit_resynchronization",
    ),
    (
        Case::RecordExplicitResynchronization,
        "receive_owner::record_resynchronization",
    ),
    (
        Case::RoutineRotation,
        "lifecycle_provider::routine_rotation",
    ),
    (
        Case::CompromiseRotation,
        "lifecycle_provider::compromise_rotation",
    ),
    (
        Case::ExactRotationRetry,
        "lifecycle_provider::exact_rotation_retry",
    ),
    (
        Case::RejectCrossRightAuthority,
        "session_transport::compile_fail_right_matrix",
    ),
    (
        Case::RejectWrongProfileCursor,
        "session_transport::cursor_binding_matrix",
    ),
    (
        Case::RejectWrongBindingCursor,
        "session_transport::cursor_binding_matrix",
    ),
    (
        Case::RejectWrongContinuityCursor,
        "session_transport::cursor_binding_matrix",
    ),
    (
        Case::RejectStaleGenerationCursor,
        "session_transport::cursor_binding_matrix",
    ),
    (
        Case::RejectWrongReceiveScopeCursor,
        "session_transport::cursor_binding_matrix",
    ),
    (
        Case::RejectWrongCursorSchema,
        "session_transport::cursor_binding_matrix",
    ),
    (
        Case::RejectWrongProviderStateEpoch,
        "session_transport::cursor_binding_matrix",
    ),
    (
        Case::RejectExpiredCursor,
        "receive_owner::expired_operation",
    ),
    (
        Case::RejectStaleCheckpoint,
        "receive_owner::stale_checkpoint",
    ),
    (
        Case::RejectOutcomeCardinalityMismatch,
        "session_transport::outcome_cardinality",
    ),
    (
        Case::RejectChangedAcknowledgementIntent,
        "session_transport::changed_ack_intent",
    ),
    (
        Case::RejectMismatchedReceivePageBinding,
        "session_transport::page_binding",
    ),
    (
        Case::RejectWrongCursorPosition,
        "session_transport::cursor_position",
    ),
    (
        Case::RejectDuplicateDeliveryId,
        "session_transport::duplicate_delivery_id",
    ),
    (
        Case::RejectForgedCommitEvidence,
        "session_transport::opaque_commit_evidence",
    ),
    (
        Case::RejectExpiredReceiveOwnerOperation,
        "receive_owner::expired_operation",
    ),
    (
        Case::RejectExpiredIssuance,
        "lifecycle_provider::expired_issuance",
    ),
    (
        Case::RejectForeignReceiveBinding,
        "receive_owner::foreign_binding",
    ),
    (
        Case::RejectStaleRotation,
        "lifecycle_provider::stale_rotation",
    ),
    (
        Case::RejectCompetingRotation,
        "lifecycle_provider::competing_rotation",
    ),
    (
        Case::RejectGenerationExhaustion,
        "session_transport::generation_exhaustion",
    ),
];

#[test]
fn every_required_lifecycle_case_has_one_retained_evidence_row() {
    let evidence = EVIDENCE.iter().copied().collect::<BTreeMap<_, _>>();

    assert_eq!(
        evidence.len(),
        EVIDENCE.len(),
        "duplicate lifecycle evidence row"
    );
    assert_eq!(evidence.len(), Case::required().len());
    for case in Case::required() {
        let evidence_id = evidence.get(case).expect("required lifecycle evidence row");
        assert!(!evidence_id.is_empty());
        assert!(
            evidence_id.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b':')
            }),
            "evidence IDs remain bounded diagnostic tokens"
        );
    }
}
