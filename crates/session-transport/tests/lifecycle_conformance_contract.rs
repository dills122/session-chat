use std::collections::BTreeSet;

use session_transport::{LifecycleConformanceCaseV1, LifecycleConformanceContractError};

#[test]
fn p1_5_lifecycle_fixture_vocabulary_is_closed_unique_and_round_trips() {
    let cases = LifecycleConformanceCaseV1::required();
    let tokens = cases
        .iter()
        .map(|case| case.as_str())
        .collect::<BTreeSet<_>>();

    assert_eq!(tokens.len(), cases.len());
    for case in cases {
        assert_eq!(
            LifecycleConformanceCaseV1::try_from(case.as_str()),
            Ok(*case)
        );
    }
    assert_eq!(
        LifecycleConformanceCaseV1::try_from("cursor-silently-fallback-to-none"),
        Err(LifecycleConformanceContractError::UnsupportedCase)
    );
}

#[test]
fn required_cases_cover_positive_restart_rotation_and_every_cursor_binding_axis() {
    use LifecycleConformanceCaseV1 as Case;

    for required in [
        Case::IssueFreshGeneration,
        Case::PersistBeforeAcknowledge,
        Case::CursorAdvance,
        Case::CursorlessCheckpointAdvance,
        Case::LoadCommittedCheckpoint,
        Case::CursorOverlapDeduplicated,
        Case::RestartResume,
        Case::RecoverCommittedAcknowledgement,
        Case::RecoverAcknowledgementAfterLeaseCrash,
        Case::AcceptAcknowledgement,
        Case::ReleaseAmbiguousAcknowledgement,
        Case::ExplicitResynchronization,
        Case::RecordExplicitResynchronization,
        Case::RoutineRotation,
        Case::CompromiseRotation,
        Case::ExactRotationRetry,
        Case::RejectWrongProfileCursor,
        Case::RejectWrongBindingCursor,
        Case::RejectWrongContinuityCursor,
        Case::RejectStaleGenerationCursor,
        Case::RejectWrongReceiveScopeCursor,
        Case::RejectWrongCursorSchema,
        Case::RejectWrongProviderStateEpoch,
        Case::RejectExpiredCursor,
        Case::RejectStaleCheckpoint,
        Case::RejectOutcomeCardinalityMismatch,
        Case::RejectChangedAcknowledgementIntent,
        Case::RejectMismatchedReceivePageBinding,
        Case::RejectWrongCursorPosition,
        Case::RejectDuplicateDeliveryId,
        Case::RejectForgedCommitEvidence,
        Case::RejectExpiredReceiveOwnerOperation,
        Case::RejectExpiredIssuance,
        Case::RejectForeignReceiveBinding,
        Case::RejectStaleRotation,
        Case::RejectCompetingRotation,
    ] {
        assert!(Case::required().contains(&required));
    }
}
