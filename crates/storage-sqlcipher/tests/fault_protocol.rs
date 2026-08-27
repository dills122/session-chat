#![cfg(session_chat_storage_fault_testing)]

use std::sync::{Arc, Mutex};

use storage_sqlcipher::fault_testing::{
    BarrierFailure, BarrierTransport, CONTROL_FRAME_BYTES, CaseId, Checkpoint, ControlFrame,
    FaultObserver, FrameKind, OracleState, Role, Scenario,
};

#[derive(Default)]
struct AcknowledgingTransport {
    observed: Mutex<Vec<ControlFrame>>,
}

impl BarrierTransport for AcknowledgingTransport {
    fn exchange(
        &self,
        encoded: [u8; CONTROL_FRAME_BYTES],
    ) -> Result<[u8; CONTROL_FRAME_BYTES], BarrierFailure> {
        let frame = ControlFrame::decode(&encoded).map_err(|_| BarrierFailure::Rejected)?;
        self.observed
            .lock()
            .map_err(|_| BarrierFailure::Rejected)?
            .push(frame);
        Ok(frame.acknowledgement().encode())
    }
}

struct EchoingTransport;

impl BarrierTransport for EchoingTransport {
    fn exchange(
        &self,
        encoded: [u8; CONTROL_FRAME_BYTES],
    ) -> Result<[u8; CONTROL_FRAME_BYTES], BarrierFailure> {
        Ok(encoded)
    }
}

fn case_id() -> CaseId {
    CaseId::new([0xA5; 16]).expect("nonzero case identifier")
}

#[test]
fn canonical_frame_round_trips_without_a_variable_payload() {
    let frame = ControlFrame::new_checkpoint(case_id(), Checkpoint::InviterAfterEpochInsert, 3)
        .expect("bounded checkpoint");
    let encoded = frame.encode();

    assert_eq!(encoded.len(), CONTROL_FRAME_BYTES);
    assert_eq!(&encoded[..8], b"SCL2CTL1");
    assert_eq!(encoded[8], 1);
    assert_eq!(encoded[9], 1);
    assert_eq!(encoded[10], 1);
    assert_eq!(encoded[11], 1);
    assert_eq!(encoded[12], 3);
    assert_eq!(encoded[13], 3);
    assert_eq!(&encoded[14..], &[0xA5; 16]);
    assert_eq!(ControlFrame::decode(&encoded), Ok(frame));
    assert_eq!(frame.kind(), FrameKind::Checkpoint);
    assert_eq!(frame.scenario(), Scenario::InviterTransaction);
    assert_eq!(frame.role(), Role::Writer);
    assert_eq!(frame.checkpoint(), Checkpoint::InviterAfterEpochInsert);
    assert_eq!(frame.occurrence(), 3);

    let acknowledgement = frame.acknowledgement();
    assert_eq!(acknowledgement.kind(), FrameKind::Acknowledgement);
    assert_eq!(acknowledgement.role(), Role::Controller);
    assert_eq!(acknowledgement.checkpoint(), frame.checkpoint());
    assert_eq!(acknowledgement.case_id(), frame.case_id());
}

#[test]
fn malformed_unknown_and_oversized_frames_fail_closed() {
    let valid = ControlFrame::new_checkpoint(case_id(), Checkpoint::InviterBeforeBegin, 0)
        .expect("checkpoint")
        .encode();

    let mut unknown_version = valid;
    unknown_version[8] = 2;
    assert!(ControlFrame::decode(&unknown_version).is_err());

    let mut unknown_kind = valid;
    unknown_kind[9] = 9;
    assert!(ControlFrame::decode(&unknown_kind).is_err());

    let mut mismatched_scenario = valid;
    mismatched_scenario[10] = 2;
    assert!(ControlFrame::decode(&mismatched_scenario).is_err());

    let mut wrong_role = valid;
    wrong_role[11] = 2;
    assert!(ControlFrame::decode(&wrong_role).is_err());

    let mut unknown_checkpoint = valid;
    unknown_checkpoint[12] = 0xFF;
    assert!(ControlFrame::decode(&unknown_checkpoint).is_err());

    let mut invalid_occurrence = valid;
    invalid_occurrence[13] = 1;
    assert!(ControlFrame::decode(&invalid_occurrence).is_err());

    let mut oversized = valid.to_vec();
    oversized.push(0);
    assert!(ControlFrame::decode(&oversized).is_err());

    let mut zero_case = valid;
    zero_case[14..].fill(0);
    assert!(ControlFrame::decode(&zero_case).is_err());

    assert!(
        ControlFrame::new_checkpoint(case_id(), Checkpoint::JoinerAfterEpochUpdate, 64,).is_err()
    );
}

#[test]
fn observer_accepts_the_closed_inviter_order_and_exact_acknowledgements() {
    let transport = Arc::new(AcknowledgingTransport::default());
    let observer = FaultObserver::new(case_id(), Scenario::InviterTransaction, transport.clone());

    let checkpoints = [
        (Checkpoint::InviterBeforeBegin, 0),
        (Checkpoint::InviterAfterGroupUpsert, 0),
        (Checkpoint::InviterAfterEpochInsert, 0),
        (Checkpoint::InviterAfterEpochInsert, 1),
        (Checkpoint::InviterAfterEpochUpdate, 0),
        (Checkpoint::InviterAfterJoinInsert, 0),
        (Checkpoint::InviterAfterReservationConsumed, 0),
        (Checkpoint::InviterBeforeCommit, 0),
        (Checkpoint::InviterAfterCommitReturn, 0),
        (Checkpoint::InviterBeforeShadowFinalize, 0),
    ];
    for (checkpoint, occurrence) in checkpoints {
        observer
            .checkpoint(checkpoint, occurrence)
            .expect("ordered checkpoint acknowledged");
    }

    let observed = transport.observed.lock().expect("observed frames");
    assert_eq!(observed.len(), checkpoints.len());
    assert!(observed.iter().all(|frame| {
        frame.kind() == FrameKind::Checkpoint
            && frame.role() == Role::Writer
            && frame.case_id() == case_id()
    }));
}

#[test]
fn duplicate_out_of_order_and_wrong_acknowledgement_are_rejected() {
    let transport = Arc::new(AcknowledgingTransport::default());
    let observer = FaultObserver::new(case_id(), Scenario::JoinerTransaction, transport.clone());
    assert!(
        observer
            .checkpoint(Checkpoint::JoinerAfterGroupUpsert, 0)
            .is_err()
    );
    assert!(transport.observed.lock().expect("observed").is_empty());

    observer
        .checkpoint(Checkpoint::JoinerBeforeBegin, 0)
        .expect("first checkpoint");
    assert!(
        observer
            .checkpoint(Checkpoint::JoinerBeforeBegin, 0)
            .is_err()
    );
    assert_eq!(transport.observed.lock().expect("observed").len(), 1);

    let wrong_ack_observer = FaultObserver::new(
        CaseId::new([0x5A; 16]).expect("case id"),
        Scenario::InviterTransaction,
        Arc::new(EchoingTransport),
    );
    assert!(
        wrong_ack_observer
            .checkpoint(Checkpoint::InviterBeforeBegin, 0)
            .is_err()
    );
}

#[test]
fn oracle_codes_are_closed_and_scenario_specific() {
    assert_eq!(OracleState::try_from(1), Ok(OracleState::InviterOld));
    assert_eq!(OracleState::try_from(2), Ok(OracleState::InviterNew));
    assert_eq!(OracleState::try_from(3), Ok(OracleState::JoinerOld));
    assert_eq!(OracleState::try_from(4), Ok(OracleState::JoinerNew));
    assert!(OracleState::try_from(0).is_err());
    assert_eq!(
        OracleState::InviterOld.scenario(),
        Scenario::InviterTransaction
    );
    assert_eq!(
        OracleState::JoinerNew.scenario(),
        Scenario::JoinerTransaction
    );
}
