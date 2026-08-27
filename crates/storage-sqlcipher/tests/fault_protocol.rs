#![cfg(session_chat_storage_fault_testing)]

use std::sync::{Arc, Mutex};

use mls_rs_core::{
    crypto::HpkeSecretKey,
    group::{EpochRecord, GroupState, GroupStateStorage},
    key_package::{KeyPackageData, KeyPackageStorage},
};
use session_protocol::{DepositCapability, LocalWelcomeDepositEndpoint, OpaqueEnvelope};
use storage_sqlcipher::fault_testing::{
    BarrierFailure, BarrierTransport, CONTROL_FRAME_BYTES, CaseId, Checkpoint, ControlFrame,
    FAULT_BUILD, FAULT_VFS_NAME, FaultObserver, FrameKind, OracleState, Role, Scenario,
};
use storage_sqlcipher::{
    InviterJoinTransaction, JoinerTransaction, PersistenceFault, VaultKey, fault_testing,
};
use zeroize::Zeroizing;

const NOW: u64 = 1_900_000_000;

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

struct WrongAckAt {
    checkpoint: Checkpoint,
}

impl BarrierTransport for WrongAckAt {
    fn exchange(
        &self,
        encoded: [u8; CONTROL_FRAME_BYTES],
    ) -> Result<[u8; CONTROL_FRAME_BYTES], BarrierFailure> {
        let frame = ControlFrame::decode(&encoded).map_err(|_| BarrierFailure::Rejected)?;
        if frame.checkpoint() == self.checkpoint {
            Ok(encoded)
        } else {
            Ok(frame.acknowledgement().encode())
        }
    }
}

fn case_id() -> CaseId {
    CaseId::new([0xA5; 16]).expect("nonzero case identifier")
}

struct TestDatabase(std::path::PathBuf);

impl TestDatabase {
    fn new(name: &str) -> Self {
        Self(std::env::temp_dir().join(format!(
            "session-chat-storage-fault-protocol-{name}-{}.sqlite3",
            std::process::id()
        )))
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.0.with_extension("sqlite3-journal"));
    }
}

fn inviter_transaction() -> InviterJoinTransaction {
    let welcome = OpaqueEnvelope::new([8; 16], NOW + 50, vec![8])
        .expect("Welcome")
        .encode_canonical()
        .expect("canonical Welcome");
    let endpoint = LocalWelcomeDepositEndpoint::new(
        [9; 16],
        [10; 16],
        DepositCapability::new([11; 32]).expect("capability"),
        NOW + 55,
    )
    .expect("endpoint")
    .encode_canonical()
    .expect("canonical endpoint");
    InviterJoinTransaction::new(
        [1; 16],
        [2; 16],
        [3; 64],
        [4; 16],
        [5; 32],
        [6; 32],
        0,
        1,
        vec![7],
        welcome,
        endpoint,
        NOW + 40,
    )
    .expect("inviter transaction")
}

fn observed_checkpoints(transport: &AcknowledgingTransport) -> Vec<(Checkpoint, u8)> {
    transport
        .observed
        .lock()
        .expect("observed frames")
        .iter()
        .map(|frame| (frame.checkpoint(), frame.occurrence()))
        .collect()
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

#[test]
fn inviter_storage_statements_emit_only_the_frozen_order() {
    let database = TestDatabase::new("inviter");
    let transport = Arc::new(AcknowledgingTransport::default());
    let observer = FaultObserver::new(
        CaseId::new([0x21; 16]).expect("case id"),
        Scenario::InviterTransaction,
        transport.clone(),
    );
    let mut storage = fault_testing::create(
        &database.0,
        VaultKey::new([0x31; 32]).expect("key"),
        observer.clone(),
    )
    .expect("fault-observed store");
    storage
        .seed_reservation([2; 16], [3; 64], [4; 16], NOW + 60, NOW)
        .expect("reservation");
    storage
        .stage_inviter(inviter_transaction(), NOW, PersistenceFault::None)
        .expect("staged inviter");

    GroupStateStorage::write(
        &mut storage,
        GroupState {
            id: vec![6; 32],
            data: Zeroizing::new(vec![0x41]),
        },
        vec![EpochRecord::new(0, Zeroizing::new(vec![0x42]))],
        vec![EpochRecord::new(0, Zeroizing::new(vec![0x43]))],
    )
    .expect("inviter transaction committed");
    observer
        .checkpoint(Checkpoint::InviterBeforeShadowFinalize, 0)
        .expect("composition checkpoint");

    assert_eq!(
        observed_checkpoints(&transport),
        vec![
            (Checkpoint::InviterBeforeBegin, 0),
            (Checkpoint::InviterAfterGroupUpsert, 0),
            (Checkpoint::InviterAfterEpochInsert, 0),
            (Checkpoint::InviterAfterEpochUpdate, 0),
            (Checkpoint::InviterAfterJoinInsert, 0),
            (Checkpoint::InviterAfterReservationConsumed, 0),
            (Checkpoint::InviterBeforeCommit, 0),
            (Checkpoint::InviterAfterCommitReturn, 0),
            (Checkpoint::InviterBeforeShadowFinalize, 0),
        ]
    );
}

#[test]
fn joiner_storage_statements_emit_only_the_frozen_order() {
    let database = TestDatabase::new("joiner");
    let transport = Arc::new(AcknowledgingTransport::default());
    let observer = FaultObserver::new(
        CaseId::new([0x22; 16]).expect("case id"),
        Scenario::JoinerTransaction,
        transport.clone(),
    );
    let mut storage = fault_testing::create(
        &database.0,
        VaultKey::new([0x32; 32]).expect("key"),
        observer,
    )
    .expect("fault-observed store");
    let key_package_reference = [0x51; 32];
    KeyPackageStorage::insert(
        &mut storage,
        key_package_reference.to_vec(),
        KeyPackageData::new(
            vec![0x52],
            HpkeSecretKey::from(vec![0x53]),
            HpkeSecretKey::from(vec![0x54]),
            NOW + 60,
        ),
    )
    .expect("KeyPackage inserted");
    storage
        .stage_joiner(
            JoinerTransaction::new([0x55; 16], [0x56; 32], key_package_reference)
                .expect("joiner transaction"),
            PersistenceFault::None,
        )
        .expect("staged joiner");

    GroupStateStorage::write(
        &mut storage,
        GroupState {
            id: vec![0x56; 32],
            data: Zeroizing::new(vec![0x57]),
        },
        vec![EpochRecord::new(0, Zeroizing::new(vec![0x58]))],
        vec![EpochRecord::new(0, Zeroizing::new(vec![0x59]))],
    )
    .expect("joiner group staged");
    KeyPackageStorage::delete(&mut storage, &key_package_reference)
        .expect("joiner transaction committed");

    assert_eq!(
        observed_checkpoints(&transport),
        vec![
            (Checkpoint::JoinerBeforeBegin, 0),
            (Checkpoint::JoinerAfterGroupUpsert, 0),
            (Checkpoint::JoinerAfterEpochInsert, 0),
            (Checkpoint::JoinerAfterEpochUpdate, 0),
            (Checkpoint::JoinerAfterCommitInsert, 0),
            (Checkpoint::JoinerBeforeKeyPackageDelete, 0),
            (Checkpoint::JoinerAfterKeyPackageDelete, 0),
            (Checkpoint::JoinerBeforeCommit, 0),
            (Checkpoint::JoinerAfterCommitReturn, 0),
        ]
    );
}

#[test]
fn named_vfs_entry_point_is_fixed_and_opt_in() {
    assert!(std::hint::black_box(FAULT_BUILD));
    assert_eq!(FAULT_VFS_NAME, "session-chat-storage-fault-v1");

    let database = TestDatabase::new("missing-vfs");
    let observer = FaultObserver::new(
        CaseId::new([0x23; 16]).expect("case id"),
        Scenario::InviterTransaction,
        Arc::new(AcknowledgingTransport::default()),
    );
    assert!(
        fault_testing::create_with_fault_vfs(
            &database.0,
            VaultKey::new([0x33; 32]).expect("key"),
            observer,
        )
        .is_err()
    );
}

#[test]
fn rejected_joiner_barrier_rolls_back_the_open_transaction() {
    let database = TestDatabase::new("joiner-rejected-barrier");
    let observer = FaultObserver::new(
        CaseId::new([0x24; 16]).expect("case id"),
        Scenario::JoinerTransaction,
        Arc::new(WrongAckAt {
            checkpoint: Checkpoint::JoinerAfterKeyPackageDelete,
        }),
    );
    let mut storage = fault_testing::create(
        &database.0,
        VaultKey::new([0x34; 32]).expect("key"),
        observer,
    )
    .expect("fault-observed store");
    let key_package_reference = [0x61; 32];
    KeyPackageStorage::insert(
        &mut storage,
        key_package_reference.to_vec(),
        KeyPackageData::new(
            vec![0x62],
            HpkeSecretKey::from(vec![0x63]),
            HpkeSecretKey::from(vec![0x64]),
            NOW + 60,
        ),
    )
    .expect("KeyPackage inserted");
    storage
        .stage_joiner(
            JoinerTransaction::new([0x65; 16], [0x66; 32], key_package_reference)
                .expect("joiner transaction"),
            PersistenceFault::None,
        )
        .expect("staged joiner");
    GroupStateStorage::write(
        &mut storage,
        GroupState {
            id: vec![0x66; 32],
            data: Zeroizing::new(vec![0x67]),
        },
        vec![],
        vec![],
    )
    .expect("joiner group staged");

    assert!(KeyPackageStorage::delete(&mut storage, &key_package_reference).is_err());
    assert!(
        storage
            .key_package_exists(&key_package_reference)
            .expect("KeyPackage lookup")
    );
    assert!(
        GroupStateStorage::state(&storage, &[0x66; 32])
            .expect("group lookup")
            .is_none()
    );
    assert!(
        storage
            .recover_joiner(&[0x65; 16])
            .expect("recovery lookup")
            .is_none()
    );
}
