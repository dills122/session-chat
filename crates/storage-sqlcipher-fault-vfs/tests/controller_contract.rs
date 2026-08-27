#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard, OnceLock},
    time::Duration,
};

use rusqlite::{Connection, OpenFlags};
use storage_sqlcipher_fault_vfs::{
    ControllerError, FaultAction, FaultCode, FaultMode, FaultPlan, FaultTarget, FileRole,
    MAX_OPERATIONS, Operation, OperationDisposition, PauseGate, VFS_NAME, ValidationError,
    controller, register,
};

fn exclusive_controller() -> MutexGuard<'static, ()> {
    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    TEST_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("test controller lock")
}

fn named_connection(path: &std::path::Path) -> Connection {
    Connection::open_with_flags_and_vfs(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        VFS_NAME,
    )
    .expect("closed named VFS must be reachable")
}

#[test]
fn public_plan_contract_is_closed_bounded_and_coarse() {
    assert_eq!(
        ControllerError::Rejected.to_string(),
        "fault VFS controller rejected"
    );
    assert_eq!(
        ValidationError::Rejected.to_string(),
        "fault VFS evidence rejected"
    );

    let target = FaultTarget::new(FileRole::MainDatabase, Operation::Write, 7)
        .expect("bounded main-database target");
    assert_eq!(target.role(), FileRole::MainDatabase);
    assert_eq!(target.operation(), Operation::Write);
    assert_eq!(target.ordinal(), 7);

    for rejected_role in [
        FileRole::Wal,
        FileRole::SharedMemory,
        FileRole::Temporary,
        FileRole::Unknown,
    ] {
        assert_eq!(
            FaultTarget::new(rejected_role, Operation::Write, 0),
            Err(ControllerError::Rejected)
        );
    }
    assert_eq!(
        FaultTarget::new(FileRole::MainDatabase, Operation::Write, MAX_OPERATIONS),
        Err(ControllerError::Rejected)
    );

    let codes = [
        (FaultCode::Full, libsqlite3_sys::SQLITE_FULL),
        (FaultCode::IoErrRead, libsqlite3_sys::SQLITE_IOERR_READ),
        (FaultCode::IoErrWrite, libsqlite3_sys::SQLITE_IOERR_WRITE),
        (FaultCode::IoErrFsync, libsqlite3_sys::SQLITE_IOERR_FSYNC),
        (
            FaultCode::IoErrTruncate,
            libsqlite3_sys::SQLITE_IOERR_TRUNCATE,
        ),
        (FaultCode::IoErrDelete, libsqlite3_sys::SQLITE_IOERR_DELETE),
        (FaultCode::IoErrLock, libsqlite3_sys::SQLITE_IOERR_LOCK),
        (FaultCode::IoErrUnlock, libsqlite3_sys::SQLITE_IOERR_UNLOCK),
        (
            FaultCode::IoErrCheckReservedLock,
            libsqlite3_sys::SQLITE_IOERR_CHECKRESERVEDLOCK,
        ),
    ];
    for (code, expected) in codes {
        assert_eq!(code.sqlite_code(), expected);
    }

    let plan = FaultPlan::return_code(target, FaultMode::Persistent, FaultCode::IoErrWrite)
        .expect("matching result-code plan");
    assert_eq!(plan.target(), target);
    assert_eq!(plan.mode(), FaultMode::Persistent);
    assert_eq!(plan.action(), FaultAction::Return(FaultCode::IoErrWrite));
    assert!(
        FaultPlan::return_code(target, FaultMode::OneShot, FaultCode::IoErrRead).is_err(),
        "a read code cannot target a write"
    );

    let gate = Arc::new(PauseGate::default());
    assert!(!gate.wait_until_reached(Duration::ZERO));
    gate.release();
    gate.release();
    let pause_target = FaultTarget::new(FileRole::RollbackJournal, Operation::Sync, 0)
        .expect("supported pause target");
    let pause = FaultPlan::pause(pause_target, gate).expect("commit-window pause");
    assert_eq!(pause.target(), pause_target);
    assert_eq!(pause.mode(), FaultMode::OneShot);
    assert_eq!(pause.action(), FaultAction::Pause);
    let unsupported_pause =
        FaultTarget::new(FileRole::MainDatabase, Operation::Read, 0).expect("bounded read target");
    assert!(FaultPlan::pause(unsupported_pause, Arc::new(PauseGate::new())).is_err());
}

#[test]
fn snapshot_records_secret_free_ordinals_and_returned_codes() {
    let _exclusive = exclusive_controller();
    register().expect("register named delegator");
    controller().reset().expect("reset controller");
    let dir = tempfile::tempdir().expect("contract tempdir");
    let connection = named_connection(&dir.path().join("contract.db"));
    connection
        .execute_batch("PRAGMA journal_mode=DELETE; CREATE TABLE values_(value INTEGER);")
        .expect("baseline schema");

    controller().reset().expect("reset after baseline");
    let target =
        FaultTarget::new(FileRole::RollbackJournal, Operation::Write, 0).expect("journal target");
    let plan =
        FaultPlan::return_code(target, FaultMode::OneShot, FaultCode::Full).expect("FULL plan");
    controller().arm(plan.clone()).expect("arm FULL");
    assert_eq!(controller().arm(plan), Err(ControllerError::Rejected));
    connection
        .execute("INSERT INTO values_ VALUES(1)", [])
        .expect_err("journal FULL must fail");

    let snapshot = controller().snapshot();
    snapshot.validate().expect("valid returned-code trace");
    assert!(!snapshot.overflowed());
    assert!(snapshot.total_operations() > 0);
    assert_eq!(snapshot.injected_failures(), 1);
    assert_eq!(snapshot.pauses(), 0);

    let mut next_matching = HashMap::new();
    let records: Vec<_> = snapshot.operations().collect();
    for (expected_global, record) in records.iter().copied().enumerate() {
        assert_eq!(usize::from(record.global_ordinal()), expected_global);
        let expected_matching = next_matching
            .entry((record.role(), record.operation()))
            .or_insert(0_u16);
        assert_eq!(record.matching_ordinal(), *expected_matching);
        *expected_matching += 1;
    }
    assert!(records.iter().any(|record| {
        record.disposition() == OperationDisposition::Returned(libsqlite3_sys::SQLITE_FULL)
    }));

    controller().disable().expect("disable FULL");
    controller().reset().expect("final reset");
    drop(connection);
}

#[test]
fn validation_rejects_a_plan_that_never_reaches_its_target() {
    let _exclusive = exclusive_controller();
    register().expect("register named delegator");
    controller().reset().expect("reset controller");
    assert_eq!(
        controller().snapshot().validate_named_reachability(),
        Err(ValidationError::Rejected),
        "an idle controller proves no named connection reached the VFS"
    );
    let target = FaultTarget::new(FileRole::MainDatabase, Operation::Write, MAX_OPERATIONS - 1)
        .expect("bounded but unreachable target");
    controller()
        .arm(
            FaultPlan::return_code(target, FaultMode::OneShot, FaultCode::IoErrWrite)
                .expect("valid target/code pairing"),
        )
        .expect("arm unreachable plan");

    let dir = tempfile::tempdir().expect("unreached tempdir");
    let connection = named_connection(&dir.path().join("unreached.db"));
    let snapshot = controller().snapshot();
    assert_eq!(snapshot.validate(), Err(ValidationError::Rejected));
    assert_eq!(
        snapshot.validate_named_reachability(),
        Err(ValidationError::Rejected)
    );

    controller().disable().expect("disable unreachable plan");
    controller().reset().expect("final reset");
    drop(connection);
}

#[test]
fn real_named_operations_fail_closed_at_the_retained_trace_bound() {
    let _exclusive = exclusive_controller();
    register().expect("register named delegator");
    controller().reset().expect("reset controller");
    let dir = tempfile::tempdir().expect("overflow tempdir");
    let path = dir.path().join("overflow.db");

    let mut rejected = false;
    for _ in 0..=MAX_OPERATIONS {
        match Connection::open_with_flags_and_vfs(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            VFS_NAME,
        ) {
            Ok(connection) => drop(connection),
            Err(_) => {
                rejected = true;
                break;
            }
        }
    }

    assert!(
        rejected,
        "the bounded trace must eventually reject more work"
    );
    let snapshot = controller().snapshot();
    assert!(snapshot.overflowed());
    assert_eq!(snapshot.total_operations(), MAX_OPERATIONS);
    assert_eq!(snapshot.validate(), Err(ValidationError::Rejected));
    controller().reset().expect("final reset");
}
