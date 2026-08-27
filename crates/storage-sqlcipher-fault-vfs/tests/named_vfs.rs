#![forbid(unsafe_code)]

use std::{
    sync::{Arc, Mutex, MutexGuard, OnceLock},
    thread,
    time::Duration,
};

use rusqlite::{Connection, OpenFlags};
use storage_sqlcipher_fault_vfs::{
    FaultCode, FaultMode, FaultPlan, FaultTarget, FileRole, Operation, OperationDisposition,
    PauseGate, VFS_NAME, ValidationError, controller, default_vfs_identity, register,
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
fn registration_is_non_default_and_only_named_connections_are_intercepted() {
    let _exclusive = exclusive_controller();
    let before = default_vfs_identity().expect("SQLite default VFS");
    register().expect("register named delegator");
    let after = default_vfs_identity().expect("SQLite default VFS after registration");
    assert_eq!(
        before, after,
        "registration must not replace SQLite's default VFS"
    );

    controller().reset().expect("idle controller reset");
    let ordinary_dir = tempfile::tempdir().expect("ordinary tempdir");
    let ordinary = Connection::open(ordinary_dir.path().join("ordinary.db"))
        .expect("ordinary default-VFS connection");
    ordinary
        .execute_batch("CREATE TABLE ordinary(value INTEGER); INSERT INTO ordinary VALUES(1);")
        .expect("ordinary write");
    drop(ordinary);
    assert_eq!(controller().snapshot().total_operations(), 0);

    let named_dir = tempfile::tempdir().expect("named tempdir");
    let named = named_connection(&named_dir.path().join("named.db"));
    named
        .execute_batch(
            "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; \
             CREATE TABLE named(value INTEGER); BEGIN IMMEDIATE; \
             INSERT INTO named VALUES(1); COMMIT;",
        )
        .expect("named write");
    drop(named);

    let snapshot = controller().snapshot();
    snapshot
        .validate_delete_journal_baseline()
        .expect("named trace is valid DELETE-journal evidence");
    assert!(snapshot.count(FileRole::MainDatabase, Operation::Open) >= 1);
    assert!(snapshot.count(FileRole::RollbackJournal, Operation::Write) >= 1);

    let missing = Connection::open_with_flags_and_vfs(
        named_dir.path().join("unreachable.db"),
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        "session-chat-storage-fault-v1-defective",
    );
    assert!(
        missing.is_err(),
        "an unregistered defective name must not fall back"
    );
}

#[test]
fn named_vfs_returns_actual_extended_ioerr_and_full_codes() {
    let _exclusive = exclusive_controller();
    register().expect("register named delegator");
    let dir = tempfile::tempdir().expect("fault tempdir");
    let connection = named_connection(&dir.path().join("fault.db"));
    connection
        .execute_batch("PRAGMA journal_mode=DELETE; CREATE TABLE values_(value INTEGER);")
        .expect("baseline schema");

    controller().reset().expect("reset after baseline");
    controller()
        .arm(
            FaultPlan::return_code(
                FaultTarget::new(FileRole::RollbackJournal, Operation::Write, 0)
                    .expect("valid target"),
                FaultMode::OneShot,
                FaultCode::Full,
            )
            .expect("valid FULL plan"),
        )
        .expect("arm FULL");
    let full = connection.execute("INSERT INTO values_ VALUES(1)", []);
    let full_code = full
        .expect_err("journal FULL must fail SQLite")
        .sqlite_error_code();
    assert_eq!(full_code, Some(rusqlite::ErrorCode::DiskFull));
    connection
        .execute("INSERT INTO values_ VALUES(1)", [])
        .expect("one-shot FULL must delegate the next matching operation");
    let full_snapshot = controller().snapshot();
    full_snapshot.validate().expect("one-shot FULL trace");
    assert_eq!(full_snapshot.injected_failures(), 1);
    controller().disable().expect("disable FULL");

    controller().reset().expect("reset after FULL");
    controller()
        .arm(
            FaultPlan::return_code(
                FaultTarget::new(FileRole::MainDatabase, Operation::Write, 0)
                    .expect("valid target"),
                FaultMode::Persistent,
                FaultCode::IoErrWrite,
            )
            .expect("valid IOERR plan"),
        )
        .expect("arm IOERR");
    let ioerr = connection.execute("INSERT INTO values_ VALUES(2)", []);
    let extended = match ioerr.expect_err("main IOERR must fail SQLite") {
        rusqlite::Error::SqliteFailure(error, _) => error.extended_code,
        _ => panic!("unexpected rusqlite error category"),
    };
    assert_eq!(extended, libsqlite3_sys::SQLITE_IOERR_WRITE);
    let repeated = connection.execute("INSERT INTO values_ VALUES(3)", []);
    let repeated_code = match repeated.expect_err("persistent IOERR must repeat") {
        rusqlite::Error::SqliteFailure(error, _) => error.extended_code,
        _ => panic!("unexpected repeated rusqlite error category"),
    };
    assert_eq!(repeated_code, libsqlite3_sys::SQLITE_IOERR_WRITE);

    let snapshot = controller().snapshot();
    snapshot.validate().expect("actual result-code trace");
    assert!(snapshot.injected_failures() >= 2);
    controller().disable().expect("disable IOERR");
    connection
        .execute("INSERT INTO values_ VALUES(4)", [])
        .expect("disabled persistent plan must delegate later writes");
    controller()
        .snapshot()
        .validate()
        .expect("post-disable delegation preserves valid evidence metadata");
    drop(connection);
}

#[test]
fn commit_window_pause_blocks_until_the_controller_releases_it() {
    let _exclusive = exclusive_controller();
    register().expect("register named delegator");
    let dir = tempfile::tempdir().expect("pause tempdir");
    let connection = named_connection(&dir.path().join("pause.db"));
    connection
        .execute_batch("PRAGMA journal_mode=DELETE; CREATE TABLE values_(value INTEGER);")
        .expect("baseline schema");
    controller().reset().expect("reset after baseline");

    let gate = Arc::new(PauseGate::new());
    controller()
        .arm(
            FaultPlan::pause(
                FaultTarget::new(FileRole::RollbackJournal, Operation::Write, 0)
                    .expect("commit-window target"),
                Arc::clone(&gate),
            )
            .expect("valid pause plan"),
        )
        .expect("arm pause");

    let writer = thread::spawn(move || {
        connection
            .execute("INSERT INTO values_ VALUES(1)", [])
            .expect("write continues after release");
    });
    assert!(gate.wait_until_reached(Duration::from_secs(5)));
    assert!(
        !writer.is_finished(),
        "writer must remain paused at the operation"
    );
    gate.release();
    writer.join().expect("writer thread");

    let snapshot = controller().snapshot();
    snapshot.validate().expect("pause trace");
    assert_eq!(snapshot.pauses(), 1);
    assert!(
        snapshot
            .operations()
            .any(|record| record.disposition() == OperationDisposition::Paused)
    );
    controller().disable().expect("disable pause");
}

#[test]
fn an_actual_wal_role_is_observed_and_rejected_by_the_delete_baseline() {
    let _exclusive = exclusive_controller();
    register().expect("register named delegator");
    controller().reset().expect("reset WAL observation");
    let dir = tempfile::tempdir().expect("WAL tempdir");
    let connection = named_connection(&dir.path().join("wal.db"));
    let mode: String = connection
        .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
        .expect("select WAL only for defective-baseline evidence");
    assert_eq!(mode, "wal");
    connection
        .execute_batch("CREATE TABLE values_(value INTEGER); INSERT INTO values_ VALUES(1);")
        .expect("exercise WAL sidecars");
    drop(connection);

    let snapshot = controller().snapshot();
    snapshot
        .validate()
        .expect("WAL role trace is internally valid");
    assert!(
        snapshot.count(FileRole::Wal, Operation::Open) > 0
            || snapshot.count(FileRole::SharedMemory, Operation::SharedMemory) > 0
    );
    assert_eq!(
        snapshot.validate_delete_journal_baseline(),
        Err(ValidationError::Rejected)
    );
}
