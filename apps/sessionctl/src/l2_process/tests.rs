//! L2 harness local unit tests.
use super::*;

fn test_evidence_binding() -> L2EvidenceBinding {
    L2EvidenceBinding {
        executables: Some(ExecutionIdentity::fixture()),
        sqlcipher_version: String::from("4.14.0"),
        sqlite_version: String::from("3.50.4"),
        baseline_artifact_digest: [0x11; 32],
        post_recovery_artifact_digest: [0x22; 32],
        redaction: true,
    }
}

fn test_evidence_case(key: &str, ordinal: u16) -> L2EvidenceCase {
    L2EvidenceCase {
        key: key.to_owned(),
        target: L2EvidenceCaseTarget::ApplicationCheckpoint {
            checkpoint: "INVITER_BEFORE_BEGIN",
            ordinal,
            expected: "I0",
            observed: "I0",
        },
        binding: test_evidence_binding(),
    }
}

#[test]
fn evidence_case_index_is_canonical_across_input_permutations() {
    let first = test_evidence_case("checkpoint-a-0", 0);
    let second = test_evidence_case("checkpoint-b-1", 1);
    let forward =
        canonical_evidence_cases(vec![first.clone(), second.clone()]).expect("forward case index");
    let reversed = canonical_evidence_cases(vec![second, first]).expect("reversed case index");
    assert!(forward == reversed);

    let duplicate = test_evidence_case("checkpoint-a-0", 2);
    assert!(canonical_evidence_cases(vec![forward[0].clone(), duplicate]).is_err());
}

#[test]
fn mixed_verifier_producer_or_fault_driver_reports_cannot_form_an_aggregate() {
    let first = test_evidence_case("checkpoint-a-0", 0);
    for role in 0..3 {
        let mut second = test_evidence_case("checkpoint-b-1", 1);
        let identity = second.binding.executables.as_mut().unwrap();
        match role {
            0 => identity.verifier = [1; 32],
            1 => identity.producer = [2; 32],
            _ => identity.fault_driver = Some([3; 32]),
        }
        assert!(canonical_evidence_cases(vec![first.clone(), second]).is_err());
    }
}

#[test]
fn canonical_checkpoint_traversal_accepts_the_maximum_depth_legal_trace() {
    let case_id = CaseId::new([0xA5; 16]).expect("case ID");
    let target = ControlFrame::new_checkpoint(case_id, Checkpoint::InviterBeforeShadowFinalize, 0)
        .expect("target");
    let mut traversal = CheckpointTraversal::new(target).expect("traversal");
    let mut frames = vec![
        ControlFrame::new_checkpoint(case_id, Checkpoint::InviterBeforeBegin, 0)
            .expect("before begin"),
        ControlFrame::new_checkpoint(case_id, Checkpoint::InviterAfterGroupUpsert, 0)
            .expect("group upsert"),
    ];
    for occurrence in 0..64 {
        frames.push(
            ControlFrame::new_checkpoint(case_id, Checkpoint::InviterAfterEpochInsert, occurrence)
                .expect("epoch insert"),
        );
    }
    for occurrence in 0..64 {
        frames.push(
            ControlFrame::new_checkpoint(case_id, Checkpoint::InviterAfterEpochUpdate, occurrence)
                .expect("epoch update"),
        );
    }
    for checkpoint in [
        Checkpoint::InviterAfterJoinInsert,
        Checkpoint::InviterAfterReservationConsumed,
        Checkpoint::InviterBeforeCommit,
        Checkpoint::InviterAfterCommitReturn,
        Checkpoint::InviterBeforeShadowFinalize,
    ] {
        frames
            .push(ControlFrame::new_checkpoint(case_id, checkpoint, 0).expect("later checkpoint"));
    }

    assert!(frames.len() > 64);
    assert!(frames.len() <= MAX_APPLICATION_CHECKPOINTS);
    for frame in &frames[..frames.len() - 1] {
        assert!(!traversal.observe(*frame).expect("ordered checkpoint"));
    }
    assert!(
        traversal
            .observe(*frames.last().expect("target frame"))
            .expect("target checkpoint")
    );
}

#[test]
fn pipe_failures_keep_distinct_secret_free_causes() {
    struct FailedRead;
    impl Read for FailedRead {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("must never appear in diagnostics"))
        }
    }
    let mut reader = PipeReader::new(FailedRead);
    assert!(matches!(
        reader.collect(CHILD_WAIT),
        Err(SessionCtlError::Stage("L2 output read"))
    ));

    let mut reader = PipeReader::new(std::io::Cursor::new(vec![0; MAX_CHILD_OUTPUT_BYTES + 1]));
    assert!(matches!(
        reader.collect(CHILD_WAIT),
        Err(SessionCtlError::Stage("L2 output bound"))
    ));

    let (sender, receiver) = mpsc::channel();
    let mut reader = PipeReader {
        receiver,
        join: None,
        buffered: Vec::new(),
        eof: false,
    };
    assert!(matches!(
        reader.collect(Duration::from_millis(1)),
        Err(SessionCtlError::Stage("L2 output timeout"))
    ));
    assert!(matches!(
        reader.read_exact_frame(1, Duration::from_millis(1)),
        Err(SessionCtlError::Stage("L2 frame timeout"))
    ));
    drop(sender);
    assert!(matches!(
        reader.collect(CHILD_WAIT),
        Err(SessionCtlError::Stage("L2 output disconnected"))
    ));
}

#[test]
fn pipe_interrupted_read_preserves_the_exact_frame() {
    struct InterruptedOnce(bool);
    impl Read for InterruptedOnce {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            if !std::mem::replace(&mut self.0, true) {
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            bytes[..3].copy_from_slice(b"abc");
            Ok(3)
        }
    }
    let mut reader = PipeReader::new(InterruptedOnce(false).take(3));
    assert_eq!(reader.read_exact_frame(3, CHILD_WAIT).unwrap(), b"abc");
    reader
        .require_empty(CHILD_WAIT)
        .expect("EOF after exact frame");
}

#[test]
fn inherited_child_output_cannot_block_pipe_reader_drop() {
    let mut command = Command::new(std::env::current_exe().expect("current test executable"));
    command
        .args([
            "--exact",
            "l2_process::tests::inherited_output_parent",
            "--nocapture",
        ])
        .env("SESSIONCTL_L2_INHERITED_OUTPUT_PARENT", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = Instant::now();
    let mut child = ManagedChild::spawn_command(command).expect("spawn output parent");
    assert!(
        child
            .wait(Duration::from_secs(1))
            .expect("parent exit")
            .success()
    );
    assert!(child.stdout.collect(Duration::from_millis(25)).is_err());
    drop(child);
    assert!(started.elapsed() < Duration::from_millis(500));
}

#[test]
fn inherited_output_parent() {
    if std::env::var_os("SESSIONCTL_L2_INHERITED_OUTPUT_PARENT").is_some() {
        let mut descendant =
            Command::new(std::env::current_exe().expect("current test executable"))
                .args([
                    "--exact",
                    "l2_process::tests::inherited_output_descendant",
                    "--nocapture",
                ])
                .env("SESSIONCTL_L2_INHERITED_OUTPUT_DESCENDANT", "1")
                .spawn()
                .expect("spawn output descendant");
        thread::spawn(move || {
            let _ = descendant.wait();
        });
    }
}

#[test]
fn inherited_output_descendant() {
    if std::env::var_os("SESSIONCTL_L2_INHERITED_OUTPUT_DESCENDANT").is_some() {
        thread::sleep(Duration::from_secs(2));
    }
}

#[test]
fn process_root_cleanup_failure_is_reported_and_drop_retries() {
    let mut root = ProcessRoot::new().expect("L2 root");
    let path = root.path().to_owned();

    assert!(
        root.cleanup_with(|_| Err(std::io::Error::other("injected cleanup failure")))
            .is_err()
    );
    assert!(path.exists());

    drop(root);
    assert!(!path.exists());
}

#[test]
fn production_schema_fingerprint_is_frozen() {
    let mut root = ProcessRoot::new().expect("L2 root");
    let key = Zeroizing::new([0x55; KEY_BYTES]);
    let storage = SqlCipherStorage::create(
        &root.path().join(DATABASE_NAME),
        VaultKey::new(*key).expect("key"),
    )
    .expect("storage");
    drop(storage);
    let connection =
        open_keyed_connection(&root.path().join(DATABASE_NAME), &key).expect("keyed connection");
    assert_eq!(
        schema_fingerprint(&connection).expect("schema fingerprint"),
        SCHEMA_FINGERPRINT_SHA256
    );
    drop(connection);
    root.cleanup().expect("cleanup");
}

#[test]
fn sanitized_git_metadata_reports_a_dirty_state_instead_of_becoming_unavailable() {
    assert!(
        git_dirty_at(&repository_root()).is_some(),
        "sanitized Git metadata must tolerate the platform temporary-directory environment",
    );
}

#[test]
fn clean_baseline_and_pause_aggregate_reject_old_state() {
    let target = L2IoSweepTarget::new(L2IoFileRole::RollbackJournal, L2IoOperation::Write, 1)
        .expect("baseline target");
    let observation =
        L2IoBaselineObservation::new(vec![target], 0, 1).expect("baseline observation");
    assert!(
        L2IoBaselineReport::new(
            Scenario::InviterTransaction,
            OracleState::InviterOld,
            observation,
            true,
            true,
            true,
            true,
            test_evidence_binding(),
        )
        .is_err()
    );

    let old_baseline = L2IoBaselineReport {
        scenario: Scenario::InviterTransaction,
        observed: OracleState::InviterOld,
        baseline: L2IoBaselineObservation::new(vec![target], 0, 1)
            .expect("old baseline observation"),
        fixture_cleanup: true,
        handle_cleanup: true,
        child_cleanup: true,
        directory_cleanup: true,
        _evidence_binding: test_evidence_binding(),
    };
    let old_pause_case = L2IoPauseKillReport {
        scenario: Scenario::InviterTransaction,
        observed: OracleState::InviterOld,
        pause: L2IoPauseObservation::new(
            L2IoFileRole::RollbackJournal,
            L2IoOperation::Write,
            0,
            0,
            1,
        )
        .expect("pause observation"),
        fixture_cleanup: true,
        handle_cleanup: true,
        child_cleanup: true,
        directory_cleanup: true,
        evidence_binding: test_evidence_binding(),
    };
    assert!(
        L2IoPauseSweepReport::new(
            Scenario::InviterTransaction,
            &old_baseline,
            &[old_pause_case],
        )
        .is_err()
    );
}
