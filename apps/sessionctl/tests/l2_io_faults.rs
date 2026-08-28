#![forbid(unsafe_code)]

#[cfg(not(session_chat_storage_fault_testing))]
#[test]
fn ordinary_build_does_not_expose_the_l2_io_driver() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_sessionctl-l2"))
        .output()
        .expect("run ordinary L2 binary");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"sessionctl-l2: unavailable\n");
}

#[cfg(session_chat_storage_fault_testing)]
mod checked {
    use std::{
        io::Read,
        path::{Path, PathBuf},
        process::{Command, Stdio},
        sync::Arc,
        thread,
        time::{Duration, Instant},
    };

    use sessionctl::l2_process::{
        L2EvidenceChannels, L2IoBaselineObservation, L2IoDriverObservation, L2IoFaultDriver,
        L2IoFaultMode, L2IoFaultObservation, L2IoFileRole, L2IoOperation, L2IoPauseDriver,
        L2IoPauseObservation, L2IoPauseSweepReport, L2IoSweepReport, L2IoSweepTarget,
        prepare_l2_io_pause_kill_case, run_l2_io_baseline, run_l2_io_fault_case,
        run_l2_io_pause_writer,
    };
    use storage_sqlcipher::fault_testing::Scenario;
    use storage_sqlcipher_fault_vfs::{
        FaultCode, FaultMode, FaultPlan, FaultTarget, FileRole, Operation, PauseGate, controller,
        register,
    };

    const PAUSE_CHILD_ROOT: &str = "SESSION_CHAT_L2_PAUSE_CHILD_ROOT";
    const PAUSE_CHILD_ROLE: &str = "SESSION_CHAT_L2_PAUSE_CHILD_ROLE";
    const PAUSE_CHILD_OPERATION: &str = "SESSION_CHAT_L2_PAUSE_CHILD_OPERATION";
    const PAUSE_CHILD_ORDINAL: &str = "SESSION_CHAT_L2_PAUSE_CHILD_ORDINAL";
    const PAUSE_MARKER: &str = "pause.reached";
    const PAUSE_CHILD_DIAGNOSTIC: &str = "SESSION_CHAT_L2_PAUSE_CHILD_DIAGNOSTIC";
    const MAX_PAUSE_CHILD_OUTPUT_BYTES: usize = 512;

    struct FullAtFirstJournalWrite {
        target: FaultTarget,
    }

    impl FullAtFirstJournalWrite {
        fn new() -> Self {
            Self {
                target: FaultTarget::new(FileRole::RollbackJournal, Operation::Write, 0)
                    .expect("closed fault target"),
            }
        }
    }

    impl L2IoFaultDriver for FullAtFirstJournalWrite {
        fn prepare_before_open(&mut self) -> bool {
            register().is_ok() && controller().reset().is_ok()
        }

        fn arm_after_open(&mut self) -> bool {
            controller().reset().is_ok()
                && FaultPlan::return_code(self.target, FaultMode::OneShot, FaultCode::Full)
                    .and_then(|plan| controller().arm(plan))
                    .is_ok()
        }

        fn disable_and_observe(
            &mut self,
            transaction_succeeded: bool,
        ) -> Option<L2IoDriverObservation> {
            if controller().disable().is_err() || transaction_succeeded {
                return None;
            }
            let snapshot = controller().snapshot();
            snapshot.validate().ok()?;
            if snapshot.operations().any(|record| {
                !matches!(
                    record.role(),
                    FileRole::MainDatabase | FileRole::RollbackJournal
                )
            }) {
                return None;
            }
            let last = snapshot.operations().last()?;
            L2IoFaultObservation::new(
                L2IoFileRole::RollbackJournal,
                L2IoOperation::Write,
                L2IoFaultMode::OneShot,
                FaultCode::Full.sqlite_code(),
                self.target.ordinal(),
                last.global_ordinal(),
                snapshot.total_operations(),
                snapshot.injected_failures(),
                transaction_succeeded,
            )
            .ok()
            .map(L2IoDriverObservation::Fault)
        }
    }

    struct BaselineTrace;

    impl L2IoFaultDriver for BaselineTrace {
        fn prepare_before_open(&mut self) -> bool {
            register().is_ok() && controller().reset().is_ok()
        }

        fn arm_after_open(&mut self) -> bool {
            controller().reset().is_ok()
        }

        fn disable_and_observe(
            &mut self,
            transaction_succeeded: bool,
        ) -> Option<L2IoDriverObservation> {
            if controller().disable().is_err() || !transaction_succeeded {
                return None;
            }
            let snapshot = controller().snapshot();
            snapshot.validate().ok()?;
            if snapshot.operations().any(|record| {
                !matches!(
                    record.role(),
                    FileRole::MainDatabase | FileRole::RollbackJournal
                )
            }) {
                return None;
            }
            let last = snapshot.operations().last()?;
            let mut targets = Vec::new();
            for (file_role, retained_role) in [
                (FileRole::MainDatabase, L2IoFileRole::MainDatabase),
                (FileRole::RollbackJournal, L2IoFileRole::RollbackJournal),
            ] {
                for (operation, retained_operation) in [
                    (Operation::Read, L2IoOperation::Read),
                    (Operation::Write, L2IoOperation::Write),
                    (Operation::Truncate, L2IoOperation::Truncate),
                    (Operation::Sync, L2IoOperation::Sync),
                    (Operation::Delete, L2IoOperation::Delete),
                    (Operation::Lock, L2IoOperation::Lock),
                    (Operation::Unlock, L2IoOperation::Unlock),
                    (
                        Operation::CheckReservedLock,
                        L2IoOperation::CheckReservedLock,
                    ),
                ] {
                    let count = snapshot.count(file_role, operation);
                    if count > 0 {
                        targets.push(
                            L2IoSweepTarget::new(retained_role, retained_operation, count).ok()?,
                        );
                    }
                }
            }
            L2IoBaselineObservation::new(
                targets,
                last.global_ordinal(),
                snapshot.total_operations(),
            )
            .ok()
            .map(L2IoDriverObservation::Baseline)
        }
    }

    struct ReturnCodeAtTarget {
        retained_target: L2IoSweepTarget,
        target: FaultTarget,
        retained_mode: L2IoFaultMode,
        mode: FaultMode,
        code: FaultCode,
    }

    impl ReturnCodeAtTarget {
        fn new(
            retained_target: L2IoSweepTarget,
            ordinal: u16,
            retained_mode: L2IoFaultMode,
            code: FaultCode,
        ) -> Self {
            let role = match retained_target.file_role() {
                L2IoFileRole::MainDatabase => FileRole::MainDatabase,
                L2IoFileRole::RollbackJournal => FileRole::RollbackJournal,
            };
            let operation = match retained_target.operation() {
                L2IoOperation::Read => Operation::Read,
                L2IoOperation::Write => Operation::Write,
                L2IoOperation::Truncate => Operation::Truncate,
                L2IoOperation::Sync => Operation::Sync,
                L2IoOperation::Delete => Operation::Delete,
                L2IoOperation::Lock => Operation::Lock,
                L2IoOperation::Unlock => Operation::Unlock,
                L2IoOperation::CheckReservedLock => Operation::CheckReservedLock,
            };
            let mode = match retained_mode {
                L2IoFaultMode::OneShot => FaultMode::OneShot,
                L2IoFaultMode::Persistent => FaultMode::Persistent,
            };
            Self {
                retained_target,
                target: FaultTarget::new(role, operation, usize::from(ordinal))
                    .expect("observed fault target"),
                retained_mode,
                mode,
                code,
            }
        }
    }

    impl L2IoFaultDriver for ReturnCodeAtTarget {
        fn prepare_before_open(&mut self) -> bool {
            register().is_ok() && controller().reset().is_ok()
        }

        fn arm_after_open(&mut self) -> bool {
            controller().reset().is_ok()
                && FaultPlan::return_code(self.target, self.mode, self.code)
                    .and_then(|plan| controller().arm(plan))
                    .is_ok()
        }

        fn disable_and_observe(
            &mut self,
            transaction_succeeded: bool,
        ) -> Option<L2IoDriverObservation> {
            if controller().disable().is_err() {
                return None;
            }
            let snapshot = controller().snapshot();
            snapshot.validate().ok()?;
            if snapshot.operations().any(|record| {
                !matches!(
                    record.role(),
                    FileRole::MainDatabase | FileRole::RollbackJournal
                )
            }) {
                return None;
            }
            let last = snapshot.operations().last()?;
            L2IoFaultObservation::new(
                self.retained_target.file_role(),
                self.retained_target.operation(),
                self.retained_mode,
                self.code.sqlite_code(),
                self.target.ordinal(),
                last.global_ordinal(),
                snapshot.total_operations(),
                snapshot.injected_failures(),
                transaction_succeeded,
            )
            .ok()
            .map(L2IoDriverObservation::Fault)
        }
    }

    fn supported_codes(operation: L2IoOperation) -> &'static [FaultCode] {
        match operation {
            L2IoOperation::Read => &[FaultCode::IoErrRead],
            L2IoOperation::Write => &[FaultCode::Full, FaultCode::IoErrWrite],
            L2IoOperation::Truncate => &[FaultCode::IoErrTruncate],
            L2IoOperation::Sync => &[FaultCode::IoErrFsync],
            L2IoOperation::Delete => &[FaultCode::IoErrDelete],
            L2IoOperation::Lock => &[FaultCode::IoErrLock],
            L2IoOperation::Unlock => &[FaultCode::IoErrUnlock],
            L2IoOperation::CheckReservedLock => &[FaultCode::IoErrCheckReservedLock],
        }
    }

    struct PauseAtTarget {
        root: PathBuf,
        target: FaultTarget,
        gate: Arc<PauseGate>,
    }

    impl L2IoPauseDriver for PauseAtTarget {
        fn prepare_before_open(&mut self) -> bool {
            register().is_ok() && controller().reset().is_ok()
        }

        fn arm_after_open(&mut self) -> bool {
            if controller().reset().is_err() {
                return false;
            }
            let gate = Arc::clone(&self.gate);
            let root = self.root.clone();
            let target = self.target;
            thread::spawn(move || {
                if !gate.wait_until_reached(Duration::from_secs(30)) {
                    return;
                }
                let snapshot = controller().snapshot();
                let Some(last) = snapshot.operations().last() else {
                    return;
                };
                if snapshot.validate().is_err()
                    || snapshot.pauses() != 1
                    || last.role() != target.role()
                    || last.operation() != target.operation()
                    || last.matching_ordinal() != target.ordinal()
                {
                    return;
                }
                let marker = format!(
                    "last={}\ntotal={}\n",
                    last.global_ordinal(),
                    snapshot.total_operations()
                );
                let _ = std::fs::write(root.join(PAUSE_MARKER), marker);
            });
            FaultPlan::pause(self.target, Arc::clone(&self.gate))
                .and_then(|plan| controller().arm(plan))
                .is_ok()
        }
    }

    fn parse_file_role(value: &str) -> Option<FileRole> {
        match value {
            "main" => Some(FileRole::MainDatabase),
            "journal" => Some(FileRole::RollbackJournal),
            _ => None,
        }
    }

    fn parse_operation(value: &str) -> Option<Operation> {
        match value {
            "write" => Some(Operation::Write),
            "sync" => Some(Operation::Sync),
            "delete" => Some(Operation::Delete),
            _ => None,
        }
    }

    fn wait_for_pause_marker(root: &Path) -> Option<(u16, usize)> {
        let marker = root.join(PAUSE_MARKER);
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Ok(contents) = std::fs::read_to_string(&marker) {
                let mut lines = contents.lines();
                let last = lines
                    .next()
                    .and_then(|line| line.strip_prefix("last="))
                    .and_then(|value| value.parse().ok());
                let total = lines
                    .next()
                    .and_then(|line| line.strip_prefix("total="))
                    .and_then(|value| value.parse().ok());
                if let (Some(last), Some(total)) = (last, total) {
                    return Some((last, total));
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
        None
    }

    fn pause_role_name(role: L2IoFileRole) -> &'static str {
        match role {
            L2IoFileRole::MainDatabase => "main",
            L2IoFileRole::RollbackJournal => "journal",
        }
    }

    fn pause_operation_name(operation: L2IoOperation) -> Option<&'static str> {
        match operation {
            L2IoOperation::Write => Some("write"),
            L2IoOperation::Sync => Some("sync"),
            L2IoOperation::Delete => Some("delete"),
            _ => None,
        }
    }

    struct ReapedPauseChild {
        status: std::process::ExitStatus,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    }

    fn terminate_and_reap(child: &mut std::process::Child) -> ReapedPauseChild {
        child.kill().expect("terminate paused child");
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Some(status) = child.try_wait().expect("poll paused child") {
                let mut stdout = Vec::new();
                child
                    .stdout
                    .take()
                    .expect("captured pause stdout")
                    .take((MAX_PAUSE_CHILD_OUTPUT_BYTES + 1) as u64)
                    .read_to_end(&mut stdout)
                    .expect("read pause stdout");
                let mut stderr = Vec::new();
                child
                    .stderr
                    .take()
                    .expect("captured pause stderr")
                    .take((MAX_PAUSE_CHILD_OUTPUT_BYTES + 1) as u64)
                    .read_to_end(&mut stderr)
                    .expect("read pause stderr");
                assert!(stdout.len() <= MAX_PAUSE_CHILD_OUTPUT_BYTES);
                assert!(stderr.len() <= MAX_PAUSE_CHILD_OUTPUT_BYTES);
                return ReapedPauseChild {
                    status,
                    stdout,
                    stderr,
                };
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("paused child was not reaped before the bounded deadline");
    }

    fn run_pause_kill_case(
        scenario: Scenario,
        target: L2IoSweepTarget,
        ordinal: u16,
    ) -> sessionctl::l2_process::L2IoPauseKillReport {
        let prepared = prepare_l2_io_pause_kill_case(
            scenario,
            target.file_role(),
            target.operation(),
            ordinal,
        )
        .expect("fresh pause/kill case");
        let operation = pause_operation_name(target.operation()).expect("commit-window operation");
        let mut child = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "checked::l2_io_pause_child",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(PAUSE_CHILD_ROOT, prepared.root())
            .env(PAUSE_CHILD_ROLE, pause_role_name(target.file_role()))
            .env(PAUSE_CHILD_OPERATION, operation)
            .env(PAUSE_CHILD_ORDINAL, ordinal.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn direct pause child");
        let Some((last_observed_ordinal, total_operations)) =
            wait_for_pause_marker(prepared.root())
        else {
            let _ = terminate_and_reap(&mut child);
            panic!("pause marker was not produced before the bounded deadline");
        };
        let reaped = terminate_and_reap(&mut child);
        assert!(!reaped.status.success());

        let observation = L2IoPauseObservation::new(
            target.file_role(),
            target.operation(),
            ordinal,
            last_observed_ordinal,
            total_operations,
        )
        .expect("bounded pause observation");
        prepared
            .finish(&executable(), observation, &reaped.stdout, &reaped.stderr)
            .expect("fresh verification after pause/kill")
    }

    fn executable() -> PathBuf {
        PathBuf::from(env!("CARGO_BIN_EXE_sessionctl-l2"))
    }

    #[test]
    fn one_shot_full_reopens_as_one_complete_inviter_state() {
        let mut driver = FullAtFirstJournalWrite::new();
        let report = run_l2_io_fault_case(&executable(), Scenario::InviterTransaction, &mut driver)
            .expect("one real SQLITE_FULL case");
        let evidence = report.encode_v1();

        for required in [
            "protocol=l2-io-observation-v1\n",
            "scenario=E2E-TXN-001\n",
            "publication=prohibited\n",
            "status=validated\n",
            "coverage=partial\n",
            "storage_scenario=inviter-transaction\n",
            "file_role=rollback-journal\n",
            "operation=write\n",
            "mode=one-shot\n",
            "target_ordinal=0\n",
            "sqlite_primary_code=13\n",
            "sqlite_extended_code=13\n",
            "child_cleanup=pass\n",
            "directory_cleanup=pass\n",
        ] {
            assert!(evidence.contains(required), "missing {required:?}");
        }
        for unsupported in [
            "\nresult=",
            "\nintegrity=",
            "\nschema=",
            "\nsemantic_oracle=",
            "\nexact_retry=",
            "\nredaction=",
        ] {
            assert!(
                !evidence.contains(unsupported),
                "unsupported public-evidence assertion {unsupported:?}",
            );
        }
        for forbidden in [".sqlite", "/tmp/", "\\temp\\", "database_key", "vault"] {
            assert!(
                !evidence.to_ascii_lowercase().contains(forbidden),
                "leaked {forbidden:?}",
            );
        }
    }

    #[test]
    fn clean_baselines_discover_only_observed_supported_ordinals() {
        for scenario in [Scenario::InviterTransaction, Scenario::JoinerTransaction] {
            let report = run_l2_io_baseline(&executable(), scenario, &mut BaselineTrace)
                .expect("clean named-VFS baseline");
            let targets: Vec<_> = report.targets().collect();

            assert!(!targets.is_empty());
            assert!(targets.iter().all(|target| target.observed_count() > 0));
            assert!(report.encode_v1().contains("coverage=partial\n"));
            assert!(report.encode_v1().contains("baseline=validated\n"));
            assert!(report.encode_v1().contains("publication=prohibited\n"));
        }
    }

    #[test]
    fn every_observed_supported_ordinal_reopens_as_one_complete_state() {
        for scenario in [Scenario::InviterTransaction, Scenario::JoinerTransaction] {
            let baseline = run_l2_io_baseline(&executable(), scenario, &mut BaselineTrace)
                .expect("clean named-VFS baseline");
            let mut cases = Vec::new();
            for target in baseline.targets() {
                for ordinal in 0..target.observed_count() {
                    for mode in [L2IoFaultMode::OneShot, L2IoFaultMode::Persistent] {
                        for &code in supported_codes(target.operation()) {
                            let report = run_l2_io_fault_case(
                                &executable(),
                                scenario,
                                &mut ReturnCodeAtTarget::new(target, ordinal, mode, code),
                            )
                            .unwrap_or_else(|error| {
                                panic!(
                                    "{scenario:?} {target:?} ordinal={ordinal} mode={mode:?} code={code:?}: {error}"
                                )
                            });
                            let evidence = report.encode_v1();
                            assert!(evidence.contains("status=validated\n"));
                            assert!(evidence.contains("coverage=partial\n"));
                            assert!(evidence.contains("directory_cleanup=pass\n"));
                            cases.push(report);
                        }
                    }
                }
            }
            let complete = L2IoSweepReport::new(scenario, &baseline, &cases)
                .expect("complete baseline-derived sweep");
            let complete_evidence = complete.encode_v1();
            assert!(complete_evidence.contains("coverage=complete\n"));
            assert!(complete_evidence.contains("status=validated\n"));
            assert!(complete_evidence.contains("publication=prohibited\n"));
            assert!(complete_evidence.contains("modes=one-shot|persistent\n"));

            if let Ok(runner_image) = std::env::var("SESSION_CHAT_L2_RUNNER_IMAGE") {
                let channels = L2EvidenceChannels::new(
                    complete_evidence.as_bytes(),
                    b"",
                    b"",
                    complete_evidence.as_bytes(),
                    b"",
                )
                .expect("bounded return-code evidence surfaces");
                let bundle = complete
                    .promote_v1(&executable(), &runner_image, &channels)
                    .expect("promote complete return-code evidence");
                for manifest in bundle.manifests() {
                    println!(
                        "L2_PUBLIC_EVIDENCE_BEGIN\n{}L2_PUBLIC_EVIDENCE_END",
                        manifest.encode_v1(),
                    );
                }
            }

            cases.pop().expect("at least one completed case");
            assert!(L2IoSweepReport::new(scenario, &baseline, &cases).is_err());
        }
    }

    #[test]
    fn l2_io_pause_child() {
        let Some(root) = std::env::var_os(PAUSE_CHILD_ROOT).map(PathBuf::from) else {
            return;
        };
        let role = std::env::var(PAUSE_CHILD_ROLE)
            .ok()
            .and_then(|value| parse_file_role(&value))
            .expect("closed pause role");
        let operation = std::env::var(PAUSE_CHILD_OPERATION)
            .ok()
            .and_then(|value| parse_operation(&value))
            .expect("closed pause operation");
        let ordinal = std::env::var(PAUSE_CHILD_ORDINAL)
            .ok()
            .and_then(|value| value.parse().ok())
            .expect("bounded pause ordinal");
        let target = FaultTarget::new(role, operation, ordinal).expect("closed pause target");
        let mut driver = PauseAtTarget {
            root: root.clone(),
            target,
            gate: Arc::new(PauseGate::new()),
        };
        if let Ok(diagnostic) = std::env::var(PAUSE_CHILD_DIAGNOSTIC) {
            eprintln!("{diagnostic}");
        }
        run_l2_io_pause_writer(&root, &mut driver).expect("pause writer must remain blocked");
    }

    #[test]
    fn pause_evidence_rejects_unsupported_and_mismatched_targets() {
        assert!(
            L2IoPauseObservation::new(L2IoFileRole::MainDatabase, L2IoOperation::Delete, 0, 0, 1,)
                .is_err()
        );
        let prepared = prepare_l2_io_pause_kill_case(
            Scenario::InviterTransaction,
            L2IoFileRole::RollbackJournal,
            L2IoOperation::Write,
            0,
        )
        .expect("fresh bound pause case");
        let mismatched =
            L2IoPauseObservation::new(L2IoFileRole::MainDatabase, L2IoOperation::Sync, 0, 0, 1)
                .expect("separately valid pause target");
        assert!(
            prepared
                .finish(&executable(), mismatched, b"", b"")
                .is_err()
        );
    }

    #[test]
    fn pause_child_canary_is_captured_and_rejected_before_public_evidence() {
        let scenario = Scenario::InviterTransaction;
        let role = L2IoFileRole::RollbackJournal;
        let operation = L2IoOperation::Write;
        let prepared = prepare_l2_io_pause_kill_case(scenario, role, operation, 0)
            .expect("fresh canary pause case");
        let mut child = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "checked::l2_io_pause_child",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(PAUSE_CHILD_ROOT, prepared.root())
            .env(PAUSE_CHILD_ROLE, pause_role_name(role))
            .env(
                PAUSE_CHILD_OPERATION,
                pause_operation_name(operation).expect("pause operation"),
            )
            .env(PAUSE_CHILD_ORDINAL, "0")
            .env(PAUSE_CHILD_DIAGNOSTIC, "SC-L2-CANARY-DATABASE-KEY")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn canary pause child");
        let Some((last_observed_ordinal, total_operations)) =
            wait_for_pause_marker(prepared.root())
        else {
            let _ = terminate_and_reap(&mut child);
            panic!("canary pause marker was not produced before the bounded deadline");
        };
        let reaped = terminate_and_reap(&mut child);
        let observation =
            L2IoPauseObservation::new(role, operation, 0, last_observed_ordinal, total_operations)
                .expect("bounded canary pause observation");

        assert!(
            prepared
                .finish(&executable(), observation, &reaped.stdout, &reaped.stderr)
                .is_err(),
            "a captured pause-child canary must block promotion",
        );
    }

    #[test]
    fn every_commit_window_pause_is_killed_before_fresh_reopen() {
        for scenario in [Scenario::InviterTransaction, Scenario::JoinerTransaction] {
            let baseline = run_l2_io_baseline(&executable(), scenario, &mut BaselineTrace)
                .expect("clean named-VFS baseline");
            let targets: Vec<_> = baseline
                .targets()
                .filter(|target| {
                    matches!(
                        (target.file_role(), target.operation()),
                        (
                            L2IoFileRole::RollbackJournal,
                            L2IoOperation::Write | L2IoOperation::Sync | L2IoOperation::Delete,
                        ) | (
                            L2IoFileRole::MainDatabase,
                            L2IoOperation::Write | L2IoOperation::Sync,
                        )
                    )
                })
                .collect();
            assert!(!targets.is_empty());
            let mut cases = Vec::new();
            for target in targets {
                for ordinal in 0..target.observed_count() {
                    let report = run_pause_kill_case(scenario, target, ordinal);
                    let evidence = report.encode_v1();
                    assert!(evidence.contains("process_termination=confirmed\n"));
                    assert!(evidence.contains("pause=confirmed\n"));
                    assert!(evidence.contains("directory_cleanup=pass\n"));
                    cases.push(report);
                }
            }
            let complete = L2IoPauseSweepReport::new(scenario, &baseline, &cases)
                .expect("complete baseline-derived pause sweep");
            let evidence = complete.encode_v1();
            assert!(evidence.contains("sweep=pause-process-kill\n"));
            assert!(evidence.contains("coverage=complete\n"));
            assert!(evidence.contains("publication=prohibited\n"));

            if let Ok(runner_image) = std::env::var("SESSION_CHAT_L2_RUNNER_IMAGE") {
                let channels = L2EvidenceChannels::new(
                    evidence.as_bytes(),
                    b"",
                    b"",
                    evidence.as_bytes(),
                    b"",
                )
                .expect("bounded pause evidence surfaces");
                let bundle = complete
                    .promote_v1(&executable(), &runner_image, &channels)
                    .expect("promote complete pause evidence");
                for manifest in bundle.manifests() {
                    println!(
                        "L2_PUBLIC_EVIDENCE_BEGIN\n{}L2_PUBLIC_EVIDENCE_END",
                        manifest.encode_v1(),
                    );
                }
            }

            cases.pop().expect("at least one pause case");
            assert!(L2IoPauseSweepReport::new(scenario, &baseline, &cases).is_err());
        }
    }
}
