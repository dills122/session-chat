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
    use std::path::PathBuf;

    use sessionctl::l2_process::{
        L2IoBaselineObservation, L2IoDriverObservation, L2IoFaultDriver, L2IoFaultMode,
        L2IoFaultObservation, L2IoFileRole, L2IoOperation, L2IoSweepReport, L2IoSweepTarget,
        run_l2_io_baseline, run_l2_io_fault_case,
    };
    use storage_sqlcipher::fault_testing::Scenario;
    use storage_sqlcipher_fault_vfs::{
        FaultCode, FaultMode, FaultPlan, FaultTarget, FileRole, Operation, controller, register,
    };

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
            "protocol=l2-io-evidence-v1\n",
            "scenario=E2E-TXN-001\n",
            "result=pass\n",
            "coverage=partial\n",
            "storage_scenario=inviter-transaction\n",
            "file_role=rollback-journal\n",
            "operation=write\n",
            "mode=one-shot\n",
            "target_ordinal=0\n",
            "sqlite_primary_code=13\n",
            "sqlite_extended_code=13\n",
            "integrity=pass\n",
            "schema=pass\n",
            "semantic_oracle=pass\n",
            "exact_retry=pass\n",
            "fresh_verifier=pass\n",
            "redaction=pass\n",
            "child_cleanup=pass\n",
            "directory_cleanup=pass\n",
        ] {
            assert!(evidence.contains(required), "missing {required:?}");
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
            assert!(report.encode_v1().contains("baseline=pass\n"));
            assert!(report.encode_v1().contains("fresh_verifier=pass\n"));
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
                            assert!(evidence.contains("result=pass\n"));
                            assert!(evidence.contains("coverage=partial\n"));
                            assert!(evidence.contains("fresh_verifier=pass\n"));
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
            assert!(complete_evidence.contains("result=pass\n"));
            assert!(complete_evidence.contains("modes=one-shot|persistent\n"));

            cases.pop().expect("at least one completed case");
            assert!(L2IoSweepReport::new(scenario, &baseline, &cases).is_err());
        }
    }
}
