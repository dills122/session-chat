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
        L2IoFaultDriver, L2IoFaultMode, L2IoFaultObservation, L2IoFileRole, L2IoOperation,
        run_l2_io_fault_case,
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
        ) -> Option<L2IoFaultObservation> {
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
}
