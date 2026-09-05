#![forbid(unsafe_code)]

#[cfg(not(session_chat_storage_fault_testing))]
#[test]
fn ordinary_build_cannot_activate_welcome_crash_cases() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_sessionctl-l2"))
        .output()
        .expect("ordinary binary");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"sessionctl-l2: unavailable\n");
}

#[cfg(session_chat_storage_fault_testing)]
mod checked {
    use sessionctl::l2_process::welcome::{run_welcome_defective_oracle_probe, run_welcome_sweep};
    #[test]
    fn every_welcome_checkpoint_recovers_without_repeating_membership() {
        let report = run_welcome_sweep(std::path::Path::new(env!("CARGO_BIN_EXE_sessionctl-l2")))
            .expect("complete Welcome sweep");
        assert_eq!(report.completed_cases(), 40);
        let evidence = report.encode_v1();
        assert!(evidence.len() < 2048);
        assert!(evidence.contains("publication=prohibited\n"));
        if let Ok(image) = std::env::var("SESSION_CHAT_L2_RUNNER_IMAGE") {
            let channels = sessionctl::l2_process::L2EvidenceChannels::new(
                evidence.as_bytes(),
                b"",
                b"",
                b"",
                b"",
            )
            .expect("channels");
            let bundle = report
                .promote_v1(
                    std::path::Path::new(env!("CARGO_BIN_EXE_sessionctl-l2")),
                    &image,
                    &channels,
                )
                .expect("provenance-bound Welcome evidence");
            for manifest in bundle.manifests() {
                println!(
                    "L2_PUBLIC_EVIDENCE_BEGIN\n{}L2_PUBLIC_EVIDENCE_END",
                    manifest.encode_v1()
                );
            }
        }
    }
    #[test]
    fn changed_membership_material_cannot_pass_welcome_recovery() {
        assert!(matches!(
            run_welcome_defective_oracle_probe(std::path::Path::new(env!(
                "CARGO_BIN_EXE_sessionctl-l2"
            ))),
            Err(sessionctl::SessionCtlError::Stage("L2 Welcome verifier"))
        ));
    }
    use sessionctl::l2_process::{
        L2IoBaselineObservation, L2IoDriverObservation, L2IoFaultDriver, L2IoFileRole,
        L2IoOperation, L2IoPauseDriver, L2IoSweepTarget,
    };
    use std::{path::PathBuf, sync::Arc, time::Duration};
    use storage_sqlcipher_fault_vfs::{
        FaultPlan, FaultTarget, FileRole, Operation, PauseGate, controller, register,
    };
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

    struct EnginePause {
        root: PathBuf,
        target: FaultTarget,
        gate: Arc<PauseGate>,
        marker: String,
    }
    impl L2IoPauseDriver for EnginePause {
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
            let marker = self.marker.clone();
            std::thread::spawn(move || {
                if !gate.wait_until_reached(Duration::from_secs(25)) {
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
                let _ = std::fs::write(root.join("welcome.pause"), marker);
            });
            FaultPlan::pause(self.target, Arc::clone(&self.gate))
                .and_then(|plan| controller().arm(plan))
                .is_ok()
        }
    }
    #[test]
    fn welcome_engine_child() {
        let Some(root) = std::env::var_os("SESSION_CHAT_WELCOME_ROOT") else {
            return;
        };
        let role_text = std::env::var("SESSION_CHAT_WELCOME_ROLE").unwrap();
        let operation_text = std::env::var("SESSION_CHAT_WELCOME_OPERATION").unwrap();
        let ordinal: usize = std::env::var("SESSION_CHAT_WELCOME_ORDINAL")
            .unwrap()
            .parse()
            .unwrap();
        let role = match role_text.as_str() {
            "main-database" => FileRole::MainDatabase,
            "rollback-journal" => FileRole::RollbackJournal,
            _ => panic!("closed role"),
        };
        let operation = match operation_text.as_str() {
            "write" => Operation::Write,
            "sync" => Operation::Sync,
            "delete" => Operation::Delete,
            _ => panic!("closed operation"),
        };
        let root = PathBuf::from(root);
        let mut driver = EnginePause {
            root: root.clone(),
            target: FaultTarget::new(role, operation, ordinal).unwrap(),
            gate: Arc::new(PauseGate::new()),
            marker: format!("{role_text}:{operation_text}:{ordinal}\n"),
        };
        sessionctl::l2_process::welcome_io::run_welcome_engine_child(&root, &mut driver)
            .expect("child must remain paused");
    }
    #[test]
    fn every_welcome_engine_commit_window_recovers_one_complete_state() {
        let report = sessionctl::l2_process::welcome_io::run_welcome_engine_sweep(
            std::path::Path::new(env!("CARGO_BIN_EXE_sessionctl-l2")),
            &std::env::current_exe().unwrap(),
            &mut BaselineTrace,
        )
        .expect("complete Welcome engine sweep");
        let evidence = report.encode_v1();
        assert!(evidence.contains("coverage=complete\n"));
        if let Ok(image) = std::env::var("SESSION_CHAT_L2_RUNNER_IMAGE") {
            let channels = sessionctl::l2_process::L2EvidenceChannels::new(
                evidence.as_bytes(),
                b"",
                b"",
                b"",
                b"",
            )
            .unwrap();
            let bundle = report
                .promote_v1(&std::env::current_exe().unwrap(), &image, &channels)
                .expect("Welcome engine promotion");
            for manifest in bundle.manifests() {
                println!(
                    "L2_PUBLIC_EVIDENCE_BEGIN\n{}L2_PUBLIC_EVIDENCE_END",
                    manifest.encode_v1()
                );
            }
        }
    }
}
