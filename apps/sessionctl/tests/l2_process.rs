#![forbid(unsafe_code)]

#[cfg(not(session_chat_storage_fault_testing))]
#[test]
fn ordinary_build_cannot_activate_the_l2_process_runner() {
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
        path::PathBuf,
        process::Command,
        time::{Duration, Instant},
    };

    use sessionctl::l2_process::{
        L2HarnessProbe, L2ProcessCase, run_l2_process_case, run_l2_process_internal_role,
        run_l2_process_probe,
    };
    use storage_sqlcipher::fault_testing::Checkpoint;

    const MAX_EVIDENCE_BYTES: usize = 2_048;

    fn executable() -> PathBuf {
        PathBuf::from(env!("CARGO_BIN_EXE_sessionctl-l2"))
    }

    #[test]
    fn checked_binary_still_rejects_public_invocation() {
        let output = Command::new(executable())
            .output()
            .expect("run checked L2 binary");

        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"sessionctl-l2: unsupported invocation\n");
    }

    #[test]
    fn graceful_continue_emits_only_bounded_redacted_harness_evidence() {
        let report = run_l2_process_probe(&executable(), L2HarnessProbe::GracefulContinue)
            .expect("graceful L2 control probe");
        let evidence = report.encode_v1();

        assert!(evidence.len() <= MAX_EVIDENCE_BYTES);
        assert!(!evidence.contains("commit=unavailable\n"));
        assert!(!evidence.contains("toolchain=unavailable\n"));
        assert!(!evidence.contains("lock_sha256=unavailable\n"));
        for required in [
            "version=1\n",
            "protocol=l2-harness-evidence-v1\n",
            "scenario=L2-HARNESS-001\n",
            "result=pass\n",
            "coverage=partial\n",
            "evidence_scope=harness-foundation\n",
            "fault_build=true\n",
            "control=continue\n",
            "expected=I1\n",
            "observed=I1\n",
            "commit=",
            "dirty=",
            "toolchain=1.97.1\n",
            "lock_sha256=",
            "integrity=pass\n",
            "schema=pass\n",
            "semantic_oracle=pass\n",
            "exact_retry=pass\n",
            "fixture_cleanup=pass\n",
            "child_cleanup=pass\n",
            "directory_cleanup=pass\n",
        ] {
            assert!(evidence.contains(required), "missing {required:?}");
        }
        let lowercase = evidence.to_ascii_lowercase();
        for forbidden in [
            "seeded-secret",
            "database_key",
            "vault",
            ".sqlite",
            "/tmp/",
            "\\temp\\",
        ] {
            assert!(!lowercase.contains(forbidden), "leaked {forbidden:?}");
        }
    }

    #[test]
    fn target_is_killed_while_unacknowledged_before_fresh_verification() {
        let report = run_l2_process_probe(&executable(), L2HarnessProbe::KillWhileBlocked)
            .expect("kill-while-blocked L2 probe");
        let evidence = report.encode_v1();

        assert!(evidence.contains("control=kill-while-unacknowledged\n"));
        assert!(evidence.contains("writer_termination=confirmed\n"));
        assert!(evidence.contains("fresh_verifier=pass\n"));
        assert!(evidence.contains("observed=I0\n"));
    }

    #[test]
    fn closed_case_contract_runs_real_representative_i0_i1_j0_j1_workloads() {
        for (checkpoint, code) in [
            (Checkpoint::InviterBeforeBegin, "I0"),
            (Checkpoint::InviterAfterCommitReturn, "I1"),
            (Checkpoint::JoinerBeforeBegin, "J0"),
            (Checkpoint::JoinerAfterCommitReturn, "J1"),
        ] {
            let case = L2ProcessCase::new(checkpoint, 0).expect("closed L2 case");
            let evidence =
                run_l2_process_case(&executable(), case, L2HarnessProbe::KillWhileBlocked)
                    .unwrap_or_else(|error| panic!("representative {code} L2 workload: {error:?}"))
                    .encode_v1();
            assert!(evidence.contains(&format!("expected={code}\n")));
            assert!(evidence.contains(&format!("observed={code}\n")));
            assert!(evidence.contains("workload=real-storage-transaction\n"));
        }

        assert!(L2ProcessCase::new(Checkpoint::InviterAfterEpochInsert, 64).is_err());
    }

    #[test]
    fn defective_frames_diagnostics_and_semantics_fail_closed() {
        for probe in [
            L2HarnessProbe::AdvanceWithoutAcknowledgement,
            L2HarnessProbe::OversizedOutput,
            L2HarnessProbe::SecretDiagnostic,
            L2HarnessProbe::MixedFixture,
            L2HarnessProbe::IdentityLoss,
            L2HarnessProbe::ReservationSubstitution,
            L2HarnessProbe::DefectiveSchema,
            L2HarnessProbe::NonzeroLeaseGeneration,
            L2HarnessProbe::ChangedAttemptCeiling,
            L2HarnessProbe::InviterRetryMutation,
            L2HarnessProbe::JoinerRetryMutation,
        ] {
            assert!(
                run_l2_process_probe(&executable(), probe).is_err(),
                "probe {probe:?} must fail"
            );
        }
    }

    #[test]
    fn missing_non_target_acknowledgement_is_bounded_and_reaped() {
        let started = Instant::now();
        assert!(
            run_l2_process_probe(&executable(), L2HarnessProbe::MissingAcknowledgement).is_err()
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn lingering_verifier_handle_is_bounded_reaped_and_cannot_report_pass() {
        let started = Instant::now();
        assert!(run_l2_process_probe(&executable(), L2HarnessProbe::LingeringHandle).is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn stalled_writer_is_bounded_and_reaped() {
        let started = Instant::now();
        assert!(run_l2_process_probe(&executable(), L2HarnessProbe::Stall).is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn internal_roles_reject_unmarked_roots_and_unknown_roles() {
        assert!(run_l2_process_internal_role("writer", PathBuf::from("/")).is_err());
        assert!(run_l2_process_internal_role("unknown", PathBuf::from("/")).is_err());
    }
}
