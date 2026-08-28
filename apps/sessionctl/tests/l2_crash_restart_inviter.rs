#![forbid(unsafe_code)]

#[cfg(not(session_chat_storage_fault_testing))]
#[test]
fn ordinary_build_cannot_activate_inviter_crash_restart_cases() {
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

    use sessionctl::SessionCtlError;
    use sessionctl::l2_process::{
        L2HarnessProbe, L2ProcessSweepReport, run_l2_process_baseline, run_l2_process_case,
        run_l2_process_probe,
    };
    use storage_sqlcipher::fault_testing::Scenario;

    const MAX_EVIDENCE_BYTES: usize = 2_048;

    fn executable() -> PathBuf {
        PathBuf::from(env!("CARGO_BIN_EXE_sessionctl-l2"))
    }

    fn assert_inviter_case_evidence(evidence: &str) {
        assert!(evidence.len() <= MAX_EVIDENCE_BYTES);
        for required in [
            "protocol=l2-harness-evidence-v1\n",
            "result=pass\n",
            "coverage=partial\n",
            "fault_build=true\n",
            "control=kill-while-unacknowledged\n",
            "workload=real-storage-transaction\n",
            "storage_scenario=inviter-transaction\n",
            "integrity=pass\n",
            "schema=pass\n",
            "semantic_oracle=pass\n",
            "exact_retry=pass\n",
            "fixture_cleanup=pass\n",
            "writer_termination=confirmed\n",
            "fresh_verifier=pass\n",
            "redaction=pass\n",
            "handle_cleanup=pass\n",
            "child_cleanup=pass\n",
            "directory_cleanup=pass\n",
        ] {
            assert!(evidence.contains(required), "missing {required:?}");
        }
        assert!(
            (evidence.contains("expected=I0\n") && evidence.contains("observed=I0\n"))
                || (evidence.contains("expected=I1\n") && evidence.contains("observed=I1\n")),
            "inviter case did not retain one exact complete-state classification",
        );

        let lowercase = evidence.to_ascii_lowercase();
        for forbidden in [
            "seeded-secret",
            "database_key",
            "invitation_generation",
            "approval_record",
            "request_fingerprint",
            "welcome=",
            ".sqlite",
            "/tmp/",
            "\\temp\\",
        ] {
            assert!(!lowercase.contains(forbidden), "leaked {forbidden:?}");
        }
    }

    #[test]
    fn every_baseline_observed_inviter_checkpoint_reopens_as_exact_i0_or_i1() {
        let executable = executable();
        let baseline = run_l2_process_baseline(&executable, Scenario::InviterTransaction)
            .expect("discover the clean inviter checkpoint trace");
        let cases = baseline.cases().collect::<Vec<_>>();
        let mut reports = Vec::with_capacity(cases.len());

        for case in &cases {
            let report = run_l2_process_case(&executable, *case, L2HarnessProbe::KillWhileBlocked)
                .unwrap_or_else(|error| panic!("baseline-observed inviter case {case:?}: {error}"));
            assert_inviter_case_evidence(&report.encode_v1());
            reports.push(report);
        }

        let sweep = L2ProcessSweepReport::new(Scenario::InviterTransaction, &baseline, &reports)
            .expect("complete inviter checkpoint sweep");
        let evidence = sweep.encode_v1();
        assert!(evidence.len() <= MAX_EVIDENCE_BYTES);
        for required in [
            "protocol=l2-checkpoint-observation-v1\n",
            "scenario=E2E-TXN-001\n",
            "publication=prohibited\n",
            "status=validated\n",
            "coverage=complete\n",
            "sweep=application-process-kill\n",
            "storage_scenario=inviter-transaction\n",
            "checkpoint_trace_sha256=",
            "observed_old_states=",
            "observed_new_states=",
        ] {
            assert!(evidence.contains(required), "missing {required:?}");
        }
        assert!(evidence.contains(&format!("completed_cases={}\n", cases.len())));
        let trace_digest = evidence
            .lines()
            .find_map(|line| line.strip_prefix("checkpoint_trace_sha256="))
            .expect("checkpoint trace digest");
        assert_eq!(trace_digest.len(), 64);
        assert!(trace_digest.bytes().all(|byte| byte.is_ascii_hexdigit()));

        reports.pop().expect("nonempty baseline");
        assert!(
            L2ProcessSweepReport::new(Scenario::InviterTransaction, &baseline, &reports,).is_err(),
            "missing checkpoint coverage must be rejected",
        );

        let duplicate =
            run_l2_process_case(&executable, cases[0], L2HarnessProbe::KillWhileBlocked)
                .expect("duplicate inviter checkpoint case");
        reports.push(duplicate);
        assert!(
            L2ProcessSweepReport::new(Scenario::InviterTransaction, &baseline, &reports,).is_err(),
            "duplicate checkpoint coverage must be rejected",
        );
    }

    #[test]
    fn mixed_state_and_conflicting_repeated_inviter_work_fail_closed() {
        assert!(
            run_l2_process_probe(&executable(), L2HarnessProbe::MixedFixture).is_err(),
            "mixed inviter state must not pass the fresh verifier",
        );
        assert!(
            matches!(
                run_l2_process_probe(&executable(), L2HarnessProbe::InviterRetryMutation),
                Err(SessionCtlError::Stage("L2 retry conflict confirmed"))
            ),
            "conflicting repeated Add/Welcome work must be rejected without mutation",
        );
    }
}
