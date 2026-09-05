#![forbid(unsafe_code)]

#[cfg(not(session_chat_storage_fault_testing))]
#[test]
fn ordinary_build_cannot_activate_joiner_crash_restart_cases() {
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

    use sessionctl::{
        SessionCtlError,
        l2_process::{
            L2EvidenceChannels, L2HarnessProbe, L2ProcessSweepReport, run_l2_process_baseline,
            run_l2_process_case, run_l2_process_probe,
        },
    };
    use storage_sqlcipher::fault_testing::Scenario;

    const MAX_EVIDENCE_BYTES: usize = 2_048;

    fn executable() -> PathBuf {
        PathBuf::from(env!("CARGO_BIN_EXE_sessionctl-l2"))
    }

    #[test]
    fn every_observed_joiner_checkpoint_reopens_as_exact_j0_or_j1() {
        let baseline = run_l2_process_baseline(&executable(), Scenario::JoinerTransaction)
            .expect("clean joiner checkpoint trace");
        let expected_cases = baseline.cases().len();
        let mut reports = Vec::with_capacity(expected_cases);

        for case in baseline.cases() {
            let report = run_l2_process_case(&executable(), case, L2HarnessProbe::KillWhileBlocked)
                .unwrap_or_else(|error| panic!("joiner case {case:?}: {error:?}"));
            let evidence = report.encode_v1();

            assert!(evidence.len() <= MAX_EVIDENCE_BYTES);
            assert!(
                (evidence.contains("expected=J0\n") && evidence.contains("observed=J0\n"))
                    || (evidence.contains("expected=J1\n") && evidence.contains("observed=J1\n"))
            );
            assert!(evidence.contains("storage_scenario=joiner-transaction\n"));
            assert!(evidence.contains("control=kill-while-unacknowledged\n"));
            assert!(evidence.contains("writer_termination=confirmed\n"));
            assert!(evidence.contains("fresh_verifier=pass\n"));
            assert!(evidence.contains("semantic_oracle=pass\n"));
            assert!(evidence.contains("exact_retry=pass\n"));
            assert!(evidence.contains("directory_cleanup=pass\n"));
            for forbidden in [
                "l2-approved",
                "database_key",
                "vault",
                ".sqlite",
                "/tmp/",
                "\\temp\\",
            ] {
                assert!(
                    !evidence.to_ascii_lowercase().contains(forbidden),
                    "leaked {forbidden:?}",
                );
            }
            reports.push(report);
        }

        let sweep = L2ProcessSweepReport::new(Scenario::JoinerTransaction, &baseline, &reports)
            .expect("complete joiner checkpoint sweep");
        let evidence = sweep.encode_v1();
        assert!(evidence.len() <= MAX_EVIDENCE_BYTES);
        assert!(evidence.contains("protocol=l2-checkpoint-observation-v1\n"));
        assert!(evidence.contains("publication=prohibited\n"));
        assert!(evidence.contains("coverage=complete\n"));
        assert!(evidence.contains("sweep=application-process-kill\n"));
        assert!(evidence.contains("storage_scenario=joiner-transaction\n"));
        assert!(evidence.contains("checkpoint_trace_sha256="));
        assert!(evidence.contains(&format!("completed_cases={expected_cases}\n")));
        assert!(evidence.contains("observed_new_states=1\n"));

        if let Ok(runner_image) = std::env::var("SESSION_CHAT_L2_RUNNER_IMAGE") {
            let channels =
                L2EvidenceChannels::new(evidence.as_bytes(), b"", b"", evidence.as_bytes(), b"")
                    .expect("bounded joiner evidence surfaces");
            let bundle = sweep
                .promote_v1(&executable(), &runner_image, &channels)
                .expect("promote complete joiner evidence");
            for manifest in bundle.manifests() {
                println!(
                    "L2_PUBLIC_EVIDENCE_BEGIN\n{}L2_PUBLIC_EVIDENCE_END",
                    manifest.encode_v1(),
                );
            }
        }

        reports.pop().expect("at least one observed checkpoint");
        assert!(
            L2ProcessSweepReport::new(Scenario::JoinerTransaction, &baseline, &reports).is_err()
        );

        let duplicate_case = baseline.cases().next().expect("at least one checkpoint");
        reports.push(
            run_l2_process_case(
                &executable(),
                duplicate_case,
                L2HarnessProbe::KillWhileBlocked,
            )
            .expect("separately valid duplicate checkpoint case"),
        );
        assert!(
            L2ProcessSweepReport::new(Scenario::JoinerTransaction, &baseline, &reports).is_err()
        );
    }

    #[test]
    fn changed_committed_joiner_retry_is_rejected_without_mutation() {
        for attempt in 0..8 {
            let error =
                run_l2_process_probe(&executable(), L2HarnessProbe::JoinerRetryMutation).err();
            assert!(
                matches!(
                    error,
                    Some(SessionCtlError::Stage("L2 retry conflict confirmed"))
                ),
                "unexpected coarse probe outcome on run {attempt}: {error:?}"
            );
        }
    }

    #[test]
    fn committed_joiner_with_retained_key_package_fails_closed() {
        assert!(
            run_l2_process_probe(&executable(), L2HarnessProbe::JoinerRetainedKeyPackage).is_err()
        );
    }
}
