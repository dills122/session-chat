#![forbid(unsafe_code)]

#[cfg(not(session_chat_storage_fault_testing))]
#[test]
fn ordinary_build_cannot_activate_public_l2_evidence() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_sessionctl-l2"))
        .output()
        .expect("run ordinary L2 binary");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"sessionctl-l2: unavailable\n");
}

#[cfg(session_chat_storage_fault_testing)]
mod checked {
    use sessionctl::l2_process::{
        L2EvidenceChannels, L2EvidenceMetadata, L2EvidenceSweep, promote_l2_evidence,
    };
    use storage_sqlcipher::fault_testing::Scenario;

    const COMPLETE_OBSERVATION: &str = concat!(
        "version=1\n",
        "protocol=l2-checkpoint-observation-v1\n",
        "scenario=E2E-TXN-001\n",
        "publication=prohibited\n",
        "status=validated\n",
        "coverage=complete\n",
        "sweep=application-process-kill\n",
        "fault_build=true\n",
        "storage_scenario=inviter-transaction\n",
        "checkpoint_trace_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        "completed_cases=9\n",
        "observed_old_states=7\n",
        "observed_new_states=2\n",
        "integrity=pass\n",
        "schema=pass\n",
        "semantic_oracle=pass\n",
        "exact_retry=pass\n",
        "fixture_cleanup=pass\n",
        "handle_cleanup=pass\n",
        "child_cleanup=pass\n",
        "directory_cleanup=pass\n",
    );

    fn metadata() -> L2EvidenceMetadata {
        L2EvidenceMetadata::new(
            "0123456789abcdef0123456789abcdef01234567",
            false,
            "1.97.1",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "macos-15",
            "macos",
            "aarch64",
            "4.14.0",
            "3.50.4",
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
        )
        .expect("closed provenance")
    }

    fn clean_channels() -> L2EvidenceChannels<'static> {
        L2EvidenceChannels::new(b"", b"", b"", b"checkpoint-only", b"encrypted-artifacts")
            .expect("bounded channels")
    }

    #[test]
    fn complete_internal_observation_promotes_to_bounded_public_manifest() {
        let manifest = promote_l2_evidence(
            L2EvidenceSweep::ApplicationProcessKill,
            Scenario::InviterTransaction,
            COMPLETE_OBSERVATION,
            &metadata(),
            &clean_channels(),
        )
        .expect("promote complete checked evidence")
        .encode_v1();

        for required in [
            "protocol=l2-evidence-v1\n",
            "scenario=E2E-TXN-001\n",
            "result=pass\n",
            "coverage=complete\n",
            "sweep=application-process-kill\n",
            "storage_scenario=inviter-transaction\n",
            "commit=0123456789abcdef0123456789abcdef01234567\n",
            "dirty=false\n",
            "toolchain=1.97.1\n",
            "platform=macos-aarch64\n",
            "runner_image=macos-15\n",
            "sqlcipher_version=4.14.0\n",
            "sqlite_version=3.50.4\n",
            "test_binary_sha256=1111111111111111111111111111111111111111111111111111111111111111\n",
            "baseline_artifact_sha256=2222222222222222222222222222222222222222222222222222222222222222\n",
            "post_recovery_artifact_sha256=3333333333333333333333333333333333333333333333333333333333333333\n",
            "integrity=pass\n",
            "schema=pass\n",
            "semantic_oracle=pass\n",
            "exact_retry=pass\n",
            "redaction=pass\n",
            "cleanup=pass\n",
        ] {
            assert!(manifest.contains(required), "missing {required:?}");
        }
        assert!(manifest.len() <= 4_096);
        assert!(!manifest.contains("publication=prohibited"));
    }

    #[test]
    fn promotion_rejects_partial_or_defective_observations() {
        for defective in [
            COMPLETE_OBSERVATION.replace("coverage=complete", "coverage=partial"),
            COMPLETE_OBSERVATION.replace("exact_retry=pass", "exact_retry=fail"),
            COMPLETE_OBSERVATION.replace("publication=prohibited\n", ""),
        ] {
            assert!(
                promote_l2_evidence(
                    L2EvidenceSweep::ApplicationProcessKill,
                    Scenario::InviterTransaction,
                    &defective,
                    &metadata(),
                    &clean_channels(),
                )
                .is_err(),
                "defective smoke observation must not promote",
            );
        }
    }

    #[test]
    fn promotion_rejects_a_canary_on_every_scanned_surface() {
        const CANARY: &[u8] = b"SC-L2-CANARY-DATABASE-KEY";
        for channels in [
            L2EvidenceChannels::new(CANARY, b"", b"", b"", b""),
            L2EvidenceChannels::new(b"", CANARY, b"", b"", b""),
            L2EvidenceChannels::new(b"", b"", CANARY, b"", b""),
            L2EvidenceChannels::new(b"", b"", b"", CANARY, b""),
            L2EvidenceChannels::new(b"", b"", b"", b"", CANARY),
        ] {
            let channels = channels.expect("bounded hostile channel");
            assert!(
                promote_l2_evidence(
                    L2EvidenceSweep::ApplicationProcessKill,
                    Scenario::InviterTransaction,
                    COMPLETE_OBSERVATION,
                    &metadata(),
                    &channels,
                )
                .is_err(),
                "canary-bearing evidence surface must fail closed",
            );
        }
    }

    #[test]
    fn promotion_rejects_unbound_or_dirty_provenance() {
        assert!(
            L2EvidenceMetadata::new(
                "unavailable",
                false,
                "1.97.1",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "macos-15",
                "macos",
                "aarch64",
                "4.14.0",
                "3.50.4",
                [0x11; 32],
                [0x22; 32],
                [0x33; 32],
            )
            .is_err()
        );
        assert!(
            L2EvidenceMetadata::new(
                "0123456789abcdef0123456789abcdef01234567",
                true,
                "1.97.1",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "macos-15",
                "macos",
                "aarch64",
                "4.14.0",
                "3.50.4",
                [0x11; 32],
                [0x22; 32],
                [0x33; 32],
            )
            .is_err()
        );
    }
}
