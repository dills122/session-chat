use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use sessionctl::{
    FastAdapterPathMode, run_fast_adapter_host, run_fast_adapter_join,
    run_fast_adapter_loopback_demo,
};
use transport_iroh::{FastPathClass, MAX_FAST_OPERATOR_HANDOFF_BYTES};

const USAGE: &str = concat!(
    "usage: sessionctl-fast-adapter host <auto|relay-only> ",
    "<absolute-new-authority-file> | join <auto|relay-only> ",
    "<absolute-authority-file>\n"
);

#[test]
fn common_adapter_harness_passes_over_a_classified_direct_loopback_path() {
    let runtime = tokio::runtime::Runtime::new().expect("Tokio runtime");
    let report = runtime
        .block_on(run_fast_adapter_loopback_demo())
        .expect("Fast adapter loopback harness");
    assert_eq!(report.initial_path().selected(), FastPathClass::Direct);
    assert_eq!(report.final_path().selected(), FastPathClass::Direct);
    assert!(report.final_path().direct_available());
    assert!(!report.final_path().relay_available());
}

#[test]
fn path_mode_parser_accepts_only_closed_evidence_modes() {
    assert_eq!(
        FastAdapterPathMode::parse("auto"),
        Ok(FastAdapterPathMode::Auto)
    );
    assert_eq!(
        FastAdapterPathMode::parse("relay-only"),
        Ok(FastAdapterPathMode::RelayOnly)
    );
    assert!(FastAdapterPathMode::parse("direct-only").is_err());
    assert!(FastAdapterPathMode::parse("private").is_err());
    assert_eq!(FastAdapterPathMode::Auto.as_str(), "auto");
    assert_eq!(FastAdapterPathMode::RelayOnly.as_str(), "relay-only");
}

#[test]
fn public_entry_points_reject_hostile_handoff_files_before_network_work() {
    let runtime = tokio::runtime::Runtime::new().expect("Tokio runtime");
    let root = temporary_directory();

    let empty = root.join("empty.v1");
    fs::write(&empty, []).expect("empty fixture");
    assert!(
        runtime
            .block_on(run_fast_adapter_join(
                FastAdapterPathMode::Auto,
                empty.clone()
            ))
            .is_err()
    );
    assert!(
        runtime
            .block_on(run_fast_adapter_host(FastAdapterPathMode::Auto, empty))
            .is_err()
    );

    let oversized = root.join("oversized.v1");
    fs::write(&oversized, vec![0_u8; MAX_FAST_OPERATOR_HANDOFF_BYTES + 1])
        .expect("oversized fixture");
    assert!(
        runtime
            .block_on(run_fast_adapter_join(FastAdapterPathMode::Auto, oversized))
            .is_err()
    );

    let malformed = root.join("malformed.v1");
    fs::write(&malformed, b"not-canonical-cbor").expect("malformed fixture");
    assert!(
        runtime
            .block_on(run_fast_adapter_join(
                FastAdapterPathMode::Auto,
                malformed.clone()
            ))
            .is_err()
    );

    assert!(
        runtime
            .block_on(run_fast_adapter_join(
                FastAdapterPathMode::Auto,
                root.clone()
            ))
            .is_err()
    );
    assert!(
        runtime
            .block_on(run_fast_adapter_host(
                FastAdapterPathMode::RelayOnly,
                root.join("missing/authority.v1"),
            ))
            .is_err()
    );
    assert!(
        runtime
            .block_on(run_fast_adapter_join(
                FastAdapterPathMode::Auto,
                root.join("missing.v1"),
            ))
            .is_err()
    );

    let overlong = PathBuf::from(format!("/{}", "x".repeat(4_097)));
    assert!(
        runtime
            .block_on(run_fast_adapter_host(
                FastAdapterPathMode::Auto,
                overlong.clone(),
            ))
            .is_err()
    );
    assert!(
        runtime
            .block_on(run_fast_adapter_join(
                FastAdapterPathMode::RelayOnly,
                overlong,
            ))
            .is_err()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let link = root.join("link.v1");
        symlink(&malformed, &link).expect("symlink fixture");
        assert!(
            runtime
                .block_on(run_fast_adapter_join(FastAdapterPathMode::Auto, link))
                .is_err()
        );
    }

    fs::remove_dir_all(root).expect("remove fixtures");
}

#[test]
fn command_rejects_unknown_invocations_without_network_work() {
    for arguments in [
        vec!["host"],
        vec!["unknown", "auto", "/tmp/session-chat-unused"],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_sessionctl-fast-adapter"))
            .args(arguments)
            .output()
            .expect("run rejected invocation");
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(String::from_utf8(output.stderr).expect("UTF-8"), USAGE);
    }
}

#[test]
fn command_rejects_bad_modes_and_paths_before_public_network_work() {
    for arguments in [
        vec!["host", "private", "/tmp/session-chat-unused"],
        vec!["host", "auto", "relative-authority"],
        vec!["join", "auto", "relative-authority"],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_sessionctl-fast-adapter"))
            .args(arguments)
            .output()
            .expect("run rejected invocation");
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).expect("UTF-8"),
            "sessionctl-fast-adapter: Fast adapter evidence run failed\n"
        );
    }

    assert!(!Path::new("relative-authority").exists());
}

fn temporary_directory() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "session-chat-fast-adapter-test-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&path).expect("temporary directory");
    path
}
