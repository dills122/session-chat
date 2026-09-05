use std::{
    fs,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const READY_WAIT: Duration = Duration::from_secs(10);

#[test]
fn separate_host_and_join_commands_complete_the_phase_one_flow() {
    let root = unique_root();
    let host = Command::new(env!("CARGO_BIN_EXE_sessionctl-pair"))
        .arg("host")
        .arg(&root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start host terminal");
    wait_for_marker(&root.join(".sessionctl-l1-root"));

    let join = Command::new(env!("CARGO_BIN_EXE_sessionctl-pair"))
        .arg("join")
        .arg(&root)
        .stdin(Stdio::null())
        .output()
        .expect("run join terminal");
    let host = host.wait_with_output().expect("wait for host terminal");

    assert!(host.status.success(), "{}", output(&host.stderr));
    assert!(join.status.success(), "{}", output(&join.stderr));
    assert!(host.stderr.is_empty());
    assert!(join.stderr.is_empty());

    let host_stdout = output(&host.stdout);
    assert!(host_stdout.contains("mode=host\nstatus=ready\n"));
    assert!(host_stdout.contains("role=alice-init\nresult=pass\n"));
    assert!(host_stdout.contains("removal=enforced\n"));
    assert!(host_stdout.ends_with("mode=host\nstatus=complete\n"));

    let join_stdout = output(&join.stdout);
    assert!(join_stdout.starts_with("mode=join\nstatus=connected\n"));
    assert!(join_stdout.contains("role=bob\nresult=pass\n"));
    assert!(join_stdout.contains("post_removal=rejected\n"));
    assert!(join_stdout.ends_with("mode=join\nstatus=complete\n"));
    assert!(!root.exists());
}

#[test]
fn pair_command_rejects_unsafe_or_unsupported_invocations() {
    for arguments in [vec!["host"], vec!["unknown", "/tmp/session-chat-unused"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_sessionctl-pair"))
            .args(arguments)
            .output()
            .expect("run rejected invocation");
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(
            self::output(&output.stderr),
            "usage: sessionctl-pair <host|join> <absolute-new-run-directory>\n"
        );
    }

    let output = Command::new(env!("CARGO_BIN_EXE_sessionctl-pair"))
        .args(["host", "relative-run-directory"])
        .output()
        .expect("run unsafe root invocation");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        self::output(&output.stderr),
        "sessionctl-pair: two-terminal proof failed\n"
    );
}

fn wait_for_marker(marker: &std::path::Path) {
    let deadline = Instant::now() + READY_WAIT;
    while !marker.exists() {
        assert!(Instant::now() < deadline, "host did not publish readiness");
        thread::sleep(Duration::from_millis(10));
    }
}

fn unique_root() -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "session-chat-two-terminal-test-{}-{nonce}",
        std::process::id()
    ));
    if root.exists() {
        fs::remove_dir_all(&root).expect("remove stale test root");
    }
    root
}

fn output(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("UTF-8 command output")
}
