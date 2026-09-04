#[test]
fn full_phase_one_flow_crosses_the_bounded_iroh_loopback_link() {
    let runtime = tokio::runtime::Runtime::new().expect("Tokio runtime");
    runtime
        .block_on(sessionctl::run_network_loopback_demo())
        .expect("full network loopback proof");
}

#[test]
fn network_command_rejects_incomplete_or_unknown_invocations() {
    for arguments in [vec!["host"], vec!["unknown", "/tmp/session-chat-unused"]] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_sessionctl-net"))
            .args(arguments)
            .output()
            .expect("run rejected network invocation");
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).expect("UTF-8 stderr"),
            concat!(
                "usage: sessionctl-net host <absolute-new-state-dir> | ",
                "join <host-endpoint-id> <absolute-new-state-dir>\n"
            )
        );
    }
}
