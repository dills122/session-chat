use sessionctl::run_phase_one_demo;

#[test]
fn headless_flow_joins_exchanges_updates_and_removes() {
    let report = run_phase_one_demo().expect("complete headless Phase 1 flow");

    assert!(report.admission_approved());
    assert!(report.welcome_delivered());
    assert_eq!(report.joined_epoch(), 1);
    assert_eq!(report.application_messages_received(), 2);
    assert_eq!(report.updated_epoch(), 2);
    assert!(report.removed());
    assert!(report.post_removal_rejected());
}

#[test]
fn command_prints_only_coarse_public_milestones() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_sessionctl"))
        .output()
        .expect("run sessionctl");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());

    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert_eq!(
        stdout,
        "admission: approved\nwelcome: delivered\nmessages: 2\nepoch: 2\nremoval: enforced\n"
    );
    for forbidden in [
        "capability",
        "ciphertext",
        "credential",
        "invitation_id",
        "key_package",
        "plaintext",
        "secret",
        "token",
    ] {
        assert!(!stdout.contains(forbidden));
    }
}

#[test]
fn command_emits_bounded_versioned_redacted_scenario_evidence() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_sessionctl"))
        .arg("--evidence-v1")
        .output()
        .expect("run sessionctl evidence mode");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());

    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert_eq!(
        stdout,
        concat!(
            "version=1\n",
            "scenario=E2E-JOIN-001\n",
            "topology=single-process-sqlcipher-local-v1\n",
            "result=pass\n",
            "admission=approved\n",
            "welcome=delivered\n",
            "joined_epoch=1\n",
            "messages=2\n",
            "updated_epoch=2\n",
            "removal=enforced\n",
            "post_removal=rejected\n",
        )
    );
    assert!(stdout.len() < 512);
    for forbidden in [
        "capability",
        "ciphertext",
        "credential",
        "invitation_id",
        "key_package",
        "plaintext",
        "secret",
        "token",
        "/tmp",
        "sqlite",
    ] {
        assert!(!stdout.contains(forbidden));
    }
}

#[test]
fn command_rejects_unknown_or_excess_arguments_without_running_the_flow() {
    for arguments in [["--unknown", ""], ["--evidence-v1", "extra"]] {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_sessionctl"));
        command.arg(arguments[0]);
        if !arguments[1].is_empty() {
            command.arg(arguments[1]);
        }
        let output = command.output().expect("run rejected invocation");
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).expect("UTF-8 stderr"),
            "sessionctl: unsupported invocation\n"
        );
    }
}
