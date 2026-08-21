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
