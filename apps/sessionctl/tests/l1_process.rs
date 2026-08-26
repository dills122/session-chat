#![forbid(unsafe_code)]

use std::{
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use sessionctl::run_l1_process_internal_role;

const MAX_EVIDENCE_BYTES: usize = 2_048;

#[test]
fn independent_process_runner_emits_bounded_redacted_evidence() {
    let output = Command::new(env!("CARGO_BIN_EXE_sessionctl-l1"))
        .output()
        .expect("run independent-process conformance binary");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(output.stdout.len() <= MAX_EVIDENCE_BYTES);

    let evidence = std::str::from_utf8(&output.stdout).expect("UTF-8 evidence");
    for required in [
        "version=1\n",
        "scenario=E2E-JOIN-001\n",
        "topology=two-clients-one-untrusted-service\n",
        "result=pass\n",
        "ipc=sessionctl-l1-ipc-v1\n",
        "alice_restart=close-reopen-independent-process\n",
        "service_forwarded=7\n",
        "admission=approved\n",
        "welcome=delivered\n",
        "joined_epoch=1\n",
        "messages=2\n",
        "updated_epoch=2\n",
        "removal=enforced\n",
        "post_removal=rejected\n",
        "redaction=pass\n",
        "child_cleanup=pass\n",
        "directory_cleanup=pass\n",
    ] {
        assert!(evidence.contains(required), "missing {required:?}");
    }

    let lowercase = evidence.to_ascii_lowercase();
    for forbidden in [
        "capability",
        "plaintext",
        "ciphertext",
        "vault",
        "database_key",
        "invitation_id",
        "mailbox_id",
        "envelope_id",
        "hello from",
        ".sqlite",
        "/tmp/",
        "\\temp\\",
    ] {
        assert!(!lowercase.contains(forbidden), "leaked term {forbidden:?}");
    }
}

#[test]
fn independent_process_runner_resolves_metadata_outside_the_repository() {
    let working_directory = marked_root("alternate-cwd");
    let output = Command::new(env!("CARGO_BIN_EXE_sessionctl-l1"))
        .current_dir(&working_directory)
        .output()
        .expect("run independent-process conformance binary outside repository");
    fs::remove_dir_all(&working_directory).expect("remove alternate working directory");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let evidence = std::str::from_utf8(&output.stdout).expect("UTF-8 evidence");
    assert!(!evidence.contains("commit=unavailable\n"));
    assert!(!evidence.contains("toolchain=unavailable\n"));
    assert!(!evidence.contains("lock_sha256=unavailable\n"));
}

#[test]
fn independent_process_runner_rejects_public_arguments() {
    let output = Command::new(env!("CARGO_BIN_EXE_sessionctl-l1"))
        .arg("--unknown")
        .output()
        .expect("run independent-process conformance binary");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"sessionctl-l1: unsupported invocation\n");
}

#[test]
fn internal_role_boundary_rejects_unmarked_and_unknown_scopes() {
    assert!(run_l1_process_internal_role("bob", "/".into()).is_err());

    let root = marked_root("unknown");
    assert!(run_l1_process_internal_role("unknown", root.clone()).is_err());
    fs::remove_dir_all(root).expect("remove marked test root");
}

#[test]
fn internal_roles_fail_closed_on_missing_or_malformed_scoped_inputs() {
    let alice_init = marked_root("alice-init");
    assert!(run_l1_process_internal_role("alice-init", alice_init.clone()).is_err());
    fs::remove_dir_all(alice_init).expect("remove Alice-init root");

    let alice_resume = marked_root("alice-resume");
    fs::create_dir(alice_resume.join("alice")).expect("create Alice state directory");
    fs::write(alice_resume.join("alice/resume.state"), b"invalid")
        .expect("write malformed Alice state");
    assert!(run_l1_process_internal_role("alice-resume", alice_resume.clone()).is_err());
    fs::remove_dir_all(alice_resume).expect("remove Alice-resume root");

    let bob = marked_root("bob");
    fs::create_dir(bob.join("direct")).expect("create Bob direct directory");
    fs::write(bob.join("direct/invitation.v2"), b"invalid").expect("write malformed invitation");
    assert!(run_l1_process_internal_role("bob", bob.clone()).is_err());
    fs::remove_dir_all(bob).expect("remove Bob root");

    let service = marked_root("service");
    fs::create_dir_all(service.join("relay/in")).expect("create relay input directory");
    fs::write(service.join("relay/in/001.frame"), b"invalid").expect("write malformed IPC frame");
    assert!(run_l1_process_internal_role("service", service.clone()).is_err());
    fs::remove_dir_all(service).expect("remove service root");
}

fn marked_root(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "session-chat-l1-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("create marked test root");
    fs::write(root.join(".sessionctl-l1-root"), b"sessionctl-l1-v1\n").expect("write root marker");
    root
}
