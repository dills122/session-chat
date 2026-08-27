#![forbid(unsafe_code)]

use std::{
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use sessionctl::{resolve_l1_process_git_commit, run_l1_process_internal_role};

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
fn git_commit_resolution_is_independent_of_checkout_head_layout() {
    let direct_root = marked_root("direct-head");
    fs::create_dir(direct_root.join(".git")).expect("create direct Git directory");
    fs::write(
        direct_root.join(".git/HEAD"),
        b"ABCDEF0123456789ABCDEF0123456789ABCDEF01\n",
    )
    .expect("write direct HEAD");
    assert_eq!(
        resolve_l1_process_git_commit(&direct_root).as_deref(),
        Some("abcdef0123456789abcdef0123456789abcdef01")
    );
    fs::remove_dir_all(&direct_root).expect("remove direct-HEAD root");

    let symbolic_root = marked_root("symbolic-head");
    let git_directory = symbolic_root.join("worktree-git");
    let common_directory = symbolic_root.join("common-git");
    fs::create_dir(&git_directory).expect("create linked-worktree Git directory");
    fs::create_dir_all(common_directory.join("refs/heads")).expect("create common refs directory");
    fs::write(symbolic_root.join(".git"), b"gitdir: worktree-git\n")
        .expect("write linked-worktree marker");
    fs::write(git_directory.join("HEAD"), b"ref: refs/heads/fixture\n")
        .expect("write symbolic HEAD");
    fs::write(git_directory.join("commondir"), b"../common-git\n")
        .expect("write common-directory marker");
    fs::write(
        common_directory.join("refs/heads/fixture"),
        b"0123456789abcdef0123456789abcdef01234567\n",
    )
    .expect("write loose branch ref");
    assert_eq!(
        resolve_l1_process_git_commit(&symbolic_root).as_deref(),
        Some("0123456789abcdef0123456789abcdef01234567")
    );
    fs::remove_dir_all(&symbolic_root).expect("remove symbolic-HEAD root");
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
fn hostile_replayed_join_is_rejected_before_durable_membership_mutation() {
    let root = marked_root("hostile-replay");
    for directory in ["direct", "relay", "relay/in", "relay/out", "alice"] {
        fs::create_dir(root.join(directory)).expect("create hostile process directory");
    }

    let output = Command::new(env!("CARGO_BIN_EXE_sessionctl-l1"))
        .args(["--internal-role", "hostile-replay-controller"])
        .arg(&root)
        .output()
        .expect("run hostile replay conformance scenario");

    let controller_removed_root = !root.exists();
    if !controller_removed_root {
        fs::remove_dir_all(&root).expect("remove failed hostile replay root");
    }
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(output.stdout.len() <= MAX_EVIDENCE_BYTES);
    assert_eq!(
        output.stdout,
        b"version=1\nscenario=E2E-JOIN-002\ncase=replayed-protected-join\nresult=pass\nreplay=rejected\nmembership=unchanged\nredaction=pass\nchild_cleanup=pass\ndirectory_cleanup=pass\n"
    );
    assert!(
        controller_removed_root,
        "controller must remove the scenario root"
    );
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

    let hostile_service = marked_root("hostile-service");
    fs::create_dir_all(hostile_service.join("relay/in"))
        .expect("create hostile relay input directory");
    fs::write(hostile_service.join("relay/in/001.frame"), b"invalid")
        .expect("write malformed hostile IPC frame");
    assert!(
        run_l1_process_internal_role("hostile-replay-service", hostile_service.clone()).is_err()
    );
    fs::remove_dir_all(hostile_service).expect("remove hostile service root");

    let hostile_bob = marked_root("hostile-bob");
    fs::create_dir(hostile_bob.join("direct")).expect("create hostile Bob direct directory");
    fs::write(hostile_bob.join("direct/invitation.v2"), b"invalid")
        .expect("write malformed hostile invitation");
    assert!(run_l1_process_internal_role("hostile-replay-bob", hostile_bob.clone()).is_err());
    fs::remove_dir_all(hostile_bob).expect("remove hostile Bob root");

    let hostile_inspector = marked_root("hostile-inspector");
    fs::create_dir(hostile_inspector.join("alice"))
        .expect("create hostile inspector state directory");
    fs::write(hostile_inspector.join("alice/resume.state"), b"invalid")
        .expect("write malformed hostile inspector state");
    assert!(
        run_l1_process_internal_role("hostile-replay-inspector", hostile_inspector.clone())
            .is_err()
    );
    fs::remove_dir_all(hostile_inspector).expect("remove hostile inspector root");

    let hostile_alice = marked_root("hostile-alice");
    assert!(run_l1_process_internal_role("hostile-replay-alice", hostile_alice.clone()).is_err());
    fs::remove_dir_all(hostile_alice).expect("remove hostile Alice root");

    let hostile_controller = marked_root("hostile-controller");
    assert!(
        run_l1_process_internal_role("hostile-replay-controller", hostile_controller.clone())
            .is_err()
    );
    assert!(
        !hostile_controller.exists(),
        "failed hostile controller must still reap children and remove its root"
    );
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
