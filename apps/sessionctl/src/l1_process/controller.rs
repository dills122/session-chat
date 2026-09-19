//! L1 process controller and hidden role dispatcher.

use super::super::StageResult;
use super::super::provenance::repository_dirty_at;
use super::super::{SessionCtlError, stage};
use super::hostile::{
    run_hostile_matrix_alice, run_hostile_matrix_bob, run_hostile_matrix_controller,
    run_hostile_matrix_inspector, run_hostile_matrix_service, run_hostile_replay_alice,
    run_hostile_replay_bob, run_hostile_replay_controller, run_hostile_replay_inspector,
    run_hostile_replay_service,
};
use super::ipc::{atomic_write, read_bounded_wait};
use super::model::{L1ProcessReport, PrivateState};
use super::resources::{
    ChildSet, ProcessRoot, git_commit_at, lock_digest_at, pinned_toolchain_at, repository_root,
    require_child_output, two_terminal_done_path, unix_now, validate_root,
};
use super::roles::{
    run_alice_init, run_alice_init_with_wait, run_alice_resume, run_bob, run_service,
    run_service_with_initial_wait,
};
use super::{
    CAPABILITY_HANDOFF_DISCLOSURE, CHILD_WAIT, FRAME_WAIT, MAX_EVIDENCE_BYTES,
    OPERATOR_HANDOFF_WAIT, TWO_TERMINAL_DONE,
};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::thread;
/// Runs two independent clients plus an untrusted forwarding service.
pub fn run_l1_process_demo() -> Result<L1ProcessReport, SessionCtlError> {
    let started_at = unix_now()?;
    let mut root = ProcessRoot::new()?;
    let mut children = ChildSet::new();
    let scenario_result = run_l1_process_children(root.path(), &mut children);
    let child_cleanup_result = children.cleanup();
    let directory_cleanup_result = root.cleanup();
    scenario_result?;
    child_cleanup_result?;
    directory_cleanup_result?;

    let repository_root = repository_root().ok_or_else(|| stage("evidence provenance"))?;
    let dirty = repository_dirty_at(&repository_root)?;
    if dirty {
        return Err(stage("evidence provenance"));
    }
    let commit = git_commit_at(&repository_root);
    let toolchain = pinned_toolchain_at(&repository_root);
    let lock_digest = lock_digest_at(&repository_root);
    if commit == "unavailable" || toolchain == "unavailable" || lock_digest == "unavailable" {
        return Err(stage("evidence provenance"));
    }

    let report = L1ProcessReport {
        started_at,
        completed_at: unix_now()?,
        commit,
        dirty,
        toolchain,
        lock_digest,
    };
    if report.encode_v1().len() > MAX_EVIDENCE_BYTES {
        return Err(stage("evidence bound"));
    }
    Ok(report)
}

/// Runs Alice and the bounded local forwarder for a user-driven two-terminal proof.
///
/// `root` must be an absolute path that does not exist. The host creates and
/// removes the marked run directory; it never reuses or deletes an unmarked
/// path.
pub fn run_two_terminal_host(root: PathBuf) -> Result<(), SessionCtlError> {
    let mut root = ProcessRoot::create_at(root)?;
    let service_root = root.path().to_path_buf();
    println!("mode=host\nstatus=ready\nroot={}", root.path().display());
    print!("{CAPABILITY_HANDOFF_DISCLOSURE}");

    let service =
        thread::spawn(move || run_service_with_initial_wait(&service_root, OPERATOR_HANDOFF_WAIT));
    let scenario_result = (|| {
        let state = run_alice_init_with_wait(root.path(), OPERATOR_HANDOFF_WAIT)?;
        run_alice_resume(root.path(), state)?;
        let completion = read_bounded_wait(
            &two_terminal_done_path(root.path()),
            TWO_TERMINAL_DONE.len(),
            FRAME_WAIT,
        )?;
        if completion != TWO_TERMINAL_DONE {
            return Err(stage("two-terminal completion"));
        }
        Ok(())
    })();
    let service_result = service
        .join()
        .map_err(|_| stage("two-terminal service join"))?;
    scenario_result?;
    service_result?;
    root.cleanup()?;
    println!("mode=host\nstatus=complete");
    Ok(())
}

/// Runs Bob against a ready host-owned directory for a two-terminal proof.
pub fn run_two_terminal_join(root: PathBuf) -> Result<(), SessionCtlError> {
    validate_root(&root)?;
    println!("mode=join\nstatus=connected");
    run_bob(&root)?;
    atomic_write(
        &two_terminal_done_path(&root),
        TWO_TERMINAL_DONE,
        TWO_TERMINAL_DONE.len(),
    )?;
    println!("mode=join\nstatus=complete");
    Ok(())
}
pub(super) fn run_l1_process_children(
    root: &Path,
    children: &mut ChildSet,
) -> Result<(), SessionCtlError> {
    let executable = std::env::current_exe().at_stage("process executable")?;
    children.spawn(&executable, "service", root)?;
    children.spawn(&executable, "bob", root)?;
    let state = children.spawn_private_writer(&executable, "alice-init", root)?;

    let alice_init = children.wait_role("alice-init", CHILD_WAIT)?;
    require_child_output(&alice_init, b"role=alice-init\nresult=pass\n")?;
    children.spawn_with_io(
        &executable,
        "alice-resume",
        root,
        state.into(),
        Stdio::piped(),
    )?;

    let alice_resume = children.wait_role("alice-resume", CHILD_WAIT)?;
    require_child_output(
        &alice_resume,
        b"role=alice-resume\nresult=pass\nmessages=1\nupdated_epoch=2\nremoval=enforced\n",
    )?;
    let bob = children.wait_role("bob", CHILD_WAIT)?;
    require_child_output(
        &bob,
        b"role=bob\nresult=pass\njoined_epoch=1\nmessages=1\nupdated_epoch=2\nremoval=enforced\npost_removal=rejected\n",
    )?;
    let service = children.wait_role("service", CHILD_WAIT)?;
    require_child_output(
        &service,
        b"role=untrusted-service\nresult=pass\nforwarded=7\n",
    )?;
    if !children.is_empty() {
        return Err(stage("process cleanup"));
    }
    Ok(())
}

/// Runs one hidden role selected only by the controller process.
pub fn run_l1_process_internal_role(role: &str, root: PathBuf) -> Result<(), SessionCtlError> {
    validate_root(&root)?;
    match role {
        "service" => run_service(&root),
        "alice-init" => run_alice_init(&root)?.write_to(std::io::stderr()),
        "alice-resume" => run_alice_resume(&root, PrivateState::read_from(std::io::stdin())?),
        "bob" => run_bob(&root),
        "hostile-replay-controller" => run_hostile_replay_controller(&root),
        "hostile-replay-service" => run_hostile_replay_service(&root),
        "hostile-replay-alice" => run_hostile_replay_alice(&root)?.write_to(std::io::stderr()),
        "hostile-replay-bob" => run_hostile_replay_bob(&root),
        "hostile-replay-inspector" => run_hostile_replay_inspector(&root),
        "hostile-matrix-controller" => run_hostile_matrix_controller(&root),
        "hostile-matrix-service" => run_hostile_matrix_service(&root),
        "hostile-matrix-alice" => run_hostile_matrix_alice(&root)?.write_to(std::io::stderr()),
        "hostile-matrix-bob" => run_hostile_matrix_bob(&root),
        "hostile-matrix-inspector" => run_hostile_matrix_inspector(&root),
        _ => Err(stage("process role")),
    }
}
