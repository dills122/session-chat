//! L1 process, IPC, root, and evidence unit tests.

use super::super::MAILBOX_EXPIRES_AT;
#[cfg(unix)]
use super::ROOT_MARKER;
use super::controller::run_l1_process_internal_role;
use super::hostile::{HostileJoinCase, build_hostile_join_request};
use super::ipc::{FrameKind, IpcFrame, atomic_write, read_bounded_wait};
use super::model::{L1ProcessReport, PrivateState};
use super::network::{
    connect_network_loopback_join, network_host_bridge, prepare_public_endpoint,
    read_bounded_wait_async, read_network_invitation, run_network_host_with_endpoint,
};
use super::resources::{
    ChildSet, ManagedChild, ProcessRoot, bounded_command_status, direct_invitation_path,
    frame_name, fresh_process_root_path, lock_digest_at, pinned_toolchain_at, validate_root,
};
#[cfg(unix)]
use super::resources::{create_private_directory, read_bounded_file};
use super::roles::run_alice_init_with_wait;
use super::{
    FRAME_WAIT, IPC_HEADER_BYTES, IPC_MAGIC, IPC_VERSION, MAX_EVIDENCE_BYTES, MAX_IPC_FRAME_BYTES,
    MAX_IPC_PARTS, MAX_LOCKFILE_BYTES, MAX_TOOLCHAIN_BYTES, NETWORK_OPERATION_WAIT,
    PRIVATE_STATE_BYTES,
};
use session_crypto_mls::{SESSION_GROUP_ID_BYTES, SessionGroupId};
use session_protocol::{MAX_WIRE_OBJECT_BYTES, OpaqueEnvelope, SignedCapabilityInvitationV2};
use std::ffi::OsStr;
use std::fs;
use std::fs::File;
#[cfg(unix)]
use std::fs::OpenOptions;
use std::future::ready;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};
use transport_iroh::{IrohFastEndpoint, IrohFastError};
use zeroize::Zeroizing;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn network_host_rejects_strays_before_accepting_the_legitimate_joiner() {
    let host_root = ProcessRoot::new().unwrap();
    let invitation_path = direct_invitation_path(host_root.path());
    let host = IrohFastEndpoint::bind_loopback().await.unwrap();
    let address = host.address();
    let task = tokio::spawn(run_network_host_with_endpoint(host_root, host));
    read_bounded_wait_async(invitation_path.clone(), MAX_WIRE_OBJECT_BYTES, FRAME_WAIT)
        .await
        .unwrap();
    let invitation = read_network_invitation(&invitation_path).unwrap();
    let invitation = SignedCapabilityInvitationV2::decode_and_verify(&invitation).unwrap();
    let protected = build_hostile_join_request(&invitation, HostileJoinCase::Copied).unwrap();
    let mut tampered = protected.encode_canonical().unwrap();
    *tampered.last_mut().unwrap() ^= 1;
    let wrong_hpke = IpcFrame::new(FrameKind::ProtectedJoin, 1, vec![tampered])
        .unwrap()
        .encode()
        .unwrap();
    let reordered = IpcFrame::new(
        FrameKind::ProtectedJoin,
        2,
        vec![protected.encode_canonical().unwrap()],
    )
    .unwrap()
    .encode()
    .unwrap();
    for payload in [None, Some(vec![0x80]), Some(wrong_hpke), Some(reordered)] {
        let peer = IrohFastEndpoint::bind_loopback().await.unwrap();
        let mut link = peer
            .connect_address(address.clone(), NETWORK_OPERATION_WAIT, MAX_IPC_FRAME_BYTES)
            .await
            .unwrap();
        if let Some(payload) = payload {
            link.send_frame(&payload, NETWORK_OPERATION_WAIT)
                .await
                .unwrap();
        }
        // A peer that never sends a stream, or sends malformed input, is
        // rejected without consuming Alice's one-shot join channel.
        assert!(link.receive_frame(Duration::from_secs(4)).await.is_err());
        link.reject();
        assert!(!task.is_finished());
    }
    let join = IrohFastEndpoint::bind_loopback().await.unwrap();
    connect_network_loopback_join(ProcessRoot::new().unwrap(), join, address, invitation_path)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn network_host_candidate_exhaustion_fails_closed() {
    let root = ProcessRoot::new().unwrap();
    let path = root.path().to_path_buf();
    let invitation = direct_invitation_path(&path);
    let host = IrohFastEndpoint::bind_loopback().await.unwrap();
    let address = host.address();
    let task = tokio::spawn(run_network_host_with_endpoint(root, host));
    read_bounded_wait_async(invitation, MAX_WIRE_OBJECT_BYTES, FRAME_WAIT)
        .await
        .unwrap();
    for _ in 0..32 {
        let peer = IrohFastEndpoint::bind_loopback().await.unwrap();
        let mut link = peer
            .connect_address(address.clone(), NETWORK_OPERATION_WAIT, MAX_IPC_FRAME_BYTES)
            .await
            .unwrap();
        link.send_frame(&[0x80], NETWORK_OPERATION_WAIT)
            .await
            .unwrap();
        assert!(link.receive_frame(Duration::from_secs(4)).await.is_err());
        link.reject();
    }
    assert!(
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(!path.exists());
}

#[test]
fn ipc_file_boundaries_under_permissive_umask() {
    const CHILD: &str = "SESSION_INGRESS_IPC_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let executable = std::env::current_exe().unwrap();
        #[cfg(unix)]
        let mut command = {
            let mut command = Command::new("sh");
            command
                .args(["-c", "umask 000; exec \"$@\"", "sh"])
                .arg(&executable);
            command
        };
        #[cfg(not(unix))]
        let mut command = Command::new(&executable);
        let child = command
            .args([
                "--exact",
                "l1_process::tests::ipc_file_boundaries_under_permissive_umask",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .spawn()
            .unwrap();
        let mut child = ManagedChild::new("IPC boundary test", child);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.child_mut().unwrap().try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(
                Instant::now() < deadline,
                "special file blocked a bounded IPC read"
            );
            thread::sleep(Duration::from_millis(10));
        }
        return;
    }
    let root = ProcessRoot::new().unwrap();
    validate_root(root.path()).unwrap();
    let regular = root.path().join("direct/regular");
    atomic_write(&regular, b"valid", 8).unwrap();
    assert_eq!(
        read_bounded_wait(&regular, 8, Duration::from_secs(1)).unwrap(),
        b"valid"
    );
    assert!(read_bounded_wait(&regular, 4, Duration::from_secs(1)).is_err());
    assert!(read_bounded_wait(root.path(), 8, Duration::from_secs(1)).is_err());
    let missing = root.path().join("direct/missing");
    assert!(read_bounded_wait(&missing, 8, Duration::from_millis(20)).is_err());
    let delayed = missing.clone();
    let writer = thread::spawn(move || {
        thread::sleep(Duration::from_millis(20));
        atomic_write(&delayed, b"later", 8).unwrap();
    });
    assert_eq!(
        read_bounded_wait(&missing, 8, Duration::from_secs(1)).unwrap(),
        b"later"
    );
    writer.join().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _, symlink};
        for path in [
            root.path().to_path_buf(),
            root.path().join("direct"),
            root.path().join("relay/in"),
            root.path().join("alice"),
        ] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        assert_eq!(
            fs::metadata(&regular).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let fifo = root.path().join("direct/fifo");
        assert!(
            Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        assert!(read_bounded_wait(&fifo, 8, Duration::from_secs(1)).is_err());
        // Keep both ends open: a blocking read would wait forever for EOF.
        let _fifo_owner = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo)
            .unwrap();
        assert!(read_bounded_wait(&fifo, 8, Duration::from_secs(1)).is_err());
        for (name, target) in [("fifo-link", &fifo), ("regular-link", &regular)] {
            let path = root.path().join("direct").join(name);
            symlink(target, &path).unwrap();
            assert!(read_bounded_wait(&path, 8, Duration::from_secs(1)).is_err());
            assert!(read_bounded_file(&path, 8).is_none());
        }
        let marker = root.path().join(".sessionctl-l1-root");
        fs::remove_file(&marker).unwrap();
        symlink(&fifo, &marker).unwrap();
        assert!(validate_root(root.path()).is_err());
        fs::remove_file(&marker).unwrap();
        atomic_write(&marker, ROOT_MARKER, ROOT_MARKER.len()).unwrap();
    }
}

#[test]
fn private_state_pipe_roundtrip_rejects_malformed_and_has_no_file_fallback() {
    let key = [0xa9; 32];
    let group_id = SessionGroupId::new([0xb8; SESSION_GROUP_ID_BYTES]).unwrap();
    let state = PrivateState {
        database_key: Zeroizing::new(key),
        group_id,
    };
    let (reader, writer) = std::io::pipe().unwrap();
    state.write_to(writer).unwrap();
    let restored = PrivateState::read_from(reader).unwrap();
    assert_eq!(*restored.database_key, key);
    assert!(restored.group_id == group_id);

    let mut encoded = Vec::new();
    restored.write_to(&mut encoded).unwrap();
    for length in [0, 7, PRIVATE_STATE_BYTES - 1] {
        assert!(PrivateState::read_from(&encoded[..length]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(PrivateState::read_from(trailing.as_slice()).is_err());
    encoded[0] ^= 1;
    assert!(PrivateState::read_from(encoded.as_slice()).is_err());
    encoded[0] ^= 1;
    encoded[8..40].fill(0);
    assert!(PrivateState::read_from(encoded.as_slice()).is_err());
}

#[tokio::test]
async fn invalid_process_root_fails_before_public_endpoint_binding() {
    let binder_called = Arc::new(AtomicBool::new(false));
    let called_by_binder = Arc::clone(&binder_called);

    let result = prepare_public_endpoint(
        PathBuf::from("relative-network-root"),
        "test endpoint",
        |_| Ok(()),
        move || {
            called_by_binder.store(true, Ordering::SeqCst);
            ready(Err(IrohFastError::EndpointUnavailable))
        },
    )
    .await;

    assert!(result.is_err());
    assert!(!binder_called.load(Ordering::SeqCst));
}

#[tokio::test]
async fn network_bridge_sends_no_invitation_after_a_public_probe() {
    let root = ProcessRoot::new().unwrap();
    let root_path = root.path().to_path_buf();
    let host = IrohFastEndpoint::bind_loopback().await.unwrap();
    let host_address = host.address();
    let join = IrohFastEndpoint::bind_loopback().await.unwrap();
    let host_task = tokio::spawn(async move {
        let link = host
            .accept(None, NETWORK_OPERATION_WAIT, MAX_IPC_FRAME_BYTES)
            .await
            .unwrap();
        network_host_bridge(&root_path, link).await
    });
    let mut connector = join
        .connect_address(host_address, NETWORK_OPERATION_WAIT, MAX_IPC_FRAME_BYTES)
        .await
        .unwrap();

    connector
        .send_frame(b"public-probe", NETWORK_OPERATION_WAIT)
        .await
        .unwrap();
    assert!(
        connector
            .receive_frame(Duration::from_secs(2))
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(2), host_task)
            .await
            .expect("host bridge stopped")
            .expect("host task")
            .is_err()
    );
}

#[test]
fn operator_handoff_wait_is_injectable_without_slow_tests() {
    let root = ProcessRoot::new().unwrap();
    let started = Instant::now();

    assert!(run_alice_init_with_wait(root.path(), Duration::from_millis(20)).is_err());
    assert!(started.elapsed() >= Duration::from_millis(20));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(direct_invitation_path(root.path()).is_file());
}

#[test]
fn invitation_reader_rejects_non_regular_paths() {
    let root = ProcessRoot::new().unwrap();

    assert!(read_network_invitation(root.path()).is_err());
}

#[cfg(unix)]
#[test]
fn invitation_reader_rejects_fifo_without_blocking() {
    let root = ProcessRoot::new().unwrap();
    let fifo = root.path().join("invitation.fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let started = Instant::now();

    assert!(read_network_invitation(&fifo).is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn process_root_cleanup_failure_is_reported_and_drop_retries() {
    let mut root = ProcessRoot::new().unwrap();
    let path = root.path().to_owned();

    assert!(
        root.cleanup_with(|_| Err(std::io::Error::other("injected removal failure")))
            .is_err()
    );
    assert!(path.exists());

    drop(root);
    assert!(!path.exists());
}

#[test]
fn process_root_creation_rejects_a_replacement_before_handle_acquisition() {
    let path = fresh_process_root_path("creation-replacement").unwrap();
    let moved = path.with_extension("created");
    let sentinel = path.join("replacement-sentinel");

    let result = ProcessRoot::create_at_with(path.clone(), |candidate| {
        fs::rename(candidate, &moved)?;
        fs::create_dir(candidate)?;
        fs::write(&sentinel, b"preserve pre-handle replacement")?;
        Ok(())
    });

    assert!(result.is_err());
    assert!(sentinel.is_file());
    assert!(moved.is_dir());
    fs::remove_dir_all(path).unwrap();
    fs::remove_dir_all(moved).unwrap();
}

#[cfg(unix)]
#[test]
fn process_root_cleanup_preserves_replacement_after_validation() {
    let mut root = ProcessRoot::new().unwrap();
    let path = root.path().to_owned();
    let moved = path.with_extension("owned");
    let sentinel = path.join("replacement-sentinel");

    let result = root.cleanup_with(|candidate| {
        fs::rename(candidate, &moved)?;
        fs::create_dir(candidate)?;
        fs::write(&sentinel, b"preserve replacement")?;
        Ok(())
    });

    let replacement_survived = sentinel.is_file();
    let owned_root_removed = !moved.exists();
    let _ = fs::remove_dir_all(&path);
    let _ = fs::remove_dir_all(&moved);

    assert!(result.is_ok());
    assert!(replacement_survived);
    assert!(owned_root_removed);
}

#[cfg(unix)]
#[test]
fn process_root_cleanup_preserves_same_marker_replacement() {
    let mut root = ProcessRoot::new().unwrap();
    let path = root.path().to_owned();
    let moved = path.with_extension("owned");
    let sentinel = path.join("replacement-sentinel");

    fs::rename(&path, &moved).unwrap();
    create_private_directory(&path).unwrap();
    fs::write(path.join(".sessionctl-l1-root"), ROOT_MARKER).unwrap();
    for directory in ["direct", "relay", "relay/in", "relay/out", "alice"] {
        create_private_directory(&path.join(directory)).unwrap();
    }
    fs::write(&sentinel, b"preserve same-marker replacement").unwrap();

    let result = root.cleanup();
    let replacement_survived = sentinel.is_file();
    let owned_root_removed = !moved.exists();
    let _ = fs::remove_dir_all(&path);
    let _ = fs::remove_dir_all(&moved);

    assert!(result.is_ok());
    assert!(replacement_survived);
    assert!(owned_root_removed);
}

#[cfg(windows)]
#[test]
fn process_root_cleanup_denies_rebinding_while_capability_is_live() {
    let mut root = ProcessRoot::new().unwrap();
    let path = root.path().to_owned();
    let moved = path.with_extension("replacement-attempt");

    let result = root.cleanup_with(|candidate| {
        assert!(fs::rename(candidate, &moved).is_err());
        Ok(())
    });

    assert!(result.is_ok());
    assert!(!path.exists());
    assert!(!moved.exists());
}

#[cfg(unix)]
#[test]
fn process_root_cleanup_rejects_symlink_replacement() {
    use std::os::unix::fs::symlink;

    let mut root = ProcessRoot::new().unwrap();
    let path = root.path().to_owned();
    let moved = path.with_extension("owned");
    let victim = path.with_extension("victim");
    create_private_directory(&victim).unwrap();
    let sentinel = victim.join("sentinel");
    fs::write(&sentinel, b"preserve symlink target").unwrap();
    fs::rename(&path, &moved).unwrap();
    symlink(&victim, &path).unwrap();

    let result = root.cleanup();
    let target_survived = sentinel.is_file();
    let _ = fs::remove_file(&path);
    let _ = fs::remove_dir_all(&moved);
    let _ = fs::remove_dir_all(&victim);

    assert!(result.is_err());
    assert!(target_survived);
}

#[test]
fn child_wait_error_keeps_child_owned_for_cleanup() {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "l1_process::tests::metadata_stall_child"])
        .env("SESSIONCTL_L1_STALL_CHILD", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = command.spawn().unwrap();
    let mut children = ChildSet(vec![ManagedChild::new("fixture", child)]);

    assert!(
        children
            .wait_role_with("fixture", Duration::from_secs(1), |_| {
                Err(std::io::Error::other("injected wait failure"))
            })
            .is_err()
    );
    assert_eq!(children.len(), 1);
    assert!(children.cleanup().is_ok());
    assert!(children.is_empty());
}

#[test]
fn oversized_repository_metadata_fails_bounded() {
    let root = ProcessRoot::new().unwrap();
    let lock = File::create(root.path().join("Cargo.lock")).unwrap();
    lock.set_len(u64::try_from(MAX_LOCKFILE_BYTES + 1).unwrap())
        .unwrap();
    let toolchain = File::create(root.path().join("rust-toolchain.toml")).unwrap();
    toolchain
        .set_len(u64::try_from(MAX_TOOLCHAIN_BYTES + 1).unwrap())
        .unwrap();

    assert_eq!(lock_digest_at(root.path()), "unavailable");
    assert_eq!(pinned_toolchain_at(root.path()), "unavailable");
}

#[test]
fn stalled_metadata_command_is_killed_within_deadline() {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "l1_process::tests::metadata_stall_child"])
        .env("SESSIONCTL_L1_STALL_CHILD", "1");
    let started = Instant::now();

    assert!(bounded_command_status(command, Duration::from_millis(25)).is_none());
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn metadata_command_does_not_wait_for_inherited_output() {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "l1_process::tests::metadata_inherited_output_parent",
            "--nocapture",
        ])
        .env("SESSIONCTL_L1_INHERITED_OUTPUT_PARENT", "1");
    let started = Instant::now();

    let _ = bounded_command_status(command, Duration::from_secs(1));
    assert!(started.elapsed() < Duration::from_millis(500));
}

#[test]
fn metadata_stall_child() {
    if std::env::var_os("SESSIONCTL_L1_STALL_CHILD").is_some() {
        thread::sleep(Duration::from_secs(5));
    }
}

#[test]
fn metadata_inherited_output_parent() {
    if std::env::var_os("SESSIONCTL_L1_INHERITED_OUTPUT_PARENT").is_some() {
        let mut descendant = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "l1_process::tests::metadata_inherited_output_descendant",
                "--nocapture",
            ])
            .env("SESSIONCTL_L1_INHERITED_OUTPUT_DESCENDANT", "1")
            .spawn()
            .unwrap();
        thread::spawn(move || {
            let _ = descendant.wait();
        });
    }
}

#[test]
fn metadata_inherited_output_descendant() {
    if std::env::var_os("SESSIONCTL_L1_INHERITED_OUTPUT_DESCENDANT").is_some() {
        thread::sleep(Duration::from_secs(2));
    }
}

#[test]
fn ipc_decoder_rejects_trailing_and_non_wire_payloads() {
    let envelope = OpaqueEnvelope::new([1; 16], MAILBOX_EXPIRES_AT, vec![2])
        .unwrap()
        .encode_canonical()
        .unwrap();
    let frame = IpcFrame::new(FrameKind::OpaqueEnvelope, 3, vec![envelope]).unwrap();
    let mut encoded = frame.encode().unwrap();
    assert!(IpcFrame::decode(&encoded).is_ok());
    encoded.push(0);
    assert!(IpcFrame::decode(&encoded).is_err());
    assert!(IpcFrame::new(FrameKind::OpaqueEnvelope, 3, vec![vec![1]]).is_err());
}

#[test]
fn ipc_decoder_rejects_every_header_and_part_bound() {
    assert!(IpcFrame::decode(&[]).is_err());
    assert!(IpcFrame::decode(&vec![0; MAX_IPC_FRAME_BYTES + 1]).is_err());

    let mut header = vec![0; IPC_HEADER_BYTES];
    header[..8].copy_from_slice(IPC_MAGIC);
    header[8] = IPC_VERSION;
    header[9] = FrameKind::OpaqueEnvelope as u8;
    header[10] = 3;
    header[11] = 1;

    let mut wrong_magic = header.clone();
    wrong_magic[0] = 0;
    assert!(IpcFrame::decode(&wrong_magic).is_err());
    let mut wrong_version = header.clone();
    wrong_version[8] = IPC_VERSION + 1;
    assert!(IpcFrame::decode(&wrong_version).is_err());
    let mut wrong_kind = header.clone();
    wrong_kind[9] = 255;
    assert!(IpcFrame::decode(&wrong_kind).is_err());
    let mut no_parts = header.clone();
    no_parts[11] = 0;
    assert!(IpcFrame::decode(&no_parts).is_err());
    let mut too_many_parts = header;
    too_many_parts[11] = u8::try_from(MAX_IPC_PARTS + 1).unwrap();
    assert!(IpcFrame::decode(&too_many_parts).is_err());

    assert!(IpcFrame::new(FrameKind::OpaqueEnvelope, 0, vec![vec![1]]).is_err());
    assert!(
        IpcFrame::new(
            FrameKind::OpaqueEnvelope,
            3,
            vec![vec![0; MAX_WIRE_OBJECT_BYTES + 1]],
        )
        .is_err()
    );
    assert!(IpcFrame::new(FrameKind::WelcomeDeposit, 2, vec![vec![1]]).is_err());
}

#[test]
fn internal_roles_reject_unmarked_roots_and_unknown_sequences() {
    assert!(run_l1_process_internal_role("unknown", PathBuf::from("/")).is_err());
    assert_eq!(frame_name(0), OsStr::new("invalid.frame"));
}

#[test]
fn evidence_is_bounded_and_has_no_local_paths() {
    let report = L1ProcessReport {
        started_at: 1,
        completed_at: 2,
        commit: "a".repeat(40),
        dirty: true,
        toolchain: String::from("1.97.1"),
        lock_digest: "b".repeat(64),
    };
    let evidence = report.encode_v1();
    assert!(evidence.len() <= MAX_EVIDENCE_BYTES);
    assert!(!evidence.contains('/'));
    assert!(!evidence.contains(".sqlite"));
}
