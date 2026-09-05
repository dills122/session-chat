#![forbid(unsafe_code)]

use std::{
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use mls_rs_core::{
    crypto::HpkeSecretKey,
    group::{EpochRecord, GroupState, GroupStateStorage},
    key_package::{KeyPackageData, KeyPackageStorage},
};
use session_crypto_hpke::AwsLcInvitationJoinProtector;
use session_protocol::{DepositCapability, LocalWelcomeDepositEndpoint, OpaqueEnvelope};
use session_transport::WelcomeOutboxPort;
use sessionctl::{
    resolve_l1_process_git_commit, run_l1_process_internal_role, run_network_host,
    run_network_join, run_two_terminal_host,
};
use storage_sqlcipher::{
    AuthorizationShadowInput, AuthorizationState, InvitationOpeningState, InvitationState,
    InviterJoinTransaction, JoinerTransaction, PersistenceFault, SqlCipherStorage, VaultKey,
    WelcomeOutboxState,
};
use zeroize::Zeroizing;

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
fn git_commit_resolution_rejects_malformed_bounded_metadata() {
    let missing = marked_root("git-missing");
    assert_eq!(resolve_l1_process_git_commit(&missing), None);
    fs::remove_dir_all(missing).expect("remove missing-Git root");

    for (label, marker) in [
        ("git-marker-utf8", vec![0xff]),
        ("git-marker-prefix", b"worktree-git\n".to_vec()),
    ] {
        let root = marked_root(label);
        fs::write(root.join(".git"), marker).expect("write malformed Git marker");
        assert_eq!(resolve_l1_process_git_commit(&root), None);
        fs::remove_dir_all(root).expect("remove malformed-marker root");
    }

    let oversized = marked_root("git-marker-oversized");
    let marker = fs::File::create(oversized.join(".git")).expect("create oversized Git marker");
    marker.set_len(4_097).expect("size oversized Git marker");
    assert_eq!(resolve_l1_process_git_commit(&oversized), None);
    fs::remove_dir_all(oversized).expect("remove oversized-marker root");

    for (label, head) in [
        ("git-head-utf8", vec![0xff]),
        ("git-head-short", b"01234567\n".to_vec()),
        (
            "git-head-nonhex",
            b"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n".to_vec(),
        ),
        ("git-ref-prefix", b"ref: heads/fixture\n".to_vec()),
        ("git-ref-absolute", b"ref: /refs/heads/fixture\n".to_vec()),
        ("git-ref-parent", b"ref: refs/heads/../fixture\n".to_vec()),
    ] {
        let root = marked_root(label);
        fs::create_dir(root.join(".git")).expect("create Git directory");
        fs::write(root.join(".git/HEAD"), head).expect("write malformed HEAD");
        assert_eq!(resolve_l1_process_git_commit(&root), None);
        fs::remove_dir_all(root).expect("remove malformed-HEAD root");
    }

    let oversized_head = marked_root("git-head-oversized");
    fs::create_dir(oversized_head.join(".git")).expect("create oversized-HEAD Git directory");
    let head = fs::File::create(oversized_head.join(".git/HEAD")).expect("create oversized HEAD");
    head.set_len(513).expect("size oversized HEAD");
    assert_eq!(resolve_l1_process_git_commit(&oversized_head), None);
    fs::remove_dir_all(oversized_head).expect("remove oversized-HEAD root");

    let loose = marked_root("git-loose-worktree");
    fs::create_dir_all(loose.join(".git/refs/heads")).expect("create loose ref directory");
    fs::write(loose.join(".git/HEAD"), b"ref: refs/heads/fixture\n").expect("write loose-ref HEAD");
    fs::write(
        loose.join(".git/refs/heads/fixture"),
        b"abcdef0123456789abcdef0123456789abcdef01\n",
    )
    .expect("write loose ref");
    assert_eq!(
        resolve_l1_process_git_commit(&loose).as_deref(),
        Some("abcdef0123456789abcdef0123456789abcdef01")
    );
    fs::remove_dir_all(loose).expect("remove loose-ref root");

    let absolute = marked_root("git-absolute-marker");
    let git_directory = absolute.join("absolute-git");
    fs::create_dir(&git_directory).expect("create absolute Git directory");
    fs::write(
        absolute.join(".git"),
        format!("gitdir: {}\n", git_directory.display()),
    )
    .expect("write absolute Git marker");
    fs::write(
        git_directory.join("HEAD"),
        b"0123456789abcdef0123456789abcdef01234567\n",
    )
    .expect("write absolute-marker HEAD");
    assert_eq!(
        resolve_l1_process_git_commit(&absolute).as_deref(),
        Some("0123456789abcdef0123456789abcdef01234567")
    );
    fs::remove_dir_all(absolute).expect("remove absolute-marker root");
}

#[tokio::test]
async fn public_wrappers_reject_invalid_local_inputs_before_external_work() {
    assert!(
        run_network_host("relative-network-root".into())
            .await
            .is_err()
    );
    assert!(
        run_network_join(
            "not-an-endpoint",
            "relative-invitation".into(),
            std::env::temp_dir().join("unused-network-join-root"),
        )
        .await
        .is_err()
    );

    let invitation_directory = marked_root("network-invitation-directory");
    assert!(
        run_network_join(
            "not-an-endpoint",
            invitation_directory.clone(),
            std::env::temp_dir().join("unused-network-join-root-2"),
        )
        .await
        .is_err()
    );
    fs::remove_dir_all(invitation_directory).expect("remove invitation-directory root");

    let host = marked_root("two-terminal-host");
    assert!(run_two_terminal_host(host.clone()).is_err());
    fs::remove_dir_all(host).expect("remove two-terminal host root");
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
fn hostile_first_contact_matrix_rejects_every_remaining_process_case() {
    let root = marked_root("hostile-matrix");
    let output = Command::new(env!("CARGO_BIN_EXE_sessionctl-l1"))
        .args(["--internal-role", "hostile-matrix-controller"])
        .arg(&root)
        .output()
        .expect("run hostile first-contact matrix");

    let controller_removed_root = !root.exists();
    if !controller_removed_root {
        fs::remove_dir_all(&root).expect("remove failed hostile matrix root");
    }
    assert!(output.status.success(), "status: {:?}", output.status);
    assert!(
        output.stderr.is_empty(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.len() <= MAX_EVIDENCE_BYTES);
    assert_eq!(
        output.stdout,
        b"version=1\nscenario=E2E-JOIN-002\ntopology=two-clients-one-untrusted-service\nresult=pass\ncases=malformed-protected-join,expired-protected-join,copied-protected-join,wrong-invitation,wrong-key-package,wrong-verifier,reordered-protected-joins\ncase_count=7\napproval=not-reached\nmls_add=not-reached\nmembership=unchanged\nservice_input=canonical-public-only\nredaction=pass\nchild_cleanup=pass\ndirectory_cleanup=pass\n"
    );
    let lowercase = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
    for forbidden in [
        "capability",
        "plaintext",
        "ciphertext",
        "vault",
        "database_key",
        "invitation_id",
        "mailbox_id",
        "envelope_id",
        ".sqlite",
        "/tmp/",
        "\\temp\\",
    ] {
        assert!(!lowercase.contains(forbidden), "leaked term {forbidden:?}");
    }
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

    for role in [
        "hostile-matrix-service",
        "hostile-matrix-alice",
        "hostile-matrix-bob",
        "hostile-matrix-inspector",
    ] {
        let root = marked_root(role);
        assert!(run_l1_process_internal_role(role, root.clone()).is_err());
        fs::remove_dir_all(root).expect("remove hostile matrix role root");
    }
}

#[test]
fn service_rejects_each_malformed_ipc_header_and_part_boundary() {
    const HEADER_BYTES: usize = 12;
    const MAGIC: &[u8; 8] = b"SCL1IPC1";

    let mut header = vec![0; HEADER_BYTES];
    header[..8].copy_from_slice(MAGIC);
    header[8] = 1;
    header[9] = 1;
    header[10] = 1;
    header[11] = 1;

    let mut cases = Vec::new();
    let mut wrong_magic = header.clone();
    wrong_magic[0] = 0;
    cases.push(("wrong-magic", wrong_magic));
    let mut wrong_version = header.clone();
    wrong_version[8] = 2;
    cases.push(("wrong-version", wrong_version));
    let mut wrong_kind = header.clone();
    wrong_kind[9] = 255;
    cases.push(("wrong-kind", wrong_kind));
    let mut no_parts = header.clone();
    no_parts[11] = 0;
    cases.push(("no-parts", no_parts));
    let mut too_many_parts = header.clone();
    too_many_parts[11] = 3;
    cases.push(("too-many-parts", too_many_parts));
    cases.push(("missing-length", header.clone()));

    let mut missing_payload = header.clone();
    missing_payload.extend_from_slice(&1_u32.to_be_bytes());
    cases.push(("missing-payload", missing_payload));
    let mut empty_part = header.clone();
    empty_part.extend_from_slice(&0_u32.to_be_bytes());
    cases.push(("empty-part", empty_part));
    let mut invalid_wire = header.clone();
    invalid_wire.extend_from_slice(&1_u32.to_be_bytes());
    invalid_wire.push(0);
    cases.push(("invalid-wire", invalid_wire.clone()));
    let mut invalid_sequence = invalid_wire.clone();
    invalid_sequence[10] = 0;
    cases.push(("invalid-sequence", invalid_sequence));
    let mut wrong_part_count = invalid_wire;
    wrong_part_count[11] = 2;
    wrong_part_count.extend_from_slice(&1_u32.to_be_bytes());
    wrong_part_count.push(0);
    cases.push(("wrong-part-count", wrong_part_count));

    let envelope = OpaqueEnvelope::new([0x31; 16], 1_900_000_300, vec![0x32])
        .expect("bounded envelope")
        .encode_canonical()
        .expect("canonical envelope");
    let opaque = encode_ipc_frame(3, 1, std::slice::from_ref(&envelope));
    cases.push(("valid-opaque-wrong-schedule", opaque.clone()));
    let mut trailing = opaque;
    trailing.push(0);
    cases.push(("trailing-byte", trailing));
    cases.push((
        "valid-opaque-invalid-sequence",
        encode_ipc_frame(3, 0, std::slice::from_ref(&envelope)),
    ));
    cases.push((
        "valid-opaque-wrong-count",
        encode_ipc_frame(3, 1, &[envelope.clone(), envelope.clone()]),
    ));

    let endpoint = LocalWelcomeDepositEndpoint::new(
        [0x33; 16],
        [0x34; 16],
        DepositCapability::new([0x35; 32]).expect("deposit capability"),
        1_900_000_400,
    )
    .expect("bounded endpoint")
    .encode_canonical()
    .expect("canonical endpoint");
    cases.push((
        "valid-welcome-wrong-schedule",
        encode_ipc_frame(2, 1, &[endpoint, envelope]),
    ));

    for (label, frame) in cases {
        assert_service_rejects_frame(label, &frame);
    }
}

#[test]
fn app_storage_owner_recovers_abandonment_joiner_consumption_and_welcome_retry() {
    const NOW: u64 = 1_900_000_000;
    let root = marked_root("app-storage-owner");
    let database = root.join("owner.sqlite3");
    let protector = AwsLcInvitationJoinProtector::new();
    let mut storage = SqlCipherStorage::create(
        &database,
        VaultKey::new([0x41; 32]).expect("nonzero storage key"),
    )
    .expect("create app owner store");
    assert_eq!(storage.schema_version().expect("schema version"), 5);
    assert!(!storage.cipher_version().expect("cipher version").is_empty());
    assert!(storage.integrity_check().expect("integrity check"));

    let invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("issue durable invitation");
    let invitation_id = *invitation.invitation().invitation_id();
    let pending = storage
        .reserve_authorization(
            &protector,
            AuthorizationShadowInput::new(
                invitation_id,
                *invitation.invitation().signature(),
                *invitation.invitation().join_challenge(),
                [0x42; 16],
                [0x43; 32],
                *invitation.invitation().inviter_verifying_key(),
                [0x44; 32],
                [0x45; 32],
                [0x46; 32],
                [0x47; 32],
                NOW,
                NOW + 120,
                NOW + 300,
            )
            .expect("bounded authorization shadow"),
            NOW,
        )
        .expect("reserve durable authorization");
    let attempt_id = *pending.attempt_id();
    storage
        .abandon_pending_authorization(pending, &protector, NOW + 1)
        .expect("abandon pending authorization");
    assert_eq!(
        storage
            .authorization_state(&attempt_id)
            .expect("authorization state"),
        Some(AuthorizationState::Abandoned)
    );
    assert_eq!(
        storage
            .invitation_opening_state(&invitation_id)
            .expect("opening state"),
        Some(InvitationOpeningState::Available)
    );

    let key_package_reference = [0x51; 32];
    KeyPackageStorage::insert(
        &mut storage,
        key_package_reference.to_vec(),
        KeyPackageData::new(
            vec![0x52],
            HpkeSecretKey::from(vec![0x53]),
            HpkeSecretKey::from(vec![0x54]),
            NOW + 60,
        ),
    )
    .expect("insert one-time KeyPackage");
    storage
        .stage_joiner(
            JoinerTransaction::new([0x55; 16], [0x56; 32], key_package_reference)
                .expect("bounded joiner transaction"),
            PersistenceFault::None,
        )
        .expect("stage joiner transaction");
    GroupStateStorage::write(
        &mut storage,
        GroupState {
            id: vec![0x56; 32],
            data: Zeroizing::new(vec![0x57]),
        },
        vec![EpochRecord::new(0, Zeroizing::new(vec![0x58]))],
        vec![EpochRecord::new(0, Zeroizing::new(vec![0x59]))],
    )
    .expect("write joiner MLS state");
    KeyPackageStorage::delete(&mut storage, &key_package_reference)
        .expect("consume exact KeyPackage");
    assert!(
        !storage
            .key_package_exists(&key_package_reference)
            .expect("KeyPackage lookup")
    );
    assert!(
        storage
            .recover_joiner(&[0x55; 16])
            .expect("joiner recovery")
            .is_some()
    );

    let reservation_id = [0x61; 16];
    let generation = [0x62; 64];
    let join_request_id = [0x63; 16];
    storage
        .seed_reservation(reservation_id, generation, join_request_id, NOW + 120, NOW)
        .expect("seed exact invitation reservation");
    let welcome = OpaqueEnvelope::new([0x64; 16], NOW + 180, vec![0x65])
        .expect("bounded Welcome")
        .encode_canonical()
        .expect("canonical Welcome");
    let endpoint = LocalWelcomeDepositEndpoint::new(
        [0x66; 16],
        [0x67; 16],
        DepositCapability::new([0x68; 32]).expect("deposit capability"),
        NOW + 240,
    )
    .expect("bounded endpoint")
    .encode_canonical()
    .expect("canonical endpoint");
    storage
        .stage_inviter(
            InviterJoinTransaction::new(
                [0x69; 16],
                reservation_id,
                generation,
                join_request_id,
                [0x6A; 32],
                [0x6B; 32],
                0,
                1,
                vec![0x6C],
                welcome,
                endpoint,
                NOW + 120,
            )
            .expect("bounded inviter transaction"),
            NOW,
            PersistenceFault::None,
        )
        .expect("stage inviter transaction");
    GroupStateStorage::write(
        &mut storage,
        GroupState {
            id: vec![0x6B; 32],
            data: Zeroizing::new(vec![0x6D]),
        },
        vec![EpochRecord::new(0, Zeroizing::new(vec![0x6E]))],
        vec![EpochRecord::new(0, Zeroizing::new(vec![0x6F]))],
    )
    .expect("commit inviter and Welcome outbox");
    assert_eq!(
        storage
            .invitation_state(&reservation_id)
            .expect("invitation state"),
        Some(InvitationState::Consumed)
    );
    let lease = storage
        .lease_next(NOW + 1, 10)
        .expect("lease pending Welcome")
        .expect("Welcome work exists");
    storage
        .report_failed(lease.discard_payload())
        .expect("release failed Welcome lease");
    let recovery = storage
        .recover_inviter(&[0x69; 16])
        .expect("inviter recovery")
        .expect("inviter transaction exists");
    assert_eq!(recovery.outbox_state, WelcomeOutboxState::Pending);
    assert_eq!(recovery.delivery_attempts, 1);

    drop(storage);
    fs::remove_dir_all(root).expect("remove app owner store");
}

fn encode_ipc_frame(kind: u8, sequence: u8, parts: &[Vec<u8>]) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"SCL1IPC1");
    encoded.extend_from_slice(&[
        1,
        kind,
        sequence,
        u8::try_from(parts.len()).expect("part count"),
    ]);
    for part in parts {
        encoded.extend_from_slice(
            &u32::try_from(part.len())
                .expect("bounded part")
                .to_be_bytes(),
        );
        encoded.extend_from_slice(part);
    }
    encoded
}

fn assert_service_rejects_frame(label: &str, frame: &[u8]) {
    let root = marked_root(label);
    fs::create_dir_all(root.join("relay/in")).expect("create relay input directory");
    fs::create_dir_all(root.join("relay/out")).expect("create relay output directory");
    fs::write(root.join("relay/in/001.frame"), frame).expect("write malformed IPC frame");
    assert!(run_l1_process_internal_role("service", root.clone()).is_err());
    fs::remove_dir_all(root).expect("remove malformed IPC root");
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
