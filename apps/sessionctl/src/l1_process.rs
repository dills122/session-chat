//! Bounded independent-process conformance runner.
//!
//! This module is a test topology, not a network transport or production
//! credential-custody design. Its relay receives only canonical public wire
//! objects and the one deposit authority it exercises. The bearer invitation
//! and encrypted-owner key state remain on distinct direct/private channels.

use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    future::{Future, ready},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use admission_capability::{
    CapabilityAdmissionPolicy, CapabilityAdmissionVerifier, CapabilityApprovalOutcome,
    ManualApprovalDecision,
};
use aws_lc_rs::digest::{SHA256, digest};
use session_admission::{AdmissionMethod, PendingAdmission};
use session_core::{InvitationPolicy, InvitationRegistry};
use session_crypto::{MessageEvent, MessageSession, ProtectedMessage};
use session_crypto_hpke::{AwsLcInvitationJoinProtector, InvitationJoinProtector};
use session_crypto_mls::{
    SESSION_GROUP_ID_BYTES, SessionGroupId, WelcomeMessage, create_client,
    create_durable_client_with_storage, create_key_package_validator,
    load_durable_client_with_storage,
};
use session_protocol::{
    CapabilityJoinRequest, InvitationJoinBinding, JoinRequestBinding, LocalWelcomeDepositEndpoint,
    MAX_WIRE_OBJECT_BYTES, MlsKeyPackageBinding, OpaqueEnvelope, ProtectedJoinRequest,
    SignedCapabilityInvitationV2,
};
use session_transport::{
    BlockingFutureSupervisor, CoordinatorOutcome, CoordinatorPolicy, DepositReceipt,
    DepositRequest, DepositRight, DispatchControl, EnvelopeDeposit, LocalMailboxPolicy,
    LocalMemoryWelcomeTransport, LocalV1DepositEndpointResolver, RetryAdvice,
    ThreadDispatchControl, TransportFailure, TransportFailureCode, WelcomeDeliveryCoordinator,
};
use storage_sqlcipher::{
    AuthorizationShadowInput, AuthorizationState, InvitationOpeningState, InviterJoinTransaction,
    PersistenceFault, SqlCipherStorage, StoreError, VaultKey, WelcomeOutboxState,
};
use transport_iroh::{
    FastEndpointAddress, FastEndpointId, IrohFastEndpoint, IrohFastError, IrohFastLink,
    MAX_FAST_FRAME_BYTES,
};
use zeroize::{Zeroize, Zeroizing};

use super::{
    INVITATION_EXPIRES_AT, MAILBOX_EXPIRES_AT, NOW, REQUEST_EXPIRES_AT, SessionCtlError,
    StageResult, encode_approval_record, random_nonzero, stage,
};

const IPC_MAGIC: &[u8; 8] = b"SCL1IPC1";
const IPC_VERSION: u8 = 1;
const IPC_HEADER_BYTES: usize = 12;
const IPC_LENGTH_BYTES: usize = 4;
const MAX_IPC_PARTS: usize = 2;
const MAX_IPC_FRAME_BYTES: usize =
    IPC_HEADER_BYTES + (MAX_IPC_PARTS * IPC_LENGTH_BYTES) + (2 * MAX_WIRE_OBJECT_BYTES);
const FRAME_WAIT: Duration = Duration::from_secs(30);
const CHILD_WAIT: Duration = Duration::from_secs(90);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_CHILD_OUTPUT_BYTES: usize = 512;
const PRIVATE_STATE_MAGIC: &[u8; 8] = b"SCL1STAT";
const PRIVATE_STATE_BYTES: usize = 8 + 32 + SESSION_GROUP_ID_BYTES;
const ROOT_MARKER: &[u8] = b"sessionctl-l1-v1\n";
const MAX_EVIDENCE_BYTES: usize = 2_048;
const EXPECTED_FRAMES: u8 = 7;
const MAX_LOCKFILE_BYTES: usize = 4 * 1024 * 1024;
const MAX_TOOLCHAIN_BYTES: usize = 4_096;
const MAX_GIT_PATH_BYTES: usize = 4_096;
const MAX_GIT_REF_BYTES: usize = 512;
const METADATA_COMMAND_WAIT: Duration = Duration::from_secs(5);
const TWO_TERMINAL_DONE: &[u8] = b"sessionctl-two-terminal-complete-v1\n";
const NETWORK_OPERATION_WAIT: Duration = Duration::from_secs(30);
const OPERATOR_HANDOFF_WAIT: Duration = Duration::from_secs(5 * 60);

const _: () = assert!(MAX_IPC_FRAME_BYTES <= MAX_FAST_FRAME_BYTES);

/// Secret-free outcome of the bounded independent-process scenario.
#[derive(Clone, Eq, PartialEq)]
pub struct L1ProcessReport {
    started_at: u64,
    completed_at: u64,
    commit: String,
    dirty: bool,
    toolchain: String,
    lock_digest: String,
}

impl L1ProcessReport {
    /// Encodes the retained versioned evidence manifest.
    #[must_use]
    pub fn encode_v1(&self) -> String {
        let evidence = format!(
            concat!(
                "version=1\n",
                "scenario=E2E-JOIN-001\n",
                "topology=two-clients-one-untrusted-service\n",
                "result=pass\n",
                "schedule_seed=1\n",
                "ipc=sessionctl-l1-ipc-v1\n",
                "wire_objects=protected-join,local-welcome-endpoint,opaque-envelope\n",
                "alice_restart=close-reopen-independent-process\n",
                "platform={}-{}\n",
                "commit={}\n",
                "dirty={}\n",
                "toolchain={}\n",
                "lock_sha256={}\n",
                "command=sessionctl-l1\n",
                "started_at={}\n",
                "completed_at={}\n",
                "frame_budget_bytes={}\n",
                "frame_wait_seconds={}\n",
                "child_wait_seconds={}\n",
                "service_forwarded=7\n",
                "admission=approved\n",
                "welcome=delivered\n",
                "joined_epoch=1\n",
                "messages=2\n",
                "updated_epoch=2\n",
                "removal=enforced\n",
                "post_removal=rejected\n",
                "artifact_hashes=omitted-authority-bearing\n",
                "redaction=pass\n",
                "child_cleanup=pass\n",
                "directory_cleanup=pass\n"
            ),
            std::env::consts::OS,
            std::env::consts::ARCH,
            self.commit,
            if self.dirty { "true" } else { "false" },
            self.toolchain,
            self.lock_digest,
            self.started_at,
            self.completed_at,
            MAX_IPC_FRAME_BYTES,
            FRAME_WAIT.as_secs(),
            CHILD_WAIT.as_secs(),
        );
        debug_assert!(evidence.len() <= MAX_EVIDENCE_BYTES);
        evidence
    }
}

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

    let repository_root = repository_root();

    let report = L1ProcessReport {
        started_at,
        completed_at: unix_now()?,
        commit: repository_root
            .as_deref()
            .map(git_commit_at)
            .unwrap_or_else(|| String::from("unavailable")),
        dirty: repository_root.as_deref().is_none_or(git_dirty_at),
        toolchain: repository_root
            .as_deref()
            .map(pinned_toolchain_at)
            .unwrap_or_else(|| String::from("unavailable")),
        lock_digest: repository_root
            .as_deref()
            .map(lock_digest_at)
            .unwrap_or_else(|| String::from("unavailable")),
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

    let service =
        thread::spawn(move || run_service_with_initial_wait(&service_root, OPERATOR_HANDOFF_WAIT));
    let scenario_result = (|| {
        run_alice_init_with_wait(root.path(), OPERATOR_HANDOFF_WAIT)?;
        run_alice_resume(root.path())?;
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

/// Hosts the full Phase 1 proof over the explicit public Iroh Fast link.
pub async fn run_network_host(root: PathBuf) -> Result<(), SessionCtlError> {
    let (root, endpoint) = prepare_public_endpoint(
        root,
        "network host endpoint",
        |_| Ok(()),
        IrohFastEndpoint::bind_public,
    )
    .await?;
    endpoint
        .wait_online(NETWORK_OPERATION_WAIT)
        .await
        .at_stage("network host online")?;
    println!(
        "mode=network-host\nprofile=fast-v1\nmetadata=peer-or-relay-addresses-timing-volume\nendpoint={}",
        endpoint.id().as_text()
    );
    run_network_host_with_endpoint(root, endpoint).await
}

/// Joins a public Iroh Fast host with a separately transferred bearer invitation.
pub async fn run_network_join(
    host: &str,
    invitation_path: PathBuf,
    root: PathBuf,
) -> Result<(), SessionCtlError> {
    let invitation = read_network_invitation(&invitation_path)?;
    let host = FastEndpointId::parse(host).at_stage("network host identity")?;
    let (root, endpoint) = prepare_public_endpoint(
        root,
        "network join endpoint",
        |root| {
            atomic_write(
                &direct_invitation_path(root.path()),
                &invitation,
                MAX_WIRE_OBJECT_BYTES,
            )
        },
        IrohFastEndpoint::bind_public,
    )
    .await?;
    endpoint
        .wait_online(NETWORK_OPERATION_WAIT)
        .await
        .at_stage("network join online")?;
    let link = endpoint
        .connect_public(host, NETWORK_OPERATION_WAIT, MAX_IPC_FRAME_BYTES)
        .await
        .at_stage("network connect")?;
    println!(
        "mode=network-join\nprofile=fast-v1\nmetadata=peer-or-relay-addresses-timing-volume\nstatus=connected"
    );
    run_network_join_with_link(root, link).await
}

/// Runs the full network composition over relay-free Iroh loopback endpoints.
pub async fn run_network_loopback_demo() -> Result<(), SessionCtlError> {
    let host_root = ProcessRoot::create_at(fresh_process_root_path("network-host")?)?;
    let join_root = ProcessRoot::create_at(fresh_process_root_path("network-join")?)?;
    let host = IrohFastEndpoint::bind_loopback()
        .await
        .at_stage("network loopback host")?;
    let host_address = host.address();
    let host_invitation = direct_invitation_path(host_root.path());
    let join = IrohFastEndpoint::bind_loopback()
        .await
        .at_stage("network loopback join")?;

    let (host_result, join_result) = tokio::join!(
        run_network_host_with_endpoint(host_root, host),
        connect_network_loopback_join(join_root, join, host_address, host_invitation),
    );
    host_result?;
    join_result
}

async fn connect_network_loopback_join(
    root: ProcessRoot,
    endpoint: IrohFastEndpoint,
    host: FastEndpointAddress,
    invitation_path: PathBuf,
) -> Result<(), SessionCtlError> {
    let invitation = read_bounded_wait_async(
        invitation_path,
        MAX_WIRE_OBJECT_BYTES,
        NETWORK_OPERATION_WAIT,
    )
    .await?;
    SignedCapabilityInvitationV2::decode_and_verify(&invitation).at_stage("network invitation")?;
    atomic_write(
        &direct_invitation_path(root.path()),
        &invitation,
        MAX_WIRE_OBJECT_BYTES,
    )?;
    let link = endpoint
        .connect_address(host, NETWORK_OPERATION_WAIT, MAX_IPC_FRAME_BYTES)
        .await
        .at_stage("network loopback connect")?;
    run_network_join_with_link(root, link).await
}

async fn run_network_host_with_endpoint(
    mut root: ProcessRoot,
    endpoint: IrohFastEndpoint,
) -> Result<(), SessionCtlError> {
    let alice_root = root.path().to_path_buf();
    let alice = tokio::task::spawn_blocking(move || {
        run_alice_init_with_wait(&alice_root, OPERATOR_HANDOFF_WAIT)?;
        run_alice_resume(&alice_root)
    });
    let scenario_result = async {
        let invitation = Zeroizing::new(
            read_bounded_wait_async(
                direct_invitation_path(root.path()),
                MAX_WIRE_OBJECT_BYTES,
                FRAME_WAIT,
            )
            .await?,
        );
        SignedCapabilityInvitationV2::decode_and_verify(&invitation)
            .at_stage("network invitation")?;
        println!(
            "mode=network-host\ninvitation=ready\ninvitation_file={}",
            direct_invitation_path(root.path()).display()
        );
        let link = endpoint
            .accept(None, OPERATOR_HANDOFF_WAIT, MAX_IPC_FRAME_BYTES)
            .await
            .at_stage("network accept")?;
        network_host_bridge(root.path(), link).await
    }
    .await;
    let alice_result = alice.await.map_err(|_| stage("network Alice task"))?;
    let cleanup_result = root.cleanup();
    scenario_result?;
    alice_result?;
    cleanup_result?;
    println!("mode=network-host\nstatus=complete");
    Ok(())
}

async fn run_network_join_with_link(
    mut root: ProcessRoot,
    mut link: IrohFastLink,
) -> Result<(), SessionCtlError> {
    let bob_root = root.path().to_path_buf();
    let bob = tokio::task::spawn_blocking(move || run_bob(&bob_root));
    let scenario_result = network_join_bridge(root.path(), &mut link).await;
    let bob_result = bob.await.map_err(|_| stage("network Bob task"))?;
    let close_result = link
        .close(NETWORK_OPERATION_WAIT)
        .await
        .at_stage("network join close");
    let cleanup_result = root.cleanup();
    scenario_result?;
    bob_result?;
    close_result?;
    cleanup_result?;
    println!("mode=network-join\nstatus=complete");
    Ok(())
}

async fn network_host_bridge(root: &Path, mut link: IrohFastLink) -> Result<(), SessionCtlError> {
    receive_network_frame(root, &mut link, 1, FrameKind::ProtectedJoin).await?;
    for sequence in [2_u8, 3] {
        send_network_frame(root, &mut link, sequence).await?;
    }
    receive_network_frame(root, &mut link, 4, FrameKind::OpaqueEnvelope).await?;
    for sequence in 5_u8..=7 {
        send_network_frame(root, &mut link, sequence).await?;
    }
    link.close(NETWORK_OPERATION_WAIT)
        .await
        .at_stage("network host close")
}

fn read_network_invitation(path: &Path) -> Result<Zeroizing<Vec<u8>>, SessionCtlError> {
    if !path.is_absolute() || path.as_os_str().len() > 4_096 {
        return Err(stage("network invitation path"));
    }
    let invitation = Zeroizing::new(read_bounded_regular_file(path, MAX_WIRE_OBJECT_BYTES)?);
    SignedCapabilityInvitationV2::decode_and_verify(&invitation).at_stage("network invitation")?;
    Ok(invitation)
}

async fn prepare_public_endpoint<Prepare, Bind, BindFuture>(
    root: PathBuf,
    endpoint_stage: &'static str,
    prepare: Prepare,
    bind: Bind,
) -> Result<(ProcessRoot, IrohFastEndpoint), SessionCtlError>
where
    Prepare: FnOnce(&ProcessRoot) -> Result<(), SessionCtlError>,
    Bind: FnOnce() -> BindFuture,
    BindFuture: Future<Output = Result<IrohFastEndpoint, IrohFastError>>,
{
    let root = ProcessRoot::create_at(root)?;
    prepare(&root)?;
    let endpoint = bind().await.at_stage(endpoint_stage)?;
    Ok((root, endpoint))
}

async fn network_join_bridge(root: &Path, link: &mut IrohFastLink) -> Result<(), SessionCtlError> {
    send_network_frame(root, link, 1).await?;
    for sequence in [2_u8, 3] {
        receive_network_frame(
            root,
            link,
            sequence,
            if sequence == 2 {
                FrameKind::WelcomeDeposit
            } else {
                FrameKind::OpaqueEnvelope
            },
        )
        .await?;
    }
    send_network_frame(root, link, 4).await?;
    for sequence in 5_u8..=7 {
        receive_network_frame(root, link, sequence, FrameKind::OpaqueEnvelope).await?;
    }
    Ok(())
}

async fn send_network_frame(
    root: &Path,
    link: &mut IrohFastLink,
    sequence: u8,
) -> Result<(), SessionCtlError> {
    let encoded =
        read_bounded_wait_async(relay_in(root, sequence), MAX_IPC_FRAME_BYTES, FRAME_WAIT).await?;
    let frame = IpcFrame::decode(&encoded)?;
    let expected = expected_frame_kind(sequence)?;
    frame.require(expected, sequence)?;
    link.send_frame(&encoded, NETWORK_OPERATION_WAIT)
        .await
        .at_stage("network frame send")
}

async fn receive_network_frame(
    root: &Path,
    link: &mut IrohFastLink,
    sequence: u8,
    expected: FrameKind,
) -> Result<(), SessionCtlError> {
    let encoded = link
        .receive_frame(NETWORK_OPERATION_WAIT)
        .await
        .at_stage("network frame receive")?;
    let frame = IpcFrame::decode(&encoded)?;
    frame.require(expected, sequence)?;
    atomic_write_async(relay_out(root, sequence), encoded, MAX_IPC_FRAME_BYTES).await
}

fn expected_frame_kind(sequence: u8) -> Result<FrameKind, SessionCtlError> {
    match sequence {
        1 => Ok(FrameKind::ProtectedJoin),
        2 => Ok(FrameKind::WelcomeDeposit),
        3..=7 => Ok(FrameKind::OpaqueEnvelope),
        _ => Err(stage("network frame schedule")),
    }
}

async fn read_bounded_wait_async(
    path: PathBuf,
    maximum: usize,
    timeout: Duration,
) -> Result<Vec<u8>, SessionCtlError> {
    tokio::task::spawn_blocking(move || read_bounded_wait(&path, maximum, timeout))
        .await
        .map_err(|_| stage("network file read task"))?
}

async fn atomic_write_async(
    path: PathBuf,
    bytes: Vec<u8>,
    maximum: usize,
) -> Result<(), SessionCtlError> {
    tokio::task::spawn_blocking(move || atomic_write(&path, &bytes, maximum))
        .await
        .map_err(|_| stage("network file write task"))?
}

fn run_l1_process_children(root: &Path, children: &mut ChildSet) -> Result<(), SessionCtlError> {
    let executable = std::env::current_exe().at_stage("process executable")?;
    children.spawn(&executable, "service", root)?;
    children.spawn(&executable, "bob", root)?;
    children.spawn(&executable, "alice-init", root)?;

    let alice_init = children.wait_role("alice-init", CHILD_WAIT)?;
    require_child_output(&alice_init, b"role=alice-init\nresult=pass\n")?;
    children.spawn(&executable, "alice-resume", root)?;

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
        "alice-init" => run_alice_init(&root),
        "alice-resume" => run_alice_resume(&root),
        "bob" => run_bob(&root),
        "hostile-replay-controller" => run_hostile_replay_controller(&root),
        "hostile-replay-service" => run_hostile_replay_service(&root),
        "hostile-replay-alice" => run_hostile_replay_alice(&root),
        "hostile-replay-bob" => run_hostile_replay_bob(&root),
        "hostile-replay-inspector" => run_hostile_replay_inspector(&root),
        "hostile-matrix-controller" => run_hostile_matrix_controller(&root),
        "hostile-matrix-service" => run_hostile_matrix_service(&root),
        "hostile-matrix-alice" => run_hostile_matrix_alice(&root),
        "hostile-matrix-bob" => run_hostile_matrix_bob(&root),
        "hostile-matrix-inspector" => run_hostile_matrix_inspector(&root),
        _ => Err(stage("process role")),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrameKind {
    ProtectedJoin = 1,
    WelcomeDeposit = 2,
    OpaqueEnvelope = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostileJoinCase {
    Malformed,
    Expired,
    Copied,
    WrongInvitation,
    WrongKeyPackage,
    WrongVerifier,
    Reordered,
}

impl HostileJoinCase {
    const ALL: [Self; 7] = [
        Self::Malformed,
        Self::Expired,
        Self::Copied,
        Self::WrongInvitation,
        Self::WrongKeyPackage,
        Self::WrongVerifier,
        Self::Reordered,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Malformed => "malformed-protected-join",
            Self::Expired => "expired-protected-join",
            Self::Copied => "copied-protected-join",
            Self::WrongInvitation => "wrong-invitation",
            Self::WrongKeyPackage => "wrong-key-package",
            Self::WrongVerifier => "wrong-verifier",
            Self::Reordered => "reordered-protected-joins",
        }
    }

    fn parse(bytes: &[u8]) -> Result<Self, SessionCtlError> {
        Self::ALL
            .into_iter()
            .find(|case| bytes == case.label().as_bytes())
            .ok_or_else(|| stage("hostile process case"))
    }

    const fn request_count(self) -> u8 {
        if matches!(self, Self::Reordered) {
            2
        } else {
            1
        }
    }
}

impl TryFrom<u8> for FrameKind {
    type Error = SessionCtlError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ProtectedJoin),
            2 => Ok(Self::WelcomeDeposit),
            3 => Ok(Self::OpaqueEnvelope),
            _ => Err(stage("IPC kind")),
        }
    }
}

struct IpcFrame {
    kind: FrameKind,
    sequence: u8,
    parts: Vec<Vec<u8>>,
}

impl IpcFrame {
    fn new(kind: FrameKind, sequence: u8, parts: Vec<Vec<u8>>) -> Result<Self, SessionCtlError> {
        let expected_parts = match kind {
            FrameKind::WelcomeDeposit => 2,
            FrameKind::ProtectedJoin | FrameKind::OpaqueEnvelope => 1,
        };
        if !(1..=EXPECTED_FRAMES).contains(&sequence)
            || parts.len() != expected_parts
            || parts
                .iter()
                .any(|part| part.is_empty() || part.len() > MAX_WIRE_OBJECT_BYTES)
        {
            return Err(stage("IPC frame"));
        }
        validate_wire_parts(kind, &parts)?;
        Ok(Self {
            kind,
            sequence,
            parts,
        })
    }

    fn decode(encoded: &[u8]) -> Result<Self, SessionCtlError> {
        if encoded.len() < IPC_HEADER_BYTES || encoded.len() > MAX_IPC_FRAME_BYTES {
            return Err(stage("IPC frame"));
        }
        if &encoded[..8] != IPC_MAGIC || encoded[8] != IPC_VERSION {
            return Err(stage("IPC frame"));
        }
        let kind = FrameKind::try_from(encoded[9])?;
        let sequence = encoded[10];
        let part_count = usize::from(encoded[11]);
        if part_count == 0 || part_count > MAX_IPC_PARTS {
            return Err(stage("IPC frame"));
        }
        let mut cursor = IPC_HEADER_BYTES;
        let mut parts = Vec::with_capacity(part_count);
        for _ in 0..part_count {
            let length_end = cursor
                .checked_add(IPC_LENGTH_BYTES)
                .ok_or_else(|| stage("IPC frame"))?;
            let length_bytes: [u8; 4] = encoded
                .get(cursor..length_end)
                .ok_or_else(|| stage("IPC frame"))?
                .try_into()
                .map_err(|_| stage("IPC frame"))?;
            let length = usize::try_from(u32::from_be_bytes(length_bytes))
                .map_err(|_| stage("IPC frame"))?;
            let part_end = length_end
                .checked_add(length)
                .ok_or_else(|| stage("IPC frame"))?;
            let part = encoded
                .get(length_end..part_end)
                .ok_or_else(|| stage("IPC frame"))?;
            parts.push(part.to_vec());
            cursor = part_end;
        }
        if cursor != encoded.len() {
            return Err(stage("IPC frame"));
        }
        let frame = Self::new(kind, sequence, parts)?;
        if frame.encode()? != encoded {
            return Err(stage("IPC canonical encoding"));
        }
        Ok(frame)
    }

    fn encode(&self) -> Result<Vec<u8>, SessionCtlError> {
        let mut encoded = Vec::with_capacity(MAX_IPC_FRAME_BYTES.min(
            IPC_HEADER_BYTES
                + (self.parts.len() * IPC_LENGTH_BYTES)
                + self.parts.iter().map(Vec::len).sum::<usize>(),
        ));
        encoded.extend_from_slice(IPC_MAGIC);
        encoded.push(IPC_VERSION);
        encoded.push(self.kind as u8);
        encoded.push(self.sequence);
        encoded.push(u8::try_from(self.parts.len()).map_err(|_| stage("IPC frame"))?);
        for part in &self.parts {
            encoded.extend_from_slice(
                &u32::try_from(part.len())
                    .map_err(|_| stage("IPC frame"))?
                    .to_be_bytes(),
            );
            encoded.extend_from_slice(part);
        }
        if encoded.len() > MAX_IPC_FRAME_BYTES {
            return Err(stage("IPC frame"));
        }
        Ok(encoded)
    }

    fn require(self, kind: FrameKind, sequence: u8) -> Result<Vec<Vec<u8>>, SessionCtlError> {
        if self.kind != kind || self.sequence != sequence {
            return Err(stage("IPC schedule"));
        }
        Ok(self.parts)
    }
}

fn validate_wire_parts(kind: FrameKind, parts: &[Vec<u8>]) -> Result<(), SessionCtlError> {
    match kind {
        FrameKind::ProtectedJoin => {
            ProtectedJoinRequest::decode_canonical(&parts[0]).at_stage("IPC protected join")?;
        }
        FrameKind::WelcomeDeposit => {
            LocalWelcomeDepositEndpoint::decode_canonical(&parts[0])
                .at_stage("IPC Welcome endpoint")?;
            OpaqueEnvelope::decode_canonical(&parts[1]).at_stage("IPC Welcome envelope")?;
        }
        FrameKind::OpaqueEnvelope => {
            OpaqueEnvelope::decode_canonical(&parts[0]).at_stage("IPC opaque envelope")?;
        }
    }
    Ok(())
}

fn run_service(root: &Path) -> Result<(), SessionCtlError> {
    run_service_with_initial_wait(root, FRAME_WAIT)
}

fn run_service_with_initial_wait(
    root: &Path,
    initial_wait: Duration,
) -> Result<(), SessionCtlError> {
    for sequence in 1..=EXPECTED_FRAMES {
        let wait = if sequence == 1 {
            initial_wait
        } else {
            FRAME_WAIT
        };
        let encoded = read_bounded_wait(&relay_in(root, sequence), MAX_IPC_FRAME_BYTES, wait)?;
        let frame = IpcFrame::decode(&encoded)?;
        let expected = match sequence {
            1 => FrameKind::ProtectedJoin,
            2 => FrameKind::WelcomeDeposit,
            3..=7 => FrameKind::OpaqueEnvelope,
            _ => return Err(stage("IPC schedule")),
        };
        frame.require(expected, sequence)?;
        atomic_write(&relay_out(root, sequence), &encoded, MAX_IPC_FRAME_BYTES)?;
    }
    print!("role=untrusted-service\nresult=pass\nforwarded=7\n");
    Ok(())
}

fn run_hostile_replay_controller(root: &Path) -> Result<(), SessionCtlError> {
    let executable = std::env::current_exe().at_stage("hostile process executable")?;
    let mut children = ChildSet::new();
    let scenario_result = (|| {
        children.spawn(&executable, "hostile-replay-service", root)?;
        children.spawn(&executable, "hostile-replay-bob", root)?;
        children.spawn(&executable, "hostile-replay-alice", root)?;

        let alice = children.wait_role("hostile-replay-alice", CHILD_WAIT)?;
        require_child_output(
            &alice,
            b"role=alice\nresult=pass\nreplay=rejected\nmembership=unchanged\n",
        )?;
        children.spawn(&executable, "hostile-replay-inspector", root)?;
        let inspector = children.wait_role("hostile-replay-inspector", CHILD_WAIT)?;
        require_child_output(
            &inspector,
            b"role=inspector\nresult=pass\ndurable_membership=unchanged\n",
        )?;
        let bob = children.wait_role("hostile-replay-bob", CHILD_WAIT)?;
        require_child_output(&bob, b"role=bob\nresult=pass\nrequests=2\n")?;
        let service = children.wait_role("hostile-replay-service", CHILD_WAIT)?;
        require_child_output(
            &service,
            b"role=untrusted-service\nresult=pass\nforwarded=2\n",
        )?;
        if !children.is_empty() {
            return Err(stage("hostile process cleanup"));
        }
        Ok(())
    })();
    let child_cleanup_result = children.cleanup();
    let directory_cleanup_result = validate_root(root)
        .and_then(|()| fs::remove_dir_all(root).at_stage("hostile process root removal"));
    scenario_result?;
    child_cleanup_result?;
    directory_cleanup_result?;

    print!(
        "version=1\nscenario=E2E-JOIN-002\ncase=replayed-protected-join\nresult=pass\nreplay=rejected\nmembership=unchanged\nredaction=pass\nchild_cleanup=pass\ndirectory_cleanup=pass\n"
    );
    Ok(())
}

fn run_hostile_replay_service(root: &Path) -> Result<(), SessionCtlError> {
    for sequence in 1..=2 {
        let encoded =
            read_bounded_wait(&relay_in(root, sequence), MAX_IPC_FRAME_BYTES, FRAME_WAIT)?;
        let frame = IpcFrame::decode(&encoded)?;
        frame.require(FrameKind::ProtectedJoin, sequence)?;
        atomic_write(&relay_out(root, sequence), &encoded, MAX_IPC_FRAME_BYTES)?;
    }
    print!("role=untrusted-service\nresult=pass\nforwarded=2\n");
    Ok(())
}

fn run_hostile_replay_alice(root: &Path) -> Result<(), SessionCtlError> {
    let database_key = Zeroizing::new(random_nonzero::<32>()?);
    let storage = SqlCipherStorage::create(
        &database_path(root),
        VaultKey::new(*database_key).at_stage("hostile process owner key")?,
    )
    .at_stage("hostile process owner store")?;
    let group_id = SessionGroupId::new(random_nonzero()?).at_stage("hostile process group ID")?;
    let alice = create_durable_client_with_storage(
        group_id,
        storage.clone(),
        storage.clone(),
        storage.clone(),
    )
    .at_stage("hostile process Alice client")?;
    let group = alice
        .create_group(group_id, NOW)
        .at_stage("hostile process Alice group")?;

    let protector = AwsLcInvitationJoinProtector::new();
    let issued = storage
        .issue_capability_invitation(&protector, NOW, INVITATION_EXPIRES_AT, NOW)
        .at_stage("hostile process invitation generation")?;
    let encoded_invitation = issued
        .invitation()
        .encode_canonical()
        .at_stage("hostile process invitation encoding")?;
    atomic_write(
        &direct_invitation_path(root),
        &encoded_invitation,
        MAX_WIRE_OBJECT_BYTES,
    )?;

    let first_bytes = receive_protected_join(root, 1)?;
    let second_bytes = receive_protected_join(root, 2)?;
    if first_bytes != second_bytes {
        return Err(stage("hostile process exact replay"));
    }
    let first = ProtectedJoinRequest::decode_canonical(&first_bytes)
        .at_stage("hostile process first protected join")?;
    let second = ProtectedJoinRequest::decode_canonical(&second_bytes)
        .at_stage("hostile process replayed protected join")?;
    let opened_first = protector
        .open_capability_request(issued.private_key(), issued.invitation(), &first)
        .at_stage("hostile process first join opening")?;
    let opened_second = protector
        .open_capability_request(issued.private_key(), issued.invitation(), &second)
        .at_stage("hostile process replayed join opening")?;
    let first_fingerprint: [u8; 32] = digest(&SHA256, &first_bytes)
        .as_ref()
        .try_into()
        .map_err(|_| stage("hostile process first fingerprint"))?;
    let first_shadow = AuthorizationShadowInput::new(
        *opened_first.request().invitation_id(),
        *issued.invitation().signature(),
        *opened_first.request().join_challenge(),
        *opened_first.request().join_request_id(),
        *opened_first.request().request_nonce(),
        *opened_first.request().intended_verifier(),
        *opened_first.request().key_package_reference(),
        *opened_first.request().credential_identity(),
        *opened_first.request().leaf_signature_key(),
        first_fingerprint,
        opened_first.request().issued_at_unix_seconds(),
        opened_first.request().expires_at_unix_seconds(),
        issued.invitation().expires_at_unix_seconds(),
    )
    .at_stage("hostile process first shadow")?;
    let second_fingerprint: [u8; 32] = digest(&SHA256, &second_bytes)
        .as_ref()
        .try_into()
        .map_err(|_| stage("hostile process replay fingerprint"))?;
    let second_shadow = AuthorizationShadowInput::new(
        *opened_second.request().invitation_id(),
        *issued.invitation().signature(),
        *opened_second.request().join_challenge(),
        *opened_second.request().join_request_id(),
        *opened_second.request().request_nonce(),
        *opened_second.request().intended_verifier(),
        *opened_second.request().key_package_reference(),
        *opened_second.request().credential_identity(),
        *opened_second.request().leaf_signature_key(),
        second_fingerprint,
        opened_second.request().issued_at_unix_seconds(),
        opened_second.request().expires_at_unix_seconds(),
        issued.invitation().expires_at_unix_seconds(),
    )
    .at_stage("hostile process replay shadow")?;
    let mut admission = CapabilityAdmissionVerifier::new(
        CapabilityAdmissionPolicy::new(3_600, 5, 8).at_stage("hostile process admission policy")?,
    );
    let _reserved = admission
        .verify_and_reserve(opened_first, NOW)
        .at_stage("hostile process first reservation")?;
    let _durable_reserved = storage
        .reserve_authorization(&protector, first_shadow, NOW)
        .at_stage("hostile process first durable reservation")?;
    let mut fresh_admission = CapabilityAdmissionVerifier::new(
        CapabilityAdmissionPolicy::new(3_600, 5, 8).at_stage("hostile process replay policy")?,
    );
    let _replay_verified = fresh_admission
        .verify_and_reserve(opened_second, NOW)
        .at_stage("hostile process replay verification")?;
    if !matches!(
        storage.reserve_authorization(&protector, second_shadow, NOW),
        Err(StoreError::Replay)
    ) || admission.pending_count() != 1
        || group.epoch() != 0
        || group.member_count() != 1
    {
        return Err(stage("hostile process replay rejection"));
    }
    drop(group);
    drop(alice);
    drop(storage);
    write_private_state(root, &database_key, group_id)?;
    print!("role=alice\nresult=pass\nreplay=rejected\nmembership=unchanged\n");
    Ok(())
}

fn run_hostile_replay_bob(root: &Path) -> Result<(), SessionCtlError> {
    let invitation_bytes = Zeroizing::new(read_bounded_wait(
        &direct_invitation_path(root),
        MAX_WIRE_OBJECT_BYTES,
        FRAME_WAIT,
    )?);
    let invitation = SignedCapabilityInvitationV2::decode_and_verify(&invitation_bytes)
        .at_stage("hostile process invitation decode")?;
    let mut welcome_transport = LocalMemoryWelcomeTransport::new(
        LocalMailboxPolicy::new(300, 1).at_stage("hostile process Welcome policy")?,
    )
    .at_stage("hostile process Welcome transport")?;
    let mailbox = welcome_transport
        .create_welcome_mailbox(REQUEST_EXPIRES_AT, NOW)
        .at_stage("hostile process Welcome mailbox")?;
    let (deposit_endpoint, _, _) = mailbox.into_parts();
    let bob = create_client().at_stage("hostile process Bob client")?;
    let key_package = bob
        .generate_key_package(NOW)
        .at_stage("hostile process Bob KeyPackage")?;
    let validated = create_key_package_validator()
        .validate_key_package(key_package.as_bytes(), NOW)
        .at_stage("hostile process Bob KeyPackage validation")?;
    let request = CapabilityJoinRequest::new(
        InvitationJoinBinding::new(
            *invitation.invitation_id(),
            *invitation.join_challenge(),
            *invitation.invitation_key_id(),
            *invitation.inviter_verifying_key(),
        )
        .at_stage("hostile process invitation binding")?,
        JoinRequestBinding::new(
            random_nonzero()?,
            NOW,
            REQUEST_EXPIRES_AT,
            random_nonzero()?,
        )
        .at_stage("hostile process request binding")?,
        MlsKeyPackageBinding::new(
            *validated.key_package_reference(),
            key_package.as_bytes().to_vec(),
            *validated.credential_identity(),
            *validated.leaf_signature_key(),
        )
        .at_stage("hostile process MLS binding")?,
        deposit_endpoint,
    )
    .at_stage("hostile process join request")?;
    let protected = AwsLcInvitationJoinProtector::new()
        .seal_capability_request(&invitation, &request)
        .at_stage("hostile process join protection")?
        .encode_canonical()
        .at_stage("hostile process join encoding")?;
    write_frame(
        &relay_in(root, 1),
        IpcFrame::new(FrameKind::ProtectedJoin, 1, vec![protected.clone()])?,
    )?;
    write_frame(
        &relay_in(root, 2),
        IpcFrame::new(FrameKind::ProtectedJoin, 2, vec![protected])?,
    )?;
    print!("role=bob\nresult=pass\nrequests=2\n");
    Ok(())
}

fn run_hostile_replay_inspector(root: &Path) -> Result<(), SessionCtlError> {
    let (database_key, group_id) = read_private_state(root)?;
    let storage = SqlCipherStorage::open(
        &database_path(root),
        VaultKey::new(*database_key).at_stage("hostile process reopen key")?,
    )
    .at_stage("hostile process owner reopen")?;
    if storage
        .recover_pre_membership_authorizations(&AwsLcInvitationJoinProtector::new(), NOW + 1)
        .at_stage("hostile process authorization recovery")?
        != 1
    {
        return Err(stage("hostile process authorization recovery"));
    }
    let invitation_bytes = Zeroizing::new(read_bounded_wait(
        &direct_invitation_path(root),
        MAX_WIRE_OBJECT_BYTES,
        FRAME_WAIT,
    )?);
    let invitation = SignedCapabilityInvitationV2::decode_and_verify(&invitation_bytes)
        .at_stage("hostile process recovery invitation")?;
    let reloaded = storage
        .load_capability_invitation(
            &AwsLcInvitationJoinProtector::new(),
            invitation.invitation_id(),
            NOW + 1,
        )
        .at_stage("hostile process opening recovery")?
        .ok_or_else(|| stage("hostile process opening recovery"))?;
    if reloaded.invitation().signature() != invitation.signature() {
        return Err(stage("hostile process opening recovery"));
    }
    let alice = load_durable_client_with_storage(
        group_id,
        storage.clone(),
        storage.clone(),
        storage.clone(),
    )
    .at_stage("hostile process Alice identity reload")?;
    if alice.load_group(group_id).is_ok() {
        return Err(stage("hostile process durable membership"));
    }
    print!("role=inspector\nresult=pass\ndurable_membership=unchanged\n");
    Ok(())
}

fn run_hostile_matrix_controller(root: &Path) -> Result<(), SessionCtlError> {
    let executable = std::env::current_exe().at_stage("hostile matrix executable")?;
    for case in HostileJoinCase::ALL {
        let mut case_root = ProcessRoot::create_at(root.join(case.label()))?;
        atomic_write(
            &hostile_case_path(case_root.path()),
            case.label().as_bytes(),
            64,
        )?;
        let mut children = ChildSet::new();
        let scenario_result = (|| {
            children.spawn(&executable, "hostile-matrix-service", case_root.path())?;
            children.spawn(&executable, "hostile-matrix-bob", case_root.path())?;
            children.spawn(&executable, "hostile-matrix-alice", case_root.path())?;

            let alice = children.wait_role("hostile-matrix-alice", CHILD_WAIT)?;
            require_child_output(
                &alice,
                format!(
                    "role=alice\nresult=pass\ncase={}\napproval=not-reached\nmls_add=not-reached\nmembership=unchanged\n",
                    case.label()
                )
                .as_bytes(),
            )?;
            children.spawn(&executable, "hostile-matrix-inspector", case_root.path())?;
            let inspector = children.wait_role("hostile-matrix-inspector", CHILD_WAIT)?;
            require_child_output(
                &inspector,
                b"role=inspector\nresult=pass\ndurable_membership=unchanged\n",
            )?;
            let bob = children.wait_role("hostile-matrix-bob", CHILD_WAIT)?;
            require_child_output(
                &bob,
                format!(
                    "role=bob\nresult=pass\ncase={}\nrequests={}\n",
                    case.label(),
                    case.request_count()
                )
                .as_bytes(),
            )?;
            let service = children.wait_role("hostile-matrix-service", CHILD_WAIT)?;
            let forwarded = if matches!(case, HostileJoinCase::Reordered) {
                1
            } else {
                case.request_count()
            };
            require_child_output(
                &service,
                format!(
                    "role=untrusted-service\nresult=pass\ncase={}\nreceived={}\nforwarded={}\n",
                    case.label(),
                    case.request_count(),
                    forwarded
                )
                .as_bytes(),
            )?;
            if !children.is_empty() {
                return Err(stage("hostile matrix process cleanup"));
            }
            Ok(())
        })();
        let child_cleanup_result = children.cleanup();
        let directory_cleanup_result = case_root.cleanup();
        scenario_result?;
        child_cleanup_result?;
        directory_cleanup_result?;
    }

    validate_root(root)?;
    fs::remove_dir_all(root).at_stage("hostile matrix root removal")?;
    print!(
        "version=1\nscenario=E2E-JOIN-002\ntopology=two-clients-one-untrusted-service\nresult=pass\ncases=malformed-protected-join,expired-protected-join,copied-protected-join,wrong-invitation,wrong-key-package,wrong-verifier,reordered-protected-joins\ncase_count=7\napproval=not-reached\nmls_add=not-reached\nmembership=unchanged\nservice_input=canonical-public-only\nredaction=pass\nchild_cleanup=pass\ndirectory_cleanup=pass\n"
    );
    Ok(())
}

fn run_hostile_matrix_service(root: &Path) -> Result<(), SessionCtlError> {
    let case = read_hostile_case(root)?;
    let mut received = Vec::with_capacity(usize::from(case.request_count()));
    for sequence in 1..=case.request_count() {
        let encoded =
            read_bounded_wait(&relay_in(root, sequence), MAX_IPC_FRAME_BYTES, FRAME_WAIT)?;
        let frame = IpcFrame::decode(&encoded)?;
        frame.require(FrameKind::ProtectedJoin, sequence)?;
        received.push(encoded);
    }

    if matches!(case, HostileJoinCase::Reordered) {
        atomic_write(&relay_out(root, 1), &received[1], MAX_IPC_FRAME_BYTES)?;
    } else if matches!(case, HostileJoinCase::Malformed) {
        let frame = IpcFrame::decode(&received[0])?;
        let mut parts = frame.require(FrameKind::ProtectedJoin, 1)?;
        let encoded = parts
            .pop()
            .ok_or_else(|| stage("hostile malformed protected join"))?;
        let protected = ProtectedJoinRequest::decode_canonical(&encoded)
            .at_stage("hostile malformed protected join")?;
        let mut ciphertext = protected.ciphertext().to_vec();
        ciphertext[0] ^= 1;
        let malformed = ProtectedJoinRequest::new(
            *protected.invitation_id(),
            *protected.invitation_key_id(),
            *protected.encapsulated_key(),
            ciphertext,
        )
        .at_stage("hostile malformed protected join")?
        .encode_canonical()
        .at_stage("hostile malformed protected join")?;
        write_frame(
            &relay_out(root, 1),
            IpcFrame::new(FrameKind::ProtectedJoin, 1, vec![malformed])?,
        )?;
    } else {
        atomic_write(&relay_out(root, 1), &received[0], MAX_IPC_FRAME_BYTES)?;
    }

    let forwarded = if matches!(case, HostileJoinCase::Reordered) {
        1
    } else {
        case.request_count()
    };
    print!(
        "role=untrusted-service\nresult=pass\ncase={}\nreceived={}\nforwarded={}\n",
        case.label(),
        case.request_count(),
        forwarded
    );
    Ok(())
}

fn run_hostile_matrix_alice(root: &Path) -> Result<(), SessionCtlError> {
    let case = read_hostile_case(root)?;
    let database_key = Zeroizing::new(random_nonzero::<32>()?);
    let storage = SqlCipherStorage::create(
        &database_path(root),
        VaultKey::new(*database_key).at_stage("hostile matrix owner key")?,
    )
    .at_stage("hostile matrix owner store")?;
    let group_id = SessionGroupId::new(random_nonzero()?).at_stage("hostile matrix group ID")?;
    let alice = create_durable_client_with_storage(
        group_id,
        storage.clone(),
        storage.clone(),
        storage.clone(),
    )
    .at_stage("hostile matrix Alice client")?;
    let group = alice
        .create_group(group_id, NOW)
        .at_stage("hostile matrix Alice group")?;
    let protector = AwsLcInvitationJoinProtector::new();
    let invitation_issued_at = if matches!(case, HostileJoinCase::Expired) {
        NOW.saturating_sub(10)
    } else {
        NOW
    };
    let issued = storage
        .issue_capability_invitation(
            &protector,
            invitation_issued_at,
            INVITATION_EXPIRES_AT,
            invitation_issued_at,
        )
        .at_stage("hostile matrix invitation generation")?;
    let foreign = storage
        .issue_capability_invitation(&protector, NOW, INVITATION_EXPIRES_AT, NOW)
        .at_stage("hostile matrix foreign invitation generation")?;
    atomic_write(
        &direct_invitation_path(root),
        &issued
            .invitation()
            .encode_canonical()
            .at_stage("hostile matrix invitation encoding")?,
        MAX_WIRE_OBJECT_BYTES,
    )?;
    atomic_write(
        &foreign_invitation_path(root),
        &foreign
            .invitation()
            .encode_canonical()
            .at_stage("hostile matrix foreign invitation encoding")?,
        MAX_WIRE_OBJECT_BYTES,
    )?;
    write_private_state(root, &database_key, group_id)?;

    match case {
        HostileJoinCase::Reordered => {
            if receive_protected_join(root, 1).is_ok() {
                return Err(stage("hostile reordered join rejection"));
            }
        }
        HostileJoinCase::Malformed | HostileJoinCase::Copied | HostileJoinCase::WrongInvitation => {
            let encoded = receive_protected_join(root, 1)?;
            let protected = ProtectedJoinRequest::decode_canonical(&encoded)
                .at_stage("hostile matrix protected join")?;
            if protector
                .open_capability_request(issued.private_key(), issued.invitation(), &protected)
                .is_ok()
            {
                return Err(stage("hostile protected join rejection"));
            }
        }
        HostileJoinCase::WrongVerifier => {
            let encoded = receive_protected_join(root, 1)?;
            let protected = ProtectedJoinRequest::decode_canonical(&encoded)
                .at_stage("hostile wrong verifier protected join")?;
            let opened = protector
                .open_capability_request(foreign.private_key(), foreign.invitation(), &protected)
                .at_stage("hostile wrong verifier opening")?;
            if opened.request().intended_verifier() == issued.invitation().inviter_verifying_key() {
                return Err(stage("hostile wrong verifier context"));
            }
        }
        HostileJoinCase::Expired | HostileJoinCase::WrongKeyPackage => {
            let encoded = receive_protected_join(root, 1)?;
            let protected = ProtectedJoinRequest::decode_canonical(&encoded)
                .at_stage("hostile matrix protected join")?;
            let opened = protector
                .open_capability_request(issued.private_key(), issued.invitation(), &protected)
                .at_stage("hostile matrix join opening")?;
            let mut admission = CapabilityAdmissionVerifier::new(
                CapabilityAdmissionPolicy::new(3_600, 5, 8)
                    .at_stage("hostile matrix admission policy")?,
            );
            if admission.verify_and_reserve(opened, NOW).is_ok() || admission.pending_count() != 0 {
                return Err(stage("hostile admission rejection"));
            }
        }
    }
    if group.epoch() != 0 || group.member_count() != 1 {
        return Err(stage("hostile matrix membership mutation"));
    }
    drop(group);
    drop(alice);
    drop(storage);
    print!(
        "role=alice\nresult=pass\ncase={}\napproval=not-reached\nmls_add=not-reached\nmembership=unchanged\n",
        case.label()
    );
    Ok(())
}

fn run_hostile_matrix_bob(root: &Path) -> Result<(), SessionCtlError> {
    let case = read_hostile_case(root)?;
    let invitation_path = if matches!(
        case,
        HostileJoinCase::Copied | HostileJoinCase::WrongVerifier
    ) {
        foreign_invitation_path(root)
    } else {
        direct_invitation_path(root)
    };
    let invitation_bytes = Zeroizing::new(read_bounded_wait(
        &invitation_path,
        MAX_WIRE_OBJECT_BYTES,
        FRAME_WAIT,
    )?);
    let invitation = SignedCapabilityInvitationV2::decode_and_verify(&invitation_bytes)
        .at_stage("hostile matrix invitation decode")?;

    for sequence in 1..=case.request_count() {
        let mut protected = build_hostile_join_request(&invitation, case)?;
        if matches!(case, HostileJoinCase::WrongInvitation) {
            protected = ProtectedJoinRequest::new(
                random_nonzero()?,
                *protected.invitation_key_id(),
                *protected.encapsulated_key(),
                protected.ciphertext().to_vec(),
            )
            .at_stage("hostile wrong invitation outer")?;
        }
        write_frame(
            &relay_in(root, sequence),
            IpcFrame::new(
                FrameKind::ProtectedJoin,
                sequence,
                vec![
                    protected
                        .encode_canonical()
                        .at_stage("hostile matrix join encoding")?,
                ],
            )?,
        )?;
    }
    print!(
        "role=bob\nresult=pass\ncase={}\nrequests={}\n",
        case.label(),
        case.request_count()
    );
    Ok(())
}

fn build_hostile_join_request(
    invitation: &SignedCapabilityInvitationV2,
    case: HostileJoinCase,
) -> Result<ProtectedJoinRequest, SessionCtlError> {
    let (issued_at, expires_at) = if matches!(case, HostileJoinCase::Expired) {
        (NOW.saturating_sub(2), NOW.saturating_sub(1))
    } else {
        (NOW, REQUEST_EXPIRES_AT)
    };
    let mut welcome_transport = LocalMemoryWelcomeTransport::new(
        LocalMailboxPolicy::new(300, 1).at_stage("hostile matrix Welcome policy")?,
    )
    .at_stage("hostile matrix Welcome transport")?;
    let mailbox = welcome_transport
        .create_welcome_mailbox(expires_at, issued_at)
        .at_stage("hostile matrix Welcome mailbox")?;
    let (deposit_endpoint, _, _) = mailbox.into_parts();
    let bob = create_client().at_stage("hostile matrix Bob client")?;
    let key_package = bob
        .generate_key_package(issued_at)
        .at_stage("hostile matrix Bob KeyPackage")?;
    let validated = create_key_package_validator()
        .validate_key_package(key_package.as_bytes(), issued_at)
        .at_stage("hostile matrix Bob KeyPackage validation")?;
    let (key_package_bytes, credential_identity, leaf_signature_key) =
        if matches!(case, HostileJoinCase::WrongKeyPackage) {
            let foreign_key_package = bob
                .generate_key_package(issued_at)
                .at_stage("hostile matrix foreign KeyPackage")?;
            let foreign_validated = create_key_package_validator()
                .validate_key_package(foreign_key_package.as_bytes(), issued_at)
                .at_stage("hostile matrix foreign KeyPackage validation")?;
            (
                foreign_key_package.as_bytes().to_vec(),
                *foreign_validated.credential_identity(),
                *foreign_validated.leaf_signature_key(),
            )
        } else {
            (
                key_package.as_bytes().to_vec(),
                *validated.credential_identity(),
                *validated.leaf_signature_key(),
            )
        };
    let request = CapabilityJoinRequest::new(
        InvitationJoinBinding::new(
            *invitation.invitation_id(),
            *invitation.join_challenge(),
            *invitation.invitation_key_id(),
            *invitation.inviter_verifying_key(),
        )
        .at_stage("hostile matrix invitation binding")?,
        JoinRequestBinding::new(random_nonzero()?, issued_at, expires_at, random_nonzero()?)
            .at_stage("hostile matrix request binding")?,
        MlsKeyPackageBinding::new(
            *validated.key_package_reference(),
            key_package_bytes,
            credential_identity,
            leaf_signature_key,
        )
        .at_stage("hostile matrix MLS binding")?,
        deposit_endpoint,
    )
    .at_stage("hostile matrix join request")?;
    AwsLcInvitationJoinProtector::new()
        .seal_capability_request(invitation, &request)
        .at_stage("hostile matrix join protection")
}

fn run_hostile_matrix_inspector(root: &Path) -> Result<(), SessionCtlError> {
    let _case = read_hostile_case(root)?;
    let (database_key, group_id) = read_private_state(root)?;
    let storage = SqlCipherStorage::open(
        &database_path(root),
        VaultKey::new(*database_key).at_stage("hostile matrix reopen key")?,
    )
    .at_stage("hostile matrix owner reopen")?;
    if storage
        .recover_pre_membership_authorizations(&AwsLcInvitationJoinProtector::new(), NOW + 1)
        .at_stage("hostile matrix authorization recovery")?
        != 0
    {
        return Err(stage("hostile matrix authorization mutation"));
    }
    let invitation_bytes = Zeroizing::new(read_bounded_wait(
        &direct_invitation_path(root),
        MAX_WIRE_OBJECT_BYTES,
        FRAME_WAIT,
    )?);
    let invitation = SignedCapabilityInvitationV2::decode_and_verify(&invitation_bytes)
        .at_stage("hostile matrix recovery invitation")?;
    if storage
        .invitation_opening_state(invitation.invitation_id())
        .at_stage("hostile matrix invitation state")?
        != Some(InvitationOpeningState::Available)
    {
        return Err(stage("hostile matrix invitation mutation"));
    }
    let alice = load_durable_client_with_storage(
        group_id,
        storage.clone(),
        storage.clone(),
        storage.clone(),
    )
    .at_stage("hostile matrix Alice identity reload")?;
    if alice.load_group(group_id).is_ok() {
        return Err(stage("hostile matrix durable membership"));
    }
    print!("role=inspector\nresult=pass\ndurable_membership=unchanged\n");
    Ok(())
}

fn read_hostile_case(root: &Path) -> Result<HostileJoinCase, SessionCtlError> {
    let encoded = read_bounded_file(&hostile_case_path(root), 64)
        .ok_or_else(|| stage("hostile process case"))?;
    HostileJoinCase::parse(&encoded)
}

fn receive_protected_join(root: &Path, sequence: u8) -> Result<Vec<u8>, SessionCtlError> {
    let frame = IpcFrame::decode(&read_bounded_wait(
        &relay_out(root, sequence),
        MAX_IPC_FRAME_BYTES,
        FRAME_WAIT,
    )?)?;
    let mut parts = frame.require(FrameKind::ProtectedJoin, sequence)?;
    parts
        .pop()
        .ok_or_else(|| stage("hostile process protected join"))
}

fn run_alice_init(root: &Path) -> Result<(), SessionCtlError> {
    run_alice_init_with_wait(root, FRAME_WAIT)
}

fn run_alice_init_with_wait(
    root: &Path,
    protected_join_wait: Duration,
) -> Result<(), SessionCtlError> {
    let database_key = Zeroizing::new(random_nonzero::<32>()?);
    let storage = SqlCipherStorage::create(
        &database_path(root),
        VaultKey::new(*database_key).at_stage("process owner key")?,
    )
    .at_stage("process owner store")?;
    let protector = AwsLcInvitationJoinProtector::new();
    let generated = storage
        .issue_capability_invitation(&protector, NOW, INVITATION_EXPIRES_AT, NOW)
        .at_stage("process invitation generation")?;
    let mut registry = InvitationRegistry::new(
        InvitationPolicy::new(3_600, 5, 8).at_stage("process invitation policy")?,
    );
    let issued = registry
        .issue_v2(generated, NOW)
        .at_stage("process invitation issue")?;
    let encoded_invitation = issued
        .encode_canonical()
        .at_stage("process invitation encoding")?;
    let validated_invitation = registry
        .validate_descriptor_v2(&encoded_invitation, NOW)
        .at_stage("process invitation validation")?;
    atomic_write(
        &direct_invitation_path(root),
        &encoded_invitation,
        MAX_WIRE_OBJECT_BYTES,
    )?;

    let protected_frame = IpcFrame::decode(&read_bounded_wait(
        &relay_out(root, 1),
        MAX_IPC_FRAME_BYTES,
        protected_join_wait,
    )?)?;
    let mut parts = protected_frame.require(FrameKind::ProtectedJoin, 1)?;
    let protected_bytes = parts.pop().ok_or_else(|| stage("process protected join"))?;
    let protected = ProtectedJoinRequest::decode_canonical(&protected_bytes)
        .at_stage("process protected join")?;
    let request_fingerprint: [u8; 32] = digest(&SHA256, &protected_bytes)
        .as_ref()
        .try_into()
        .map_err(|_| stage("process request fingerprint"))?;
    let opened = protector
        .open_capability_request(issued.private_key(), issued.invitation(), &protected)
        .at_stage("process join opening")?;
    let join_request_id = *opened.request().join_request_id();
    let expected_key_package_reference = *opened.request().key_package_reference();
    let authorization_shadow = AuthorizationShadowInput::new(
        *opened.request().invitation_id(),
        *issued.invitation().signature(),
        *opened.request().join_challenge(),
        join_request_id,
        *opened.request().request_nonce(),
        *opened.request().intended_verifier(),
        expected_key_package_reference,
        *opened.request().credential_identity(),
        *opened.request().leaf_signature_key(),
        request_fingerprint,
        opened.request().issued_at_unix_seconds(),
        opened.request().expires_at_unix_seconds(),
        issued.invitation().expires_at_unix_seconds(),
    )
    .at_stage("process authorization shadow")?;

    let validated_key_package = create_key_package_validator()
        .validate_key_package(opened.request().key_package(), NOW)
        .at_stage("process KeyPackage validation")?;
    if validated_key_package.key_package_reference() != &expected_key_package_reference {
        return Err(stage("process KeyPackage binding"));
    }
    let mut admission = CapabilityAdmissionVerifier::new(
        CapabilityAdmissionPolicy::new(3_600, 5, 8).at_stage("process admission policy")?,
    );
    let verified = admission
        .verify_and_reserve(opened, NOW)
        .at_stage("process admission verification")?;
    let pending = admission
        .reserve_v2_for_approval(&mut registry, &validated_invitation, verified, NOW)
        .at_stage("process approval reservation")?;
    let approval_context = pending.approval_context();
    if approval_context.method() != AdmissionMethod::SecretCapability
        || approval_context.key_package_reference() != &expected_key_package_reference
    {
        return Err(stage("process approval context"));
    }
    let durable_pending = storage
        .reserve_authorization(&protector, authorization_shadow, NOW)
        .at_stage("process durable reservation")?;
    let authorization_attempt_id = *durable_pending.attempt_id();
    let approval_record = encode_approval_record(approval_context);
    let CapabilityApprovalOutcome::Approved(approved) = admission
        .decide_v2(&mut registry, pending, ManualApprovalDecision::Approve, NOW)
        .at_stage("process approval")?
    else {
        return Err(stage("process approval"));
    };
    let durable_approved = storage
        .approve_authorization(durable_pending, &protector, NOW)
        .at_stage("process durable approval")?;

    let group_id = SessionGroupId::new(random_nonzero()?).at_stage("process group ID")?;
    let alice = create_durable_client_with_storage(
        group_id,
        storage.clone(),
        storage.clone(),
        storage.clone(),
    )
    .at_stage("process Alice client")?;
    let mut group = alice
        .create_group(group_id, NOW)
        .at_stage("process Alice group")?;
    let prepared = admission
        .prepare_approved_add(&mut registry, approved, &mut group, NOW)
        .at_stage("process MLS Add")?;
    let pending_durability = match prepared.apply_awaiting_durability(NOW) {
        Ok(pending) => pending,
        Err(_) => {
            storage
                .abandon_approved_authorization(durable_approved, &protector, NOW)
                .at_stage("process durable MLS apply cleanup")?;
            return Err(stage("process MLS apply"));
        }
    };
    let welcome_envelope = OpaqueEnvelope::new(
        random_nonzero()?,
        REQUEST_EXPIRES_AT,
        pending_durability.welcome().as_bytes().to_vec(),
    )
    .at_stage("process Welcome envelope")?;
    let canonical_welcome = welcome_envelope
        .encode_canonical()
        .at_stage("process Welcome encoding")?;
    let transaction_id = random_nonzero()?;
    let transaction = InviterJoinTransaction::new(
        transaction_id,
        *issued.invitation().invitation_id(),
        *issued.invitation().signature(),
        join_request_id,
        request_fingerprint,
        *group.group_id(),
        0,
        1,
        approval_record,
        canonical_welcome,
        pending_durability
            .response_endpoint()
            .encode_canonical()
            .at_stage("process endpoint encoding")?,
        REQUEST_EXPIRES_AT,
    )
    .at_stage("process inviter transaction")?;
    let membership = storage
        .begin_membership_authorization(durable_approved, transaction_id, &protector, NOW)
        .at_stage("process membership authorization")?;
    let (committed_addition, _response_endpoint, shadow_settlement) =
        pending_durability.into_durable_owner_parts();
    committed_addition
        .stage_and_write_to_storage(&mut group, |binding| {
            storage.stage_authorized_inviter(
                membership,
                binding,
                transaction,
                NOW,
                PersistenceFault::None,
            )
        })
        .at_stage("process group storage")?;
    let recovered = storage
        .recover_inviter(&transaction_id)
        .at_stage("process membership recovery")?;
    if recovered.is_none_or(|record| {
        record.epoch_after != 1
            || record.outbox_state != WelcomeOutboxState::Pending
            || record.delivery_attempts != 0
    }) {
        return Err(stage("process membership recovery"));
    }
    if storage
        .recover_authorization_outcome(&authorization_attempt_id, &transaction_id, &protector, NOW)
        .at_stage("process authorization recovery")?
        != AuthorizationState::Committed
        || storage
            .invitation_opening_state(issued.invitation().invitation_id())
            .at_stage("process invitation state")?
            != Some(InvitationOpeningState::Consumed)
    {
        return Err(stage("process membership finalization"));
    }
    shadow_settlement
        .finalize_committed()
        .at_stage("process membership shadow finalization")?;
    drop(group);
    drop(alice);
    drop(storage);

    write_private_state(root, &database_key, group_id)?;
    print!("role=alice-init\nresult=pass\n");
    Ok(())
}

fn run_alice_resume(root: &Path) -> Result<(), SessionCtlError> {
    let (database_key, group_id) = read_private_state(root)?;
    let mut storage = SqlCipherStorage::open(
        &database_path(root),
        VaultKey::new(*database_key).at_stage("process reopen key")?,
    )
    .at_stage("process owner reopen")?;
    let alice = load_durable_client_with_storage(
        group_id,
        storage.clone(),
        storage.clone(),
        storage.clone(),
    )
    .at_stage("process Alice identity reload")?;
    let mut group = alice
        .load_group(group_id)
        .at_stage("process Alice group reload")?;
    if group.epoch() != 1 || group.member_count() != 2 {
        return Err(stage("process Alice reload state"));
    }

    let coordinator = WelcomeDeliveryCoordinator::new(
        CoordinatorPolicy::new(Duration::from_secs(2), 30, MAX_WIRE_OBJECT_BYTES as u64)
            .at_stage("process coordinator policy")?,
    );
    let (control, _cancellation) = ThreadDispatchControl::new();
    let mut relay = RelayDepositAdapter::new(relay_in(root, 2));
    let outcome = BlockingFutureSupervisor::run(
        coordinator.run_once(
            &mut storage,
            &mut LocalV1DepositEndpointResolver,
            &mut relay,
            &control,
        ),
        &control,
        Instant::now() + Duration::from_secs(3),
    )
    .at_stage("process Welcome supervision")?
    .at_stage("process Welcome coordination")?;
    if outcome != CoordinatorOutcome::Accepted {
        return Err(stage("process Welcome coordination"));
    }

    send_opaque(
        root,
        3,
        group
            .protect_application_message(b"hello from Alice")
            .at_stage("process Alice message")?,
    )?;
    let reply = receive_protected(root, 4)?;
    let MessageEvent::Application(application) = group
        .process_protected_message(reply)
        .at_stage("process Alice reply")?
    else {
        return Err(stage("process Alice reply"));
    };
    if application.as_bytes() != b"hello from Bob" {
        return Err(stage("process Alice reply"));
    }

    let update = group
        .prepare_epoch_update(NOW)
        .at_stage("process update preparation")?
        .apply()
        .at_stage("process update apply")?
        .into_commit();
    send_opaque(
        root,
        5,
        ProtectedMessage::from_bytes(update.as_bytes()).at_stage("process update framing")?,
    )?;
    let removal = group
        .prepare_remove_peer(NOW)
        .at_stage("process removal preparation")?
        .apply()
        .at_stage("process removal apply")?
        .into_commit();
    send_opaque(
        root,
        6,
        ProtectedMessage::from_bytes(removal.as_bytes()).at_stage("process removal framing")?,
    )?;
    let post_removal = group
        .protect_application_message(b"message after removal")
        .at_stage("process post-removal protection")?;
    send_opaque(root, 7, post_removal)?;
    if group.epoch() != 3 || group.member_count() != 1 {
        return Err(stage("process removal state"));
    }
    print!("role=alice-resume\nresult=pass\nmessages=1\nupdated_epoch=2\nremoval=enforced\n");
    Ok(())
}

fn run_bob(root: &Path) -> Result<(), SessionCtlError> {
    let invitation_bytes = Zeroizing::new(read_bounded_wait(
        &direct_invitation_path(root),
        MAX_WIRE_OBJECT_BYTES,
        FRAME_WAIT,
    )?);
    let invitation = SignedCapabilityInvitationV2::decode_and_verify(&invitation_bytes)
        .at_stage("process invitation decode")?;
    let mut welcome_transport = LocalMemoryWelcomeTransport::new(
        LocalMailboxPolicy::new(300, 1).at_stage("process Welcome policy")?,
    )
    .at_stage("process Welcome transport")?;
    let mailbox = welcome_transport
        .create_welcome_mailbox(REQUEST_EXPIRES_AT, NOW)
        .at_stage("process Welcome mailbox")?;
    let (deposit_endpoint, receive_capability, acknowledgement_capability) = mailbox.into_parts();
    let bob = create_client().at_stage("process Bob client")?;
    let key_package = bob
        .generate_key_package(NOW)
        .at_stage("process Bob KeyPackage")?;
    let validated = create_key_package_validator()
        .validate_key_package(key_package.as_bytes(), NOW)
        .at_stage("process Bob KeyPackage validation")?;
    let invitation_binding = InvitationJoinBinding::new(
        *invitation.invitation_id(),
        *invitation.join_challenge(),
        *invitation.invitation_key_id(),
        *invitation.inviter_verifying_key(),
    )
    .at_stage("process invitation binding")?;
    let request_binding = JoinRequestBinding::new(
        random_nonzero()?,
        NOW,
        REQUEST_EXPIRES_AT,
        random_nonzero()?,
    )
    .at_stage("process request binding")?;
    let mls_binding = MlsKeyPackageBinding::new(
        *validated.key_package_reference(),
        key_package.as_bytes().to_vec(),
        *validated.credential_identity(),
        *validated.leaf_signature_key(),
    )
    .at_stage("process MLS binding")?;
    let request = CapabilityJoinRequest::new(
        invitation_binding,
        request_binding,
        mls_binding,
        deposit_endpoint,
    )
    .at_stage("process join request")?;
    let protected = AwsLcInvitationJoinProtector::new()
        .seal_capability_request(&invitation, &request)
        .at_stage("process join protection")?
        .encode_canonical()
        .at_stage("process join encoding")?;
    write_frame(
        &relay_in(root, 1),
        IpcFrame::new(FrameKind::ProtectedJoin, 1, vec![protected])?,
    )?;

    let welcome_frame = IpcFrame::decode(&read_bounded_wait(
        &relay_out(root, 2),
        MAX_IPC_FRAME_BYTES,
        FRAME_WAIT,
    )?)?;
    let mut welcome_parts = welcome_frame.require(FrameKind::WelcomeDeposit, 2)?;
    let endpoint = LocalWelcomeDepositEndpoint::decode_canonical(&welcome_parts.remove(0))
        .at_stage("process Welcome endpoint")?;
    let envelope = OpaqueEnvelope::decode_canonical(&welcome_parts.remove(0))
        .at_stage("process Welcome envelope")?;
    let delivery_id = welcome_transport
        .deposit(&endpoint, envelope, NOW)
        .at_stage("process Welcome deposit")?;
    let received = welcome_transport
        .receive(&receive_capability, NOW)
        .at_stage("process Welcome receive")?
        .ok_or_else(|| stage("process Welcome receive"))?;
    if received.delivery_id() != &delivery_id {
        return Err(stage("process Welcome identity"));
    }
    let welcome = WelcomeMessage::from_bytes(received.envelope().ciphertext())
        .at_stage("process Welcome framing")?;
    let mut group = bob.join_group(welcome, NOW).at_stage("process Bob join")?;
    welcome_transport
        .acknowledge(&acknowledgement_capability, delivery_id, NOW)
        .at_stage("process Welcome acknowledgement")?;
    if group.epoch() != 1 {
        return Err(stage("process joined epoch"));
    }

    let first = receive_protected(root, 3)?;
    let MessageEvent::Application(application) = group
        .process_protected_message(first)
        .at_stage("process Bob message")?
    else {
        return Err(stage("process Bob message"));
    };
    if application.as_bytes() != b"hello from Alice" {
        return Err(stage("process Bob message"));
    }
    send_opaque(
        root,
        4,
        group
            .protect_application_message(b"hello from Bob")
            .at_stage("process Bob reply")?,
    )?;
    if group
        .process_protected_message(receive_protected(root, 5)?)
        .at_stage("process Bob update")?
        != MessageEvent::EpochAdvanced
        || group.epoch() != 2
    {
        return Err(stage("process Bob update"));
    }
    let removed = group
        .process_protected_message(receive_protected(root, 6)?)
        .at_stage("process Bob removal")?
        == MessageEvent::Removed;
    if !removed {
        return Err(stage("process Bob removal"));
    }
    let post_removal_rejected = group
        .process_protected_message(receive_protected(root, 7)?)
        .is_err();
    if !post_removal_rejected {
        return Err(stage("process post-removal rejection"));
    }
    print!(
        "role=bob\nresult=pass\njoined_epoch=1\nmessages=1\nupdated_epoch=2\nremoval=enforced\npost_removal=rejected\n"
    );
    Ok(())
}

fn send_opaque(
    root: &Path,
    sequence: u8,
    message: ProtectedMessage,
) -> Result<(), SessionCtlError> {
    let envelope = OpaqueEnvelope::new(random_nonzero()?, MAILBOX_EXPIRES_AT, message.into_bytes())
        .at_stage("process message envelope")?
        .encode_canonical()
        .at_stage("process message encoding")?;
    write_frame(
        &relay_in(root, sequence),
        IpcFrame::new(FrameKind::OpaqueEnvelope, sequence, vec![envelope])?,
    )
}

fn receive_protected(root: &Path, sequence: u8) -> Result<ProtectedMessage, SessionCtlError> {
    let frame = IpcFrame::decode(&read_bounded_wait(
        &relay_out(root, sequence),
        MAX_IPC_FRAME_BYTES,
        FRAME_WAIT,
    )?)?;
    let mut parts = frame.require(FrameKind::OpaqueEnvelope, sequence)?;
    let envelope = OpaqueEnvelope::decode_canonical(
        &parts
            .pop()
            .ok_or_else(|| stage("process message receive"))?,
    )
    .at_stage("process message receive")?;
    ProtectedMessage::from_bytes(envelope.ciphertext()).at_stage("process message framing")
}

struct RelayDepositAdapter {
    destination: PathBuf,
}

impl RelayDepositAdapter {
    fn new(destination: PathBuf) -> Self {
        Self { destination }
    }
}

impl EnvelopeDeposit for RelayDepositAdapter {
    type DepositEndpoint = LocalWelcomeDepositEndpoint;

    fn deposit<'a>(
        &'a mut self,
        endpoint: &'a DepositRight<Self::DepositEndpoint>,
        request: DepositRequest,
        control: &'a dyn DispatchControl,
    ) -> impl std::future::Future<Output = Result<DepositReceipt, TransportFailure>> + Send + 'a
    {
        let result = (|| {
            control.checkpoint(request.budget())?;
            let endpoint_bytes = endpoint
                .provider()
                .encode_canonical()
                .map_err(|_| transport_failure(TransportFailureCode::InvalidAuthority))?;
            let envelope_bytes = request.envelope().as_bytes().to_vec();
            let frame = IpcFrame::new(
                FrameKind::WelcomeDeposit,
                2,
                vec![endpoint_bytes, envelope_bytes],
            )
            .map_err(|_| transport_failure(TransportFailureCode::Internal))?;
            write_frame(&self.destination, frame)
                .map_err(|_| transport_failure(TransportFailureCode::Unavailable))?;
            control.checkpoint(request.budget())?;
            let delivery_id = session_transport::DeliveryId::from_provider_bytes(
                random_nonzero().map_err(|_| transport_failure(TransportFailureCode::Internal))?,
            )
            .ok_or_else(|| transport_failure(TransportFailureCode::Internal))?;
            Ok(DepositReceipt::accepted(delivery_id))
        })();
        ready(result)
    }
}

fn transport_failure(code: TransportFailureCode) -> TransportFailure {
    TransportFailure::new(code, RetryAdvice::Never)
}

fn write_frame(path: &Path, frame: IpcFrame) -> Result<(), SessionCtlError> {
    atomic_write(path, &frame.encode()?, MAX_IPC_FRAME_BYTES)
}

fn atomic_write(path: &Path, bytes: &[u8], maximum: usize) -> Result<(), SessionCtlError> {
    if bytes.is_empty() || bytes.len() > maximum || path.exists() {
        return Err(stage("process channel write"));
    }
    let temporary = path.with_extension("partial");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).at_stage("process channel write")?;
    file.write_all(bytes).at_stage("process channel write")?;
    file.sync_all().at_stage("process channel write")?;
    drop(file);
    fs::rename(&temporary, path).at_stage("process channel publish")?;
    Ok(())
}

fn read_bounded_wait(
    path: &Path,
    maximum: usize,
    timeout: Duration,
) -> Result<Vec<u8>, SessionCtlError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| stage("process channel deadline"))?;
    loop {
        match File::open(path) {
            Ok(file) => return read_bounded(file, maximum),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if Instant::now() >= deadline {
                    return Err(stage("process channel timeout"));
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(_) => return Err(stage("process channel read")),
        }
    }
}

fn read_bounded(mut file: impl Read, maximum: usize) -> Result<Vec<u8>, SessionCtlError> {
    let limit = u64::try_from(maximum)
        .map_err(|_| stage("process channel bound"))?
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(maximum.min(4_096));
    file.by_ref()
        .take(limit)
        .read_to_end(&mut bytes)
        .at_stage("process channel read")?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(stage("process channel bound"));
    }
    Ok(bytes)
}

fn read_bounded_regular_file(path: &Path, maximum: usize) -> Result<Vec<u8>, SessionCtlError> {
    let before = fs::symlink_metadata(path).at_stage("network invitation metadata")?;
    if !before.file_type().is_file()
        || before.len() == 0
        || before.len() > u64::try_from(maximum).map_err(|_| stage("network invitation bound"))?
    {
        return Err(stage("network invitation file"));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let file = options.open(path).at_stage("network invitation read")?;
    let after = file.metadata().at_stage("network invitation metadata")?;
    if !after.file_type().is_file()
        || after.len() != before.len()
        || after.len() == 0
        || after.len() > u64::try_from(maximum).map_err(|_| stage("network invitation bound"))?
    {
        return Err(stage("network invitation file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(stage("network invitation file"));
        }
    }
    read_bounded(file, maximum)
}

fn write_private_state(
    root: &Path,
    database_key: &[u8; 32],
    group_id: SessionGroupId,
) -> Result<(), SessionCtlError> {
    let mut state = Zeroizing::new(Vec::with_capacity(PRIVATE_STATE_BYTES));
    state.extend_from_slice(PRIVATE_STATE_MAGIC);
    state.extend_from_slice(database_key);
    state.extend_from_slice(group_id.as_bytes());
    atomic_write(
        &private_state_path(root),
        state.as_slice(),
        PRIVATE_STATE_BYTES,
    )
}

fn read_private_state(
    root: &Path,
) -> Result<(Zeroizing<[u8; 32]>, SessionGroupId), SessionCtlError> {
    let path = private_state_path(root);
    let mut encoded = Zeroizing::new(read_bounded_wait(&path, PRIVATE_STATE_BYTES, FRAME_WAIT)?);
    fs::remove_file(&path).at_stage("process private state removal")?;
    if encoded.len() != PRIVATE_STATE_BYTES || &encoded[..8] != PRIVATE_STATE_MAGIC {
        return Err(stage("process private state"));
    }
    let database_key = Zeroizing::new(
        encoded[8..40]
            .try_into()
            .map_err(|_| stage("process private state"))?,
    );
    let group_id = SessionGroupId::new(
        encoded[40..]
            .try_into()
            .map_err(|_| stage("process private state"))?,
    )
    .at_stage("process private state")?;
    encoded.zeroize();
    Ok((database_key, group_id))
}

struct ProcessRoot(Option<PathBuf>);

impl ProcessRoot {
    fn new() -> Result<Self, SessionCtlError> {
        Self::create_at(fresh_process_root_path("l1")?)
    }

    fn create_at(root: PathBuf) -> Result<Self, SessionCtlError> {
        if !root.is_absolute() || root.as_os_str().len() > 4_096 || root.exists() {
            return Err(stage("process root"));
        }
        fs::create_dir(&root).at_stage("process root")?;
        let process_root = Self(Some(root));
        atomic_write(
            &process_root.path().join(".sessionctl-l1-root"),
            ROOT_MARKER,
            ROOT_MARKER.len(),
        )?;
        for directory in [
            process_root.path().join("direct"),
            process_root.path().join("relay"),
            process_root.path().join("relay/in"),
            process_root.path().join("relay/out"),
            process_root.path().join("alice"),
        ] {
            fs::create_dir(&directory).at_stage("process root")?;
        }
        Ok(process_root)
    }

    fn path(&self) -> &Path {
        self.0
            .as_deref()
            .expect("process root is unavailable after cleanup")
    }

    fn cleanup(&mut self) -> Result<(), SessionCtlError> {
        self.cleanup_with(|path| fs::remove_dir_all(path))
    }

    fn cleanup_with(
        &mut self,
        remove: impl FnOnce(&Path) -> std::io::Result<()>,
    ) -> Result<(), SessionCtlError> {
        let Some(path) = self.0.as_deref() else {
            return Ok(());
        };
        validate_root(path)?;
        remove(path).at_stage("process root removal")?;
        self.0 = None;
        Ok(())
    }
}

impl Drop for ProcessRoot {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn fresh_process_root_path(label: &str) -> Result<PathBuf, SessionCtlError> {
    let identifier: [u8; 16] = random_nonzero()?;
    let name = format!(
        "session-chat-{label}-{}",
        identifier
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    Ok(std::env::temp_dir().join(name))
}

fn validate_root(root: &Path) -> Result<(), SessionCtlError> {
    if !root.is_absolute()
        || root.as_os_str().len() > 4_096
        || read_bounded_file(&root.join(".sessionctl-l1-root"), ROOT_MARKER.len()).as_deref()
            != Some(ROOT_MARKER)
    {
        return Err(stage("process root validation"));
    }
    Ok(())
}

fn two_terminal_done_path(root: &Path) -> PathBuf {
    root.join("join-complete")
}

struct ManagedChild {
    role: &'static str,
    child: Option<Child>,
}

impl ManagedChild {
    const fn new(role: &'static str, child: Child) -> Self {
        Self {
            role,
            child: Some(child),
        }
    }

    fn child_mut(&mut self) -> Result<&mut Child, SessionCtlError> {
        self.child.as_mut().ok_or_else(|| stage("process child"))
    }

    fn terminate_and_reap(&mut self) -> std::io::Result<()> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        let result = match child.try_wait() {
            Ok(Some(_)) => Ok(()),
            Ok(None) => match child.kill() {
                Ok(()) => child.wait().map(|_| ()),
                Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                    child.wait().map(|_| ())
                }
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        };
        if result.is_err() {
            self.child = Some(child);
        }
        result
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        let _ = self.terminate_and_reap();
    }
}

struct ChildSet(Vec<ManagedChild>);

impl ChildSet {
    const fn new() -> Self {
        Self(Vec::new())
    }

    fn spawn(
        &mut self,
        executable: &Path,
        role: &'static str,
        root: &Path,
    ) -> Result<(), SessionCtlError> {
        let child = Command::new(executable)
            .arg("--internal-role")
            .arg(role)
            .arg(root)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .at_stage("process spawn")?;
        self.0.push(ManagedChild::new(role, child));
        Ok(())
    }

    fn wait_role(
        &mut self,
        role: &'static str,
        timeout: Duration,
    ) -> Result<ChildOutput, SessionCtlError> {
        self.wait_role_with(role, timeout, Child::try_wait)
    }

    fn wait_role_with(
        &mut self,
        role: &'static str,
        timeout: Duration,
        mut try_wait: impl FnMut(&mut Child) -> std::io::Result<Option<ExitStatus>>,
    ) -> Result<ChildOutput, SessionCtlError> {
        let index = self
            .0
            .iter()
            .position(|child| child.role == role)
            .ok_or_else(|| stage("process child"))?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| stage("process child deadline"))?;
        loop {
            let status = try_wait(self.0[index].child_mut()?).at_stage("process child wait")?;
            if let Some(status) = status {
                let managed = self.0.remove(index);
                return collect_child_output(managed, status);
            }
            if Instant::now() >= deadline {
                return Err(stage("process child timeout"));
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    fn cleanup(&mut self) -> Result<(), SessionCtlError> {
        let mut cleanup_failed = false;
        for managed in &mut self.0 {
            cleanup_failed |= managed.terminate_and_reap().is_err();
        }
        self.0.retain(|managed| managed.child.is_some());
        if cleanup_failed || !self.0.is_empty() {
            return Err(stage("process child cleanup"));
        }
        Ok(())
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for ChildSet {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

struct ChildOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn collect_child_output(
    mut managed: ManagedChild,
    status: ExitStatus,
) -> Result<ChildOutput, SessionCtlError> {
    let child = managed.child_mut()?;
    let stdout = child
        .stdout
        .take()
        .map(|stdout| read_bounded(stdout, MAX_CHILD_OUTPUT_BYTES))
        .transpose()?
        .unwrap_or_default();
    let stderr = child
        .stderr
        .take()
        .map(|stderr| read_optional_bounded(stderr, MAX_CHILD_OUTPUT_BYTES))
        .transpose()?
        .unwrap_or_default();
    Ok(ChildOutput {
        status,
        stdout,
        stderr,
    })
}

fn read_optional_bounded(mut file: impl Read, maximum: usize) -> Result<Vec<u8>, SessionCtlError> {
    let mut bytes = Vec::with_capacity(maximum);
    Read::by_ref(&mut file)
        .take(u64::try_from(maximum).map_err(|_| stage("process output"))? + 1)
        .read_to_end(&mut bytes)
        .at_stage("process output")?;
    if bytes.len() > maximum {
        return Err(stage("process output bound"));
    }
    Ok(bytes)
}

fn require_child_output(output: &ChildOutput, expected: &[u8]) -> Result<(), SessionCtlError> {
    if !output.status.success() || !output.stderr.is_empty() || output.stdout != expected {
        return Err(stage("process child result"));
    }
    Ok(())
}

fn direct_invitation_path(root: &Path) -> PathBuf {
    root.join("direct/invitation.v2")
}

fn foreign_invitation_path(root: &Path) -> PathBuf {
    root.join("direct/foreign-invitation.v2")
}

fn hostile_case_path(root: &Path) -> PathBuf {
    root.join("direct/hostile.case")
}

fn private_state_path(root: &Path) -> PathBuf {
    root.join("alice/resume.state")
}

fn database_path(root: &Path) -> PathBuf {
    root.join("alice/owner.sqlite3")
}

fn relay_in(root: &Path, sequence: u8) -> PathBuf {
    root.join("relay/in").join(frame_name(sequence))
}

fn relay_out(root: &Path, sequence: u8) -> PathBuf {
    root.join("relay/out").join(frame_name(sequence))
}

fn frame_name(sequence: u8) -> &'static OsStr {
    match sequence {
        1 => OsStr::new("001.frame"),
        2 => OsStr::new("002.frame"),
        3 => OsStr::new("003.frame"),
        4 => OsStr::new("004.frame"),
        5 => OsStr::new("005.frame"),
        6 => OsStr::new("006.frame"),
        7 => OsStr::new("007.frame"),
        _ => OsStr::new("invalid.frame"),
    }
}

fn unix_now() -> Result<u64, SessionCtlError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .at_stage("process wall clock")
        .map(|duration| duration.as_secs())
}

fn repository_root() -> Option<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .parent()
        .map(Path::to_path_buf)
}

fn git_commit_at(repository_root: &Path) -> String {
    resolve_git_commit(repository_root).unwrap_or_else(|| String::from("unavailable"))
}

/// Resolves bounded Git commit metadata for the retained conformance harness.
///
/// This checkout-independent integration seam is not a product metadata API.
#[doc(hidden)]
pub fn resolve_l1_process_git_commit(repository_root: &Path) -> Option<String> {
    resolve_git_commit(repository_root)
}

fn git_dirty_at(repository_root: &Path) -> bool {
    let tracked = git_status_at(repository_root, &["diff-index", "--quiet", "HEAD", "--"]);
    if tracked.is_none_or(|status| status.code() != Some(0)) {
        return true;
    }
    let untracked = git_status_at(
        repository_root,
        &[
            "ls-files",
            "--others",
            "--exclude-standard",
            "--error-unmatch",
            ":(glob)**",
        ],
    );
    untracked.is_none_or(|status| status.code() != Some(1))
}

fn lock_digest_at(repository_root: &Path) -> String {
    read_bounded_file(&repository_root.join("Cargo.lock"), MAX_LOCKFILE_BYTES)
        .map(|bytes| hex(digest(&SHA256, &bytes).as_ref()))
        .unwrap_or_else(|| String::from("unavailable"))
}

fn pinned_toolchain_at(repository_root: &Path) -> String {
    let Some(encoded) = read_bounded_file(
        &repository_root.join("rust-toolchain.toml"),
        MAX_TOOLCHAIN_BYTES,
    ) else {
        return String::from("unavailable");
    };
    let Ok(contents) = String::from_utf8(encoded) else {
        return String::from("unavailable");
    };
    contents
        .lines()
        .find_map(|line| line.trim().strip_prefix("channel = \"")?.strip_suffix('"'))
        .filter(|channel| {
            !channel.is_empty()
                && channel.len() <= 32
                && channel
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        })
        .map(str::to_owned)
        .unwrap_or_else(|| String::from("unavailable"))
}

fn read_bounded_file(path: &Path, maximum: usize) -> Option<Vec<u8>> {
    let mut file = File::open(path).ok()?;
    if file.metadata().ok()?.len() > u64::try_from(maximum).ok()? {
        return None;
    }
    let mut bytes = Vec::with_capacity(maximum.min(4_096));
    Read::by_ref(&mut file)
        .take(u64::try_from(maximum).ok()?.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() <= maximum).then_some(bytes)
}

fn resolve_git_commit(repository_root: &Path) -> Option<String> {
    let git_marker = repository_root.join(".git");
    let git_directory = if git_marker.is_dir() {
        git_marker
    } else {
        let marker = String::from_utf8(read_bounded_file(&git_marker, MAX_GIT_PATH_BYTES)?).ok()?;
        let path = marker.trim().strip_prefix("gitdir: ")?;
        let path = Path::new(path);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            repository_root.join(path)
        }
    };
    let head = String::from_utf8(read_bounded_file(
        &git_directory.join("HEAD"),
        MAX_GIT_REF_BYTES,
    )?)
    .ok()?;
    if let Some(commit) = parse_git_commit(head.trim()) {
        return Some(commit);
    }
    let reference = head.trim().strip_prefix("ref: ")?;
    let reference_path = Path::new(reference);
    if !reference.starts_with("refs/")
        || reference_path.is_absolute()
        || !reference_path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
    {
        return None;
    }
    let common_directory = read_bounded_file(&git_directory.join("commondir"), MAX_GIT_PATH_BYTES)
        .and_then(|encoded| String::from_utf8(encoded).ok())
        .map_or_else(
            || git_directory.clone(),
            |path| git_directory.join(path.trim()),
        );
    [git_directory, common_directory]
        .into_iter()
        .find_map(|directory| {
            let encoded = read_bounded_file(&directory.join(reference_path), MAX_GIT_REF_BYTES)?;
            let value = String::from_utf8(encoded).ok()?;
            parse_git_commit(value.trim())
        })
}

fn parse_git_commit(value: &str) -> Option<String> {
    (value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

fn git_status_at(repository_root: &Path, arguments: &[&str]) -> Option<ExitStatus> {
    let mut command = Command::new("git");
    command.current_dir(repository_root).args(arguments);
    bounded_command_status(command, METADATA_COMMAND_WAIT)
}

fn bounded_command_status(mut command: Command, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now().checked_add(timeout)?;
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut managed = ManagedChild::new("metadata", child);
    loop {
        let wait_result = match managed.child_mut() {
            Ok(child) => child.try_wait(),
            Err(_) => {
                let _ = managed.terminate_and_reap();
                return None;
            }
        };
        match wait_result {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {}
            Err(_) => {
                let _ = managed.terminate_and_reap();
                return None;
            }
        }
        if Instant::now() >= deadline {
            let _ = managed.terminate_and_reap();
            return None;
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

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
}
