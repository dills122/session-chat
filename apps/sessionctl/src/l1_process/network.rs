//! Explicit FastV1 network bridge and operator handoff.

use super::super::StageResult;
use super::super::{SessionCtlError, stage};
use super::ipc::{FrameKind, IpcFrame, atomic_write, read_bounded_regular_file, read_bounded_wait};
use super::resources::{
    ProcessRoot, direct_invitation_path, fresh_process_root_path, relay_in, relay_out,
};
use super::roles::{run_alice_init_with_receiver, run_alice_resume, run_bob};
use super::{
    CAPABILITY_HANDOFF_DISCLOSURE, FRAME_WAIT, MAX_IPC_FRAME_BYTES, NETWORK_OPERATION_WAIT,
    OPERATOR_HANDOFF_WAIT,
};
use session_protocol::{MAX_WIRE_OBJECT_BYTES, SignedCapabilityInvitationV2};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use transport_iroh::{
    FastEndpointAddress, FastEndpointId, IrohFastEndpoint, IrohFastError, IrohFastLink,
};
use zeroize::Zeroizing;
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

pub(super) async fn connect_network_loopback_join(
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

pub(super) async fn run_network_host_with_endpoint(
    mut root: ProcessRoot,
    endpoint: IrohFastEndpoint,
) -> Result<(), SessionCtlError> {
    let alice_root = root.path().to_path_buf();
    let (candidates, receiver) =
        std::sync::mpsc::sync_channel::<(Vec<u8>, tokio::sync::oneshot::Sender<bool>)>(1);
    let alice = tokio::task::spawn_blocking(move || {
        let state = run_alice_init_with_receiver(&alice_root, |validate| {
            let deadline = Instant::now() + OPERATOR_HANDOFF_WAIT;
            for _ in 0..32 {
                let (bytes, reply) = receiver
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    .map_err(|_| stage("network admission wait"))?;
                let accepted = validate(&bytes);
                if reply.send(accepted).is_err() {
                    continue;
                }
                if accepted {
                    return Ok(bytes);
                }
            }
            Err(stage("network admission attempts"))
        })?;
        run_alice_resume(&alice_root, state)
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
            "mode=network-host\n{CAPABILITY_HANDOFF_DISCLOSURE}invitation=ready\ninvitation_file={}",
            direct_invitation_path(root.path()).display()
        );
        let deadline = tokio::time::Instant::now() + OPERATOR_HANDOFF_WAIT;
        for _ in 0..32 {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() { break; }
            let Ok(mut link) = endpoint.accept_candidate(None, remaining, Duration::from_secs(2), MAX_IPC_FRAME_BYTES).await else { continue; };
            let candidate_deadline = deadline.min(tokio::time::Instant::now() + Duration::from_secs(2));
            let Ok(Ok(bytes)) = tokio::time::timeout_at(candidate_deadline, link.receive_frame(Duration::from_secs(2))).await else {
                link.reject(); continue;
            };
            let (reply, accepted) = tokio::sync::oneshot::channel();
            candidates.try_send((bytes, reply)).map_err(|_| stage("network admission queue"))?;
            if !matches!(tokio::time::timeout_at(candidate_deadline, accepted).await, Ok(Ok(true))) {
                link.reject(); continue;
            }
            return network_host_bridge_after_join(root.path(), link).await;
        }
        Err(stage("network admission unavailable"))
    }
    .await;
    drop(candidates);
    let alice_result = alice.await.map_err(|_| stage("network Alice task"))?;
    let cleanup_result = root.cleanup();
    scenario_result?;
    alice_result?;
    cleanup_result?;
    println!("mode=network-host\nstatus=complete");
    Ok(())
}

pub(super) async fn run_network_join_with_link(
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

#[cfg(test)]
pub(super) async fn network_host_bridge(
    root: &Path,
    mut link: IrohFastLink,
) -> Result<(), SessionCtlError> {
    receive_network_frame(root, &mut link, 1, FrameKind::ProtectedJoin).await?;
    network_host_bridge_after_join(root, link).await
}

pub(super) async fn network_host_bridge_after_join(
    root: &Path,
    mut link: IrohFastLink,
) -> Result<(), SessionCtlError> {
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

pub(super) fn read_network_invitation(path: &Path) -> Result<Zeroizing<Vec<u8>>, SessionCtlError> {
    if !path.is_absolute() || path.as_os_str().len() > 4_096 {
        return Err(stage("network invitation path"));
    }
    let invitation = Zeroizing::new(read_bounded_regular_file(path, MAX_WIRE_OBJECT_BYTES)?);
    SignedCapabilityInvitationV2::decode_and_verify(&invitation).at_stage("network invitation")?;
    Ok(invitation)
}

pub(super) async fn prepare_public_endpoint<Prepare, Bind, BindFuture>(
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

pub(super) async fn network_join_bridge(
    root: &Path,
    link: &mut IrohFastLink,
) -> Result<(), SessionCtlError> {
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

pub(super) async fn send_network_frame(
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

pub(super) async fn receive_network_frame(
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

pub(super) fn expected_frame_kind(sequence: u8) -> Result<FrameKind, SessionCtlError> {
    match sequence {
        1 => Ok(FrameKind::ProtectedJoin),
        2 => Ok(FrameKind::WelcomeDeposit),
        3..=7 => Ok(FrameKind::OpaqueEnvelope),
        _ => Err(stage("network frame schedule")),
    }
}

pub(super) async fn read_bounded_wait_async(
    path: PathBuf,
    maximum: usize,
    timeout: Duration,
) -> Result<Vec<u8>, SessionCtlError> {
    tokio::task::spawn_blocking(move || read_bounded_wait(&path, maximum, timeout))
        .await
        .map_err(|_| stage("network file read task"))?
}

pub(super) async fn atomic_write_async(
    path: PathBuf,
    bytes: Vec<u8>,
    maximum: usize,
) -> Result<(), SessionCtlError> {
    tokio::task::spawn_blocking(move || atomic_write(&path, &bytes, maximum))
        .await
        .map_err(|_| stage("network file write task"))?
}
