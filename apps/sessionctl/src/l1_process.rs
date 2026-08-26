//! Bounded independent-process conformance runner.
//!
//! This module is a test topology, not a network transport or production
//! credential-custody design. Its relay receives only canonical public wire
//! objects and the one deposit authority it exercises. The bearer invitation
//! and encrypted-owner key state remain on distinct direct/private channels.

use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    future::ready,
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
    InvitationState, InviterJoinTransaction, PersistenceFault, SqlCipherStorage, VaultKey,
    WelcomeOutboxState,
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
                "child_cleanup=pass\n"
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
    let root = ProcessRoot::new()?;
    let executable = std::env::current_exe().at_stage("process executable")?;
    let mut children = ChildSet::new();
    children.spawn(&executable, "service", root.path())?;
    children.spawn(&executable, "bob", root.path())?;
    children.spawn(&executable, "alice-init", root.path())?;

    let alice_init = children.wait_role("alice-init", CHILD_WAIT)?;
    require_child_output(&alice_init, b"role=alice-init\nresult=pass\n")?;
    children.spawn(&executable, "alice-resume", root.path())?;

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

    let report = L1ProcessReport {
        started_at,
        completed_at: unix_now()?,
        commit: git_commit(),
        dirty: git_dirty(),
        toolchain: pinned_toolchain(),
        lock_digest: lock_digest(),
    };
    if report.encode_v1().len() > MAX_EVIDENCE_BYTES {
        return Err(stage("evidence bound"));
    }
    Ok(report)
}

/// Runs one hidden role selected only by the controller process.
pub fn run_l1_process_internal_role(role: &str, root: PathBuf) -> Result<(), SessionCtlError> {
    validate_root(&root)?;
    match role {
        "service" => run_service(&root),
        "alice-init" => run_alice_init(&root),
        "alice-resume" => run_alice_resume(&root),
        "bob" => run_bob(&root),
        _ => Err(stage("process role")),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrameKind {
    ProtectedJoin = 1,
    WelcomeDeposit = 2,
    OpaqueEnvelope = 3,
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
    for sequence in 1..=EXPECTED_FRAMES {
        let encoded =
            read_bounded_wait(&relay_in(root, sequence), MAX_IPC_FRAME_BYTES, FRAME_WAIT)?;
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

fn run_alice_init(root: &Path) -> Result<(), SessionCtlError> {
    let database_key = Zeroizing::new(random_nonzero::<32>()?);
    let storage = SqlCipherStorage::create(
        &database_path(root),
        VaultKey::new(*database_key).at_stage("process owner key")?,
    )
    .at_stage("process owner store")?;
    let protector = AwsLcInvitationJoinProtector::new();
    let generated = protector
        .generate_capability_invitation(NOW, INVITATION_EXPIRES_AT)
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
        FRAME_WAIT,
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
    storage
        .seed_reservation(
            *issued.invitation().invitation_id(),
            *issued.invitation().signature(),
            join_request_id,
            INVITATION_EXPIRES_AT,
            NOW,
        )
        .at_stage("process durable reservation")?;
    let approval_record = encode_approval_record(approval_context);
    let CapabilityApprovalOutcome::Approved(approved) = admission
        .decide_v2(&mut registry, pending, ManualApprovalDecision::Approve, NOW)
        .at_stage("process approval")?
    else {
        return Err(stage("process approval"));
    };

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
    let pending_durability = prepared
        .apply_awaiting_durability(NOW)
        .at_stage("process MLS apply")?;
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
    storage
        .stage_inviter(transaction, NOW, PersistenceFault::None)
        .at_stage("process membership staging")?;
    group.write_to_storage().at_stage("process group storage")?;
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
    let committed = pending_durability
        .finalize_committed()
        .at_stage("process membership finalization")?;
    if committed.key_package_reference() != &expected_key_package_reference
        || storage
            .invitation_state(issued.invitation().invitation_id())
            .at_stage("process invitation state")?
            != Some(InvitationState::Consumed)
    {
        return Err(stage("process membership finalization"));
    }
    drop(committed);
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

struct ProcessRoot(PathBuf);

impl ProcessRoot {
    fn new() -> Result<Self, SessionCtlError> {
        let identifier: [u8; 16] = random_nonzero()?;
        let name = format!(
            "session-chat-l1-{}",
            identifier
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let root = std::env::temp_dir().join(name);
        fs::create_dir(&root).at_stage("process root")?;
        for directory in [
            root.join("direct"),
            root.join("relay"),
            root.join("relay/in"),
            root.join("relay/out"),
            root.join("alice"),
        ] {
            fs::create_dir(&directory).at_stage("process root")?;
        }
        atomic_write(
            &root.join(".sessionctl-l1-root"),
            ROOT_MARKER,
            ROOT_MARKER.len(),
        )?;
        Ok(Self(root))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ProcessRoot {
    fn drop(&mut self) {
        let marker = self.0.join(".sessionctl-l1-root");
        if fs::read(&marker).ok().as_deref() == Some(ROOT_MARKER) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

fn validate_root(root: &Path) -> Result<(), SessionCtlError> {
    if !root.is_absolute()
        || root.as_os_str().len() > 4_096
        || fs::read(root.join(".sessionctl-l1-root")).ok().as_deref() != Some(ROOT_MARKER)
    {
        return Err(stage("process root validation"));
    }
    Ok(())
}

struct ManagedChild {
    role: &'static str,
    child: Child,
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
        self.0.push(ManagedChild { role, child });
        Ok(())
    }

    fn wait_role(
        &mut self,
        role: &'static str,
        timeout: Duration,
    ) -> Result<ChildOutput, SessionCtlError> {
        let index = self
            .0
            .iter()
            .position(|child| child.role == role)
            .ok_or_else(|| stage("process child"))?;
        let mut managed = self.0.remove(index);
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| stage("process child deadline"))?;
        loop {
            if let Some(status) = managed.child.try_wait().at_stage("process child wait")? {
                return collect_child_output(managed.child, status);
            }
            if Instant::now() >= deadline {
                let _ = managed.child.kill();
                let _ = managed.child.wait();
                return Err(stage("process child timeout"));
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for ChildSet {
    fn drop(&mut self) {
        for managed in &mut self.0 {
            let _ = managed.child.kill();
            let _ = managed.child.wait();
        }
    }
}

struct ChildOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn collect_child_output(
    mut child: Child,
    status: ExitStatus,
) -> Result<ChildOutput, SessionCtlError> {
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
    file.by_ref()
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

fn git_commit() -> String {
    command_output("git", &["rev-parse", "HEAD"])
        .filter(|value| value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .unwrap_or_else(|| String::from("unavailable"))
}

fn git_dirty() -> bool {
    Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=normal"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()
        .is_none_or(|output| !output.status.success() || !output.stdout.is_empty())
}

fn lock_digest() -> String {
    fs::read("Cargo.lock")
        .ok()
        .filter(|bytes| bytes.len() <= 4 * 1024 * 1024)
        .map(|bytes| hex(digest(&SHA256, &bytes).as_ref()))
        .unwrap_or_else(|| String::from("unavailable"))
}

fn pinned_toolchain() -> String {
    let Ok(contents) = fs::read_to_string("rust-toolchain.toml") else {
        return String::from("unavailable");
    };
    if contents.len() > 4_096 {
        return String::from("unavailable");
    }
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

fn command_output(program: &str, arguments: &[&str]) -> Option<String> {
    let output = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() || output.stdout.len() > 128 {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|value| value.trim().to_owned())
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
