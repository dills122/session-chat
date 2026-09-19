//! L1 Alice, Bob, service, and relay roles.

use super::super::StageResult;
use super::super::{
    INVITATION_EXPIRES_AT, MAILBOX_EXPIRES_AT, NOW, REQUEST_EXPIRES_AT, SessionCtlError,
    encode_approval_record, random_nonzero, stage,
};
use super::ipc::{FrameKind, IpcFrame, atomic_write, read_bounded_wait, write_frame};
use super::model::PrivateState;
use super::resources::{database_path, direct_invitation_path, relay_in, relay_out};
use super::{EXPECTED_FRAMES, FRAME_WAIT, MAX_IPC_FRAME_BYTES};
use admission_capability::{
    CapabilityAdmissionPolicy, CapabilityAdmissionVerifier, CapabilityApprovalOutcome,
    ManualApprovalDecision,
};
use aws_lc_rs::digest::{SHA256, digest};
use session_admission::AdmissionMethod;
use session_admission::PendingAdmission;
use session_core::{InvitationPolicy, InvitationRegistry};
use session_crypto::MessageSession;
use session_crypto::{MessageEvent, ProtectedMessage};
use session_crypto_hpke::AwsLcInvitationJoinProtector;
use session_crypto_hpke::InvitationJoinProtector;
use session_crypto_mls::{
    SessionGroupId, WelcomeMessage, create_client, create_durable_client_with_storage,
    create_key_package_validator, load_durable_client_with_storage,
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
use std::future::ready;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use storage_sqlcipher::{
    AuthorizationShadowInput, AuthorizationState, InvitationOpeningState, InviterJoinTransaction,
    PersistenceFault, SqlCipherStorage, StoreError, VaultKey, WelcomeOutboxState,
};
use zeroize::Zeroizing;
pub(super) fn run_service(root: &Path) -> Result<(), SessionCtlError> {
    run_service_with_initial_wait(root, FRAME_WAIT)
}

pub(super) fn run_service_with_initial_wait(
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
pub(super) fn run_alice_init(root: &Path) -> Result<PrivateState, SessionCtlError> {
    run_alice_init_with_wait(root, FRAME_WAIT)
}

pub(super) fn run_alice_init_with_wait(
    root: &Path,
    protected_join_wait: Duration,
) -> Result<PrivateState, SessionCtlError> {
    run_alice_init_with_receiver(root, |_| {
        read_bounded_wait(
            &relay_out(root, 1),
            MAX_IPC_FRAME_BYTES,
            protected_join_wait,
        )
    })
}

pub(super) fn run_alice_init_with_receiver(
    root: &Path,
    receive: impl FnOnce(&dyn Fn(&[u8]) -> bool) -> Result<Vec<u8>, SessionCtlError>,
) -> Result<PrivateState, SessionCtlError> {
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

    let encoded_join = receive(&|bytes| {
        let Ok(frame) = IpcFrame::decode(bytes) else {
            return false;
        };
        let Ok(mut parts) = frame.require(FrameKind::ProtectedJoin, 1) else {
            return false;
        };
        let Some(bytes) = parts.pop() else {
            return false;
        };
        let Ok(protected) = ProtectedJoinRequest::decode_canonical(&bytes) else {
            return false;
        };
        protector
            .open_capability_request(issued.private_key(), issued.invitation(), &protected)
            .is_ok()
    })?;
    let protected_frame = IpcFrame::decode(&encoded_join)?;
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
    let welcome_envelope_id = random_nonzero()?;
    let transaction_id = random_nonzero()?;
    let response_endpoint = pending_durability
        .response_endpoint()
        .encode_canonical()
        .at_stage("process endpoint encoding")?;
    let membership = storage
        .begin_membership_authorization(durable_approved, transaction_id, &protector, NOW)
        .at_stage("process membership authorization")?;
    let (committed_addition, _response_endpoint, shadow_settlement) =
        pending_durability.into_durable_owner_parts();
    committed_addition
        .stage_and_write_to_storage(&mut group, |binding| {
            let transaction = InviterJoinTransaction::new_bound(
                transaction_id,
                *issued.invitation().invitation_id(),
                *issued.invitation().signature(),
                join_request_id,
                request_fingerprint,
                *group_id.as_bytes(),
                0,
                1,
                approval_record,
                welcome_envelope_id,
                REQUEST_EXPIRES_AT,
                response_endpoint,
                REQUEST_EXPIRES_AT,
            )
            .map_err(|_| StoreError::Rejected)?;
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

    print!("role=alice-init\nresult=pass\n");
    Ok(PrivateState {
        database_key,
        group_id,
    })
}

pub(super) fn run_alice_resume(root: &Path, state: PrivateState) -> Result<(), SessionCtlError> {
    let PrivateState {
        database_key,
        group_id,
    } = state;
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

pub(super) fn run_bob(root: &Path) -> Result<(), SessionCtlError> {
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

pub(super) fn send_opaque(
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

pub(super) fn receive_protected(
    root: &Path,
    sequence: u8,
) -> Result<ProtectedMessage, SessionCtlError> {
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

pub(super) struct RelayDepositAdapter {
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

pub(super) fn transport_failure(code: TransportFailureCode) -> TransportFailure {
    TransportFailure::new(code, RetryAdvice::Never)
}
