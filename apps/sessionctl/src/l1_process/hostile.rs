//! Hostile first-contact and replay cases.

use super::super::StageResult;
use super::super::{
    INVITATION_EXPIRES_AT, NOW, REQUEST_EXPIRES_AT, SessionCtlError, random_nonzero, stage,
};
use super::ipc::{FrameKind, IpcFrame, atomic_write, read_bounded_wait, write_frame};
use super::model::PrivateState;
use super::resources::{
    ChildSet, ProcessRoot, database_path, direct_invitation_path, foreign_invitation_path,
    hostile_case_path, read_bounded_file, relay_in, relay_out, require_child_output,
};
use super::{CHILD_WAIT, FRAME_WAIT, MAX_IPC_FRAME_BYTES};
use admission_capability::{
    CapabilityAdmissionError, CapabilityAdmissionPolicy, CapabilityAdmissionVerifier,
};
use aws_lc_rs::digest::{SHA256, digest};
use session_core::{InvitationLifecycle, InvitationPolicy, InvitationRegistry};
use session_crypto_hpke::AwsLcInvitationJoinProtector;
use session_crypto_hpke::InvitationJoinProtector;
use session_crypto_mls::{
    SessionGroupId, create_client, create_durable_client_with_storage,
    create_key_package_validator, load_durable_client_with_storage,
};
use session_protocol::{
    CapabilityJoinRequest, InvitationJoinBinding, JoinRequestBinding, MAX_WIRE_OBJECT_BYTES,
    MlsKeyPackageBinding, ProtectedJoinRequest, SignedCapabilityInvitationV2,
};
use session_transport::{LocalMailboxPolicy, LocalMemoryWelcomeTransport};
use std::path::Path;
use std::process::Stdio;
use storage_sqlcipher::{
    AuthorizationShadowInput, InvitationOpeningState, SqlCipherStorage, StoreError, VaultKey,
};
use zeroize::Zeroizing;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HostileJoinCase {
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

    pub(super) fn parse(bytes: &[u8]) -> Result<Self, SessionCtlError> {
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
pub(super) fn run_hostile_replay_controller(root: &Path) -> Result<(), SessionCtlError> {
    let executable = std::env::current_exe().at_stage("hostile process executable")?;
    let mut children = ChildSet::new();
    let scenario_result = (|| {
        children.spawn(&executable, "hostile-replay-service", root)?;
        children.spawn(&executable, "hostile-replay-bob", root)?;
        let state = children.spawn_private_writer(&executable, "hostile-replay-alice", root)?;

        let alice = children.wait_role("hostile-replay-alice", CHILD_WAIT)?;
        require_child_output(
            &alice,
            b"role=alice\nresult=pass\nreplay=rejected\nmembership=unchanged\n",
        )?;
        children.spawn_with_io(
            &executable,
            "hostile-replay-inspector",
            root,
            state.into(),
            Stdio::piped(),
        )?;
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
    scenario_result?;
    child_cleanup_result?;

    print!(
        "version=1\nscenario=E2E-JOIN-002\ncase=replayed-protected-join\nresult=pass\nreplay=rejected\nmembership=unchanged\nredaction=pass\nchild_cleanup=pass\ndirectory_cleanup=delegated\n"
    );
    Ok(())
}

pub(super) fn run_hostile_replay_service(root: &Path) -> Result<(), SessionCtlError> {
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

pub(super) fn run_hostile_replay_alice(root: &Path) -> Result<PrivateState, SessionCtlError> {
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
    print!("role=alice\nresult=pass\nreplay=rejected\nmembership=unchanged\n");
    Ok(PrivateState {
        database_key,
        group_id,
    })
}

pub(super) fn run_hostile_replay_bob(root: &Path) -> Result<(), SessionCtlError> {
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

pub(super) fn run_hostile_replay_inspector(root: &Path) -> Result<(), SessionCtlError> {
    let PrivateState {
        database_key,
        group_id,
    } = PrivateState::read_from(std::io::stdin())?;
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

pub(super) fn run_hostile_matrix_controller(root: &Path) -> Result<(), SessionCtlError> {
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
            let state = children.spawn_private_writer(
                &executable,
                "hostile-matrix-alice",
                case_root.path(),
            )?;

            let alice = children.wait_role("hostile-matrix-alice", CHILD_WAIT)?;
            let admission_boundary = if matches!(case, HostileJoinCase::WrongVerifier) {
                "admission_boundary=reserve-v2-for-approval-rejected\n"
            } else {
                ""
            };
            require_child_output(
                &alice,
                format!(
                    "role=alice\nresult=pass\ncase={}\n{admission_boundary}approval=not-reached\nmls_add=not-reached\nmembership=unchanged\n",
                    case.label(),
                )
                .as_bytes(),
            )?;
            children.spawn_with_io(
                &executable,
                "hostile-matrix-inspector",
                case_root.path(),
                state.into(),
                Stdio::piped(),
            )?;
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

    print!(
        "version=1\nscenario=E2E-JOIN-002\ntopology=two-clients-one-untrusted-service\nresult=pass\ncases=malformed-protected-join,expired-protected-join,copied-protected-join,wrong-invitation,wrong-key-package,wrong-verifier,reordered-protected-joins\ncase_count=7\napproval=not-reached\nmls_add=not-reached\nmembership=unchanged\nservice_input=canonical-public-only\nredaction=pass\nchild_cleanup=pass\ndirectory_cleanup=delegated\n"
    );
    Ok(())
}

pub(super) fn run_hostile_matrix_service(root: &Path) -> Result<(), SessionCtlError> {
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

pub(super) fn run_hostile_matrix_alice(root: &Path) -> Result<PrivateState, SessionCtlError> {
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
    let generated = storage
        .issue_capability_invitation(
            &protector,
            invitation_issued_at,
            INVITATION_EXPIRES_AT,
            invitation_issued_at,
        )
        .at_stage("hostile matrix invitation generation")?;
    let mut registry = InvitationRegistry::new(
        InvitationPolicy::new(3_600, 5, 8).at_stage("hostile matrix invitation policy")?,
    );
    let issued = registry
        .issue_v2(generated, NOW)
        .at_stage("hostile matrix invitation issue")?;
    let encoded_invitation = issued
        .invitation()
        .encode_canonical()
        .at_stage("hostile matrix invitation encoding")?;
    let validated_invitation = registry
        .validate_descriptor_v2(&encoded_invitation, NOW)
        .at_stage("hostile matrix invitation validation")?;
    let foreign = storage
        .issue_capability_invitation(&protector, NOW, INVITATION_EXPIRES_AT, NOW)
        .at_stage("hostile matrix foreign invitation generation")?;
    atomic_write(
        &direct_invitation_path(root),
        &encoded_invitation,
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
            let mut admission = CapabilityAdmissionVerifier::new(
                CapabilityAdmissionPolicy::new(3_600, 5, 8)
                    .at_stage("hostile wrong verifier admission policy")?,
            );
            let verified = admission
                .verify_and_reserve(opened, NOW)
                .at_stage("hostile wrong verifier verification")?;
            if !matches!(
                admission.reserve_v2_for_approval(
                    &mut registry,
                    &validated_invitation,
                    verified,
                    NOW,
                ),
                Err(CapabilityAdmissionError::Rejected)
            ) || admission.pending_count() != 0
                || registry.lifecycle(issued.invitation().invitation_id())
                    != Some(InvitationLifecycle::Available)
            {
                return Err(stage("hostile wrong verifier reservation rejection"));
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
    let admission_boundary = if matches!(case, HostileJoinCase::WrongVerifier) {
        "admission_boundary=reserve-v2-for-approval-rejected\n"
    } else {
        ""
    };
    print!(
        "role=alice\nresult=pass\ncase={}\n{admission_boundary}approval=not-reached\nmls_add=not-reached\nmembership=unchanged\n",
        case.label(),
    );
    Ok(PrivateState {
        database_key,
        group_id,
    })
}

pub(super) fn run_hostile_matrix_bob(root: &Path) -> Result<(), SessionCtlError> {
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

pub(super) fn build_hostile_join_request(
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
            let foreign_bob = create_client().at_stage("hostile matrix foreign Bob client")?;
            let foreign_key_package = foreign_bob
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

pub(super) fn run_hostile_matrix_inspector(root: &Path) -> Result<(), SessionCtlError> {
    let _case = read_hostile_case(root)?;
    let PrivateState {
        database_key,
        group_id,
    } = PrivateState::read_from(std::io::stdin())?;
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

pub(super) fn read_hostile_case(root: &Path) -> Result<HostileJoinCase, SessionCtlError> {
    let encoded = read_bounded_file(&hostile_case_path(root), 64)
        .ok_or_else(|| stage("hostile process case"))?;
    HostileJoinCase::parse(&encoded)
}

pub(super) fn receive_protected_join(
    root: &Path,
    sequence: u8,
) -> Result<Vec<u8>, SessionCtlError> {
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
