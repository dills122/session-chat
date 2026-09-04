use std::{
    future::Future,
    path::PathBuf,
    pin::pin,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use admission_capability::{
    CapabilityAdmissionPolicy, CapabilityAdmissionVerifier, CapabilityApprovalOutcome,
    ManualApprovalDecision,
};
use aws_lc_rs::digest::{SHA256, digest};
use session_admission::{AdmissionMethod, PendingAdmission};
use session_core::{InvitationLifecycle, InvitationPolicy, InvitationRegistry};
use session_crypto_hpke::{AwsLcInvitationJoinProtector, InvitationJoinProtector};
use session_crypto_mls::{
    SessionGroupId, WelcomeMessage, create_client, create_client_with_storage,
    create_key_package_validator,
};
use session_protocol::{
    CapabilityJoinRequest, InvitationJoinBinding, JoinRequestBinding, MlsKeyPackageBinding,
    OpaqueEnvelope,
};
use session_transport::{
    CoordinatorOutcome, CoordinatorPolicy, DispatchControl, LocalMailboxPolicy,
    LocalMemoryWelcomeTransport, LocalV1DepositEndpointResolver, WelcomeDeliveryCoordinator,
};
use storage_sqlcipher::{
    AuthorizationShadowInput, AuthorizationState, InvitationOpeningState, InviterJoinTransaction,
    PersistenceFault, SqlCipherStorage, StoreError, VaultKey, WelcomeOutboxState,
};

const NOW: u64 = 1_900_000_000;
const REQUEST_ID: [u8; 16] = [0x31; 16];
const TRANSACTION_ID: [u8; 16] = [0x41; 16];

struct TestDatabase(PathBuf);

impl TestDatabase {
    fn new(name: &str) -> Self {
        Self(std::env::temp_dir().join(format!(
            "session-chat-storage-sqlcipher-capability-composition-{name}-{}.sqlite3",
            std::process::id(),
        )))
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.0.with_extension("sqlite3-journal"));
    }
}

struct TestControl {
    monotonic_now: Instant,
    wall_now_unix_seconds: u64,
}

impl DispatchControl for TestControl {
    fn monotonic_now(&self) -> Instant {
        self.monotonic_now
    }

    fn wall_now_unix_seconds(&self) -> Option<u64> {
        Some(self.wall_now_unix_seconds)
    }

    fn is_cancelled(&self) -> bool {
        false
    }
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("local composition future unexpectedly pending"),
    }
}

fn vault_key() -> VaultKey {
    VaultKey::new([0x51; 32]).expect("nonzero test key")
}

#[test]
fn real_capability_admission_mls_commit_and_restart_delivery_are_one_shot() {
    let database = TestDatabase::new("commit");
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let mut transport =
        LocalMemoryWelcomeTransport::new(LocalMailboxPolicy::new(300, 1).expect("mailbox policy"))
            .expect("memory adapter");
    let (deposit_endpoint, receive_capability, acknowledgement_capability) = transport
        .create_welcome_mailbox(NOW + 240, NOW)
        .expect("right-specific mailbox")
        .into_parts();

    let protector = AwsLcInvitationJoinProtector::new();
    let generated = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("durably issued invitation");
    let invitation_id = *generated.invitation().invitation_id();
    let mut registry =
        InvitationRegistry::new(InvitationPolicy::new(3_600, 5, 8).expect("invitation policy"));
    let issued = registry
        .issue_v2(generated, NOW)
        .expect("issued invitation");
    let invitation_generation = *issued.invitation().signature();
    let validated_invitation = registry
        .validate_descriptor_v2(
            &issued.encode_canonical().expect("canonical invitation"),
            NOW,
        )
        .expect("validated local invitation");

    let bob = create_client().expect("Bob client");
    let bob_key_package = bob.generate_key_package(NOW).expect("Bob KeyPackage");
    let exact_key_package = create_key_package_validator()
        .validate_key_package(bob_key_package.as_bytes(), NOW)
        .expect("validated exact KeyPackage");
    let request = CapabilityJoinRequest::new(
        InvitationJoinBinding::new(
            invitation_id,
            *issued.invitation().join_challenge(),
            *issued.invitation().invitation_key_id(),
            *issued.invitation().inviter_verifying_key(),
        )
        .expect("invitation binding"),
        JoinRequestBinding::new(REQUEST_ID, NOW, NOW + 240, [0x61; 32]).expect("request binding"),
        MlsKeyPackageBinding::new(
            *exact_key_package.key_package_reference(),
            bob_key_package.as_bytes().to_vec(),
            *exact_key_package.credential_identity(),
            *exact_key_package.leaf_signature_key(),
        )
        .expect("KeyPackage binding"),
        deposit_endpoint,
    )
    .expect("capability request");
    let protected_request = protector
        .seal_capability_request(issued.invitation(), &request)
        .expect("protected request");
    let protected_request_bytes = protected_request
        .encode_canonical()
        .expect("canonical protected request");
    let request_fingerprint: [u8; 32] = digest(&SHA256, &protected_request_bytes)
        .as_ref()
        .try_into()
        .expect("SHA-256 output");
    let opened = protector
        .open_capability_request(
            issued.private_key(),
            issued.invitation(),
            &protected_request,
        )
        .expect("opened request");

    let mut verifier = CapabilityAdmissionVerifier::new(
        CapabilityAdmissionPolicy::new(3_600, 5, 8).expect("admission policy"),
    );
    let verified = verifier
        .verify_and_reserve(opened, NOW)
        .expect("automated admission");
    let pending = verifier
        .reserve_v2_for_approval(&mut registry, &validated_invitation, verified, NOW)
        .expect("exact invitation reservation");
    let approval = pending.approval_context();
    let approval_record = encode_approval_record(approval);
    let durable_pending = storage
        .reserve_authorization(
            &protector,
            AuthorizationShadowInput::new(
                invitation_id,
                invitation_generation,
                *request.join_challenge(),
                REQUEST_ID,
                *request.request_nonce(),
                *request.intended_verifier(),
                *exact_key_package.key_package_reference(),
                *exact_key_package.credential_identity(),
                *exact_key_package.leaf_signature_key(),
                request_fingerprint,
                request.issued_at_unix_seconds(),
                request.expires_at_unix_seconds(),
                issued.invitation().expires_at_unix_seconds(),
            )
            .expect("bounded authorization shadow"),
            NOW,
        )
        .expect("durable authorization reserved");
    let attempt_id = *durable_pending.attempt_id();
    let CapabilityApprovalOutcome::Approved(approved) = verifier
        .decide_v2(&mut registry, pending, ManualApprovalDecision::Approve, NOW)
        .expect("approval decision")
    else {
        panic!("approval must produce exact authority");
    };
    let durable_approved = storage
        .approve_authorization(durable_pending, &protector, NOW)
        .expect("durable approval recorded");

    let alice = create_client_with_storage(storage.clone(), storage.clone()).expect("Alice client");
    let mut alice_group = alice
        .create_group(SessionGroupId::new([0x71; 32]).expect("group id"), NOW)
        .expect("Alice group");
    let durability_pending = verifier
        .prepare_approved_add(&mut registry, approved, &mut alice_group, NOW)
        .expect("approved exact Add")
        .apply_awaiting_durability(NOW)
        .expect("transient MLS Add");
    let envelope = OpaqueEnvelope::new(
        [0x81; 16],
        NOW + 180,
        durability_pending.welcome().as_bytes().to_vec(),
    )
    .expect("Welcome envelope");
    let canonical_envelope = envelope
        .encode_canonical()
        .expect("canonical Welcome envelope");
    let transaction = InviterJoinTransaction::new(
        TRANSACTION_ID,
        invitation_id,
        invitation_generation,
        REQUEST_ID,
        request_fingerprint,
        *alice_group.group_id(),
        0,
        1,
        approval_record,
        canonical_envelope.clone(),
        durability_pending
            .response_endpoint()
            .encode_canonical()
            .expect("canonical endpoint"),
        NOW + 120,
    )
    .expect("bounded inviter transaction");
    let membership = storage
        .begin_membership_authorization(durable_approved, TRANSACTION_ID, &protector, NOW)
        .expect("durable membership authorized");
    let (committed_addition, _response_endpoint, shadow_settlement) =
        durability_pending.into_durable_owner_parts();
    assert!(
        committed_addition
            .stage_and_write_to_storage(&mut alice_group, |binding| {
                storage.stage_authorized_inviter(
                    membership,
                    binding,
                    transaction,
                    NOW,
                    PersistenceFault::AfterCommit,
                )
            })
            .is_err()
    );

    let recovered = storage
        .recover_inviter(&TRANSACTION_ID)
        .expect("recover ambiguous result")
        .expect("SQL commit succeeded");
    assert_eq!(recovered.epoch_after, 1);
    assert_eq!(recovered.outbox_state, WelcomeOutboxState::Pending);
    assert_eq!(
        storage
            .recover_authorization_outcome(&attempt_id, &TRANSACTION_ID, &protector, NOW + 1,)
            .expect("recover exact durable authorization"),
        AuthorizationState::Committed
    );
    shadow_settlement
        .finalize_committed()
        .expect("settle provider shadows after durable commit");
    assert_eq!(alice_group.epoch(), 1);
    assert_eq!(alice_group.member_count(), 2);
    assert_eq!(
        storage
            .invitation_opening_state(&invitation_id)
            .expect("durable opening state"),
        Some(InvitationOpeningState::Consumed)
    );
    assert_eq!(
        registry.lifecycle(&invitation_id),
        Some(InvitationLifecycle::Consumed)
    );

    let replay = protector
        .open_capability_request(
            issued.private_key(),
            issued.invitation(),
            &protected_request,
        )
        .expect("same authenticated request reopens");
    let mut fresh_verifier = CapabilityAdmissionVerifier::new(
        CapabilityAdmissionPolicy::new(3_600, 5, 8).expect("fresh admission policy"),
    );
    let replay_verified = fresh_verifier
        .verify_and_reserve(replay, NOW)
        .expect("fresh verifier validates replay before durable check");
    assert_eq!(replay_verified.join_request_id(), &REQUEST_ID);
    assert!(matches!(
        storage.reserve_authorization(
            &protector,
            AuthorizationShadowInput::new(
                invitation_id,
                invitation_generation,
                *request.join_challenge(),
                REQUEST_ID,
                *request.request_nonce(),
                *request.intended_verifier(),
                *exact_key_package.key_package_reference(),
                *exact_key_package.credential_identity(),
                *exact_key_package.leaf_signature_key(),
                request_fingerprint,
                request.issued_at_unix_seconds(),
                request.expires_at_unix_seconds(),
                issued.invitation().expires_at_unix_seconds(),
            )
            .expect("replay shadow"),
            NOW,
        ),
        Err(StoreError::Replay)
    ));

    drop(alice_group);
    drop(alice);
    drop(storage);
    let mut reopened = SqlCipherStorage::open(&database.0, vault_key()).expect("store reopens");
    let coordinator = WelcomeDeliveryCoordinator::new(
        CoordinatorPolicy::new(Duration::from_secs(1), 30, 64 * 1024).expect("coordinator policy"),
    );
    let control = TestControl {
        monotonic_now: Instant::now(),
        wall_now_unix_seconds: NOW + 1,
    };
    assert_eq!(
        ready(coordinator.run_once(
            &mut reopened,
            &mut LocalV1DepositEndpointResolver,
            &mut transport,
            &control,
        ))
        .expect("durable delivery pass"),
        CoordinatorOutcome::Accepted
    );
    let received = transport
        .receive(&receive_capability, NOW + 1)
        .expect("mailbox receive")
        .expect("Welcome retained");
    assert_eq!(
        received
            .envelope()
            .encode_canonical()
            .expect("received canonical envelope"),
        canonical_envelope
    );
    let bob_group = bob
        .join_group(
            WelcomeMessage::from_bytes(received.envelope().ciphertext()).expect("bounded Welcome"),
            NOW + 1,
        )
        .expect("Bob joins the exact committed group");
    assert_eq!(bob_group.epoch(), 1);
    assert_eq!(bob_group.member_count(), 2);
    assert_eq!(
        reopened
            .recover_inviter(&TRANSACTION_ID)
            .expect("delivery recovery")
            .expect("transaction remains retained")
            .outbox_state,
        WelcomeOutboxState::Delivered
    );
    assert_eq!(
        ready(coordinator.run_once(
            &mut reopened,
            &mut LocalV1DepositEndpointResolver,
            &mut transport,
            &control,
        ))
        .expect("no second membership or delivery work"),
        CoordinatorOutcome::Idle
    );
    transport
        .acknowledge(
            &acknowledgement_capability,
            *received.delivery_id(),
            NOW + 1,
        )
        .expect("acknowledge Welcome");
}

#[test]
fn approved_capability_restart_abandons_live_authority_and_reloads_exact_generation() {
    let database = TestDatabase::new("approved-restart");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let generated = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("durably issued invitation");
    let invitation_id = *generated.invitation().invitation_id();
    let invitation_generation = *generated.invitation().signature();
    let mut registry =
        InvitationRegistry::new(InvitationPolicy::new(3_600, 5, 8).expect("invitation policy"));
    let issued = registry
        .issue_v2(generated, NOW)
        .expect("issued invitation");
    let canonical_invitation = issued.encode_canonical().expect("canonical invitation");
    let validated_invitation = registry
        .validate_descriptor_v2(&canonical_invitation, NOW)
        .expect("validated invitation");

    let mut transport =
        LocalMemoryWelcomeTransport::new(LocalMailboxPolicy::new(300, 2).expect("mailbox policy"))
            .expect("memory adapter");
    let first_endpoint = transport
        .create_welcome_mailbox(NOW + 240, NOW)
        .expect("first mailbox")
        .into_parts()
        .0;
    let bob = create_client().expect("Bob client");
    let bob_key_package = bob.generate_key_package(NOW).expect("Bob KeyPackage");
    let exact_key_package = create_key_package_validator()
        .validate_key_package(bob_key_package.as_bytes(), NOW)
        .expect("validated KeyPackage");
    let first_request = CapabilityJoinRequest::new(
        InvitationJoinBinding::new(
            invitation_id,
            *issued.invitation().join_challenge(),
            *issued.invitation().invitation_key_id(),
            *issued.invitation().inviter_verifying_key(),
        )
        .expect("invitation binding"),
        JoinRequestBinding::new(REQUEST_ID, NOW, NOW + 240, [0x61; 32])
            .expect("first request binding"),
        MlsKeyPackageBinding::new(
            *exact_key_package.key_package_reference(),
            bob_key_package.as_bytes().to_vec(),
            *exact_key_package.credential_identity(),
            *exact_key_package.leaf_signature_key(),
        )
        .expect("first MLS binding"),
        first_endpoint,
    )
    .expect("first request");
    let first_protected = protector
        .seal_capability_request(issued.invitation(), &first_request)
        .expect("first protected request");
    let first_protected_bytes = first_protected
        .encode_canonical()
        .expect("canonical first request");
    let first_fingerprint: [u8; 32] = digest(&SHA256, &first_protected_bytes)
        .as_ref()
        .try_into()
        .expect("first SHA-256 output");
    let first_opened = protector
        .open_capability_request(issued.private_key(), issued.invitation(), &first_protected)
        .expect("opened first request");
    let mut verifier = CapabilityAdmissionVerifier::new(
        CapabilityAdmissionPolicy::new(3_600, 5, 8).expect("admission policy"),
    );
    let first_verified = verifier
        .verify_and_reserve(first_opened, NOW)
        .expect("first admission verified");
    let pending = verifier
        .reserve_v2_for_approval(&mut registry, &validated_invitation, first_verified, NOW)
        .expect("first approval reserved");
    let durable_pending = storage
        .reserve_authorization(
            &protector,
            AuthorizationShadowInput::new(
                invitation_id,
                invitation_generation,
                *first_request.join_challenge(),
                REQUEST_ID,
                *first_request.request_nonce(),
                *first_request.intended_verifier(),
                *exact_key_package.key_package_reference(),
                *exact_key_package.credential_identity(),
                *exact_key_package.leaf_signature_key(),
                first_fingerprint,
                first_request.issued_at_unix_seconds(),
                first_request.expires_at_unix_seconds(),
                issued.invitation().expires_at_unix_seconds(),
            )
            .expect("first authorization shadow"),
            NOW,
        )
        .expect("first durable reservation");
    let attempt_id = *durable_pending.attempt_id();
    let CapabilityApprovalOutcome::Approved(provider_approved) = verifier
        .decide_v2(&mut registry, pending, ManualApprovalDecision::Approve, NOW)
        .expect("provider approval")
    else {
        panic!("approval must produce exact provider authority");
    };
    let durable_approved = storage
        .approve_authorization(durable_pending, &protector, NOW)
        .expect("durable approval");

    drop(provider_approved);
    drop(durable_approved);
    drop(verifier);
    drop(registry);
    drop(issued);
    drop(storage);

    let reopened = SqlCipherStorage::open(&database.0, vault_key()).expect("fresh store opens");
    assert_eq!(
        reopened
            .recover_pre_membership_authorizations(&protector, NOW + 1)
            .expect("fresh-process pre-membership recovery"),
        1
    );
    assert_eq!(
        reopened
            .authorization_state(&attempt_id)
            .expect("recovered authorization state"),
        Some(AuthorizationState::Abandoned)
    );
    assert_eq!(
        reopened
            .invitation_opening_state(&invitation_id)
            .expect("released opening state"),
        Some(InvitationOpeningState::Available)
    );
    let reloaded = reopened
        .load_capability_invitation(&protector, &invitation_id, NOW + 1)
        .expect("opening load")
        .expect("exact opening remains available");
    assert_eq!(reloaded.invitation().signature(), &invitation_generation);
    assert_eq!(
        reloaded
            .invitation()
            .encode_canonical()
            .expect("reloaded canonical invitation"),
        canonical_invitation
    );

    let replay_opened = protector
        .open_capability_request(
            reloaded.private_key(),
            reloaded.invitation(),
            &first_protected,
        )
        .expect("old request still authenticates");
    let mut replay_verifier = CapabilityAdmissionVerifier::new(
        CapabilityAdmissionPolicy::new(3_600, 5, 8).expect("replay policy"),
    );
    let _replay_verified = replay_verifier
        .verify_and_reserve(replay_opened, NOW + 1)
        .expect("old request reaches durable replay check");
    assert!(matches!(
        reopened.reserve_authorization(
            &protector,
            AuthorizationShadowInput::new(
                invitation_id,
                invitation_generation,
                *first_request.join_challenge(),
                REQUEST_ID,
                *first_request.request_nonce(),
                *first_request.intended_verifier(),
                *exact_key_package.key_package_reference(),
                *exact_key_package.credential_identity(),
                *exact_key_package.leaf_signature_key(),
                first_fingerprint,
                first_request.issued_at_unix_seconds(),
                first_request.expires_at_unix_seconds(),
                reloaded.invitation().expires_at_unix_seconds(),
            )
            .expect("replay shadow"),
            NOW + 1,
        ),
        Err(StoreError::Replay)
    ));

    let second_endpoint = transport
        .create_welcome_mailbox(NOW + 240, NOW + 1)
        .expect("second mailbox")
        .into_parts()
        .0;
    let second_request_id = [0x32; 16];
    let second_request = CapabilityJoinRequest::new(
        InvitationJoinBinding::new(
            invitation_id,
            *reloaded.invitation().join_challenge(),
            *reloaded.invitation().invitation_key_id(),
            *reloaded.invitation().inviter_verifying_key(),
        )
        .expect("reloaded invitation binding"),
        JoinRequestBinding::new(second_request_id, NOW + 1, NOW + 240, [0x62; 32])
            .expect("second request binding"),
        MlsKeyPackageBinding::new(
            *exact_key_package.key_package_reference(),
            bob_key_package.as_bytes().to_vec(),
            *exact_key_package.credential_identity(),
            *exact_key_package.leaf_signature_key(),
        )
        .expect("second MLS binding"),
        second_endpoint,
    )
    .expect("second request");
    let second_protected = protector
        .seal_capability_request(reloaded.invitation(), &second_request)
        .expect("second protected request");
    let second_bytes = second_protected
        .encode_canonical()
        .expect("canonical second request");
    let second_fingerprint: [u8; 32] = digest(&SHA256, &second_bytes)
        .as_ref()
        .try_into()
        .expect("second SHA-256 output");
    let second_opened = protector
        .open_capability_request(
            reloaded.private_key(),
            reloaded.invitation(),
            &second_protected,
        )
        .expect("opened second request");
    let mut second_verifier = CapabilityAdmissionVerifier::new(
        CapabilityAdmissionPolicy::new(3_600, 5, 8).expect("second policy"),
    );
    let _second_verified = second_verifier
        .verify_and_reserve(second_opened, NOW + 1)
        .expect("second admission verified");
    let second_pending = reopened
        .reserve_authorization(
            &protector,
            AuthorizationShadowInput::new(
                invitation_id,
                invitation_generation,
                *second_request.join_challenge(),
                second_request_id,
                *second_request.request_nonce(),
                *second_request.intended_verifier(),
                *exact_key_package.key_package_reference(),
                *exact_key_package.credential_identity(),
                *exact_key_package.leaf_signature_key(),
                second_fingerprint,
                second_request.issued_at_unix_seconds(),
                second_request.expires_at_unix_seconds(),
                reloaded.invitation().expires_at_unix_seconds(),
            )
            .expect("second authorization shadow"),
            NOW + 1,
        )
        .expect("different request reserves reloaded exact generation");
    reopened
        .abandon_pending_authorization(second_pending, &protector, NOW + 1)
        .expect("second attempt cleanup");
}

fn encode_approval_record(context: session_admission::ApprovalContext) -> Vec<u8> {
    let mut record = Vec::with_capacity(73);
    record.push(match context.method() {
        AdmissionMethod::SecretCapability => 1,
    });
    record.extend_from_slice(context.invitation_id());
    record.extend_from_slice(context.join_request_id());
    record.extend_from_slice(context.key_package_reference());
    record.extend_from_slice(&context.expires_at_unix_seconds().to_be_bytes());
    record
}
