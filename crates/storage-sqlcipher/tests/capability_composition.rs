use std::{
    future::Future,
    path::PathBuf,
    pin::pin,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use admission_capability::{
    CapabilityAdmissionError, CapabilityAdmissionPolicy, CapabilityAdmissionVerifier,
    CapabilityApprovalOutcome, ManualApprovalDecision,
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
    InvitationState, InviterJoinTransaction, PersistenceFault, SqlCipherStorage, VaultKey,
    WelcomeOutboxState,
};

const NOW: u64 = 1_900_000_000;
const REQUEST_ID: [u8; 16] = [0x31; 16];
const TRANSACTION_ID: [u8; 16] = [0x41; 16];

struct TestDatabase(PathBuf);

impl TestDatabase {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "session-chat-storage-sqlcipher-capability-composition-{}.sqlite3",
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
    let database = TestDatabase::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let mut transport =
        LocalMemoryWelcomeTransport::new(LocalMailboxPolicy::new(300, 1).expect("mailbox policy"))
            .expect("memory adapter");
    let (deposit_endpoint, receive_capability, acknowledgement_capability) = transport
        .create_welcome_mailbox(NOW + 240, NOW)
        .expect("right-specific mailbox")
        .into_parts();

    let protector = AwsLcInvitationJoinProtector::new();
    let generated = protector
        .generate_capability_invitation(NOW, NOW + 300)
        .expect("generated invitation");
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

    storage
        .seed_reservation(
            invitation_id,
            invitation_generation,
            REQUEST_ID,
            NOW + 300,
            NOW,
        )
        .expect("durable reservation");
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
    let CapabilityApprovalOutcome::Approved(approved) = verifier
        .decide_v2(&mut registry, pending, ManualApprovalDecision::Approve, NOW)
        .expect("approval decision")
    else {
        panic!("approval must produce exact authority");
    };

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
    storage
        .stage_inviter(transaction, NOW, PersistenceFault::AfterCommit)
        .expect("stage real transaction");
    assert!(alice_group.write_to_storage().is_err());

    let recovered = storage
        .recover_inviter(&TRANSACTION_ID)
        .expect("recover ambiguous result")
        .expect("SQL commit succeeded");
    assert_eq!(recovered.epoch_after, 1);
    assert_eq!(recovered.outbox_state, WelcomeOutboxState::Pending);
    let committed = durability_pending
        .finalize_committed()
        .expect("reflect durable commit in in-memory shadow");
    assert_eq!(committed.welcome().as_bytes(), envelope.ciphertext());
    assert_eq!(alice_group.epoch(), 1);
    assert_eq!(alice_group.member_count(), 2);
    assert_eq!(
        registry.lifecycle(&invitation_id),
        Some(InvitationLifecycle::Consumed)
    );
    assert_eq!(
        storage
            .invitation_state(&invitation_id)
            .expect("durable invitation state"),
        Some(InvitationState::Consumed)
    );

    let replay = protector
        .open_capability_request(
            issued.private_key(),
            issued.invitation(),
            &protected_request,
        )
        .expect("same authenticated request reopens");
    assert!(matches!(
        verifier.verify_and_reserve(replay, NOW),
        Err(CapabilityAdmissionError::Replay)
    ));

    drop(committed);
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
