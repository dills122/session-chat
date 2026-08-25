use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use session_inviter_transaction::{
    CommitFault, InMemoryInviterJoinStore, InvitationState, InviterJoinCommit, OutboxState,
    ReservedInvitation, TransactionError, TransactionPolicy,
};
use session_protocol::{LocalWelcomeDepositEndpoint, OpaqueEnvelope};
use session_transport::{
    CoordinatorError, CoordinatorOutcome, CoordinatorPolicy, EnvelopeTransport, LocalMailboxPolicy,
    LocalMemoryWelcomeTransport, LocalV1DepositEndpointResolver, TransportFailureCode,
    WelcomeDeliveryCoordinator,
};

const NOW: u64 = 1_700_000_000;

struct TestControl {
    monotonic_now: Instant,
    wall_now_unix_seconds: u64,
}

impl session_transport::DispatchControl for TestControl {
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
        Poll::Pending => panic!("local integration future unexpectedly pending"),
    }
}

fn policy() -> TransactionPolicy {
    TransactionPolicy::new(4, 255, 4_096, 2_097_152, 65_536, 4_096, 3, 60)
        .expect("transaction policy")
}

fn coordinator() -> WelcomeDeliveryCoordinator {
    WelcomeDeliveryCoordinator::new(
        CoordinatorPolicy::new(Duration::from_secs(5), 10, 65_536).expect("coordinator policy"),
    )
}

fn seeded_commit(
    store: &mut InMemoryInviterJoinStore,
    endpoint: &LocalWelcomeDepositEndpoint,
) -> Vec<u8> {
    store
        .seed_reservation(
            ReservedInvitation::new([1; 16], [2; 64], [3; 16], NOW + 300).expect("reservation"),
            NOW,
        )
        .expect("reservation seeded");
    let welcome = OpaqueEnvelope::new([8; 16], NOW + 180, vec![9; 32])
        .expect("Welcome envelope")
        .encode_canonical()
        .expect("canonical Welcome");
    let commit = InviterJoinCommit::new(
        [10; 16],
        [1; 16],
        [2; 64],
        [3; 16],
        [4; 32],
        vec![5; 16],
        7,
        8,
        vec![6; 32],
        vec![7; 512],
        welcome.clone(),
        endpoint.encode_canonical().expect("canonical endpoint"),
        NOW + 120,
    );
    store
        .commit_with_fault(&commit, NOW, CommitFault::None)
        .expect("atomic commit");
    welcome
}

fn local_composition() -> (
    LocalMemoryWelcomeTransport,
    LocalWelcomeDepositEndpoint,
    session_transport::LocalWelcomeReceiveCapability,
) {
    let mut adapter =
        LocalMemoryWelcomeTransport::new(LocalMailboxPolicy::new(600, 1).expect("mailbox policy"))
            .expect("local adapter");
    let (deposit, receive, _acknowledgement) = adapter
        .create_welcome_mailbox(NOW + 300, NOW)
        .expect("Welcome mailbox")
        .into_parts();
    (adapter, deposit, receive)
}

#[test]
fn committed_inviter_outbox_delivers_once_without_reopening_membership() {
    let (mut adapter, endpoint, receive) = local_composition();
    let mut store = InMemoryInviterJoinStore::new(policy());
    let expected_bytes = seeded_commit(&mut store, &endpoint);
    let expected = OpaqueEnvelope::decode_canonical(&expected_bytes).expect("Welcome decodes");
    let start = Instant::now();
    let control = TestControl {
        monotonic_now: start,
        wall_now_unix_seconds: NOW,
    };
    let mut resolver = LocalV1DepositEndpointResolver;

    assert_eq!(
        ready(coordinator().run_once(&mut store, &mut resolver, &mut adapter, &control))
            .expect("coordinator pass"),
        CoordinatorOutcome::Accepted
    );
    assert_eq!(
        adapter
            .receive(&receive, NOW)
            .expect("receive")
            .expect("Welcome retained")
            .envelope(),
        &expected
    );
    let view = store.recover(&[10; 16]).expect("transaction retained");
    assert_eq!(view.outbox_state, OutboxState::Delivered);
    assert_eq!(view.delivery_attempts, 1);
    assert_eq!(view.epoch_after, 8);
    assert_eq!(
        store.invitation_state(&[1; 16]),
        Some(InvitationState::Consumed)
    );
    assert_eq!(store.committed_count(), 1);
    assert_eq!(
        ready(coordinator().run_once(&mut store, &mut resolver, &mut adapter, &control))
            .expect("second pass"),
        CoordinatorOutcome::Idle
    );
}

#[test]
fn ambiguous_remote_acceptance_retries_exact_identity_without_repeating_commit() {
    let (mut adapter, endpoint, receive) = local_composition();
    let mut store = InMemoryInviterJoinStore::new(policy());
    seeded_commit(&mut store, &endpoint);

    let stale = store
        .lease_delivery([10; 16], NOW, 1)
        .expect("first owner lease");
    let first_delivery = {
        let payload = store
            .delivery_payload(&stale, NOW)
            .expect("live delivery payload");
        let stored_endpoint =
            LocalWelcomeDepositEndpoint::decode_canonical(payload.deposit_endpoint)
                .expect("stored endpoint reconstructs");
        let stored_envelope = OpaqueEnvelope::decode_canonical(payload.welcome_envelope)
            .expect("stored envelope reconstructs");
        EnvelopeTransport::deposit(&mut adapter, &stored_endpoint, stored_envelope, NOW)
            .expect("remote accepted before owner result was recorded")
    };

    let start = Instant::now();
    let control = TestControl {
        monotonic_now: start,
        wall_now_unix_seconds: NOW + 1,
    };
    let mut resolver = LocalV1DepositEndpointResolver;
    assert_eq!(
        ready(coordinator().run_once(&mut store, &mut resolver, &mut adapter, &control))
            .expect("exact retry reconciles"),
        CoordinatorOutcome::Accepted
    );
    let received = adapter
        .receive(&receive, NOW + 1)
        .expect("receive")
        .expect("one logical Welcome");
    assert_eq!(received.delivery_id(), &first_delivery);
    let view = store.recover(&[10; 16]).expect("transaction retained");
    assert_eq!(view.outbox_state, OutboxState::Delivered);
    assert_eq!(view.delivery_attempts, 2);
    assert_eq!(view.epoch_after, 8);
    assert_eq!(store.committed_count(), 1);
    assert_eq!(
        store.complete_delivery(&stale, NOW + 2),
        Err(TransactionError::LeaseMismatch)
    );
}

#[test]
fn adapter_failure_returns_only_the_outbox_to_pending() {
    let (_owning_adapter, endpoint, _receive) = local_composition();
    let mut foreign_adapter =
        LocalMemoryWelcomeTransport::new(LocalMailboxPolicy::new(600, 1).expect("mailbox policy"))
            .expect("foreign adapter");
    let mut store = InMemoryInviterJoinStore::new(policy());
    seeded_commit(&mut store, &endpoint);
    let start = Instant::now();
    let control = TestControl {
        monotonic_now: start,
        wall_now_unix_seconds: NOW,
    };
    let mut resolver = LocalV1DepositEndpointResolver;

    let result =
        ready(coordinator().run_once(&mut store, &mut resolver, &mut foreign_adapter, &control));
    assert!(matches!(
        result,
        Err(CoordinatorError::Transport(failure))
            if failure.code() == TransportFailureCode::InvalidAuthority
    ));
    let view = store.recover(&[10; 16]).expect("transaction retained");
    assert_eq!(view.outbox_state, OutboxState::Pending);
    assert_eq!(view.delivery_attempts, 1);
    assert_eq!(view.epoch_after, 8);
    assert_eq!(
        store.invitation_state(&[1; 16]),
        Some(InvitationState::Consumed)
    );
    assert_eq!(store.committed_count(), 1);
}
