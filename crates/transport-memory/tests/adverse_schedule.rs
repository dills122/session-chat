use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use session_protocol::OpaqueEnvelope;
use session_transport::{
    AcknowledgementRequest, BoundedDeliveryIds, CanonicalEnvelope, DepositRequest, DispatchControl,
    EnvelopeDelivery, OperationBudget, PollRequest, PollWait, TransportFailureCode,
};
use transport_memory::{
    AcknowledgementLoss, DeliveryAction, DeterministicMemoryTransport, MemoryAvailability,
    MemoryMailboxPolicy, MemoryTransportError,
};

const NOW: u64 = 1_700_000_000;

struct LiveControl {
    now: Instant,
}

impl DispatchControl for LiveControl {
    fn monotonic_now(&self) -> Instant {
        self.now
    }

    fn wall_now_unix_seconds(&self) -> Option<u64> {
        Some(NOW)
    }

    fn is_cancelled(&self) -> bool {
        false
    }
}

fn ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("memory adverse operation unexpectedly remained pending"),
    }
}

fn transport() -> DeterministicMemoryTransport {
    DeterministicMemoryTransport::new(
        MemoryMailboxPolicy::new(300, 1, 4, 4).expect("bounded policy"),
    )
    .expect("memory transport")
}

fn envelope(id: u8, ciphertext: u8) -> OpaqueEnvelope {
    OpaqueEnvelope::new([id; 16], NOW + 120, vec![ciphertext; 32]).expect("bounded envelope")
}

fn budget(now: Instant) -> OperationBudget {
    OperationBudget::new(now + Duration::from_secs(5), 4_096, 1).expect("bounded budget")
}

fn deposit_request(envelope: OpaqueEnvelope, now: Instant) -> DepositRequest {
    DepositRequest::new(
        CanonicalEnvelope::from_opaque(envelope).expect("canonical envelope"),
        budget(now),
    )
    .expect("bounded request")
}

fn poll_request(now: Instant) -> PollRequest {
    PollRequest::new(None, 4, 4_096, PollWait::immediate(), budget(now)).expect("bounded poll")
}

#[test]
fn total_unavailability_fails_before_consuming_the_next_delivery_action() {
    let start = Instant::now();
    let control = LiveControl { now: start };
    let mut transport = transport();
    let (deposit, receive, _) = transport
        .create_mailbox(NOW + 180, NOW)
        .expect("mailbox")
        .into_dispatch_parts();
    transport
        .queue_action(DeliveryAction::Drop)
        .expect("drop remains armed");
    transport.set_availability(MemoryAvailability::Unavailable);

    let Err(failure) = ready(EnvelopeDelivery::deposit(
        &mut transport,
        &deposit,
        deposit_request(envelope(0x11, 0x21), start),
        &control,
    )) else {
        panic!("unavailable adapter must fail closed");
    };
    assert_eq!(failure.code(), TransportFailureCode::Unavailable);
    assert_eq!(
        transport.conformance_snapshot().queued_delivery_actions(),
        1
    );

    transport.set_availability(MemoryAvailability::Available);
    ready(EnvelopeDelivery::deposit(
        &mut transport,
        &deposit,
        deposit_request(envelope(0x11, 0x21), start),
        &control,
    ))
    .expect("same operation is accepted when available");
    assert!(
        ready(EnvelopeDelivery::poll(
            &mut transport,
            &receive,
            poll_request(start),
            &control,
        ))
        .expect("poll")
        .is_empty(),
        "the previously armed drop must be consumed only by the live deposit"
    );
}

#[test]
fn corrupt_poll_is_one_shot_and_does_not_dequeue_the_valid_envelope() {
    let start = Instant::now();
    let control = LiveControl { now: start };
    let mut transport = transport();
    let (deposit, receive, _) = transport
        .create_mailbox(NOW + 180, NOW)
        .expect("mailbox")
        .into_dispatch_parts();
    let receipt = ready(EnvelopeDelivery::deposit(
        &mut transport,
        &deposit,
        deposit_request(envelope(0x31, 0x41), start),
        &control,
    ))
    .expect("deposit");
    transport
        .corrupt_next_poll(&receive, *receipt.delivery_id())
        .expect("known live delivery can arm corruption");

    let Err(failure) = ready(EnvelopeDelivery::poll(
        &mut transport,
        &receive,
        poll_request(start),
        &control,
    )) else {
        panic!("corrupt provider response must be normalized");
    };
    assert_eq!(failure.code(), TransportFailureCode::CorruptRemoteResponse);

    let recovered = ready(EnvelopeDelivery::poll(
        &mut transport,
        &receive,
        poll_request(start),
        &control,
    ))
    .expect("one-shot corruption leaves the valid queue intact");
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered.items()[0].delivery_id(), receipt.delivery_id());
}

#[test]
fn explicit_stale_replay_can_arrive_after_ack_without_resurrecting_provider_state() {
    let start = Instant::now();
    let control = LiveControl { now: start };
    let mut transport = transport();
    let (deposit, receive, acknowledgement) = transport
        .create_mailbox(NOW + 180, NOW)
        .expect("mailbox")
        .into_dispatch_parts();
    let original = envelope(0x51, 0x61);
    let expected = original.encode_canonical().expect("canonical bytes");
    let receipt = ready(EnvelopeDelivery::deposit(
        &mut transport,
        &deposit,
        deposit_request(original.clone(), start),
        &control,
    ))
    .expect("deposit");
    ready(EnvelopeDelivery::poll(
        &mut transport,
        &receive,
        poll_request(start),
        &control,
    ))
    .expect("first delivery");
    let ids = BoundedDeliveryIds::new(vec![*receipt.delivery_id()]).expect("exact set");
    ready(EnvelopeDelivery::acknowledge(
        &mut transport,
        &acknowledgement,
        AcknowledgementRequest::new(ids, budget(start)),
        &control,
    ))
    .expect("acknowledge original");
    assert_eq!(transport.conformance_snapshot().live_envelopes(), 0);

    transport
        .replay_stale(&receive, *receipt.delivery_id(), original)
        .expect("test controller injects an explicit stale provider replay");
    let replay = ready(EnvelopeDelivery::poll(
        &mut transport,
        &receive,
        poll_request(start),
        &control,
    ))
    .expect("stale replay crosses the adapter boundary");
    assert_eq!(replay.len(), 1);
    assert_eq!(replay.items()[0].delivery_id(), receipt.delivery_id());
    assert_eq!(replay.items()[0].envelope().as_bytes(), expected);
    assert_eq!(transport.conformance_snapshot().live_envelopes(), 0);
}

#[test]
fn acknowledgement_loss_distinguishes_known_precommit_and_ambiguous_postcommit_results() {
    let start = Instant::now();
    let control = LiveControl { now: start };
    let mut transport = transport();
    let (deposit, receive, acknowledgement) = transport
        .create_mailbox(NOW + 180, NOW)
        .expect("mailbox")
        .into_dispatch_parts();

    for (id, loss, expected_live_after_failure) in [
        (0x71, AcknowledgementLoss::BeforeCommit, 1),
        (0x72, AcknowledgementLoss::AfterCommit, 0),
    ] {
        let receipt = ready(EnvelopeDelivery::deposit(
            &mut transport,
            &deposit,
            deposit_request(envelope(id, id + 1), start),
            &control,
        ))
        .expect("deposit");
        ready(EnvelopeDelivery::poll(
            &mut transport,
            &receive,
            poll_request(start),
            &control,
        ))
        .expect("poll");
        transport
            .lose_next_acknowledgement(loss)
            .expect("one acknowledgement fault");
        if loss == AcknowledgementLoss::BeforeCommit {
            assert_eq!(
                transport.lose_next_acknowledgement(AcknowledgementLoss::AfterCommit),
                Err(MemoryTransportError::CapacityExceeded),
                "a second fault cannot overwrite the armed one"
            );
        }
        let ids = BoundedDeliveryIds::new(vec![*receipt.delivery_id()]).expect("exact set");
        let failure = ready(EnvelopeDelivery::acknowledge(
            &mut transport,
            &acknowledgement,
            AcknowledgementRequest::new(ids, budget(start)),
            &control,
        ))
        .expect_err("scripted acknowledgement result is lost");
        assert_eq!(failure.code(), TransportFailureCode::Unavailable);
        assert_eq!(
            transport.conformance_snapshot().live_envelopes(),
            expected_live_after_failure
        );

        let retry_ids =
            BoundedDeliveryIds::new(vec![*receipt.delivery_id()]).expect("same exact set");
        ready(EnvelopeDelivery::acknowledge(
            &mut transport,
            &acknowledgement,
            AcknowledgementRequest::new(retry_ids, budget(start)),
            &control,
        ))
        .expect("exact acknowledgement retry is safe");
        assert_eq!(transport.conformance_snapshot().live_envelopes(), 0);
    }
}

#[test]
fn stale_replay_controls_are_bounded_exact_byte_only_and_secret_free() {
    let start = Instant::now();
    let control = LiveControl { now: start };
    let mut transport = transport();
    let (deposit, receive, acknowledgement) = transport
        .create_mailbox(NOW + 180, NOW)
        .expect("mailbox")
        .into_dispatch_parts();
    let original = envelope(0x81, b'S');
    let receipt = ready(EnvelopeDelivery::deposit(
        &mut transport,
        &deposit,
        deposit_request(original.clone(), start),
        &control,
    ))
    .expect("deposit");
    ready(EnvelopeDelivery::poll(
        &mut transport,
        &receive,
        poll_request(start),
        &control,
    ))
    .expect("poll");
    let ids = BoundedDeliveryIds::new(vec![*receipt.delivery_id()]).expect("exact set");
    ready(EnvelopeDelivery::acknowledge(
        &mut transport,
        &acknowledgement,
        AcknowledgementRequest::new(ids, budget(start)),
        &control,
    ))
    .expect("acknowledge");

    assert_eq!(
        transport.replay_stale(&receive, *receipt.delivery_id(), envelope(0x81, b'T')),
        Err(MemoryTransportError::Rejected),
        "changed bytes under one delivery ID cannot enter the replay queue"
    );
    for _ in 0..32 {
        transport
            .replay_stale(&receive, *receipt.delivery_id(), original.clone())
            .expect("bounded stale replay slot");
    }
    assert_eq!(
        transport.replay_stale(&receive, *receipt.delivery_id(), original),
        Err(MemoryTransportError::CapacityExceeded)
    );
    let snapshot = transport.conformance_snapshot();
    assert_eq!(snapshot.queued_stale_replays(), 32);
    assert!(!format!("{snapshot:?}").contains("SSSSSSSS"));
}

#[test]
fn adverse_delivery_controls_are_bound_to_the_exact_receive_right() {
    let start = Instant::now();
    let control = LiveControl { now: start };
    let mut transport = DeterministicMemoryTransport::new(
        MemoryMailboxPolicy::new(300, 2, 4, 4).expect("bounded policy"),
    )
    .expect("memory transport");
    let (deposit, receive, acknowledgement) = transport
        .create_mailbox(NOW + 180, NOW)
        .expect("target mailbox")
        .into_dispatch_parts();
    let (_, foreign_receive, _) = transport
        .create_mailbox(NOW + 180, NOW)
        .expect("foreign mailbox")
        .into_dispatch_parts();
    let original = envelope(0x91, b'R');
    let receipt = ready(EnvelopeDelivery::deposit(
        &mut transport,
        &deposit,
        deposit_request(original.clone(), start),
        &control,
    ))
    .expect("deposit");

    assert_eq!(
        transport.corrupt_next_poll(&foreign_receive, *receipt.delivery_id()),
        Err(MemoryTransportError::Rejected)
    );
    ready(EnvelopeDelivery::poll(
        &mut transport,
        &receive,
        poll_request(start),
        &control,
    ))
    .expect("foreign right cannot corrupt the target mailbox");
    let ids = BoundedDeliveryIds::new(vec![*receipt.delivery_id()]).expect("exact set");
    ready(EnvelopeDelivery::acknowledge(
        &mut transport,
        &acknowledgement,
        AcknowledgementRequest::new(ids, budget(start)),
        &control,
    ))
    .expect("acknowledge");
    assert_eq!(
        transport.replay_stale(&foreign_receive, *receipt.delivery_id(), original.clone()),
        Err(MemoryTransportError::Rejected)
    );
    transport
        .replay_stale(&receive, *receipt.delivery_id(), original)
        .expect("the exact receive right scopes the stale replay");
}

#[test]
fn corrupt_poll_fault_is_cleared_when_acknowledgement_removes_its_target() {
    let start = Instant::now();
    let control = LiveControl { now: start };
    let mut transport = transport();
    let (deposit, receive, acknowledgement) = transport
        .create_mailbox(NOW + 180, NOW)
        .expect("mailbox")
        .into_dispatch_parts();
    let receipt = ready(EnvelopeDelivery::deposit(
        &mut transport,
        &deposit,
        deposit_request(envelope(0x92, b'C'), start),
        &control,
    ))
    .expect("deposit");
    transport
        .corrupt_next_poll(&receive, *receipt.delivery_id())
        .expect("arm exact corrupt poll");
    assert!(transport.conformance_snapshot().corrupt_poll_armed());

    let ids = BoundedDeliveryIds::new(vec![*receipt.delivery_id()]).expect("exact set");
    ready(EnvelopeDelivery::acknowledge(
        &mut transport,
        &acknowledgement,
        AcknowledgementRequest::new(ids, budget(start)),
        &control,
    ))
    .expect("acknowledgement removes target");

    assert!(!transport.conformance_snapshot().corrupt_poll_armed());
    assert!(
        ready(EnvelopeDelivery::poll(
            &mut transport,
            &receive,
            poll_request(start),
            &control,
        ))
        .expect("no stranded fault remains")
        .is_empty()
    );
}

#[test]
fn corrupt_poll_fault_is_cleared_when_mailbox_expiry_prunes_its_target() {
    let start = Instant::now();
    let control = LiveControl { now: start };
    let mut transport = transport();
    let (deposit, receive, _) = transport
        .create_mailbox(NOW + 2, NOW)
        .expect("short-lived mailbox")
        .into_dispatch_parts();
    let expiring = OpaqueEnvelope::new([0x93; 16], NOW + 1, vec![b'E'; 32])
        .expect("bounded expiring envelope");
    let receipt = ready(EnvelopeDelivery::deposit(
        &mut transport,
        &deposit,
        deposit_request(expiring, start),
        &control,
    ))
    .expect("deposit");
    transport
        .corrupt_next_poll(&receive, *receipt.delivery_id())
        .expect("arm exact corrupt poll");
    assert!(transport.conformance_snapshot().corrupt_poll_armed());

    transport
        .create_mailbox(NOW + 182, NOW + 2)
        .expect("creating a live mailbox prunes the expired target mailbox");

    assert!(!transport.conformance_snapshot().corrupt_poll_armed());
}
