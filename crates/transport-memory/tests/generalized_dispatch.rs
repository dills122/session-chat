use std::{
    future::Future,
    pin::pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use session_protocol::OpaqueEnvelope;
use session_transport::{
    AcknowledgementRequest, BoundedDeliveryIds, CanonicalEnvelope, Cursor, DeliveryId,
    DepositRequest, DispatchControl, EnvelopeDelivery, OperationBudget, PollRequest, PollWait,
    RetryAdvice, TransportFailureCode,
};
use transport_memory::{DeliveryAction, DeterministicMemoryTransport, MemoryMailboxPolicy};

const NOW: u64 = 1_700_000_000;

struct TestControl {
    monotonic_now: Instant,
    wall_now_unix_seconds: Option<u64>,
    cancelled: bool,
}

impl DispatchControl for TestControl {
    fn monotonic_now(&self) -> Instant {
        self.monotonic_now
    }

    fn wall_now_unix_seconds(&self) -> Option<u64> {
        self.wall_now_unix_seconds
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled
    }
}

struct AdvancingWallControl {
    monotonic_now: Instant,
    first_wall_unix_seconds: u64,
    later_wall_unix_seconds: u64,
    observations: AtomicUsize,
}

struct CancelOnSecondCheckpoint {
    monotonic_now: Instant,
    wall_now_unix_seconds: u64,
    checkpoints: AtomicUsize,
}

impl DispatchControl for CancelOnSecondCheckpoint {
    fn monotonic_now(&self) -> Instant {
        self.monotonic_now
    }

    fn wall_now_unix_seconds(&self) -> Option<u64> {
        Some(self.wall_now_unix_seconds)
    }

    fn is_cancelled(&self) -> bool {
        self.checkpoints.fetch_add(1, Ordering::SeqCst) > 0
    }
}

struct DeadlineOnSecondCheckpoint {
    first_monotonic_now: Instant,
    later_monotonic_now: Instant,
    wall_now_unix_seconds: u64,
    checkpoints: AtomicUsize,
}

impl DispatchControl for DeadlineOnSecondCheckpoint {
    fn monotonic_now(&self) -> Instant {
        if self.checkpoints.fetch_add(1, Ordering::SeqCst) == 0 {
            self.first_monotonic_now
        } else {
            self.later_monotonic_now
        }
    }

    fn wall_now_unix_seconds(&self) -> Option<u64> {
        Some(self.wall_now_unix_seconds)
    }

    fn is_cancelled(&self) -> bool {
        false
    }
}

struct WallClockFailureOnSecondCheckpoint {
    monotonic_now: Instant,
    wall_now_unix_seconds: u64,
    checkpoints: AtomicUsize,
}

impl DispatchControl for WallClockFailureOnSecondCheckpoint {
    fn monotonic_now(&self) -> Instant {
        self.monotonic_now
    }

    fn wall_now_unix_seconds(&self) -> Option<u64> {
        if self.checkpoints.fetch_add(1, Ordering::SeqCst) == 0 {
            Some(self.wall_now_unix_seconds)
        } else {
            None
        }
    }

    fn is_cancelled(&self) -> bool {
        false
    }
}

impl DispatchControl for AdvancingWallControl {
    fn monotonic_now(&self) -> Instant {
        self.monotonic_now
    }

    fn wall_now_unix_seconds(&self) -> Option<u64> {
        let observation = self.observations.fetch_add(1, Ordering::SeqCst);
        Some(if observation == 0 {
            self.first_wall_unix_seconds
        } else {
            self.later_wall_unix_seconds
        })
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
        Poll::Pending => panic!("memory dispatch unexpectedly remained pending"),
    }
}

fn transport() -> DeterministicMemoryTransport {
    DeterministicMemoryTransport::new(
        MemoryMailboxPolicy::new(300, 2, 4, 4).expect("bounded policy"),
    )
    .expect("memory transport")
}

fn envelope(id: u8, ciphertext: u8) -> OpaqueEnvelope {
    OpaqueEnvelope::new([id; 16], NOW + 120, vec![ciphertext; 32]).expect("bounded opaque envelope")
}

fn deposit_request(envelope: OpaqueEnvelope, deadline: Instant) -> DepositRequest {
    DepositRequest::new(
        CanonicalEnvelope::from_opaque(envelope).expect("canonical envelope"),
        OperationBudget::new(deadline, 4_096, 1).expect("bounded budget"),
    )
    .expect("bounded deposit request")
}

fn poll_request(deadline: Instant, cursor: Option<Cursor>) -> PollRequest {
    PollRequest::new(
        cursor,
        4,
        4_096,
        PollWait::immediate(),
        OperationBudget::new(deadline, 4_096, 1).expect("bounded budget"),
    )
    .expect("bounded poll request")
}

fn assert_ambiguous_committed_deposit_recovers(
    operation_start: Instant,
    recovery_now: Instant,
    failing_control: &dyn DispatchControl,
    expected_code: TransportFailureCode,
) {
    let stable = TestControl {
        monotonic_now: recovery_now,
        wall_now_unix_seconds: Some(NOW),
        cancelled: false,
    };
    let mut transport = transport();
    let (deposit, receive, _) = transport
        .create_mailbox(NOW + 180, NOW)
        .expect("mailbox")
        .into_dispatch_parts();
    transport
        .queue_action(DeliveryAction::Drop)
        .expect("first accepted attempt is committed but not visible");

    let Err(failure) = ready(EnvelopeDelivery::deposit(
        &mut transport,
        &deposit,
        deposit_request(
            envelope(0x18, 0x28),
            operation_start + Duration::from_secs(5),
        ),
        failing_control,
    )) else {
        panic!("the final checkpoint must make completion ambiguous");
    };
    assert_eq!(failure.code(), expected_code);
    assert_eq!(failure.retry_advice(), RetryAdvice::Never);

    let receipt = ready(EnvelopeDelivery::deposit(
        &mut transport,
        &deposit,
        deposit_request(envelope(0x18, 0x28), recovery_now + Duration::from_secs(5)),
        &stable,
    ))
    .expect("a fresh coordinator budget may reconcile the exact same operation identity");
    let batch = ready(EnvelopeDelivery::poll(
        &mut transport,
        &receive,
        poll_request(recovery_now + Duration::from_secs(5), None),
        &stable,
    ))
    .expect("reconciled delivery is readable");

    assert_eq!(batch.len(), 1);
    assert_eq!(batch.items()[0].delivery_id(), receipt.delivery_id());
    assert_eq!(
        batch.items()[0].envelope().as_bytes(),
        envelope(0x18, 0x28)
            .encode_canonical()
            .expect("canonical bytes")
    );
}

#[test]
fn post_commit_cancellation_allows_exact_identity_reconciliation_under_a_fresh_budget() {
    let start = Instant::now();
    assert_ambiguous_committed_deposit_recovers(
        start,
        start + Duration::from_secs(1),
        &CancelOnSecondCheckpoint {
            monotonic_now: start,
            wall_now_unix_seconds: NOW,
            checkpoints: AtomicUsize::new(0),
        },
        TransportFailureCode::Cancelled,
    );
}

#[test]
fn post_commit_deadline_allows_exact_identity_reconciliation_under_a_fresh_budget() {
    let start = Instant::now();
    assert_ambiguous_committed_deposit_recovers(
        start,
        start + Duration::from_secs(6),
        &DeadlineOnSecondCheckpoint {
            first_monotonic_now: start,
            later_monotonic_now: start + Duration::from_secs(5),
            wall_now_unix_seconds: NOW,
            checkpoints: AtomicUsize::new(0),
        },
        TransportFailureCode::DeadlineExceeded,
    );
}

#[test]
fn post_commit_clock_failure_allows_exact_identity_reconciliation_under_a_fresh_budget() {
    let start = Instant::now();
    assert_ambiguous_committed_deposit_recovers(
        start,
        start + Duration::from_secs(1),
        &WallClockFailureOnSecondCheckpoint {
            monotonic_now: start,
            wall_now_unix_seconds: NOW,
            checkpoints: AtomicUsize::new(0),
        },
        TransportFailureCode::Internal,
    );
}

#[test]
fn memory_adapter_carries_exact_canonical_bytes_through_the_generalized_boundary() {
    let start = Instant::now();
    let control = TestControl {
        monotonic_now: start,
        wall_now_unix_seconds: Some(NOW),
        cancelled: false,
    };
    let mut transport = transport();
    let (deposit, receive, acknowledgement) = transport
        .create_mailbox(NOW + 180, NOW)
        .expect("mailbox")
        .into_dispatch_parts();
    let opaque = envelope(0x11, 0x21);
    let expected = opaque.encode_canonical().expect("canonical bytes");

    let receipt = ready(EnvelopeDelivery::deposit(
        &mut transport,
        &deposit,
        deposit_request(opaque, start + Duration::from_secs(5)),
        &control,
    ))
    .expect("generalized deposit");
    let batch = ready(EnvelopeDelivery::poll(
        &mut transport,
        &receive,
        poll_request(start + Duration::from_secs(5), None),
        &control,
    ))
    .expect("generalized poll");

    assert_eq!(batch.len(), 1);
    assert_eq!(batch.items()[0].delivery_id(), receipt.delivery_id());
    assert_eq!(batch.items()[0].envelope().as_bytes(), expected);

    let unknown = DeliveryId::from_provider_bytes([0x22; 16]).expect("delivery ID");
    let ids = BoundedDeliveryIds::new(vec![*receipt.delivery_id(), unknown])
        .expect("bounded acknowledgement set");
    let acknowledgement_request = AcknowledgementRequest::new(
        ids,
        OperationBudget::new(start + Duration::from_secs(5), 4_096, 1).expect("bounded budget"),
    );
    ready(EnvelopeDelivery::acknowledge(
        &mut transport,
        &acknowledgement,
        acknowledgement_request,
        &control,
    ))
    .expect("generalized acknowledgement");
    let repeated_ids = BoundedDeliveryIds::new(vec![*receipt.delivery_id(), unknown])
        .expect("same exact acknowledgement set");
    let repeated_request = AcknowledgementRequest::new(
        repeated_ids,
        OperationBudget::new(start + Duration::from_secs(5), 4_096, 1).expect("bounded budget"),
    );
    ready(EnvelopeDelivery::acknowledge(
        &mut transport,
        &acknowledgement,
        repeated_request,
        &control,
    ))
    .expect("lost acknowledgement retry is an indistinguishable no-op");

    assert!(
        ready(EnvelopeDelivery::poll(
            &mut transport,
            &receive,
            poll_request(start + Duration::from_secs(5), None),
            &control,
        ))
        .expect("mailbox remains readable")
        .is_empty()
    );
}

#[test]
fn cancelled_dispatch_does_not_consume_the_next_deterministic_action() {
    let start = Instant::now();
    let cancelled = TestControl {
        monotonic_now: start,
        wall_now_unix_seconds: Some(NOW),
        cancelled: true,
    };
    let live = TestControl {
        monotonic_now: start,
        wall_now_unix_seconds: Some(NOW),
        cancelled: false,
    };
    let mut transport = transport();
    let (deposit, receive, _) = transport
        .create_mailbox(NOW + 180, NOW)
        .expect("mailbox")
        .into_dispatch_parts();
    transport
        .queue_action(DeliveryAction::Drop)
        .expect("next accepted attempt is dropped");

    let Err(failure) = ready(EnvelopeDelivery::deposit(
        &mut transport,
        &deposit,
        deposit_request(envelope(0x31, 0x41), start + Duration::from_secs(5)),
        &cancelled,
    )) else {
        panic!("cancelled deposit must fail closed");
    };
    assert_eq!(failure.code(), TransportFailureCode::Cancelled);

    ready(EnvelopeDelivery::deposit(
        &mut transport,
        &deposit,
        deposit_request(envelope(0x31, 0x41), start + Duration::from_secs(5)),
        &live,
    ))
    .expect("live retry accepted");
    assert!(
        ready(EnvelopeDelivery::poll(
            &mut transport,
            &receive,
            poll_request(start + Duration::from_secs(5), None),
            &live,
        ))
        .expect("poll")
        .is_empty()
    );
}

#[test]
fn generalized_memory_deposit_reports_idempotency_conflict_without_overwrite() {
    let start = Instant::now();
    let control = TestControl {
        monotonic_now: start,
        wall_now_unix_seconds: Some(NOW),
        cancelled: false,
    };
    let mut transport = transport();
    let (deposit, receive, _) = transport
        .create_mailbox(NOW + 180, NOW)
        .expect("mailbox")
        .into_dispatch_parts();

    ready(EnvelopeDelivery::deposit(
        &mut transport,
        &deposit,
        deposit_request(envelope(0x51, 0x61), start + Duration::from_secs(5)),
        &control,
    ))
    .expect("first deposit");
    let Err(failure) = ready(EnvelopeDelivery::deposit(
        &mut transport,
        &deposit,
        deposit_request(envelope(0x51, 0x62), start + Duration::from_secs(5)),
        &control,
    )) else {
        panic!("changed bytes under one ID must conflict");
    };
    assert_eq!(failure.code(), TransportFailureCode::IdempotencyConflict);

    let batch = ready(EnvelopeDelivery::poll(
        &mut transport,
        &receive,
        poll_request(start + Duration::from_secs(5), None),
        &control,
    ))
    .expect("poll original");
    assert_eq!(batch.items()[0].envelope().as_bytes(), {
        let original = envelope(0x51, 0x61);
        original.encode_canonical().expect("canonical bytes")
    });
}

#[test]
fn generalized_deposit_normalizes_scheduling_capacity_without_consuming_state() {
    let start = Instant::now();
    let control = TestControl {
        monotonic_now: start,
        wall_now_unix_seconds: Some(NOW),
        cancelled: false,
    };
    let mut transport = DeterministicMemoryTransport::new(
        MemoryMailboxPolicy::new(300, 1, 1, 1).expect("bounded policy"),
    )
    .expect("memory transport");
    let (deposit, _, _) = transport
        .create_mailbox(NOW + 180, NOW)
        .expect("mailbox")
        .into_dispatch_parts();
    let original = envelope(0x5a, 0x6a);
    transport
        .queue_action(DeliveryAction::Duplicate)
        .expect("fill both scheduled-copy slots");
    ready(EnvelopeDelivery::deposit(
        &mut transport,
        &deposit,
        deposit_request(original.clone(), start + Duration::from_secs(5)),
        &control,
    ))
    .expect("first delivery fills the schedule");

    let Err(failure) = ready(EnvelopeDelivery::deposit(
        &mut transport,
        &deposit,
        deposit_request(original, start + Duration::from_secs(5)),
        &control,
    )) else {
        panic!("exact retry cannot exceed the schedule bound");
    };
    assert_eq!(failure.code(), TransportFailureCode::QueueFull);
    let snapshot = transport.conformance_snapshot();
    assert_eq!(snapshot.live_envelopes(), 1);
    assert_eq!(snapshot.visible_copies(), 2);
}

#[test]
fn memory_cursor_is_non_authorizing_and_invalid_until_state_semantics_are_implemented() {
    let start = Instant::now();
    let control = TestControl {
        monotonic_now: start,
        wall_now_unix_seconds: Some(NOW),
        cancelled: false,
    };
    let mut transport = transport();
    let (_, receive, acknowledgement) = transport
        .create_mailbox(NOW + 180, NOW)
        .expect("mailbox")
        .into_dispatch_parts();
    let cursor = Cursor::new(vec![0x71; 16]).expect("bounded opaque cursor");

    let Err(failure) = ready(EnvelopeDelivery::poll(
        &mut transport,
        &receive,
        poll_request(start + Duration::from_secs(5), Some(cursor)),
        &control,
    )) else {
        panic!("unsupported cursor state must fail closed");
    };
    assert_eq!(failure.code(), TransportFailureCode::InvalidCursor);

    let unknown = DeliveryId::from_provider_bytes([0x72; 16]).expect("delivery ID");
    let ids = BoundedDeliveryIds::new(vec![unknown]).expect("bounded exact set");
    let request = AcknowledgementRequest::new(
        ids,
        OperationBudget::new(start + Duration::from_secs(5), 4_096, 1).expect("bounded budget"),
    );
    ready(EnvelopeDelivery::acknowledge(
        &mut transport,
        &acknowledgement,
        request,
        &control,
    ))
    .expect("unknown IDs are idempotent no-ops under valid authority");
}

#[test]
fn generalized_memory_failures_omit_seeded_ciphertext_cursor_and_identifier_bytes() {
    let start = Instant::now();
    let control = TestControl {
        monotonic_now: start,
        wall_now_unix_seconds: Some(NOW),
        cancelled: false,
    };
    let mut transport = transport();
    let (deposit, receive, _) = transport
        .create_mailbox(NOW + 180, NOW)
        .expect("mailbox")
        .into_dispatch_parts();
    let original = envelope(0x73, 0x74);
    ready(EnvelopeDelivery::deposit(
        &mut transport,
        &deposit,
        deposit_request(original, start + Duration::from_secs(5)),
        &control,
    ))
    .expect("first deposit");

    let seeded_ciphertext = vec![b'C'; 48];
    let changed = OpaqueEnvelope::new([0x73; 16], NOW + 120, seeded_ciphertext.clone())
        .expect("bounded envelope");
    let Err(conflict) = ready(EnvelopeDelivery::deposit(
        &mut transport,
        &deposit,
        deposit_request(changed, start + Duration::from_secs(5)),
        &control,
    )) else {
        panic!("changed bytes must conflict");
    };
    let seeded_cursor = vec![b'R'; 32];
    let cursor = Cursor::new(seeded_cursor.clone()).expect("bounded cursor");
    let Err(invalid_cursor) = ready(EnvelopeDelivery::poll(
        &mut transport,
        &receive,
        poll_request(start + Duration::from_secs(5), Some(cursor)),
        &control,
    )) else {
        panic!("memory cursor must fail closed");
    };
    let diagnostics = format!("{conflict:?} {conflict} {invalid_cursor:?} {invalid_cursor}");

    for seeded in [&seeded_ciphertext, &seeded_cursor] {
        assert!(
            !diagnostics
                .as_bytes()
                .windows(seeded.len())
                .any(|window| window == seeded),
            "normalized diagnostics must omit seeded untrusted bytes"
        );
    }
    assert!(
        !diagnostics
            .as_bytes()
            .windows(16)
            .any(|window| window == [0x73; 16]),
        "normalized diagnostics must omit full envelope identifiers"
    );
}

#[test]
fn poll_byte_page_rejection_does_not_dequeue_the_oversized_head_item() {
    let start = Instant::now();
    let control = TestControl {
        monotonic_now: start,
        wall_now_unix_seconds: Some(NOW),
        cancelled: false,
    };
    let mut transport = transport();
    let (deposit, receive, _) = transport
        .create_mailbox(NOW + 180, NOW)
        .expect("mailbox")
        .into_dispatch_parts();
    let opaque =
        OpaqueEnvelope::new([0x75; 16], NOW + 120, vec![0x76; 128]).expect("bounded envelope");
    ready(EnvelopeDelivery::deposit(
        &mut transport,
        &deposit,
        deposit_request(opaque, start + Duration::from_secs(5)),
        &control,
    ))
    .expect("deposit");
    let small_page = PollRequest::new(
        None,
        1,
        64,
        PollWait::immediate(),
        OperationBudget::new(start + Duration::from_secs(5), 4_096, 1).expect("bounded budget"),
    )
    .expect("bounded small page");

    let Err(failure) = ready(EnvelopeDelivery::poll(
        &mut transport,
        &receive,
        small_page,
        &control,
    )) else {
        panic!("head item above the requested byte page must fail explicitly");
    };
    assert_eq!(failure.code(), TransportFailureCode::EnvelopeTooLarge);

    let recovered = ready(EnvelopeDelivery::poll(
        &mut transport,
        &receive,
        poll_request(start + Duration::from_secs(5), None),
        &control,
    ))
    .expect("larger retry reads the retained head item");
    assert_eq!(recovered.len(), 1);
}

#[test]
fn poll_revalidates_expiry_with_the_final_wall_clock_observation() {
    let start = Instant::now();
    let stable = TestControl {
        monotonic_now: start,
        wall_now_unix_seconds: Some(NOW),
        cancelled: false,
    };
    let advancing = AdvancingWallControl {
        monotonic_now: start,
        first_wall_unix_seconds: NOW,
        later_wall_unix_seconds: NOW + 120,
        observations: AtomicUsize::new(0),
    };
    let mut transport = transport();
    let (deposit, receive, _) = transport
        .create_mailbox(NOW + 180, NOW)
        .expect("mailbox")
        .into_dispatch_parts();

    ready(EnvelopeDelivery::deposit(
        &mut transport,
        &deposit,
        deposit_request(envelope(0x75, 0x76), start + Duration::from_secs(5)),
        &stable,
    ))
    .expect("deposit before expiry");

    let batch = ready(EnvelopeDelivery::poll(
        &mut transport,
        &receive,
        poll_request(start + Duration::from_secs(5), None),
        &advancing,
    ))
    .expect("poll rejects staged expiry without surfacing stale data");

    assert!(batch.is_empty());
}

#[test]
fn acknowledgement_revalidates_authority_expiry_with_the_final_wall_observation() {
    let start = Instant::now();
    let stable = TestControl {
        monotonic_now: start,
        wall_now_unix_seconds: Some(NOW),
        cancelled: false,
    };
    let advancing = AdvancingWallControl {
        monotonic_now: start,
        first_wall_unix_seconds: NOW,
        later_wall_unix_seconds: NOW + 180,
        observations: AtomicUsize::new(0),
    };
    let mut transport = transport();
    let (deposit, _, acknowledgement) = transport
        .create_mailbox(NOW + 180, NOW)
        .expect("mailbox")
        .into_dispatch_parts();
    let receipt = ready(EnvelopeDelivery::deposit(
        &mut transport,
        &deposit,
        deposit_request(envelope(0x77, 0x78), start + Duration::from_secs(5)),
        &stable,
    ))
    .expect("deposit before authority expiry");
    let ids = BoundedDeliveryIds::new(vec![*receipt.delivery_id()]).expect("exact set");

    let failure = ready(EnvelopeDelivery::acknowledge(
        &mut transport,
        &acknowledgement,
        AcknowledgementRequest::new(
            ids,
            OperationBudget::new(start + Duration::from_secs(5), 4_096, 1).expect("bounded budget"),
        ),
        &advancing,
    ))
    .expect_err("authority expiring at the final observation must not mutate state");

    assert_eq!(failure.code(), TransportFailureCode::InvalidAuthority);
    assert_eq!(transport.conformance_snapshot().live_envelopes(), 1);
}
