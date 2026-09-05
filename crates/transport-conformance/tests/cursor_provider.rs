use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use session_protocol::OpaqueEnvelope;
use session_transport::{
    AcknowledgementLeaseV1, AcknowledgementRequest, BindingFingerprint, CanonicalEnvelope, Cursor,
    DepositRequest, DispatchControl, EnvelopeDelivery, MailboxIssueRequestV1, MailboxLifecycle,
    OperationBudget, PollRequest, PollWait, ReceiveCheckpointRevision, ReceiveCheckpointV1,
    ReceivePageCommitV1, ReceiveStateOwnerPort, TransportFailureCode, TransportProfileId,
};
use transport_conformance::{DeterministicLifecycleProviderV1, DeterministicReceiveStateOwnerV1};

const NOW: u64 = 1_700_000_000;

struct FixedControl {
    monotonic: Instant,
}

impl DispatchControl for FixedControl {
    fn monotonic_now(&self) -> Instant {
        self.monotonic
    }

    fn wall_now_unix_seconds(&self) -> Option<u64> {
        Some(NOW)
    }

    fn is_cancelled(&self) -> bool {
        false
    }
}

fn operation() -> (FixedControl, OperationBudget) {
    let monotonic = Instant::now();
    (
        FixedControl { monotonic },
        OperationBudget::new(monotonic + Duration::from_secs(30), 65_536, 1)
            .expect("bounded operation"),
    )
}

fn ready<T>(future: impl Future<Output = T>) -> T {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("deterministic provider operation must be immediately ready"),
    }
}

#[test]
fn cursor_provider_composes_with_owner_commit_acknowledgement_and_restart() {
    let mut provider = DeterministicLifecycleProviderV1::new();
    let contract = provider.lifecycle_contract();
    let (control, budget) = operation();
    let issue = MailboxIssueRequestV1::new(
        TransportProfileId::FastV1,
        BindingFingerprint::from_bytes([0x11; 32]).expect("binding fingerprint"),
        NOW + 600,
        budget,
    )
    .expect("issue request");
    let authorities = ready(provider.issue(contract, issue, &control))
        .expect("issue mailbox")
        .into_authorities();
    let (binding, deposit, receive, acknowledgement, _rotation) = authorities.into_parts();

    let envelope = CanonicalEnvelope::from_opaque(
        OpaqueEnvelope::new([0x31; 16], NOW + 300, vec![0x41; 32]).expect("opaque envelope"),
    )
    .expect("canonical envelope");
    let request = DepositRequest::new(envelope, budget).expect("deposit request");
    ready(EnvelopeDelivery::deposit(
        &mut provider,
        &deposit,
        request,
        &control,
    ))
    .expect("deposit envelope");

    let checkpoint = ReceiveCheckpointV1::new_generation(
        binding,
        ReceiveCheckpointRevision::new(1).expect("revision"),
        NOW,
    )
    .expect("fresh checkpoint");
    let poll = checkpoint
        .poll_request(8, 65_536, PollWait::immediate(), budget, NOW)
        .expect("checkpoint-bound poll");
    let batch = ready(EnvelopeDelivery::poll(
        &mut provider,
        &receive,
        poll,
        &control,
    ))
    .expect("poll cursor page");
    assert_eq!(batch.len(), 1);
    assert!(batch.next_cursor().is_some());

    let transition = ReceivePageCommitV1::new(checkpoint, batch).expect("owner transition");
    let mut owner = DeterministicReceiveStateOwnerV1::new();
    let committed = owner
        .commit_receive_page(transition, NOW)
        .expect("commit cursor page");
    let lease = owner
        .lease_acknowledgement(committed, NOW)
        .expect("lease acknowledgement")
        .expect("acknowledgement intent");
    let acknowledgement_request = AcknowledgementRequest::new(
        session_transport::BoundedDeliveryIds::new(lease.delivery_ids().as_slice().to_vec())
            .expect("bounded acknowledgement IDs"),
        budget,
    );
    ready(EnvelopeDelivery::acknowledge(
        &mut provider,
        &acknowledgement,
        acknowledgement_request,
        &control,
    ))
    .expect("acknowledge provider page");
    owner
        .accept_acknowledgement(lease)
        .expect("accept acknowledgement result");

    let mut owner = owner.restart();
    let resumed = owner
        .load_checkpoint(&binding, NOW)
        .expect("load checkpoint")
        .expect("persisted checkpoint");
    let poll = resumed
        .poll_request(8, 65_536, PollWait::immediate(), budget, NOW)
        .expect("cursor resume poll");
    let batch = ready(EnvelopeDelivery::poll(
        &mut provider,
        &receive,
        poll,
        &control,
    ))
    .expect("resume cursor");
    assert!(batch.is_empty());
}

#[test]
fn cursor_provider_rejects_changed_exact_retry_and_unissued_cursor() {
    let mut provider = DeterministicLifecycleProviderV1::new();
    let contract = provider.lifecycle_contract();
    let (control, budget) = operation();
    let issue = MailboxIssueRequestV1::new(
        TransportProfileId::FastV1,
        BindingFingerprint::from_bytes([0x21; 32]).expect("binding fingerprint"),
        NOW + 600,
        budget,
    )
    .expect("issue request");
    let (binding, deposit, receive, _acknowledgement, _rotation) =
        ready(provider.issue(contract, issue, &control))
            .expect("issue mailbox")
            .into_authorities()
            .into_parts();

    let first = CanonicalEnvelope::from_opaque(
        OpaqueEnvelope::new([0x51; 16], NOW + 300, vec![0x61; 32]).expect("first opaque envelope"),
    )
    .expect("first canonical envelope");
    ready(EnvelopeDelivery::deposit(
        &mut provider,
        &deposit,
        DepositRequest::new(first, budget).expect("first deposit"),
        &control,
    ))
    .expect("first deposit accepted");

    let changed = CanonicalEnvelope::from_opaque(
        OpaqueEnvelope::new([0x51; 16], NOW + 300, vec![0x62; 32])
            .expect("changed opaque envelope"),
    )
    .expect("changed canonical envelope");
    let Err(conflict) = ready(EnvelopeDelivery::deposit(
        &mut provider,
        &deposit,
        DepositRequest::new(changed, budget).expect("changed retry"),
        &control,
    )) else {
        panic!("changed bytes under one envelope ID must fail");
    };
    assert_eq!(conflict.code(), TransportFailureCode::IdempotencyConflict);

    let poll = PollRequest::new(
        Some(Cursor::new(u64::MAX.to_be_bytes().to_vec()).expect("cursor")),
        8,
        65_536,
        PollWait::immediate(),
        budget,
    )
    .expect("unissued cursor request shape");
    let Err(invalid) = ready(EnvelopeDelivery::poll(
        &mut provider,
        &receive,
        poll,
        &control,
    )) else {
        panic!("unissued cursor must fail");
    };
    assert_eq!(invalid.code(), TransportFailureCode::InvalidCursor);

    assert_eq!(binding.generation().get(), 1);
}
