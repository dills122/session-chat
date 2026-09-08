use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use session_transport::{
    AcknowledgementReceipt, AcknowledgementRequest, AcknowledgementRight, CanonicalEnvelope,
    DeliveryId, DepositReceipt, DepositRequest, DepositRight, DispatchControl, EnvelopeDelivery,
    OperationBudget, PollRequest, ReceiveBatch, ReceiveRight, ReceivedCanonicalEnvelope,
    RetryAdvice, TransportFailure, TransportFailureCode,
};
use transport_conformance::{DeliveryConformanceStepV1, run_connected_delivery_conformance_v1};
use transport_memory::{DeterministicMemoryTransport, MemoryMailboxPolicy};

const NOW: u64 = 1_700_000_000;

struct FixedControl;

impl DispatchControl for FixedControl {
    fn monotonic_now(&self) -> Instant {
        Instant::now()
    }

    fn wall_now_unix_seconds(&self) -> Option<u64> {
        Some(NOW)
    }

    fn is_cancelled(&self) -> bool {
        false
    }
}

fn budget() -> OperationBudget {
    OperationBudget::new(Instant::now() + Duration::from_secs(5), 512 * 1024, 1)
        .expect("valid operation budget")
}

fn ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("memory delivery unexpectedly remained pending"),
    }
}

#[test]
fn memory_adapter_passes_the_shared_connected_delivery_case() {
    let mut transport = DeterministicMemoryTransport::new(
        MemoryMailboxPolicy::new(300, 2, 8, 8).expect("bounded memory policy"),
    )
    .expect("memory transport");
    let (deposit, receive, acknowledgement) = transport
        .create_mailbox(NOW + 300, NOW)
        .expect("create mailbox")
        .into_dispatch_parts();

    ready(run_connected_delivery_conformance_v1(
        &mut transport,
        &deposit,
        &receive,
        &acknowledgement,
        NOW,
        &FixedControl,
        budget,
    ))
    .expect("memory adapter passes shared delivery case");
}

struct DestructivePollAdapter {
    accepted: Option<Vec<u8>>,
    pending: Option<CanonicalEnvelope>,
    delivery_id: DeliveryId,
}

impl EnvelopeDelivery for DestructivePollAdapter {
    type DepositEndpoint = ();
    type ReceiveCapability = ();
    type AcknowledgementCapability = ();

    async fn deposit(
        &mut self,
        _endpoint: &DepositRight<Self::DepositEndpoint>,
        request: DepositRequest,
        _control: &dyn DispatchControl,
    ) -> Result<DepositReceipt, TransportFailure> {
        let (envelope, _) = request.into_parts();
        match &self.accepted {
            None => {
                self.accepted = Some(envelope.as_bytes().to_vec());
                self.pending = Some(envelope);
            }
            Some(accepted) if accepted == envelope.as_bytes() => {
                self.pending = Some(envelope);
            }
            Some(_) => {
                return Err(TransportFailure::new(
                    TransportFailureCode::IdempotencyConflict,
                    RetryAdvice::Never,
                ));
            }
        }
        Ok(DepositReceipt::accepted(self.delivery_id))
    }

    async fn poll(
        &mut self,
        _authority: &ReceiveRight<Self::ReceiveCapability>,
        request: PollRequest,
        _control: &dyn DispatchControl,
    ) -> Result<ReceiveBatch, TransportFailure> {
        let items = self
            .pending
            .take()
            .map(|envelope| ReceivedCanonicalEnvelope::new(self.delivery_id, envelope))
            .into_iter()
            .collect();
        ReceiveBatch::new(items, None, &request, NOW)
            .map_err(|_| TransportFailure::new(TransportFailureCode::Internal, RetryAdvice::Never))
    }

    async fn acknowledge(
        &mut self,
        _authority: &AcknowledgementRight<Self::AcknowledgementCapability>,
        _request: AcknowledgementRequest,
        _control: &dyn DispatchControl,
    ) -> Result<AcknowledgementReceipt, TransportFailure> {
        Ok(AcknowledgementReceipt::accepted())
    }
}

#[test]
fn destructive_poll_adapter_fails_the_shared_connected_delivery_case() {
    let mut adapter = DestructivePollAdapter {
        accepted: None,
        pending: None,
        delivery_id: DeliveryId::from_provider_bytes([0x71; 16]).expect("delivery ID"),
    };
    let deposit = DepositRight::from_provider(());
    let receive = ReceiveRight::from_provider(());
    let acknowledgement = AcknowledgementRight::from_provider(());

    let failure = ready(run_connected_delivery_conformance_v1(
        &mut adapter,
        &deposit,
        &receive,
        &acknowledgement,
        NOW,
        &FixedControl,
        budget,
    ))
    .expect_err("destructive poll must fail conformance");
    assert_eq!(
        failure.step(),
        DeliveryConformanceStepV1::UnacknowledgedRetentionPoll
    );
}
