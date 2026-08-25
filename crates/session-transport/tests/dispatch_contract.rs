use std::{
    future::Future,
    pin::pin,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use session_protocol::OpaqueEnvelope;
use session_transport::{
    AcknowledgementReceipt, AcknowledgementRequest, AcknowledgementRight, BoundedDeliveryIds,
    CanonicalEnvelope, DeliveryId, DepositReceipt, DepositRequest, DepositRight, DispatchControl,
    EnvelopeDelivery, OperationBudget, PollRequest, PollWait, ReceiveBatch, ReceiveRight,
    TransportFailure, TransportFailureCode,
};

const NOW: u64 = 1_700_000_000;

struct DepositAuthority;
struct ReceiveAuthority;
struct AcknowledgementAuthority;

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

#[derive(Default)]
struct RecordingDispatch {
    deposits: usize,
    polls: usize,
    acknowledgements: usize,
}

#[derive(Default)]
struct PendingDispatch {
    started: bool,
    dropped: bool,
}

struct MutableControl {
    monotonic_base: Instant,
    elapsed_seconds: AtomicU64,
    wall_now_unix_seconds: u64,
    cancelled: AtomicBool,
}

impl DispatchControl for MutableControl {
    fn monotonic_now(&self) -> Instant {
        self.monotonic_base + Duration::from_secs(self.elapsed_seconds.load(Ordering::Acquire))
    }

    fn wall_now_unix_seconds(&self) -> Option<u64> {
        Some(self.wall_now_unix_seconds)
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

#[derive(Default)]
struct TwoStageDispatch {
    provider_entered: bool,
    local_commit_applied: bool,
}

struct TwoStageDeposit<'a> {
    dispatch: &'a mut TwoStageDispatch,
    request: DepositRequest,
    control: &'a dyn DispatchControl,
    provider_returned: bool,
}

impl Future for TwoStageDeposit<'_> {
    type Output = Result<DepositReceipt, TransportFailure>;

    fn poll(mut self: std::pin::Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.provider_returned {
            if let Err(failure) = self.control.checkpoint(self.request.budget()) {
                return Poll::Ready(Err(failure));
            }
            self.dispatch.provider_entered = true;
            self.provider_returned = true;
            context.waker().wake_by_ref();
            return Poll::Pending;
        }
        if let Err(failure) = self.control.checkpoint(self.request.budget()) {
            return Poll::Ready(Err(failure));
        }
        self.dispatch.local_commit_applied = true;
        Poll::Ready(Ok(DepositReceipt::accepted(
            DeliveryId::from_provider_bytes([0x51; 16]).expect("delivery ID"),
        )))
    }
}

impl EnvelopeDelivery for TwoStageDispatch {
    type DepositEndpoint = DepositAuthority;
    type ReceiveCapability = ReceiveAuthority;
    type AcknowledgementCapability = AcknowledgementAuthority;

    fn deposit<'a>(
        &'a mut self,
        _endpoint: &'a DepositRight<Self::DepositEndpoint>,
        request: DepositRequest,
        control: &'a dyn DispatchControl,
    ) -> impl Future<Output = Result<DepositReceipt, TransportFailure>> + Send + 'a {
        TwoStageDeposit {
            dispatch: self,
            request,
            control,
            provider_returned: false,
        }
    }

    async fn poll(
        &mut self,
        _authority: &ReceiveRight<Self::ReceiveCapability>,
        request: PollRequest,
        control: &dyn DispatchControl,
    ) -> Result<ReceiveBatch, TransportFailure> {
        let observation = control.checkpoint(request.budget())?;
        ReceiveBatch::new(
            Vec::new(),
            None,
            &request,
            observation.wall_now_unix_seconds(),
        )
        .map_err(|_| {
            TransportFailure::new(
                TransportFailureCode::CorruptRemoteResponse,
                session_transport::RetryAdvice::Never,
            )
        })
    }

    fn acknowledge<'a>(
        &'a mut self,
        _authority: &'a AcknowledgementRight<Self::AcknowledgementCapability>,
        _request: AcknowledgementRequest,
        _control: &'a dyn DispatchControl,
    ) -> impl Future<Output = Result<AcknowledgementReceipt, TransportFailure>> + Send + 'a {
        std::future::ready(Ok(AcknowledgementReceipt::accepted()))
    }
}

struct PendingDeposit<'a> {
    dispatch: &'a mut PendingDispatch,
}

impl Future for PendingDeposit<'_> {
    type Output = Result<DepositReceipt, TransportFailure>;

    fn poll(mut self: std::pin::Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        self.dispatch.started = true;
        Poll::Pending
    }
}

impl Drop for PendingDeposit<'_> {
    fn drop(&mut self) {
        self.dispatch.dropped = true;
    }
}

impl EnvelopeDelivery for PendingDispatch {
    type DepositEndpoint = DepositAuthority;
    type ReceiveCapability = ReceiveAuthority;
    type AcknowledgementCapability = AcknowledgementAuthority;

    fn deposit<'a>(
        &'a mut self,
        _endpoint: &'a DepositRight<Self::DepositEndpoint>,
        _request: DepositRequest,
        _control: &'a dyn DispatchControl,
    ) -> impl Future<Output = Result<DepositReceipt, TransportFailure>> + Send + 'a {
        PendingDeposit { dispatch: self }
    }

    async fn poll(
        &mut self,
        _authority: &ReceiveRight<Self::ReceiveCapability>,
        request: PollRequest,
        control: &dyn DispatchControl,
    ) -> Result<ReceiveBatch, TransportFailure> {
        let observation = control.checkpoint(request.budget())?;
        ReceiveBatch::new(
            Vec::new(),
            None,
            &request,
            observation.wall_now_unix_seconds(),
        )
        .map_err(|_| {
            TransportFailure::new(
                TransportFailureCode::CorruptRemoteResponse,
                session_transport::RetryAdvice::Never,
            )
        })
    }

    fn acknowledge<'a>(
        &'a mut self,
        _authority: &'a AcknowledgementRight<Self::AcknowledgementCapability>,
        _request: AcknowledgementRequest,
        _control: &'a dyn DispatchControl,
    ) -> impl Future<Output = Result<AcknowledgementReceipt, TransportFailure>> + Send + 'a {
        std::future::ready(Ok(AcknowledgementReceipt::accepted()))
    }
}

impl EnvelopeDelivery for RecordingDispatch {
    type DepositEndpoint = DepositAuthority;
    type ReceiveCapability = ReceiveAuthority;
    type AcknowledgementCapability = AcknowledgementAuthority;

    async fn deposit(
        &mut self,
        _endpoint: &DepositRight<Self::DepositEndpoint>,
        request: DepositRequest,
        control: &dyn DispatchControl,
    ) -> Result<DepositReceipt, TransportFailure> {
        control.checkpoint(request.budget())?;
        self.deposits += 1;
        Ok(DepositReceipt::accepted(
            DeliveryId::from_provider_bytes([0x41; 16]).expect("delivery ID"),
        ))
    }

    async fn poll(
        &mut self,
        _authority: &ReceiveRight<Self::ReceiveCapability>,
        request: PollRequest,
        control: &dyn DispatchControl,
    ) -> Result<ReceiveBatch, TransportFailure> {
        let observation = control.checkpoint(request.budget())?;
        self.polls += 1;
        ReceiveBatch::new(
            Vec::new(),
            None,
            &request,
            observation.wall_now_unix_seconds(),
        )
        .map_err(|_| {
            TransportFailure::new(
                TransportFailureCode::CorruptRemoteResponse,
                session_transport::RetryAdvice::Never,
            )
        })
    }

    async fn acknowledge(
        &mut self,
        _authority: &AcknowledgementRight<Self::AcknowledgementCapability>,
        request: AcknowledgementRequest,
        control: &dyn DispatchControl,
    ) -> Result<AcknowledgementReceipt, TransportFailure> {
        control.checkpoint(request.budget())?;
        self.acknowledgements += 1;
        Ok(AcknowledgementReceipt::accepted())
    }
}

fn ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("test dispatch unexpectedly remained pending"),
    }
}

fn deposit_request(deadline: Instant) -> DepositRequest {
    let envelope =
        OpaqueEnvelope::new([0x31; 16], NOW + 60, vec![0x32; 32]).expect("bounded opaque envelope");
    let budget = OperationBudget::new(deadline, 4_096, 1).expect("bounded budget");
    DepositRequest::new(
        CanonicalEnvelope::from_opaque(envelope).expect("canonical envelope"),
        budget,
    )
    .expect("bounded deposit request")
}

#[test]
fn generalized_dispatch_accepts_only_the_right_specific_operation_inputs() {
    let start = Instant::now();
    let control = TestControl {
        monotonic_now: start,
        wall_now_unix_seconds: Some(NOW),
        cancelled: false,
    };
    let mut dispatch = RecordingDispatch::default();
    let deposit = DepositRight::from_provider(DepositAuthority);
    let receive = ReceiveRight::from_provider(ReceiveAuthority);
    let acknowledgement = AcknowledgementRight::from_provider(AcknowledgementAuthority);

    let receipt = ready(dispatch.deposit(
        &deposit,
        deposit_request(start + Duration::from_secs(5)),
        &control,
    ))
    .expect("deposit accepted");
    assert_eq!(receipt.delivery_id().as_bytes(), &[0x41; 16]);

    let poll_budget = OperationBudget::new(start + Duration::from_secs(5), 4_096, 1)
        .expect("bounded poll budget");
    let poll =
        PollRequest::new(None, 1, 4_096, PollWait::immediate(), poll_budget).expect("bounded poll");
    let batch = ready(dispatch.poll(&receive, poll, &control)).expect("poll accepted");
    assert!(batch.items().is_empty());

    let ids = BoundedDeliveryIds::new(vec![
        DeliveryId::from_provider_bytes([0x41; 16]).expect("delivery ID"),
    ])
    .expect("bounded acknowledgement IDs");
    let acknowledgement_request = AcknowledgementRequest::new(ids, poll_budget);
    ready(dispatch.acknowledge(&acknowledgement, acknowledgement_request, &control))
        .expect("acknowledgement accepted");

    assert_eq!(dispatch.deposits, 1);
    assert_eq!(dispatch.polls, 1);
    assert_eq!(dispatch.acknowledgements, 1);
}

#[test]
fn dispatch_checkpoint_rejects_cancellation_and_deadline_before_adapter_mutation() {
    let start = Instant::now();
    let mut dispatch = RecordingDispatch::default();
    let deposit = DepositRight::from_provider(DepositAuthority);
    let cancelled = TestControl {
        monotonic_now: start,
        wall_now_unix_seconds: Some(NOW),
        cancelled: true,
    };

    let Err(cancellation) = ready(dispatch.deposit(
        &deposit,
        deposit_request(start + Duration::from_secs(5)),
        &cancelled,
    )) else {
        panic!("cancelled work must fail closed");
    };
    assert_eq!(cancellation.code(), TransportFailureCode::Cancelled);
    assert_eq!(dispatch.deposits, 0);

    let expired = TestControl {
        monotonic_now: start + Duration::from_secs(5),
        wall_now_unix_seconds: Some(NOW),
        cancelled: false,
    };
    let Err(deadline) = ready(dispatch.deposit(&deposit, deposit_request(start), &expired)) else {
        panic!("expired work must fail closed");
    };
    assert_eq!(deadline.code(), TransportFailureCode::DeadlineExceeded);
    assert_eq!(dispatch.deposits, 0);

    let cancelled_at_deadline = TestControl {
        monotonic_now: start,
        wall_now_unix_seconds: Some(NOW),
        cancelled: true,
    };
    let failure = cancelled_at_deadline
        .checkpoint(
            OperationBudget::new(start, 1, 1).expect("bounded operation despite elapsed deadline"),
        )
        .expect_err("simultaneous cancellation and deadline must fail");
    assert_eq!(failure.code(), TransportFailureCode::Cancelled);
}

#[test]
fn dispatch_observation_keeps_monotonic_budget_time_separate_from_wall_expiry_time() {
    let start = Instant::now();
    let control = TestControl {
        monotonic_now: start,
        wall_now_unix_seconds: Some(NOW + 30),
        cancelled: false,
    };
    let observation = control
        .checkpoint(
            OperationBudget::new(start + Duration::from_secs(1), 1, 1).expect("bounded budget"),
        )
        .expect("live operation");

    assert_eq!(observation.monotonic_now(), start);
    assert_eq!(observation.wall_now_unix_seconds(), NOW + 30);
}

#[test]
fn dropping_a_pending_dispatch_future_cancels_its_owned_work() {
    let start = Instant::now();
    let control = TestControl {
        monotonic_now: start,
        wall_now_unix_seconds: Some(NOW),
        cancelled: false,
    };
    let mut dispatch = PendingDispatch::default();
    let deposit = DepositRight::from_provider(DepositAuthority);
    let mut operation = Box::pin(dispatch.deposit(
        &deposit,
        deposit_request(start + Duration::from_secs(5)),
        &control,
    ));
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);

    assert!(operation.as_mut().poll(&mut context).is_pending());
    drop(operation);

    assert!(dispatch.started);
    assert!(dispatch.dropped);
}

#[test]
fn unavailable_wall_clock_fails_closed_before_adapter_mutation() {
    let start = Instant::now();
    let control = TestControl {
        monotonic_now: start,
        wall_now_unix_seconds: None,
        cancelled: false,
    };
    let mut dispatch = RecordingDispatch::default();
    let deposit = DepositRight::from_provider(DepositAuthority);

    let Err(failure) = ready(dispatch.deposit(
        &deposit,
        deposit_request(start + Duration::from_secs(5)),
        &control,
    )) else {
        panic!("an unavailable wall clock must fail closed");
    };

    assert_eq!(failure.code(), TransportFailureCode::Internal);
    assert_eq!(dispatch.deposits, 0);
}

#[test]
fn adapter_rechecks_cancellation_after_a_provider_boundary_before_local_commit() {
    let start = Instant::now();
    let control = MutableControl {
        monotonic_base: start,
        elapsed_seconds: AtomicU64::new(0),
        wall_now_unix_seconds: NOW,
        cancelled: AtomicBool::new(false),
    };
    let mut dispatch = TwoStageDispatch::default();
    let deposit = DepositRight::from_provider(DepositAuthority);
    let mut operation = Box::pin(dispatch.deposit(
        &deposit,
        deposit_request(start + Duration::from_secs(5)),
        &control,
    ));
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);

    assert!(operation.as_mut().poll(&mut context).is_pending());
    control.cancelled.store(true, Ordering::Release);
    let Poll::Ready(Err(failure)) = operation.as_mut().poll(&mut context) else {
        panic!("post-provider cancellation must fail before local commit");
    };
    assert_eq!(failure.code(), TransportFailureCode::Cancelled);
    drop(operation);

    assert!(dispatch.provider_entered);
    assert!(!dispatch.local_commit_applied);
}

#[test]
fn adapter_rechecks_deadline_after_a_provider_boundary_before_local_commit() {
    let start = Instant::now();
    let control = MutableControl {
        monotonic_base: start,
        elapsed_seconds: AtomicU64::new(0),
        wall_now_unix_seconds: NOW,
        cancelled: AtomicBool::new(false),
    };
    let mut dispatch = TwoStageDispatch::default();
    let deposit = DepositRight::from_provider(DepositAuthority);
    let mut operation = Box::pin(dispatch.deposit(
        &deposit,
        deposit_request(start + Duration::from_secs(5)),
        &control,
    ));
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);

    assert!(operation.as_mut().poll(&mut context).is_pending());
    control.elapsed_seconds.store(5, Ordering::Release);
    let Poll::Ready(Err(failure)) = operation.as_mut().poll(&mut context) else {
        panic!("post-provider deadline must fail before local commit");
    };
    assert_eq!(failure.code(), TransportFailureCode::DeadlineExceeded);
    drop(operation);

    assert!(dispatch.provider_entered);
    assert!(!dispatch.local_commit_applied);
}
