use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use session_protocol::OpaqueEnvelope;
use session_transport::{
    AcknowledgementReceipt, AcknowledgementRequest, AcknowledgementRight, BlockingFutureSupervisor,
    CoordinatorError, CoordinatorOutcome, CoordinatorPolicy, DeliveryId, DepositEndpointResolver,
    DepositReceipt, DepositRequest, DepositRight, DispatchControl, EnvelopeDelivery, LeasedWelcome,
    LocalMailboxPolicy, LocalMemoryWelcomeTransport, LocalV1DepositEndpointResolver,
    OutboxPortError, PollRequest, ReceiveBatch, ReceiveRight, RetryAdvice, SupervisionError,
    ThreadDispatchControl, TransportFailure, TransportFailureCode, WelcomeDeliveryCoordinator,
    WelcomeOutboxPort,
};

const NOW: u64 = 1_700_000_000;

#[derive(Clone, Copy)]
struct Lease(u8);

struct TestStore {
    job: Option<(Vec<u8>, Vec<u8>, u64)>,
    leased: bool,
    accepted: usize,
    failed: usize,
}

impl WelcomeOutboxPort for TestStore {
    type Lease = Lease;

    fn lease_next(
        &mut self,
        _now_unix_seconds: u64,
        _lease_seconds: u64,
    ) -> Result<Option<LeasedWelcome<Self::Lease>>, OutboxPortError> {
        let Some((envelope, endpoint, outbox_expiry)) = self.job.take() else {
            return Ok(None);
        };
        self.leased = true;
        Ok(Some(LeasedWelcome::from_owner(
            Lease(1),
            envelope,
            endpoint,
            outbox_expiry,
        )))
    }

    fn report_accepted(
        &mut self,
        lease: Self::Lease,
        _now_unix_seconds: u64,
    ) -> Result<(), OutboxPortError> {
        assert_eq!(lease.0, 1);
        self.leased = false;
        self.accepted += 1;
        Ok(())
    }

    fn report_failed(&mut self, lease: Self::Lease) -> Result<(), OutboxPortError> {
        assert_eq!(lease.0, 1);
        self.leased = false;
        self.failed += 1;
        Ok(())
    }
}

struct Endpoint;

struct TestResolver;

impl<D> DepositEndpointResolver<D> for TestResolver
where
    D: EnvelopeDelivery<DepositEndpoint = Endpoint>,
{
    fn resolve(
        &mut self,
        encoded_endpoint: &[u8],
        _now_unix_seconds: u64,
    ) -> Result<DepositRight<Endpoint>, session_transport::EndpointResolutionError> {
        if encoded_endpoint != b"endpoint" {
            return Err(session_transport::EndpointResolutionError::Rejected);
        }
        Ok(DepositRight::from_provider(Endpoint))
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

struct ReadyAdapter {
    calls: usize,
    fail: bool,
    seen_envelope: Vec<u8>,
    seen_attempts: u16,
}

impl EnvelopeDelivery for ReadyAdapter {
    type DepositEndpoint = Endpoint;
    type ReceiveCapability = ();
    type AcknowledgementCapability = ();

    async fn deposit(
        &mut self,
        _endpoint: &DepositRight<Self::DepositEndpoint>,
        request: DepositRequest,
        control: &dyn DispatchControl,
    ) -> Result<DepositReceipt, TransportFailure> {
        control.checkpoint(request.budget())?;
        self.calls += 1;
        self.seen_attempts = request.budget().max_attempts();
        self.seen_envelope = request.envelope().as_bytes().to_vec();
        if self.fail {
            Err(TransportFailure::new(
                TransportFailureCode::Unavailable,
                RetryAdvice::Backoff,
            ))
        } else {
            Ok(DepositReceipt::accepted(
                DeliveryId::from_provider_bytes([0x44; 16]).expect("delivery identifier"),
            ))
        }
    }

    async fn poll(
        &mut self,
        _authority: &ReceiveRight<Self::ReceiveCapability>,
        _request: PollRequest,
        _control: &dyn DispatchControl,
    ) -> Result<ReceiveBatch, TransportFailure> {
        unreachable!("deposit-only coordinator")
    }

    async fn acknowledge(
        &mut self,
        _authority: &AcknowledgementRight<Self::AcknowledgementCapability>,
        _request: AcknowledgementRequest,
        _control: &dyn DispatchControl,
    ) -> Result<AcknowledgementReceipt, TransportFailure> {
        unreachable!("deposit-only coordinator")
    }
}

struct PendingAdapter {
    started: bool,
    dropped: bool,
}

struct PendingDeposit<'a> {
    adapter: &'a mut PendingAdapter,
}

impl Future for PendingDeposit<'_> {
    type Output = Result<DepositReceipt, TransportFailure>;

    fn poll(mut self: std::pin::Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        self.adapter.started = true;
        Poll::Pending
    }
}

impl Drop for PendingDeposit<'_> {
    fn drop(&mut self) {
        self.adapter.dropped = true;
    }
}

impl EnvelopeDelivery for PendingAdapter {
    type DepositEndpoint = Endpoint;
    type ReceiveCapability = ();
    type AcknowledgementCapability = ();

    fn deposit<'a>(
        &'a mut self,
        _endpoint: &'a DepositRight<Self::DepositEndpoint>,
        _request: DepositRequest,
        _control: &'a dyn DispatchControl,
    ) -> impl Future<Output = Result<DepositReceipt, TransportFailure>> + Send + 'a {
        PendingDeposit { adapter: self }
    }

    async fn poll(
        &mut self,
        _authority: &ReceiveRight<Self::ReceiveCapability>,
        _request: PollRequest,
        _control: &dyn DispatchControl,
    ) -> Result<ReceiveBatch, TransportFailure> {
        unreachable!("deposit-only coordinator")
    }

    async fn acknowledge(
        &mut self,
        _authority: &AcknowledgementRight<Self::AcknowledgementCapability>,
        _request: AcknowledgementRequest,
        _control: &dyn DispatchControl,
    ) -> Result<AcknowledgementReceipt, TransportFailure> {
        unreachable!("deposit-only coordinator")
    }
}

fn canonical_envelope() -> Vec<u8> {
    canonical_envelope_at(NOW + 60)
}

fn canonical_envelope_at(expires_at_unix_seconds: u64) -> Vec<u8> {
    OpaqueEnvelope::new([0x31; 16], expires_at_unix_seconds, vec![0x32; 32])
        .expect("bounded envelope")
        .encode_canonical()
        .expect("canonical envelope")
}

fn store(envelope: Vec<u8>) -> TestStore {
    TestStore {
        job: Some((envelope, b"endpoint".to_vec(), NOW + 30)),
        leased: false,
        accepted: 0,
        failed: 0,
    }
}

fn coordinator() -> WelcomeDeliveryCoordinator {
    WelcomeDeliveryCoordinator::new(
        CoordinatorPolicy::new(Duration::from_secs(5), 10, 65_536).expect("policy"),
    )
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("future unexpectedly pending"),
    }
}

#[test]
fn one_owner_lease_performs_one_exact_single_attempt_deposit() {
    let start = Instant::now();
    let control = TestControl {
        monotonic_now: start,
        wall_now_unix_seconds: NOW,
    };
    let expected = canonical_envelope();
    let mut store = store(expected.clone());
    let mut adapter = ReadyAdapter {
        calls: 0,
        fail: false,
        seen_envelope: Vec::new(),
        seen_attempts: 0,
    };
    let mut resolver = TestResolver;

    assert_eq!(
        ready(coordinator().run_once(&mut store, &mut resolver, &mut adapter, &control)),
        Ok(CoordinatorOutcome::Accepted)
    );
    assert_eq!(adapter.calls, 1);
    assert_eq!(adapter.seen_attempts, 1);
    assert_eq!(adapter.seen_envelope, expected);
    assert_eq!(store.accepted, 1);
    assert_eq!(store.failed, 0);

    assert_eq!(
        ready(coordinator().run_once(&mut store, &mut resolver, &mut adapter, &control)),
        Ok(CoordinatorOutcome::Idle)
    );
    assert_eq!(adapter.calls, 1);
}

#[test]
fn adapter_failure_releases_only_the_exact_owner_lease() {
    let start = Instant::now();
    let control = TestControl {
        monotonic_now: start,
        wall_now_unix_seconds: NOW,
    };
    let mut store = store(canonical_envelope());
    let mut adapter = ReadyAdapter {
        calls: 0,
        fail: true,
        seen_envelope: Vec::new(),
        seen_attempts: 0,
    };
    let mut resolver = TestResolver;

    assert_eq!(
        ready(coordinator().run_once(&mut store, &mut resolver, &mut adapter, &control)),
        Err(CoordinatorError::Transport(TransportFailure::new(
            TransportFailureCode::Unavailable,
            RetryAdvice::Backoff,
        )))
    );
    assert_eq!(store.accepted, 0);
    assert_eq!(store.failed, 1);
    assert!(!store.leased);
}

#[test]
fn malformed_owner_work_fails_before_adapter_entry() {
    let start = Instant::now();
    let control = TestControl {
        monotonic_now: start,
        wall_now_unix_seconds: NOW,
    };
    let mut store = store(vec![0xff]);
    let mut adapter = ReadyAdapter {
        calls: 0,
        fail: false,
        seen_envelope: Vec::new(),
        seen_attempts: 0,
    };
    let mut resolver = TestResolver;

    assert_eq!(
        ready(coordinator().run_once(&mut store, &mut resolver, &mut adapter, &control)),
        Err(CoordinatorError::InvalidOwnerWork)
    );
    assert_eq!(adapter.calls, 0);
    assert_eq!(store.failed, 1);
}

#[test]
fn deadline_supervision_drops_pending_adapter_work_and_leaves_owner_lease() {
    let (control, _cancellation) = ThreadDispatchControl::new();
    let wall_now = control
        .wall_now_unix_seconds()
        .expect("system wall clock is available");
    let mut store = TestStore {
        job: Some((
            canonical_envelope_at(wall_now + 60),
            b"endpoint".to_vec(),
            wall_now + 30,
        )),
        leased: false,
        accepted: 0,
        failed: 0,
    };
    let mut adapter = PendingAdapter {
        started: false,
        dropped: false,
    };
    let mut resolver = TestResolver;
    let coordinator = coordinator();
    assert_eq!(
        BlockingFutureSupervisor::run(
            coordinator.run_once(&mut store, &mut resolver, &mut adapter, &control),
            &control,
            Instant::now() + Duration::from_millis(20),
        ),
        Err(SupervisionError::DeadlineElapsed)
    );

    assert!(adapter.started);
    assert!(adapter.dropped);
    assert!(store.leased);
    assert_eq!(store.accepted, 0);
    assert_eq!(store.failed, 0);
}

#[test]
fn canonical_local_endpoint_reconstructs_and_deposits_into_the_real_mailbox() {
    let start = Instant::now();
    let control = TestControl {
        monotonic_now: start,
        wall_now_unix_seconds: NOW,
    };
    let mut adapter =
        LocalMemoryWelcomeTransport::new(LocalMailboxPolicy::new(300, 1).expect("mailbox policy"))
            .expect("local adapter");
    let (deposit, receive, _acknowledgement) = adapter
        .create_welcome_mailbox(NOW + 120, NOW)
        .expect("mailbox")
        .into_parts();
    let encoded_endpoint = deposit.encode_canonical().expect("canonical endpoint");
    let expected_bytes = canonical_envelope();
    let expected_envelope =
        OpaqueEnvelope::decode_canonical(&expected_bytes).expect("canonical envelope decodes");
    let mut store = TestStore {
        job: Some((expected_bytes, encoded_endpoint, NOW + 30)),
        leased: false,
        accepted: 0,
        failed: 0,
    };
    let mut resolver = LocalV1DepositEndpointResolver;

    assert_eq!(
        ready(coordinator().run_once(&mut store, &mut resolver, &mut adapter, &control)),
        Ok(CoordinatorOutcome::Accepted)
    );
    let received = adapter
        .receive(&receive, NOW)
        .expect("mailbox receive")
        .expect("one Welcome retained");
    assert_eq!(received.envelope(), &expected_envelope);
    assert_eq!(store.accepted, 1);
}
