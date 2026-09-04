use std::{
    collections::BTreeMap,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use session_protocol::OpaqueEnvelope;
use session_transport::{
    AcknowledgementReceipt, AcknowledgementRequest, AcknowledgementRight, DeliveryId,
    DepositReceipt, DepositRequest, DepositRight, DispatchControl, EnvelopeDelivery,
    OperationBudget, PollRequest, ReceiveBatch, ReceiveRight, TransportFailure,
};
use transport_conformance::{
    AcknowledgementLossFaultV1, AdapterControlErrorV1, AdapterSnapshotV1, AdverseTraceAdapterV1,
    AdverseTraceV1, AvailabilityFaultV1, ConformanceFuture, DepositFaultV1, RunErrorCategoryV1,
    run_adverse_trace_twice_v1,
};
use transport_memory::{
    AcknowledgementLoss, DeliveryAction, DeterministicMemoryTransport,
    MemoryAcknowledgementCapability, MemoryAvailability, MemoryDepositEndpoint,
    MemoryMailboxPolicy, MemoryReceiveCapability, MemoryTransportError,
};

const RUNNER_TRACE: &[u8] = include_bytes!("fixtures/memory-runner-v1.txt");
const COMMON_VERDICTS_TRACE: &[u8] = include_bytes!("fixtures/memory-common-verdicts-v1.txt");
const QUEUE_SATURATION_TRACE: &[u8] = include_bytes!("fixtures/memory-queue-saturation-v1.txt");
const ARBITRARY_DELAY_TRACE: &[u8] = include_bytes!("fixtures/memory-arbitrary-delay-v1.txt");

struct MailboxRights {
    deposit: DepositRight<MemoryDepositEndpoint>,
    receive: ReceiveRight<MemoryReceiveCapability>,
    acknowledgement: AcknowledgementRight<MemoryAcknowledgementCapability>,
}

struct MemoryTraceAdapter {
    transport: DeterministicMemoryTransport,
    mailboxes: BTreeMap<u8, MailboxRights>,
    behavior: AdapterBehavior,
    deposit_attempts: usize,
    seeded_provider_context: Option<&'static str>,
    active_operations: Arc<AtomicUsize>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum AdapterBehavior {
    Conforming,
    DelayedDrop { release_on_drop: bool },
    ChangedRetryReceipt,
    CrossScopePoll,
    IgnoreDepositControl,
    IgnoreQueueCapacity,
    SeededOpenFailure,
}

impl MemoryTraceAdapter {
    fn new() -> Self {
        Self {
            transport: DeterministicMemoryTransport::new(
                MemoryMailboxPolicy::new(300, 4, 8, 8).expect("bounded memory policy"),
            )
            .expect("memory transport"),
            mailboxes: BTreeMap::new(),
            behavior: AdapterBehavior::Conforming,
            deposit_attempts: 0,
            seeded_provider_context: None,
            active_operations: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn with_delayed_drop_deposit() -> Self {
        Self {
            behavior: AdapterBehavior::DelayedDrop {
                release_on_drop: true,
            },
            ..Self::new()
        }
    }

    fn with_changed_retry_receipt() -> Self {
        Self {
            behavior: AdapterBehavior::ChangedRetryReceipt,
            ..Self::new()
        }
    }

    fn with_cross_scope_poll() -> Self {
        Self {
            behavior: AdapterBehavior::CrossScopePoll,
            ..Self::new()
        }
    }

    fn with_ignored_deposit_control() -> Self {
        Self {
            behavior: AdapterBehavior::IgnoreDepositControl,
            ..Self::new()
        }
    }

    fn with_ignored_queue_capacity() -> Self {
        Self {
            behavior: AdapterBehavior::IgnoreQueueCapacity,
            ..Self::new()
        }
    }

    fn with_leaky_drop_deposit() -> Self {
        Self {
            behavior: AdapterBehavior::DelayedDrop {
                release_on_drop: false,
            },
            ..Self::new()
        }
    }

    fn with_seeded_open_failure(seeded_provider_context: &'static str) -> Self {
        Self {
            behavior: AdapterBehavior::SeededOpenFailure,
            seeded_provider_context: Some(seeded_provider_context),
            ..Self::new()
        }
    }
}

struct DelayedDropDepositFuture<'a> {
    control: &'a dyn DispatchControl,
    budget: OperationBudget,
    active_operations: Arc<AtomicUsize>,
    first_poll: bool,
    release_on_drop: bool,
    output: PhantomData<Result<DepositReceipt, TransportFailure>>,
}

impl<'a> DelayedDropDepositFuture<'a> {
    fn new(
        control: &'a dyn DispatchControl,
        budget: OperationBudget,
        active_operations: Arc<AtomicUsize>,
        release_on_drop: bool,
    ) -> Self {
        active_operations.fetch_add(1, Ordering::SeqCst);
        Self {
            control,
            budget,
            active_operations,
            first_poll: true,
            release_on_drop,
            output: PhantomData,
        }
    }
}

impl Future for DelayedDropDepositFuture<'_> {
    type Output = Result<DepositReceipt, TransportFailure>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.first_poll {
            self.first_poll = false;
            if let Err(failure) = self.control.checkpoint(self.budget) {
                return Poll::Ready(Err(failure));
            }
        }
        let waker = context.waker().clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            waker.wake();
        });
        Poll::Pending
    }
}

impl Drop for DelayedDropDepositFuture<'_> {
    fn drop(&mut self) {
        if self.release_on_drop {
            self.active_operations.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl AdverseTraceAdapterV1 for MemoryTraceAdapter {
    fn open_mailbox(
        &mut self,
        mailbox: u8,
        expires_at_unix_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<(), AdapterControlErrorV1> {
        if self.behavior == AdapterBehavior::SeededOpenFailure {
            let _provider_context_that_cannot_cross_the_bridge = self.seeded_provider_context;
            return Err(AdapterControlErrorV1::Internal);
        }
        let (deposit, receive, acknowledgement) = self
            .transport
            .create_mailbox(expires_at_unix_seconds, now_unix_seconds)
            .map_err(map_control_error)?
            .into_dispatch_parts();
        if self
            .mailboxes
            .insert(
                mailbox,
                MailboxRights {
                    deposit,
                    receive,
                    acknowledgement,
                },
            )
            .is_some()
        {
            return Err(AdapterControlErrorV1::Rejected);
        }
        Ok(())
    }

    fn arm_deposit(&mut self, fault: DepositFaultV1) -> Result<(), AdapterControlErrorV1> {
        self.transport
            .queue_action(match fault {
                DepositFaultV1::Deliver => DeliveryAction::Deliver,
                DepositFaultV1::Drop => DeliveryAction::Drop,
                DepositFaultV1::Hold => DeliveryAction::Hold,
                DepositFaultV1::Duplicate => DeliveryAction::Duplicate,
            })
            .map_err(map_control_error)
    }

    fn release_held(
        &mut self,
        index: u16,
        now_unix_seconds: u64,
    ) -> Result<(), AdapterControlErrorV1> {
        self.transport
            .release_held(usize::from(index), now_unix_seconds)
            .map(|_| ())
            .map_err(map_control_error)
    }

    fn replay_stale(
        &mut self,
        mailbox: u8,
        delivery_id: DeliveryId,
        envelope: OpaqueEnvelope,
    ) -> Result<(), AdapterControlErrorV1> {
        let Self {
            transport,
            mailboxes,
            ..
        } = self;
        let receive = &mailboxes
            .get(&mailbox)
            .ok_or(AdapterControlErrorV1::Rejected)?
            .receive;
        transport
            .replay_stale(receive, delivery_id, envelope)
            .map_err(map_control_error)
    }

    fn corrupt_next_poll(
        &mut self,
        mailbox: u8,
        delivery_id: DeliveryId,
    ) -> Result<(), AdapterControlErrorV1> {
        let Self {
            transport,
            mailboxes,
            ..
        } = self;
        let receive = &mailboxes
            .get(&mailbox)
            .ok_or(AdapterControlErrorV1::Rejected)?
            .receive;
        transport
            .corrupt_next_poll(receive, delivery_id)
            .map_err(map_control_error)
    }

    fn set_availability(
        &mut self,
        availability: AvailabilityFaultV1,
    ) -> Result<(), AdapterControlErrorV1> {
        self.transport.set_availability(match availability {
            AvailabilityFaultV1::Available => MemoryAvailability::Available,
            AvailabilityFaultV1::Unavailable => MemoryAvailability::Unavailable,
        });
        Ok(())
    }

    fn lose_next_acknowledgement(
        &mut self,
        loss: AcknowledgementLossFaultV1,
    ) -> Result<(), AdapterControlErrorV1> {
        self.transport
            .lose_next_acknowledgement(match loss {
                AcknowledgementLossFaultV1::BeforeCommit => AcknowledgementLoss::BeforeCommit,
                AcknowledgementLossFaultV1::AfterCommit => AcknowledgementLoss::AfterCommit,
            })
            .map_err(map_control_error)
    }

    fn deposit<'a>(
        &'a mut self,
        mailbox: u8,
        request: DepositRequest,
        control: &'a dyn DispatchControl,
    ) -> Result<
        ConformanceFuture<'a, Result<DepositReceipt, TransportFailure>>,
        AdapterControlErrorV1,
    > {
        let deposit_attempt = self.deposit_attempts;
        self.deposit_attempts = self.deposit_attempts.saturating_add(1);
        if let AdapterBehavior::DelayedDrop { release_on_drop } = self.behavior {
            return Ok(Box::pin(DelayedDropDepositFuture::new(
                control,
                request.budget(),
                Arc::clone(&self.active_operations),
                release_on_drop,
            )));
        }
        if self.behavior == AdapterBehavior::IgnoreDepositControl {
            let fabricated =
                DeliveryId::from_provider_bytes([0xfd; 16]).expect("nonzero defective receipt");
            return Ok(Box::pin(std::future::ready(Ok(DepositReceipt::accepted(
                fabricated,
            )))));
        }
        if self.behavior == AdapterBehavior::IgnoreQueueCapacity && deposit_attempt == 8 {
            let fabricated =
                DeliveryId::from_provider_bytes([0xfc; 16]).expect("nonzero defective receipt");
            let result = control
                .checkpoint(request.budget())
                .map(|_| DepositReceipt::accepted(fabricated));
            return Ok(Box::pin(std::future::ready(result)));
        }
        let Self {
            transport,
            mailboxes,
            ..
        } = self;
        let rights = mailboxes
            .get(&mailbox)
            .ok_or(AdapterControlErrorV1::Rejected)?;
        let operation = EnvelopeDelivery::deposit(transport, &rights.deposit, request, control);
        if self.behavior == AdapterBehavior::ChangedRetryReceipt && deposit_attempt > 0 {
            let changed =
                DeliveryId::from_provider_bytes([0xfe; 16]).expect("nonzero defective receipt");
            return Ok(Box::pin(async move {
                operation.await.map(|_| DepositReceipt::accepted(changed))
            }));
        }
        Ok(Box::pin(operation))
    }

    fn poll<'a>(
        &'a mut self,
        mailbox: u8,
        request: PollRequest,
        control: &'a dyn DispatchControl,
    ) -> Result<ConformanceFuture<'a, Result<ReceiveBatch, TransportFailure>>, AdapterControlErrorV1>
    {
        let Self {
            transport,
            mailboxes,
            ..
        } = self;
        let selected_mailbox = if self.behavior == AdapterBehavior::CrossScopePoll {
            mailboxes
                .keys()
                .copied()
                .find(|candidate| *candidate != mailbox)
                .unwrap_or(mailbox)
        } else {
            mailbox
        };
        let rights = mailboxes
            .get(&selected_mailbox)
            .ok_or(AdapterControlErrorV1::Rejected)?;
        Ok(Box::pin(EnvelopeDelivery::poll(
            transport,
            &rights.receive,
            request,
            control,
        )))
    }

    fn acknowledge<'a>(
        &'a mut self,
        mailbox: u8,
        request: AcknowledgementRequest,
        control: &'a dyn DispatchControl,
    ) -> Result<
        ConformanceFuture<'a, Result<AcknowledgementReceipt, TransportFailure>>,
        AdapterControlErrorV1,
    > {
        let Self {
            transport,
            mailboxes,
            ..
        } = self;
        let rights = mailboxes
            .get(&mailbox)
            .ok_or(AdapterControlErrorV1::Rejected)?;
        Ok(Box::pin(EnvelopeDelivery::acknowledge(
            transport,
            &rights.acknowledgement,
            request,
            control,
        )))
    }

    fn snapshot(&self) -> AdapterSnapshotV1 {
        let snapshot = self.transport.conformance_snapshot();
        AdapterSnapshotV1::new(
            self.active_operations.load(Ordering::SeqCst),
            snapshot.live_envelopes(),
            snapshot.live_encoded_bytes(),
            snapshot.visible_copies(),
            snapshot.held_copies(),
            snapshot.queued_delivery_actions(),
            snapshot.queued_stale_replays(),
            snapshot.corrupt_poll_armed(),
            snapshot.acknowledgement_loss_armed(),
            snapshot.availability() == MemoryAvailability::Available,
        )
    }
}

fn map_control_error(error: MemoryTransportError) -> AdapterControlErrorV1 {
    match error {
        MemoryTransportError::CapacityExceeded => AdapterControlErrorV1::Capacity,
        MemoryTransportError::Rejected => AdapterControlErrorV1::Rejected,
        MemoryTransportError::InvalidPolicy | MemoryTransportError::ProviderFailure => {
            AdapterControlErrorV1::Internal
        }
    }
}

#[test]
fn memory_trace_replays_twice_with_identical_secret_free_output() {
    assert!(
        !RUNNER_TRACE.contains(&b'\r'),
        "canonical trace fixtures must retain LF line endings"
    );
    let trace = AdverseTraceV1::parse(RUNNER_TRACE).expect("canonical runner trace");
    let report = run_adverse_trace_twice_v1(&trace, MemoryTraceAdapter::new)
        .expect("memory adapter must satisfy the trace twice");

    assert_eq!(
        report.as_bytes(),
        b"session-chat.transport.adverse-report/v1\nprofile|local\nstep|1|mailbox-opened|1\nstep|2|fault-applied\nstep|3|deposit-accepted|1\nstep|4|fault-applied\nstep|5|poll-accepted|1:1|none\nstep|6|ack-accepted\nend|quiescent\n"
    );
}

#[test]
fn memory_adapter_passes_the_composed_common_verdict_trace() {
    assert!(
        !COMMON_VERDICTS_TRACE.contains(&b'\r'),
        "canonical trace fixtures must retain LF line endings"
    );
    let trace = AdverseTraceV1::parse(COMMON_VERDICTS_TRACE)
        .expect("canonical composed common-verdict trace");
    let report = run_adverse_trace_twice_v1(&trace, MemoryTraceAdapter::new)
        .expect("memory adapter must pass the composed common verdicts twice");
    let report = std::str::from_utf8(report.as_bytes()).expect("ASCII normalized report");

    assert!(report.contains("step|4|poll-accepted|1:1|none\n"));
    assert!(report.contains("step|11|failed|corrupt-remote-response|never\n"));
    assert!(report.contains("step|14|failed|unavailable|never\n"));
    assert!(report.contains("step|19|failed|unavailable|never\n"));
    assert!(report.contains("step|27|failed|invalid-cursor|never\n"));
    assert!(report.contains("step|29|failed|expired-envelope|never\n"));
    assert!(report.ends_with("end|quiescent\n"));
}

#[test]
fn queue_saturation_is_deterministic_and_detects_an_over_accepting_bridge() {
    assert!(
        !QUEUE_SATURATION_TRACE.contains(&b'\r'),
        "canonical trace fixtures must retain LF line endings"
    );
    let trace = AdverseTraceV1::parse(QUEUE_SATURATION_TRACE)
        .expect("canonical queue-saturation verdict trace");
    let report = run_adverse_trace_twice_v1(&trace, MemoryTraceAdapter::new)
        .expect("the bounded memory adapter must fail closed at queue saturation twice");
    let report = std::str::from_utf8(report.as_bytes()).expect("ASCII normalized report");

    assert!(report.contains("step|10|failed|queue-full|never\n"));
    assert!(report.contains("step|11|poll-accepted|1:1,2:2,3:3,4:4,5:5,6:6,7:7,8:8|none\n"));
    assert!(report.ends_with("end|quiescent\n"));

    let failure =
        run_adverse_trace_twice_v1(&trace, MemoryTraceAdapter::with_ignored_queue_capacity)
            .expect_err("accepting the over-capacity deposit must fail the common verdict");
    assert_eq!(failure.category(), RunErrorCategoryV1::UnexpectedEvent);
    assert_eq!(failure.step(), Some(10));
}

#[test]
fn held_delivery_survives_bounded_arbitrary_virtual_delay_without_sleeping() {
    assert!(
        !ARBITRARY_DELAY_TRACE.contains(&b'\r'),
        "canonical trace fixtures must retain LF line endings"
    );
    let trace = AdverseTraceV1::parse(ARBITRARY_DELAY_TRACE)
        .expect("canonical bounded arbitrary-delay verdict trace");
    let report = run_adverse_trace_twice_v1(&trace, MemoryTraceAdapter::new)
        .expect("held delivery must remain deterministic across virtual delay");
    let report = std::str::from_utf8(report.as_bytes()).expect("ASCII normalized report");

    assert!(report.contains("step|5|poll-accepted|none|none\n"));
    assert!(report.contains("step|8|poll-accepted|1:1|none\n"));
    assert!(report.ends_with("end|quiescent\n"));
}

#[test]
fn runner_rejects_adapter_work_left_after_the_final_step() {
    let trace = AdverseTraceV1::parse(
        b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\nenvelope|1|1|1|32|120\nstep|1|open-mailbox|1|180|expect|mailbox-opened|1\nstep|2|arm-deposit|drop|expect|fault-applied\nstep|3|deposit|1|1|5000|4096|1|live:0:0;live:0:0|ready|expect|deposit-accepted|1\n",
    )
    .expect("canonical non-quiescent trace");

    let failure = run_adverse_trace_twice_v1(&trace, MemoryTraceAdapter::new)
        .expect_err("accepted but retained dropped work is not quiescent");
    assert_eq!(failure.category(), RunErrorCategoryV1::NonQuiescent);
    assert_eq!(failure.step(), None);
}

#[test]
fn virtual_control_normalizes_fail_closed_checkpoint_outcomes() {
    let cases = [
        ("cancelled", "cancelled"),
        ("deadline", "deadline-exceeded"),
        ("wall-unavailable", "internal"),
    ];

    for (directive, failure_code) in cases {
        let bytes = format!(
            "session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\nenvelope|1|1|1|32|120\nstep|1|open-mailbox|1|180|expect|mailbox-opened|1\nstep|2|deposit|1|1|5000|4096|1|{directive}|ready|expect|failed|{failure_code}|never\n"
        );
        let trace = AdverseTraceV1::parse(bytes.as_bytes()).expect("canonical failure trace");
        let report = run_adverse_trace_twice_v1(&trace, MemoryTraceAdapter::new)
            .expect("virtual checkpoint failure is deterministic and quiescent");
        let diagnostics = String::from_utf8(report.as_bytes().to_vec()).expect("ASCII report");

        assert!(diagnostics.contains(&format!("step|2|failed|{failure_code}|never\n")));
    }
}

#[test]
fn local_memory_runner_rejects_unbound_profile_labels() {
    let trace = AdverseTraceV1::parse(
        b"session-chat.transport.adverse-trace/v1\nprofile|private-mixnet\nwall-start|1700000000\nstep|1|open-mailbox|1|180|expect|mailbox-opened|1\n",
    )
    .expect("canonical but unbound profile trace");

    let failure = run_adverse_trace_twice_v1(&trace, MemoryTraceAdapter::new)
        .expect_err("the LocalV1 runner must not mint private-profile evidence");
    assert_eq!(failure.category(), RunErrorCategoryV1::UnsupportedProfile);
    assert_eq!(failure.step(), None);
}

#[test]
fn exact_retry_reuses_the_same_normalized_delivery_alias() {
    let trace = AdverseTraceV1::parse(
        b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\nenvelope|1|1|1|32|120\nstep|1|open-mailbox|1|180|expect|mailbox-opened|1\nstep|2|deposit|1|1|5000|4096|1|live:0:0;live:0:0|ready|expect|deposit-accepted|1\nstep|3|deposit|1|1|5000|4096|1|live:0:0;live:0:0|ready|expect|deposit-accepted|1\nstep|4|poll|1|none|4|4096|0|5000|4096|1|live:0:0;live:0:0|ready|expect|poll-accepted|1:1|none\nstep|5|ack|1|1|5000|4096|1|live:0:0;live:0:0|ready|expect|ack-accepted\n",
    )
    .expect("canonical exact-retry trace");

    let report = run_adverse_trace_twice_v1(&trace, MemoryTraceAdapter::new)
        .expect("the exact retry must retain one normalized receipt identity");
    assert_eq!(
        report.as_bytes(),
        b"session-chat.transport.adverse-report/v1\nprofile|local\nstep|1|mailbox-opened|1\nstep|2|deposit-accepted|1\nstep|3|deposit-accepted|1\nstep|4|poll-accepted|1:1|none\nstep|5|ack-accepted\nend|quiescent\n"
    );
}

#[test]
fn delayed_wake_drop_releases_bridge_owned_work_before_quiescence() {
    let trace = AdverseTraceV1::parse(
        b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\nenvelope|1|1|1|32|120\nstep|1|open-mailbox|1|180|expect|mailbox-opened|1\nstep|2|deposit|1|1|5000|4096|1|live:0:0|poll-once-drop|expect|future-dropped\n",
    )
    .expect("canonical delayed-drop trace");

    let report = run_adverse_trace_twice_v1(&trace, MemoryTraceAdapter::with_delayed_drop_deposit)
        .expect("delayed wake, drop cleanup, and final quiescence must compose end to end");
    assert_eq!(
        report.as_bytes(),
        b"session-chat.transport.adverse-report/v1\nprofile|local\nstep|1|mailbox-opened|1\nstep|2|future-dropped\nend|quiescent\n"
    );
}

#[test]
fn harness_rejects_changed_receipt_on_an_exact_retry() {
    let trace = AdverseTraceV1::parse(
        b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\nenvelope|1|1|1|32|120\nstep|1|open-mailbox|1|180|expect|mailbox-opened|1\nstep|2|deposit|1|1|5000|4096|1|live:0:0;live:0:0|ready|expect|deposit-accepted|1\nstep|3|deposit|1|1|5000|4096|1|live:0:0;live:0:0|ready|expect|deposit-accepted|1\nstep|4|poll|1|none|4|4096|0|5000|4096|1|live:0:0;live:0:0|ready|expect|poll-accepted|1:1|none\nstep|5|ack|1|1|5000|4096|1|live:0:0;live:0:0|ready|expect|ack-accepted\n",
    )
    .expect("canonical exact-retry verdict");
    run_adverse_trace_twice_v1(&trace, MemoryTraceAdapter::new)
        .expect("the conforming adapter passes the same verdict");

    let failure =
        run_adverse_trace_twice_v1(&trace, MemoryTraceAdapter::with_changed_retry_receipt)
            .expect_err("a changed provider receipt must fail exact-retry binding");
    assert_eq!(failure.category(), RunErrorCategoryV1::UnexpectedEvent);
    assert_eq!(failure.step(), Some(3));
}

#[test]
fn harness_rejects_a_poll_that_crosses_mailbox_scope() {
    let trace = AdverseTraceV1::parse(
        b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\nenvelope|1|1|1|32|120\nstep|1|open-mailbox|1|180|expect|mailbox-opened|1\nstep|2|open-mailbox|2|180|expect|mailbox-opened|2\nstep|3|deposit|1|1|5000|4096|1|live:0:0;live:0:0|ready|expect|deposit-accepted|1\nstep|4|poll|2|none|4|4096|0|5000|4096|1|live:0:0;live:0:0|ready|expect|poll-accepted|none|none\nstep|5|poll|1|none|4|4096|0|5000|4096|1|live:0:0;live:0:0|ready|expect|poll-accepted|1:1|none\nstep|6|ack|1|1|5000|4096|1|live:0:0;live:0:0|ready|expect|ack-accepted\n",
    )
    .expect("canonical mailbox-scope verdict");
    run_adverse_trace_twice_v1(&trace, MemoryTraceAdapter::new)
        .expect("the conforming adapter keeps the empty mailbox isolated");

    let failure = run_adverse_trace_twice_v1(&trace, MemoryTraceAdapter::with_cross_scope_poll)
        .expect_err("a receive batch cannot cross mailbox scope");
    assert_eq!(failure.category(), RunErrorCategoryV1::UnexpectedEvent);
    assert_eq!(failure.step(), Some(4));
}

#[test]
fn harness_rejects_an_adapter_that_ignores_deadline_control() {
    let trace = AdverseTraceV1::parse(
        b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\nenvelope|1|1|1|32|120\nstep|1|open-mailbox|1|180|expect|mailbox-opened|1\nstep|2|deposit|1|1|5000|4096|1|deadline|ready|expect|failed|deadline-exceeded|never\n",
    )
    .expect("canonical deadline verdict");
    run_adverse_trace_twice_v1(&trace, MemoryTraceAdapter::new)
        .expect("the conforming adapter observes the deadline checkpoint");

    let failure =
        run_adverse_trace_twice_v1(&trace, MemoryTraceAdapter::with_ignored_deposit_control)
            .expect_err("an adapter cannot skip the scripted deadline checkpoint");
    assert_eq!(
        failure.category(),
        RunErrorCategoryV1::InvalidCheckpointScript
    );
    assert_eq!(failure.step(), Some(2));
}

#[test]
fn harness_rejects_drop_cleanup_that_leaves_active_work() {
    let trace = AdverseTraceV1::parse(
        b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\nenvelope|1|1|1|32|120\nstep|1|open-mailbox|1|180|expect|mailbox-opened|1\nstep|2|deposit|1|1|5000|4096|1|live:0:0|poll-once-drop|expect|future-dropped\n",
    )
    .expect("canonical drop-cleanup verdict");
    run_adverse_trace_twice_v1(&trace, MemoryTraceAdapter::with_delayed_drop_deposit)
        .expect("the conforming bridge releases active work on drop");

    let failure = run_adverse_trace_twice_v1(&trace, MemoryTraceAdapter::with_leaky_drop_deposit)
        .expect_err("active bridge work must prevent a quiescent verdict");
    assert_eq!(failure.category(), RunErrorCategoryV1::NonQuiescent);
    assert_eq!(failure.step(), None);
}

#[test]
fn seeded_provider_failure_cannot_enter_runner_diagnostics() {
    const SEEDED_PROVIDER_CONTEXT: &str = "SEEDED-ROUTE-CAPABILITY-PROVIDER-ERROR";
    let trace = AdverseTraceV1::parse(
        b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\nstep|1|open-mailbox|1|180|expect|mailbox-opened|1\n",
    )
    .expect("canonical adapter-control verdict");

    let failure = run_adverse_trace_twice_v1(&trace, || {
        MemoryTraceAdapter::with_seeded_open_failure(SEEDED_PROVIDER_CONTEXT)
    })
    .expect_err("the bridge maps provider failure to a closed runner category");
    let diagnostics = format!("{failure:?} {failure}");
    assert_eq!(failure.category(), RunErrorCategoryV1::AdapterControl);
    assert_eq!(failure.step(), Some(1));
    assert!(!diagnostics.contains(SEEDED_PROVIDER_CONTEXT));
}
