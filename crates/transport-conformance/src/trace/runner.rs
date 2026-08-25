use std::{
    collections::BTreeMap,
    fmt,
    future::Future,
    pin::{Pin, pin},
    sync::{Arc, Condvar, Mutex},
    task::{Context, Poll, Wake, Waker},
    time::{Duration, Instant},
};

use session_protocol::OpaqueEnvelope;
use session_transport::{
    AcknowledgementReceipt, AcknowledgementRequest, BoundedDeliveryIds, CanonicalEnvelope, Cursor,
    DeliveryId, DepositReceipt, DepositRequest, DispatchControl, DispatchObservation,
    OperationBudget, PollRequest, PollWait, ReceiveBatch, RetryAdvice, TransportFailure,
    TransportFailureCode,
};

use super::{
    AcknowledgementLossV1, AdverseTraceV1, Alias, AvailabilityV1, CheckpointDirectiveV1,
    DepositOutcomeV1, DriveModeV1, ExpectedEventV1, OperationBudgetV1, OperationControlV1,
    TraceActionV1,
};

const REPORT_HEADER: &str = "session-chat.transport.adverse-report/v1";
const MAX_DRIVER_POLLS: usize = 16;
const MAX_DRIVER_WAKE_WAIT: Duration = Duration::from_secs(1);

/// One bounded future returned by an adapter-specific conformance bridge.
pub type ConformanceFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Coarse adapter-control failure that cannot carry provider text or identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterControlErrorV1 {
    Rejected,
    Capacity,
    Internal,
}

/// One deterministic outcome for the next otherwise valid deposit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepositFaultV1 {
    Deliver,
    Drop,
    Hold,
    Duplicate,
}

/// Persistent availability selected by a conformance trace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AvailabilityFaultV1 {
    Available,
    Unavailable,
}

/// One-shot acknowledgement-result loss selected by a conformance trace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcknowledgementLossFaultV1 {
    BeforeCommit,
    AfterCommit,
}

/// Secret-free bounded adapter-reported state used for end-of-trace quiescence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterSnapshotV1 {
    active_operations: usize,
    live_envelopes: usize,
    live_encoded_bytes: usize,
    visible_copies: usize,
    held_copies: usize,
    queued_deposit_faults: usize,
    queued_stale_replays: usize,
    corrupt_poll_armed: bool,
    acknowledgement_loss_armed: bool,
    available: bool,
}

impl AdapterSnapshotV1 {
    /// Constructs an adapter-reported snapshot from bounded counts and flags only.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        active_operations: usize,
        live_envelopes: usize,
        live_encoded_bytes: usize,
        visible_copies: usize,
        held_copies: usize,
        queued_deposit_faults: usize,
        queued_stale_replays: usize,
        corrupt_poll_armed: bool,
        acknowledgement_loss_armed: bool,
        available: bool,
    ) -> Self {
        Self {
            active_operations,
            live_envelopes,
            live_encoded_bytes,
            visible_copies,
            held_copies,
            queued_deposit_faults,
            queued_stale_replays,
            corrupt_poll_armed,
            acknowledgement_loss_armed,
            available,
        }
    }

    const fn is_quiescent(self) -> bool {
        self.active_operations == 0
            && self.live_envelopes == 0
            && self.live_encoded_bytes == 0
            && self.visible_copies == 0
            && self.held_copies == 0
            && self.queued_deposit_faults == 0
            && self.queued_stale_replays == 0
            && !self.corrupt_poll_armed
            && !self.acknowledgement_loss_armed
            && self.available
    }
}

/// Provider-specific bridge used by the provider-neutral adverse-trace runner.
///
/// Implementations retain all rights internally behind numeric mailbox aliases.
/// They must never place provider errors, identifiers, routes, or authority
/// material in the returned control error or snapshot.
pub trait AdverseTraceAdapterV1: Sized {
    fn open_mailbox(
        &mut self,
        mailbox: u8,
        expires_at_unix_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<(), AdapterControlErrorV1>;

    fn arm_deposit(&mut self, fault: DepositFaultV1) -> Result<(), AdapterControlErrorV1>;

    fn release_held(
        &mut self,
        index: u16,
        now_unix_seconds: u64,
    ) -> Result<(), AdapterControlErrorV1>;

    fn replay_stale(
        &mut self,
        mailbox: u8,
        delivery_id: DeliveryId,
        envelope: OpaqueEnvelope,
    ) -> Result<(), AdapterControlErrorV1>;

    fn corrupt_next_poll(
        &mut self,
        mailbox: u8,
        delivery_id: DeliveryId,
    ) -> Result<(), AdapterControlErrorV1>;

    fn set_availability(
        &mut self,
        availability: AvailabilityFaultV1,
    ) -> Result<(), AdapterControlErrorV1>;

    fn lose_next_acknowledgement(
        &mut self,
        loss: AcknowledgementLossFaultV1,
    ) -> Result<(), AdapterControlErrorV1>;

    fn deposit<'a>(
        &'a mut self,
        mailbox: u8,
        request: DepositRequest,
        control: &'a dyn DispatchControl,
    ) -> Result<
        ConformanceFuture<'a, Result<DepositReceipt, TransportFailure>>,
        AdapterControlErrorV1,
    >;

    fn poll<'a>(
        &'a mut self,
        mailbox: u8,
        request: PollRequest,
        control: &'a dyn DispatchControl,
    ) -> Result<ConformanceFuture<'a, Result<ReceiveBatch, TransportFailure>>, AdapterControlErrorV1>;

    fn acknowledge<'a>(
        &'a mut self,
        mailbox: u8,
        request: AcknowledgementRequest,
        control: &'a dyn DispatchControl,
    ) -> Result<
        ConformanceFuture<'a, Result<AcknowledgementReceipt, TransportFailure>>,
        AdapterControlErrorV1,
    >;

    fn snapshot(&self) -> AdapterSnapshotV1;
}

/// Stable, secret-free runner failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunErrorCategoryV1 {
    UnsupportedProfile,
    FixtureGeneration,
    AdapterControl,
    MissingAlias,
    UnexpectedEvent,
    InvalidCheckpointScript,
    PendingWithoutWake,
    PollLimitExceeded,
    UnsupportedOutcome,
    NonQuiescent,
    NonDeterministic,
}

/// Context-free runner failure safe for ordinary test diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunErrorV1 {
    category: RunErrorCategoryV1,
    step: Option<u16>,
}

impl RunErrorV1 {
    /// Returns the stable failure category.
    #[must_use]
    pub const fn category(self) -> RunErrorCategoryV1 {
        self.category
    }

    /// Returns only the trace step number, never rejected or provider data.
    #[must_use]
    pub const fn step(self) -> Option<u16> {
        self.step
    }
}

impl fmt::Display for RunErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("transport conformance trace execution failed")
    }
}

impl std::error::Error for RunErrorV1 {}

/// Canonical secret-free normalized output from one double replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunReportV1(Box<[u8]>);

impl RunReportV1 {
    /// Returns normalized report bytes containing aliases and outcome tokens only.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Replays one LocalV1 trace against two fresh adapters and requires identical reports.
///
/// The factory must return semantically independent adapter instances with no
/// shared provider state. Rust cannot prove that obligation; deliberately
/// defective factory and adapter tests remain a completion gate for the common
/// verdict suite.
pub fn run_adverse_trace_twice_v1<A, F>(
    trace: &AdverseTraceV1,
    mut factory: F,
) -> Result<RunReportV1, RunErrorV1>
where
    A: AdverseTraceAdapterV1,
    F: FnMut() -> A,
{
    if trace.profile != session_transport::TransportProfileId::LocalV1 {
        return Err(run_error(RunErrorCategoryV1::UnsupportedProfile, None));
    }
    let first = run_once(trace, factory())?;
    let second = run_once(trace, factory())?;
    if first != second {
        return Err(run_error(RunErrorCategoryV1::NonDeterministic, None));
    }
    Ok(first)
}

#[derive(Clone)]
struct GeneratedEnvelope {
    opaque: OpaqueEnvelope,
    canonical_bytes: Box<[u8]>,
}

struct DeliveryRecord {
    id: DeliveryId,
    mailbox: Alias,
    envelope: Alias,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum NormalizedEvent {
    MailboxOpened(Alias),
    FaultApplied,
    DepositAccepted(Alias),
    PollAccepted {
        items: Box<[(Alias, Alias)]>,
        cursor: Option<Alias>,
    },
    AcknowledgementAccepted,
    Failed {
        code: Box<str>,
        retry: Box<str>,
    },
    FutureDropped,
    Quiescent,
}

#[derive(Clone, Copy)]
struct VirtualClock {
    monotonic: Instant,
    wall: u64,
}

fn run_once<A: AdverseTraceAdapterV1>(
    trace: &AdverseTraceV1,
    mut adapter: A,
) -> Result<RunReportV1, RunErrorV1> {
    let envelopes = generate_envelopes(trace)?;
    let cursors = generate_cursors(trace);
    let mut deliveries = BTreeMap::new();
    let mut clock = VirtualClock {
        monotonic: Instant::now(),
        wall: trace.wall_start_unix_seconds,
    };
    let mut report = String::new();
    report.push_str(REPORT_HEADER);
    report.push('\n');
    report.push_str("profile|");
    report.push_str("local");
    report.push('\n');

    for step in &trace.steps {
        let actual = execute_step(
            &mut adapter,
            &envelopes,
            &cursors,
            &mut deliveries,
            &mut clock,
            &step.action,
            &step.expected,
            step.index,
        )?;
        let expected = normalize_expected(&step.expected);
        if actual != expected {
            return Err(run_error(
                RunErrorCategoryV1::UnexpectedEvent,
                Some(step.index),
            ));
        }
        report.push_str("step|");
        report.push_str(&step.index.to_string());
        report.push('|');
        encode_event(&actual, &mut report);
        report.push('\n');
    }

    if !adapter.snapshot().is_quiescent() {
        return Err(run_error(RunErrorCategoryV1::NonQuiescent, None));
    }
    report.push_str("end|quiescent\n");
    Ok(RunReportV1(report.into_bytes().into_boxed_slice()))
}

#[allow(clippy::too_many_arguments)]
fn execute_step<A: AdverseTraceAdapterV1>(
    adapter: &mut A,
    envelopes: &BTreeMap<Alias, GeneratedEnvelope>,
    cursors: &BTreeMap<Alias, Box<[u8]>>,
    deliveries: &mut BTreeMap<Alias, DeliveryRecord>,
    clock: &mut VirtualClock,
    action: &TraceActionV1,
    expected: &ExpectedEventV1,
    step: u16,
) -> Result<NormalizedEvent, RunErrorV1> {
    match action {
        TraceActionV1::OpenMailbox {
            mailbox,
            lifetime_seconds,
        } => {
            let expires_at = clock
                .wall
                .checked_add(u64::from(*lifetime_seconds))
                .ok_or_else(|| run_error(RunErrorCategoryV1::FixtureGeneration, Some(step)))?;
            adapter
                .open_mailbox(mailbox.0, expires_at, clock.wall)
                .map_err(|_| run_error(RunErrorCategoryV1::AdapterControl, Some(step)))?;
            Ok(NormalizedEvent::MailboxOpened(*mailbox))
        }
        TraceActionV1::ArmDeposit(outcome) => {
            adapter
                .arm_deposit(match outcome {
                    DepositOutcomeV1::Deliver => DepositFaultV1::Deliver,
                    DepositOutcomeV1::Drop => DepositFaultV1::Drop,
                    DepositOutcomeV1::Hold => DepositFaultV1::Hold,
                    DepositOutcomeV1::Duplicate => DepositFaultV1::Duplicate,
                })
                .map_err(|_| run_error(RunErrorCategoryV1::AdapterControl, Some(step)))?;
            Ok(NormalizedEvent::FaultApplied)
        }
        TraceActionV1::ReleaseHeld(index) => {
            adapter
                .release_held(*index, clock.wall)
                .map_err(|_| run_error(RunErrorCategoryV1::AdapterControl, Some(step)))?;
            Ok(NormalizedEvent::FaultApplied)
        }
        TraceActionV1::ReplayStale(delivery) => {
            let record = deliveries
                .get(delivery)
                .ok_or_else(|| run_error(RunErrorCategoryV1::MissingAlias, Some(step)))?;
            let envelope = envelopes
                .get(&record.envelope)
                .ok_or_else(|| run_error(RunErrorCategoryV1::MissingAlias, Some(step)))?;
            adapter
                .replay_stale(record.mailbox.0, record.id, envelope.opaque.clone())
                .map_err(|_| run_error(RunErrorCategoryV1::AdapterControl, Some(step)))?;
            Ok(NormalizedEvent::FaultApplied)
        }
        TraceActionV1::CorruptNextPoll(delivery) => {
            let record = deliveries
                .get(delivery)
                .ok_or_else(|| run_error(RunErrorCategoryV1::MissingAlias, Some(step)))?;
            adapter
                .corrupt_next_poll(record.mailbox.0, record.id)
                .map_err(|_| run_error(RunErrorCategoryV1::AdapterControl, Some(step)))?;
            Ok(NormalizedEvent::FaultApplied)
        }
        TraceActionV1::SetAvailability(availability) => {
            adapter
                .set_availability(match availability {
                    AvailabilityV1::Available => AvailabilityFaultV1::Available,
                    AvailabilityV1::Unavailable => AvailabilityFaultV1::Unavailable,
                })
                .map_err(|_| run_error(RunErrorCategoryV1::AdapterControl, Some(step)))?;
            Ok(NormalizedEvent::FaultApplied)
        }
        TraceActionV1::LoseNextAcknowledgement(loss) => {
            adapter
                .lose_next_acknowledgement(match loss {
                    AcknowledgementLossV1::BeforeCommit => AcknowledgementLossFaultV1::BeforeCommit,
                    AcknowledgementLossV1::AfterCommit => AcknowledgementLossFaultV1::AfterCommit,
                })
                .map_err(|_| run_error(RunErrorCategoryV1::AdapterControl, Some(step)))?;
            Ok(NormalizedEvent::FaultApplied)
        }
        TraceActionV1::AdvanceClock {
            monotonic_ms,
            wall_seconds,
        } => {
            clock.monotonic = clock
                .monotonic
                .checked_add(Duration::from_millis(u64::from(*monotonic_ms)))
                .ok_or_else(|| run_error(RunErrorCategoryV1::FixtureGeneration, Some(step)))?;
            clock.wall = add_signed(clock.wall, *wall_seconds)
                .ok_or_else(|| run_error(RunErrorCategoryV1::FixtureGeneration, Some(step)))?;
            Ok(NormalizedEvent::FaultApplied)
        }
        TraceActionV1::Deposit {
            mailbox,
            envelope,
            budget,
            control,
        } => {
            let generated = envelopes
                .get(envelope)
                .ok_or_else(|| run_error(RunErrorCategoryV1::MissingAlias, Some(step)))?;
            let operation_budget = operation_budget(*clock, *budget, step)?;
            let request = DepositRequest::new(
                CanonicalEnvelope::from_opaque(generated.opaque.clone())
                    .map_err(|_| run_error(RunErrorCategoryV1::FixtureGeneration, Some(step)))?,
                operation_budget,
            )
            .map_err(|_| run_error(RunErrorCategoryV1::FixtureGeneration, Some(step)))?;
            let scripted = ScriptedControl::new(*clock, operation_budget, control);
            let future = adapter
                .deposit(mailbox.0, request, &scripted)
                .map_err(|_| run_error(RunErrorCategoryV1::AdapterControl, Some(step)))?;
            let driven = drive(future, control.drive, step)?;
            *clock = scripted.finish(step)?;
            match driven {
                Driven::Ready(Ok(receipt)) => {
                    let ExpectedEventV1::DepositAccepted(alias) = expected else {
                        return Err(run_error(RunErrorCategoryV1::UnexpectedEvent, Some(step)));
                    };
                    record_deposit_receipt(
                        deliveries,
                        *alias,
                        *receipt.delivery_id(),
                        *mailbox,
                        *envelope,
                        step,
                    )?;
                    Ok(NormalizedEvent::DepositAccepted(*alias))
                }
                Driven::Ready(Err(failure)) => normalize_failure(failure, step),
                Driven::Dropped => Ok(NormalizedEvent::FutureDropped),
            }
        }
        TraceActionV1::Poll {
            mailbox,
            cursor,
            max_envelopes,
            max_encoded_bytes,
            wait_ms,
            budget,
            control,
        } => {
            let operation_budget = operation_budget(*clock, *budget, step)?;
            let cursor = cursor
                .map(|alias| {
                    let bytes = cursors
                        .get(&alias)
                        .ok_or_else(|| run_error(RunErrorCategoryV1::MissingAlias, Some(step)))?;
                    Cursor::new(bytes.to_vec())
                        .map_err(|_| run_error(RunErrorCategoryV1::FixtureGeneration, Some(step)))
                })
                .transpose()?;
            let wait = if *wait_ms == 0 {
                PollWait::immediate()
            } else {
                PollWait::up_to(Duration::from_millis(u64::from(*wait_ms)))
                    .map_err(|_| run_error(RunErrorCategoryV1::FixtureGeneration, Some(step)))?
            };
            let request = PollRequest::new(
                cursor,
                *max_envelopes,
                *max_encoded_bytes,
                wait,
                operation_budget,
            )
            .map_err(|_| run_error(RunErrorCategoryV1::FixtureGeneration, Some(step)))?;
            let scripted = ScriptedControl::new(*clock, operation_budget, control);
            let future = adapter
                .poll(mailbox.0, request, &scripted)
                .map_err(|_| run_error(RunErrorCategoryV1::AdapterControl, Some(step)))?;
            let driven = drive(future, control.drive, step)?;
            *clock = scripted.finish(step)?;
            match driven {
                Driven::Ready(Ok(batch)) => {
                    normalize_batch(batch, *mailbox, envelopes, cursors, deliveries, step)
                }
                Driven::Ready(Err(failure)) => normalize_failure(failure, step),
                Driven::Dropped => Ok(NormalizedEvent::FutureDropped),
            }
        }
        TraceActionV1::Acknowledge {
            mailbox,
            deliveries: aliases,
            budget,
            control,
        } => {
            let ids = aliases
                .iter()
                .map(|alias| {
                    deliveries
                        .get(alias)
                        .map(|record| record.id)
                        .ok_or_else(|| run_error(RunErrorCategoryV1::MissingAlias, Some(step)))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let ids = BoundedDeliveryIds::new(ids)
                .map_err(|_| run_error(RunErrorCategoryV1::FixtureGeneration, Some(step)))?;
            let operation_budget = operation_budget(*clock, *budget, step)?;
            let request = AcknowledgementRequest::new(ids, operation_budget);
            let scripted = ScriptedControl::new(*clock, operation_budget, control);
            let future = adapter
                .acknowledge(mailbox.0, request, &scripted)
                .map_err(|_| run_error(RunErrorCategoryV1::AdapterControl, Some(step)))?;
            let driven = drive(future, control.drive, step)?;
            *clock = scripted.finish(step)?;
            match driven {
                Driven::Ready(Ok(_)) => Ok(NormalizedEvent::AcknowledgementAccepted),
                Driven::Ready(Err(failure)) => normalize_failure(failure, step),
                Driven::Dropped => Ok(NormalizedEvent::FutureDropped),
            }
        }
    }
}

fn generate_envelopes(
    trace: &AdverseTraceV1,
) -> Result<BTreeMap<Alias, GeneratedEnvelope>, RunErrorV1> {
    trace
        .envelopes
        .iter()
        .map(|fixture| {
            let expires_at = trace
                .wall_start_unix_seconds
                .checked_add(u64::from(fixture.expiry_offset_seconds))
                .ok_or_else(|| run_error(RunErrorCategoryV1::FixtureGeneration, None))?;
            let ciphertext = (0..fixture.ciphertext_len)
                .map(|index| fixture.content_variant.0 ^ index.to_le_bytes()[0] ^ 0xa5)
                .collect();
            let opaque =
                OpaqueEnvelope::new([fixture.logical_id_alias.0; 16], expires_at, ciphertext)
                    .map_err(|_| run_error(RunErrorCategoryV1::FixtureGeneration, None))?;
            let canonical_bytes = opaque
                .encode_canonical()
                .map_err(|_| run_error(RunErrorCategoryV1::FixtureGeneration, None))?
                .into_boxed_slice();
            Ok((
                fixture.alias,
                GeneratedEnvelope {
                    opaque,
                    canonical_bytes,
                },
            ))
        })
        .collect()
}

fn generate_cursors(trace: &AdverseTraceV1) -> BTreeMap<Alias, Box<[u8]>> {
    trace
        .cursors
        .iter()
        .map(|fixture| {
            let bytes = (0..fixture.encoded_len)
                .map(|index| fixture.content_variant.0 ^ index.to_le_bytes()[0] ^ 0x5a)
                .collect::<Vec<_>>()
                .into_boxed_slice();
            (fixture.alias, bytes)
        })
        .collect()
}

fn operation_budget(
    clock: VirtualClock,
    budget: OperationBudgetV1,
    step: u16,
) -> Result<OperationBudget, RunErrorV1> {
    let deadline = clock
        .monotonic
        .checked_add(Duration::from_millis(u64::from(budget.deadline_offset_ms)))
        .ok_or_else(|| run_error(RunErrorCategoryV1::FixtureGeneration, Some(step)))?;
    OperationBudget::new(
        deadline,
        u64::from(budget.max_encoded_bytes),
        budget.max_attempts,
    )
    .map_err(|_| run_error(RunErrorCategoryV1::FixtureGeneration, Some(step)))
}

fn normalize_batch(
    batch: ReceiveBatch,
    mailbox: Alias,
    envelopes: &BTreeMap<Alias, GeneratedEnvelope>,
    cursors: &BTreeMap<Alias, Box<[u8]>>,
    deliveries: &BTreeMap<Alias, DeliveryRecord>,
    step: u16,
) -> Result<NormalizedEvent, RunErrorV1> {
    let items = batch
        .items()
        .iter()
        .map(|item| {
            let (delivery, record) = deliveries
                .iter()
                .find(|(_, record)| record.id == *item.delivery_id())
                .ok_or_else(|| run_error(RunErrorCategoryV1::MissingAlias, Some(step)))?;
            if record.mailbox != mailbox {
                return Err(run_error(RunErrorCategoryV1::UnexpectedEvent, Some(step)));
            }
            let fixture = envelopes
                .get(&record.envelope)
                .ok_or_else(|| run_error(RunErrorCategoryV1::MissingAlias, Some(step)))?;
            if fixture.canonical_bytes.as_ref() != item.envelope().as_bytes() {
                return Err(run_error(RunErrorCategoryV1::UnexpectedEvent, Some(step)));
            }
            Ok((*delivery, record.envelope))
        })
        .collect::<Result<Vec<_>, RunErrorV1>>()?
        .into_boxed_slice();
    let cursor = batch
        .next_cursor()
        .map(|actual| {
            cursors
                .iter()
                .find_map(|(alias, bytes)| (bytes.as_ref() == actual.as_bytes()).then_some(*alias))
                .ok_or_else(|| run_error(RunErrorCategoryV1::MissingAlias, Some(step)))
        })
        .transpose()?;
    Ok(NormalizedEvent::PollAccepted { items, cursor })
}

fn normalize_failure(failure: TransportFailure, step: u16) -> Result<NormalizedEvent, RunErrorV1> {
    let code = match failure.code() {
        TransportFailureCode::InvalidAuthority => "invalid-authority",
        TransportFailureCode::AuthorityScopeMismatch => "authority-scope-mismatch",
        TransportFailureCode::ExpiredEnvelope => "expired-envelope",
        TransportFailureCode::EnvelopeTooLarge => "envelope-too-large",
        TransportFailureCode::IdempotencyConflict => "idempotency-conflict",
        TransportFailureCode::InvalidCursor => "invalid-cursor",
        TransportFailureCode::QueueFull => "queue-full",
        TransportFailureCode::RateLimited => "rate-limited",
        TransportFailureCode::Unavailable => "unavailable",
        TransportFailureCode::DeadlineExceeded => "deadline-exceeded",
        TransportFailureCode::Cancelled => "cancelled",
        TransportFailureCode::CorruptRemoteResponse => "corrupt-remote-response",
        TransportFailureCode::PolicyViolation => "policy-violation",
        TransportFailureCode::Misconfigured => "misconfigured",
        TransportFailureCode::Internal => "internal",
        _ => {
            return Err(run_error(
                RunErrorCategoryV1::UnsupportedOutcome,
                Some(step),
            ));
        }
    };
    let retry = match failure.retry_advice() {
        RetryAdvice::Never => "never".to_owned(),
        RetryAdvice::Backoff => "backoff".to_owned(),
        RetryAdvice::After(delay) => format!("after-ns:{}", delay.duration().as_nanos()),
    };
    Ok(NormalizedEvent::Failed {
        code: code.into(),
        retry: retry.into(),
    })
}

fn normalize_expected(expected: &ExpectedEventV1) -> NormalizedEvent {
    match expected {
        ExpectedEventV1::MailboxOpened(alias) => NormalizedEvent::MailboxOpened(*alias),
        ExpectedEventV1::FaultApplied => NormalizedEvent::FaultApplied,
        ExpectedEventV1::DepositAccepted(alias) => NormalizedEvent::DepositAccepted(*alias),
        ExpectedEventV1::PollAccepted { items, cursor } => NormalizedEvent::PollAccepted {
            items: items.clone(),
            cursor: *cursor,
        },
        ExpectedEventV1::AcknowledgementAccepted => NormalizedEvent::AcknowledgementAccepted,
        ExpectedEventV1::Failed { code, retry } => NormalizedEvent::Failed {
            code: code.clone(),
            retry: retry.clone(),
        },
        ExpectedEventV1::FutureDropped => NormalizedEvent::FutureDropped,
        ExpectedEventV1::Quiescent => NormalizedEvent::Quiescent,
    }
}

fn encode_event(event: &NormalizedEvent, output: &mut String) {
    match event {
        NormalizedEvent::MailboxOpened(alias) => {
            output.push_str("mailbox-opened|");
            output.push_str(&alias.0.to_string());
        }
        NormalizedEvent::FaultApplied => output.push_str("fault-applied"),
        NormalizedEvent::DepositAccepted(alias) => {
            output.push_str("deposit-accepted|");
            output.push_str(&alias.0.to_string());
        }
        NormalizedEvent::PollAccepted { items, cursor } => {
            output.push_str("poll-accepted|");
            if items.is_empty() {
                output.push_str("none");
            } else {
                for (index, (delivery, envelope)) in items.iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    output.push_str(&delivery.0.to_string());
                    output.push(':');
                    output.push_str(&envelope.0.to_string());
                }
            }
            output.push('|');
            match cursor {
                Some(alias) => output.push_str(&alias.0.to_string()),
                None => output.push_str("none"),
            }
        }
        NormalizedEvent::AcknowledgementAccepted => output.push_str("ack-accepted"),
        NormalizedEvent::Failed { code, retry } => {
            output.push_str("failed|");
            output.push_str(code);
            output.push('|');
            output.push_str(retry);
        }
        NormalizedEvent::FutureDropped => output.push_str("future-dropped"),
        NormalizedEvent::Quiescent => output.push_str("quiescent"),
    }
}

enum Driven<T> {
    Ready(T),
    Dropped,
}

fn drive<T>(
    future: impl Future<Output = T>,
    mode: DriveModeV1,
    step: u16,
) -> Result<Driven<T>, RunErrorV1> {
    let wake_count = Arc::new(CountingWake {
        generation: Mutex::new(0),
        notified: Condvar::new(),
    });
    let waker = Waker::from(Arc::clone(&wake_count));
    let mut context = Context::from_waker(&waker);
    let mut future = pin!(future);
    for poll_index in 0..MAX_DRIVER_POLLS {
        let wake_generation = wake_count.generation();
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => {
                if mode == DriveModeV1::PollOnceThenDrop {
                    return Err(run_error(RunErrorCategoryV1::UnexpectedEvent, Some(step)));
                }
                return Ok(Driven::Ready(value));
            }
            Poll::Pending => {
                if !wake_count.wait_for_wake_after(wake_generation) {
                    return Err(run_error(
                        RunErrorCategoryV1::PendingWithoutWake,
                        Some(step),
                    ));
                }
                if mode == DriveModeV1::PollOnceThenDrop {
                    return Ok(Driven::Dropped);
                }
                if poll_index + 1 == MAX_DRIVER_POLLS {
                    return Err(run_error(RunErrorCategoryV1::PollLimitExceeded, Some(step)));
                }
            }
        }
    }
    Err(run_error(RunErrorCategoryV1::PollLimitExceeded, Some(step)))
}

fn record_deposit_receipt(
    deliveries: &mut BTreeMap<Alias, DeliveryRecord>,
    alias: Alias,
    id: DeliveryId,
    mailbox: Alias,
    envelope: Alias,
    step: u16,
) -> Result<(), RunErrorV1> {
    if let Some(existing) = deliveries.get(&alias) {
        if existing.id != id || existing.mailbox != mailbox || existing.envelope != envelope {
            return Err(run_error(RunErrorCategoryV1::UnexpectedEvent, Some(step)));
        }
        return Ok(());
    }
    if deliveries.values().any(|existing| existing.id == id) {
        return Err(run_error(RunErrorCategoryV1::UnexpectedEvent, Some(step)));
    }
    deliveries.insert(
        alias,
        DeliveryRecord {
            id,
            mailbox,
            envelope,
        },
    );
    Ok(())
}

struct CountingWake {
    generation: Mutex<usize>,
    notified: Condvar,
}

impl CountingWake {
    fn generation(&self) -> usize {
        *self
            .generation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn wait_for_wake_after(&self, observed: usize) -> bool {
        let generation = self
            .generation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (generation, _) = self
            .notified
            .wait_timeout_while(generation, MAX_DRIVER_WAKE_WAIT, |value| *value <= observed)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *generation > observed
    }
}

impl Wake for CountingWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let mut wakes = self
            .generation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *wakes = wakes.saturating_add(1);
        self.notified.notify_one();
    }
}

struct ScriptedControl {
    state: Mutex<ScriptedState>,
    directives: Box<[CheckpointDirectiveV1]>,
    budget: OperationBudget,
}

struct ScriptedState {
    clock: VirtualClock,
    consumed: usize,
    exhausted: bool,
}

impl ScriptedControl {
    fn new(clock: VirtualClock, budget: OperationBudget, control: &OperationControlV1) -> Self {
        Self {
            state: Mutex::new(ScriptedState {
                clock,
                consumed: 0,
                exhausted: false,
            }),
            directives: control.checkpoints.clone(),
            budget,
        }
    }

    fn finish(&self, step: u16) -> Result<VirtualClock, RunErrorV1> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.exhausted || state.consumed != self.directives.len() {
            return Err(run_error(
                RunErrorCategoryV1::InvalidCheckpointScript,
                Some(step),
            ));
        }
        Ok(state.clock)
    }
}

impl DispatchControl for ScriptedControl {
    fn monotonic_now(&self) -> Instant {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clock
            .monotonic
    }

    fn wall_now_unix_seconds(&self) -> Option<u64> {
        Some(
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clock
                .wall,
        )
    }

    fn is_cancelled(&self) -> bool {
        false
    }

    fn checkpoint(&self, budget: OperationBudget) -> Result<DispatchObservation, TransportFailure> {
        if budget != self.budget {
            return Err(TransportFailure::new(
                TransportFailureCode::PolicyViolation,
                RetryAdvice::Never,
            ));
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(directive) = self.directives.get(state.consumed).copied() else {
            state.exhausted = true;
            return Err(TransportFailure::new(
                TransportFailureCode::Cancelled,
                RetryAdvice::Never,
            ));
        };
        state.consumed += 1;
        match directive {
            CheckpointDirectiveV1::Live {
                monotonic_advance_ms,
                wall_advance_seconds,
            } => {
                state.clock.monotonic = state
                    .clock
                    .monotonic
                    .checked_add(Duration::from_millis(u64::from(monotonic_advance_ms)))
                    .ok_or_else(|| {
                        TransportFailure::new(TransportFailureCode::Internal, RetryAdvice::Never)
                    })?;
                state.clock.wall =
                    add_signed(state.clock.wall, wall_advance_seconds).ok_or_else(|| {
                        TransportFailure::new(TransportFailureCode::Internal, RetryAdvice::Never)
                    })?;
                if state.clock.monotonic >= budget.deadline() {
                    return Err(TransportFailure::new(
                        TransportFailureCode::DeadlineExceeded,
                        RetryAdvice::Never,
                    ));
                }
                Ok(DispatchObservation::new(
                    state.clock.monotonic,
                    state.clock.wall,
                ))
            }
            CheckpointDirectiveV1::Cancelled => Err(TransportFailure::new(
                TransportFailureCode::Cancelled,
                RetryAdvice::Never,
            )),
            CheckpointDirectiveV1::DeadlineReached => {
                state.clock.monotonic = budget.deadline();
                Err(TransportFailure::new(
                    TransportFailureCode::DeadlineExceeded,
                    RetryAdvice::Never,
                ))
            }
            CheckpointDirectiveV1::WallUnavailable => Err(TransportFailure::new(
                TransportFailureCode::Internal,
                RetryAdvice::Never,
            )),
        }
    }
}

fn add_signed(value: u64, delta: i32) -> Option<u64> {
    if delta >= 0 {
        value.checked_add(u64::from(delta.unsigned_abs()))
    } else {
        value.checked_sub(u64::from(delta.unsigned_abs()))
    }
}

const fn run_error(category: RunErrorCategoryV1, step: Option<u16>) -> RunErrorV1 {
    RunErrorV1 { category, step }
}

#[cfg(test)]
mod tests {
    use super::*;
    use session_transport::BoundedRetryDelay;

    const NOW: u64 = 1_700_000_000;

    fn generated(alias: u8) -> GeneratedEnvelope {
        let opaque =
            OpaqueEnvelope::new([alias; 16], NOW + 120, vec![alias; 32]).expect("bounded envelope");
        let canonical_bytes = opaque
            .encode_canonical()
            .expect("canonical envelope")
            .into_boxed_slice();
        GeneratedEnvelope {
            opaque,
            canonical_bytes,
        }
    }

    fn batch(delivery_id: DeliveryId, envelope: &GeneratedEnvelope) -> ReceiveBatch {
        let now = Instant::now();
        let request = PollRequest::new(
            None,
            4,
            4_096,
            PollWait::immediate(),
            OperationBudget::new(now + Duration::from_secs(5), 4_096, 1).expect("bounded budget"),
        )
        .expect("bounded poll");
        ReceiveBatch::new(
            vec![session_transport::ReceivedCanonicalEnvelope::new(
                delivery_id,
                CanonicalEnvelope::from_opaque(envelope.opaque.clone())
                    .expect("canonical envelope"),
            )],
            None,
            &request,
            NOW,
        )
        .expect("bounded batch")
    }

    #[test]
    fn poll_normalization_rejects_foreign_mailbox_and_swapped_envelope_pairs() {
        let id = DeliveryId::from_provider_bytes([1; 16]).expect("nonzero ID");
        let envelope_one = generated(1);
        let envelope_two = generated(2);
        let envelopes = BTreeMap::from([
            (Alias(1), envelope_one.clone()),
            (Alias(2), envelope_two.clone()),
        ]);
        let deliveries = BTreeMap::from([(
            Alias(1),
            DeliveryRecord {
                id,
                mailbox: Alias(1),
                envelope: Alias(1),
            },
        )]);

        let foreign = normalize_batch(
            batch(id, &envelope_one),
            Alias(2),
            &envelopes,
            &BTreeMap::new(),
            &deliveries,
            7,
        )
        .expect_err("a known receipt cannot cross mailbox scope");
        assert_eq!(foreign.category(), RunErrorCategoryV1::UnexpectedEvent);

        let swapped = normalize_batch(
            batch(id, &envelope_two),
            Alias(1),
            &envelopes,
            &BTreeMap::new(),
            &deliveries,
            8,
        )
        .expect_err("a known receipt cannot be paired with another known envelope");
        assert_eq!(swapped.category(), RunErrorCategoryV1::UnexpectedEvent);
    }

    #[test]
    fn receipt_alias_binding_rejects_changed_or_duplicated_provider_ids() {
        let first = DeliveryId::from_provider_bytes([1; 16]).expect("nonzero ID");
        let changed = DeliveryId::from_provider_bytes([2; 16]).expect("nonzero ID");
        let mut deliveries = BTreeMap::new();

        record_deposit_receipt(&mut deliveries, Alias(1), first, Alias(1), Alias(1), 1)
            .expect("first receipt introduces the alias");
        record_deposit_receipt(&mut deliveries, Alias(1), first, Alias(1), Alias(1), 2)
            .expect("exact retry reuses the same binding");

        assert_eq!(
            record_deposit_receipt(&mut deliveries, Alias(1), changed, Alias(1), Alias(1), 3,)
                .expect_err("changed receipt breaks exact retry")
                .category(),
            RunErrorCategoryV1::UnexpectedEvent
        );
        assert_eq!(
            record_deposit_receipt(&mut deliveries, Alias(2), first, Alias(1), Alias(1), 4,)
                .expect_err("one provider receipt cannot mint another alias")
                .category(),
            RunErrorCategoryV1::UnexpectedEvent
        );
    }

    #[test]
    fn poll_once_drop_requires_pending_work_to_arrange_a_wake() {
        let never_wakes = std::future::poll_fn(|_| Poll::<()>::Pending);
        let Err(failure) = drive(never_wakes, DriveModeV1::PollOnceThenDrop, 9) else {
            panic!("a never-waking operation exceeds the harness wake bound");
        };
        assert_eq!(failure.category(), RunErrorCategoryV1::PendingWithoutWake);

        let wakes = std::future::poll_fn(|context| {
            context.waker().wake_by_ref();
            Poll::<()>::Pending
        });
        assert!(matches!(
            drive(wakes, DriveModeV1::PollOnceThenDrop, 10).expect("waking future may be dropped"),
            Driven::Dropped
        ));
    }

    #[test]
    fn poll_once_drop_accepts_a_wake_after_poll_returns() {
        let spawned = Arc::new(Mutex::new(false));
        let delayed = std::future::poll_fn({
            let spawned = Arc::clone(&spawned);
            move |context| {
                let mut spawned = spawned
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if !*spawned {
                    *spawned = true;
                    let waker = context.waker().clone();
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_millis(10));
                        waker.wake();
                    });
                }
                Poll::<()>::Pending
            }
        });

        assert!(matches!(
            drive(delayed, DriveModeV1::PollOnceThenDrop, 11)
                .expect("a delayed legal wake may be observed before drop"),
            Driven::Dropped
        ));
    }

    #[test]
    fn retry_normalization_preserves_every_bounded_nanosecond() {
        let cases = [
            Duration::from_nanos(1),
            Duration::from_millis(500),
            Duration::from_millis(1_100),
            Duration::from_millis(1_900),
            Duration::from_secs(3_600),
        ];

        for delay in cases {
            let failure = TransportFailure::new(
                TransportFailureCode::Unavailable,
                RetryAdvice::After(BoundedRetryDelay::new(delay).expect("bounded retry delay")),
            );
            let normalized = normalize_failure(failure, 12).expect("supported failure");
            let NormalizedEvent::Failed { retry, .. } = normalized else {
                panic!("transport failure must normalize as a failed event");
            };
            assert_eq!(retry.as_ref(), format!("after-ns:{}", delay.as_nanos()));
        }
    }
}
