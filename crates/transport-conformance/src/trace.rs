use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use session_protocol::MAX_ENVELOPE_CIPHERTEXT_BYTES;
use session_transport::{
    MAX_ACKNOWLEDGEMENT_IDS, MAX_CURSOR_BYTES, MAX_POLL_ENCODED_BYTES, MAX_POLL_ENVELOPES,
    TransportProfileId,
};

mod runner;

pub use runner::{
    AcknowledgementLossFaultV1, AdapterControlErrorV1, AdapterSnapshotV1, AdverseTraceAdapterV1,
    AvailabilityFaultV1, ConformanceFuture, DepositFaultV1, RunErrorCategoryV1, RunErrorV1,
    RunReportV1, run_adverse_trace_twice_v1,
};

pub const MAX_TRACE_BYTES: usize = 64 * 1024;
pub const MAX_TRACE_LINE_BYTES: usize = 512;
pub const MAX_TRACE_STEPS: usize = 256;
const MAX_TRACE_ALIASES: u8 = 64;
const MAX_CHECKPOINTS: usize = 8;
const MAX_DEADLINE_OFFSET_MILLISECONDS: u32 = 120_000;
const MAX_CLOCK_ADVANCE_MILLISECONDS: u32 = 24 * 60 * 60 * 1_000;
const MAX_WALL_ADVANCE_SECONDS: i32 = 24 * 60 * 60;
const MAX_RETRY_DELAY_NANOSECONDS: u64 = 3_600_000_000_000;
const HEADER: &str = "session-chat.transport.adverse-trace/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceErrorCategory {
    TraceTooLarge,
    LineTooLarge,
    UnsupportedVersion,
    NonCanonical,
    UnknownRecord,
    InvalidRecord,
    InvalidValue,
    DuplicateAlias,
    ForwardReference,
    NonContiguousStep,
    TooManySteps,
    TooManyCheckpoints,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceError {
    category: TraceErrorCategory,
    line: Option<u16>,
}

impl TraceError {
    #[must_use]
    pub const fn category(self) -> TraceErrorCategory {
        self.category
    }

    #[must_use]
    pub const fn line(self) -> Option<u16> {
        self.line
    }
}

impl fmt::Display for TraceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("transport conformance trace rejected")
    }
}

impl std::error::Error for TraceError {}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Alias(u8);

impl Alias {
    fn parse(value: &str, line: u16) -> Result<Self, TraceError> {
        let value = parse_u8(value, line)?;
        if value == 0 || value > MAX_TRACE_ALIASES {
            return Err(error(TraceErrorCategory::InvalidValue, line));
        }
        Ok(Self(value))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopeFixtureV1 {
    alias: Alias,
    logical_id_alias: Alias,
    content_variant: Alias,
    ciphertext_len: u32,
    expiry_offset_seconds: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CursorFixtureV1 {
    alias: Alias,
    content_variant: Alias,
    encoded_len: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DepositOutcomeV1 {
    Deliver,
    Drop,
    Hold,
    Duplicate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AvailabilityV1 {
    Available,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AcknowledgementLossV1 {
    BeforeCommit,
    AfterCommit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DriveModeV1 {
    RunToReady,
    PollOnceThenDrop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CheckpointDirectiveV1 {
    Live {
        monotonic_advance_ms: u32,
        wall_advance_seconds: i32,
    },
    Cancelled,
    DeadlineReached,
    WallUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OperationControlV1 {
    checkpoints: Box<[CheckpointDirectiveV1]>,
    drive: DriveModeV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OperationBudgetV1 {
    deadline_offset_ms: u32,
    max_encoded_bytes: u32,
    max_attempts: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TraceActionV1 {
    OpenMailbox {
        mailbox: Alias,
        lifetime_seconds: u32,
    },
    ArmDeposit(DepositOutcomeV1),
    ReleaseHeld(u16),
    ReplayStale(Alias),
    CorruptNextPoll(Alias),
    SetAvailability(AvailabilityV1),
    LoseNextAcknowledgement(AcknowledgementLossV1),
    AdvanceClock {
        monotonic_ms: u32,
        wall_seconds: i32,
    },
    Deposit {
        mailbox: Alias,
        envelope: Alias,
        budget: OperationBudgetV1,
        control: OperationControlV1,
    },
    Poll {
        mailbox: Alias,
        cursor: Option<Alias>,
        max_envelopes: u16,
        max_encoded_bytes: u32,
        wait_ms: u32,
        budget: OperationBudgetV1,
        control: OperationControlV1,
    },
    Acknowledge {
        mailbox: Alias,
        deliveries: Box<[Alias]>,
        budget: OperationBudgetV1,
        control: OperationControlV1,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ExpectedEventV1 {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceStepV1 {
    index: u16,
    action: TraceActionV1,
    expected: ExpectedEventV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdverseTraceV1 {
    profile: TransportProfileId,
    wall_start_unix_seconds: u64,
    envelopes: Box<[EnvelopeFixtureV1]>,
    cursors: Box<[CursorFixtureV1]>,
    steps: Box<[TraceStepV1]>,
}

impl AdverseTraceV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, TraceError> {
        if bytes.len() > MAX_TRACE_BYTES {
            return Err(TraceError {
                category: TraceErrorCategory::TraceTooLarge,
                line: None,
            });
        }
        if bytes.is_empty() || !bytes.ends_with(b"\n") || bytes.contains(&b'\r') {
            return Err(TraceError {
                category: TraceErrorCategory::NonCanonical,
                line: None,
            });
        }
        let text = std::str::from_utf8(bytes).map_err(|_| TraceError {
            category: TraceErrorCategory::NonCanonical,
            line: None,
        })?;
        let lines: Vec<&str> = text
            .strip_suffix('\n')
            .expect("checked suffix")
            .split('\n')
            .collect();
        for (index, line) in lines.iter().enumerate() {
            let line_number = line_number(index)?;
            if line.len() > MAX_TRACE_LINE_BYTES {
                return Err(error(TraceErrorCategory::LineTooLarge, line_number));
            }
            if line.is_empty() || !line.bytes().all(is_canonical_trace_byte) {
                return Err(error(TraceErrorCategory::NonCanonical, line_number));
            }
        }
        if lines.first().copied() != Some(HEADER) {
            return Err(error(TraceErrorCategory::UnsupportedVersion, 1));
        }
        let profile_line = lines
            .get(1)
            .ok_or_else(|| error(TraceErrorCategory::InvalidRecord, 2))?;
        let profile = parse_profile(profile_line, 2)?;
        let wall_line = lines
            .get(2)
            .ok_or_else(|| error(TraceErrorCategory::InvalidRecord, 3))?;
        let wall_start_unix_seconds = parse_wall_start(wall_line, 3)?;

        let mut envelopes = Vec::new();
        let mut cursors = Vec::new();
        let mut steps = Vec::new();
        let mut envelope_aliases = BTreeSet::new();
        let mut cursor_aliases = BTreeSet::new();
        let mut mailbox_aliases = BTreeSet::new();
        let mut delivery_aliases = BTreeSet::new();
        let mut delivery_bindings = BTreeMap::new();
        let mut deposit_bindings = BTreeMap::new();
        let mut saw_step = false;

        for (index, line) in lines.iter().enumerate().skip(3) {
            let line_number = line_number(index)?;
            let fields: Vec<&str> = line.split('|').collect();
            match fields.first().copied() {
                Some("envelope") if !saw_step => {
                    let fixture = parse_envelope(&fields, line_number)?;
                    if !envelope_aliases.insert(fixture.alias) {
                        return Err(error(TraceErrorCategory::DuplicateAlias, line_number));
                    }
                    envelopes.push(fixture);
                }
                Some("cursor") if !saw_step => {
                    let fixture = parse_cursor(&fields, line_number)?;
                    if !cursor_aliases.insert(fixture.alias) {
                        return Err(error(TraceErrorCategory::DuplicateAlias, line_number));
                    }
                    cursors.push(fixture);
                }
                Some("step") => {
                    saw_step = true;
                    if steps.len() >= MAX_TRACE_STEPS {
                        return Err(error(TraceErrorCategory::TooManySteps, line_number));
                    }
                    let expected_index = u16::try_from(steps.len() + 1)
                        .map_err(|_| error(TraceErrorCategory::TooManySteps, line_number))?;
                    let step = parse_step(
                        &fields,
                        line_number,
                        expected_index,
                        &envelope_aliases,
                        &cursor_aliases,
                        &mut mailbox_aliases,
                        &mut delivery_aliases,
                        &mut delivery_bindings,
                        &mut deposit_bindings,
                    )?;
                    steps.push(step);
                }
                Some("envelope" | "cursor") => {
                    return Err(error(TraceErrorCategory::NonCanonical, line_number));
                }
                _ => return Err(error(TraceErrorCategory::UnknownRecord, line_number)),
            }
        }
        if steps.is_empty() {
            return Err(error(TraceErrorCategory::InvalidRecord, 3));
        }
        let trace = Self {
            profile,
            wall_start_unix_seconds,
            envelopes: envelopes.into_boxed_slice(),
            cursors: cursors.into_boxed_slice(),
            steps: steps.into_boxed_slice(),
        };
        if trace.encode_canonical() != bytes {
            return Err(TraceError {
                category: TraceErrorCategory::NonCanonical,
                line: None,
            });
        }
        Ok(trace)
    }

    #[must_use]
    pub const fn profile(&self) -> TransportProfileId {
        self.profile
    }

    #[must_use]
    pub const fn wall_start_unix_seconds(&self) -> u64 {
        self.wall_start_unix_seconds
    }

    #[must_use]
    pub fn envelopes(&self) -> &[EnvelopeFixtureV1] {
        &self.envelopes
    }

    #[must_use]
    pub fn cursors(&self) -> &[CursorFixtureV1] {
        &self.cursors
    }

    #[must_use]
    pub fn steps(&self) -> &[TraceStepV1] {
        &self.steps
    }

    #[must_use]
    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut output = String::new();
        output.push_str(HEADER);
        output.push('\n');
        output.push_str("profile|");
        output.push_str(profile_token(self.profile));
        output.push('\n');
        output.push_str("wall-start|");
        output.push_str(&self.wall_start_unix_seconds.to_string());
        output.push('\n');
        for fixture in &self.envelopes {
            output.push_str(&format!(
                "envelope|{}|{}|{}|{}|{}\n",
                fixture.alias.0,
                fixture.logical_id_alias.0,
                fixture.content_variant.0,
                fixture.ciphertext_len,
                fixture.expiry_offset_seconds
            ));
        }
        for fixture in &self.cursors {
            output.push_str(&format!(
                "cursor|{}|{}|{}\n",
                fixture.alias.0, fixture.content_variant.0, fixture.encoded_len
            ));
        }
        for step in &self.steps {
            encode_step(step, &mut output);
        }
        output.into_bytes()
    }
}

fn parse_profile(line: &str, line_number: u16) -> Result<TransportProfileId, TraceError> {
    let fields: Vec<&str> = line.split('|').collect();
    if fields.len() != 2 || fields[0] != "profile" {
        return Err(error(TraceErrorCategory::InvalidRecord, line_number));
    }
    match fields[1] {
        "local" => Ok(TransportProfileId::LocalV1),
        "fast" => Ok(TransportProfileId::FastV1),
        "private-interactive" => Ok(TransportProfileId::PrivateInteractiveV1),
        "private-mixnet" => Ok(TransportProfileId::PrivateMixnetV1),
        "off-grid" => Ok(TransportProfileId::OffGridV1),
        _ => Err(error(TraceErrorCategory::InvalidValue, line_number)),
    }
}

fn profile_token(profile: TransportProfileId) -> &'static str {
    match profile {
        TransportProfileId::LocalV1 => "local",
        TransportProfileId::FastV1 => "fast",
        TransportProfileId::PrivateInteractiveV1 => "private-interactive",
        TransportProfileId::PrivateMixnetV1 => "private-mixnet",
        TransportProfileId::OffGridV1 => "off-grid",
    }
}

fn parse_wall_start(line: &str, line_number: u16) -> Result<u64, TraceError> {
    let fields: Vec<&str> = line.split('|').collect();
    if fields.len() != 2 || fields[0] != "wall-start" {
        return Err(error(TraceErrorCategory::InvalidRecord, line_number));
    }
    parse_u64(fields[1], line_number)
}

fn parse_envelope(fields: &[&str], line: u16) -> Result<EnvelopeFixtureV1, TraceError> {
    if fields.len() != 6 {
        return Err(error(TraceErrorCategory::InvalidRecord, line));
    }
    let ciphertext_len = parse_u32(fields[4], line)?;
    let expiry_offset_seconds = parse_u32(fields[5], line)?;
    if ciphertext_len == 0
        || usize::try_from(ciphertext_len)
            .map_or(true, |length| length > MAX_ENVELOPE_CIPHERTEXT_BYTES)
        || expiry_offset_seconds == 0
        || expiry_offset_seconds > u32::try_from(MAX_WALL_ADVANCE_SECONDS).expect("positive bound")
    {
        return Err(error(TraceErrorCategory::InvalidValue, line));
    }
    Ok(EnvelopeFixtureV1 {
        alias: Alias::parse(fields[1], line)?,
        logical_id_alias: Alias::parse(fields[2], line)?,
        content_variant: Alias::parse(fields[3], line)?,
        ciphertext_len,
        expiry_offset_seconds,
    })
}

fn parse_cursor(fields: &[&str], line: u16) -> Result<CursorFixtureV1, TraceError> {
    if fields.len() != 4 {
        return Err(error(TraceErrorCategory::InvalidRecord, line));
    }
    let encoded_len = parse_u16(fields[3], line)?;
    if encoded_len == 0 || usize::from(encoded_len) > MAX_CURSOR_BYTES {
        return Err(error(TraceErrorCategory::InvalidValue, line));
    }
    Ok(CursorFixtureV1 {
        alias: Alias::parse(fields[1], line)?,
        content_variant: Alias::parse(fields[2], line)?,
        encoded_len,
    })
}

#[allow(clippy::too_many_arguments)]
fn parse_step(
    fields: &[&str],
    line: u16,
    expected_index: u16,
    envelope_aliases: &BTreeSet<Alias>,
    cursor_aliases: &BTreeSet<Alias>,
    mailbox_aliases: &mut BTreeSet<Alias>,
    delivery_aliases: &mut BTreeSet<Alias>,
    delivery_bindings: &mut BTreeMap<Alias, (Alias, Alias)>,
    deposit_bindings: &mut BTreeMap<(Alias, Alias), Alias>,
) -> Result<TraceStepV1, TraceError> {
    if fields.len() < 6 {
        return Err(error(TraceErrorCategory::InvalidRecord, line));
    }
    let index = parse_u16(fields[1], line)?;
    if index != expected_index {
        return Err(error(TraceErrorCategory::NonContiguousStep, line));
    }
    let expect_at = fields
        .iter()
        .position(|field| *field == "expect")
        .ok_or_else(|| error(TraceErrorCategory::InvalidRecord, line))?;
    if expect_at < 3 || expect_at + 1 >= fields.len() {
        return Err(error(TraceErrorCategory::InvalidRecord, line));
    }
    let action = parse_action(
        &fields[2..expect_at],
        line,
        envelope_aliases,
        cursor_aliases,
        mailbox_aliases,
        delivery_aliases,
    )?;
    let expected = parse_expected(&fields[expect_at + 1..], line)?;
    validate_references_and_introductions(
        &action,
        &expected,
        line,
        envelope_aliases,
        cursor_aliases,
        mailbox_aliases,
        delivery_aliases,
        delivery_bindings,
        deposit_bindings,
    )?;
    Ok(TraceStepV1 {
        index,
        action,
        expected,
    })
}

fn parse_action(
    fields: &[&str],
    line: u16,
    envelope_aliases: &BTreeSet<Alias>,
    cursor_aliases: &BTreeSet<Alias>,
    mailbox_aliases: &BTreeSet<Alias>,
    delivery_aliases: &BTreeSet<Alias>,
) -> Result<TraceActionV1, TraceError> {
    match fields.first().copied() {
        Some("open-mailbox") if fields.len() == 3 => Ok(TraceActionV1::OpenMailbox {
            mailbox: Alias::parse(fields[1], line)?,
            lifetime_seconds: bounded_positive_u32(
                fields[2],
                MAX_WALL_ADVANCE_SECONDS as u32,
                line,
            )?,
        }),
        Some("arm-deposit") if fields.len() == 2 => {
            Ok(TraceActionV1::ArmDeposit(match fields[1] {
                "deliver" => DepositOutcomeV1::Deliver,
                "drop" => DepositOutcomeV1::Drop,
                "hold" => DepositOutcomeV1::Hold,
                "duplicate" => DepositOutcomeV1::Duplicate,
                _ => return Err(error(TraceErrorCategory::InvalidValue, line)),
            }))
        }
        Some("release-held") if fields.len() == 2 => {
            Ok(TraceActionV1::ReleaseHeld(parse_u16(fields[1], line)?))
        }
        Some("replay-stale") if fields.len() == 2 => Ok(TraceActionV1::ReplayStale(known_alias(
            fields[1],
            delivery_aliases,
            line,
        )?)),
        Some("corrupt-next-poll") if fields.len() == 2 => Ok(TraceActionV1::CorruptNextPoll(
            known_alias(fields[1], delivery_aliases, line)?,
        )),
        Some("set-availability") if fields.len() == 2 => {
            Ok(TraceActionV1::SetAvailability(match fields[1] {
                "available" => AvailabilityV1::Available,
                "unavailable" => AvailabilityV1::Unavailable,
                _ => return Err(error(TraceErrorCategory::InvalidValue, line)),
            }))
        }
        Some("lose-next-ack") if fields.len() == 2 => {
            Ok(TraceActionV1::LoseNextAcknowledgement(match fields[1] {
                "before-commit" => AcknowledgementLossV1::BeforeCommit,
                "after-commit" => AcknowledgementLossV1::AfterCommit,
                _ => return Err(error(TraceErrorCategory::InvalidValue, line)),
            }))
        }
        Some("advance-clock") if fields.len() == 3 => {
            let monotonic_ms = parse_u32(fields[1], line)?;
            let wall_seconds = parse_i32(fields[2], line)?;
            if monotonic_ms > MAX_CLOCK_ADVANCE_MILLISECONDS
                || wall_seconds.unsigned_abs() > MAX_WALL_ADVANCE_SECONDS as u32
            {
                return Err(error(TraceErrorCategory::InvalidValue, line));
            }
            Ok(TraceActionV1::AdvanceClock {
                monotonic_ms,
                wall_seconds,
            })
        }
        Some("deposit") if fields.len() == 8 => {
            let mailbox = known_alias(fields[1], mailbox_aliases, line)?;
            let envelope = known_alias(fields[2], envelope_aliases, line)?;
            Ok(TraceActionV1::Deposit {
                mailbox,
                envelope,
                budget: parse_budget(&fields[3..6], line)?,
                control: parse_control(fields[6], fields[7], line)?,
            })
        }
        Some("poll") if fields.len() == 11 => {
            let mailbox = known_alias(fields[1], mailbox_aliases, line)?;
            let cursor = parse_optional_known_alias(fields[2], cursor_aliases, line)?;
            let max_envelopes = parse_u16(fields[3], line)?;
            let max_encoded_bytes = parse_u32(fields[4], line)?;
            let wait_ms = parse_u32(fields[5], line)?;
            let budget = parse_budget(&fields[6..9], line)?;
            if max_envelopes == 0
                || max_envelopes > MAX_POLL_ENVELOPES
                || max_encoded_bytes == 0
                || max_encoded_bytes > MAX_POLL_ENCODED_BYTES
                || max_encoded_bytes > budget.max_encoded_bytes
                || (wait_ms != 0 && wait_ms < 1_000)
                || wait_ms > 60_000
            {
                return Err(error(TraceErrorCategory::InvalidValue, line));
            }
            Ok(TraceActionV1::Poll {
                mailbox,
                cursor,
                max_envelopes,
                max_encoded_bytes,
                wait_ms,
                budget,
                control: parse_control(fields[9], fields[10], line)?,
            })
        }
        Some("ack") if fields.len() == 8 => {
            let mailbox = known_alias(fields[1], mailbox_aliases, line)?;
            let deliveries = parse_alias_list(fields[2], delivery_aliases, line)?;
            Ok(TraceActionV1::Acknowledge {
                mailbox,
                deliveries,
                budget: parse_budget(&fields[3..6], line)?,
                control: parse_control(fields[6], fields[7], line)?,
            })
        }
        Some(_) => Err(error(TraceErrorCategory::InvalidRecord, line)),
        None => Err(error(TraceErrorCategory::InvalidRecord, line)),
    }
}

fn parse_expected(fields: &[&str], line: u16) -> Result<ExpectedEventV1, TraceError> {
    match fields.first().copied() {
        Some("mailbox-opened") if fields.len() == 2 => Ok(ExpectedEventV1::MailboxOpened(
            Alias::parse(fields[1], line)?,
        )),
        Some("fault-applied") if fields.len() == 1 => Ok(ExpectedEventV1::FaultApplied),
        Some("deposit-accepted") if fields.len() == 2 => Ok(ExpectedEventV1::DepositAccepted(
            Alias::parse(fields[1], line)?,
        )),
        Some("poll-accepted") if fields.len() == 3 => Ok(ExpectedEventV1::PollAccepted {
            items: parse_item_list(fields[1], line)?,
            cursor: parse_optional_alias(fields[2], line)?,
        }),
        Some("ack-accepted") if fields.len() == 1 => Ok(ExpectedEventV1::AcknowledgementAccepted),
        Some("failed") if fields.len() == 3 => {
            validate_failure_code(fields[1], line)?;
            validate_retry(fields[2], line)?;
            Ok(ExpectedEventV1::Failed {
                code: fields[1].into(),
                retry: fields[2].into(),
            })
        }
        Some("future-dropped") if fields.len() == 1 => Ok(ExpectedEventV1::FutureDropped),
        Some("quiescent") if fields.len() == 1 => Ok(ExpectedEventV1::Quiescent),
        _ => Err(error(TraceErrorCategory::InvalidRecord, line)),
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_references_and_introductions(
    action: &TraceActionV1,
    expected: &ExpectedEventV1,
    line: u16,
    envelope_aliases: &BTreeSet<Alias>,
    cursor_aliases: &BTreeSet<Alias>,
    mailbox_aliases: &mut BTreeSet<Alias>,
    delivery_aliases: &mut BTreeSet<Alias>,
    delivery_bindings: &mut BTreeMap<Alias, (Alias, Alias)>,
    deposit_bindings: &mut BTreeMap<(Alias, Alias), Alias>,
) -> Result<(), TraceError> {
    if let TraceActionV1::OpenMailbox { mailbox, .. } = action {
        if !matches!(expected, ExpectedEventV1::MailboxOpened(alias) if alias == mailbox) {
            return Err(error(TraceErrorCategory::InvalidRecord, line));
        }
        if !mailbox_aliases.insert(*mailbox) {
            return Err(error(TraceErrorCategory::DuplicateAlias, line));
        }
    }
    if let TraceActionV1::Deposit {
        mailbox, envelope, ..
    } = action
        && let ExpectedEventV1::DepositAccepted(delivery) = expected
    {
        let binding = (*mailbox, *envelope);
        if delivery_bindings
            .get(delivery)
            .is_some_and(|existing| *existing != binding)
            || deposit_bindings
                .get(&binding)
                .is_some_and(|existing| existing != delivery)
        {
            return Err(error(TraceErrorCategory::InvalidRecord, line));
        }
        delivery_aliases.insert(*delivery);
        delivery_bindings.insert(*delivery, binding);
        deposit_bindings.insert(binding, *delivery);
    }
    if let ExpectedEventV1::PollAccepted { items, cursor } = expected {
        for (delivery, envelope) in items {
            if !delivery_aliases.contains(delivery) || !envelope_aliases.contains(envelope) {
                return Err(error(TraceErrorCategory::ForwardReference, line));
            }
        }
        if cursor.is_some_and(|alias| !cursor_aliases.contains(&alias)) {
            return Err(error(TraceErrorCategory::ForwardReference, line));
        }
    }
    Ok(())
}

fn parse_budget(fields: &[&str], line: u16) -> Result<OperationBudgetV1, TraceError> {
    if fields.len() != 3 {
        return Err(error(TraceErrorCategory::InvalidRecord, line));
    }
    let deadline_offset_ms =
        bounded_positive_u32(fields[0], MAX_DEADLINE_OFFSET_MILLISECONDS, line)?;
    let max_encoded_bytes = bounded_positive_u32(fields[1], MAX_POLL_ENCODED_BYTES, line)?;
    let max_attempts = parse_u16(fields[2], line)?;
    if max_attempts == 0 || max_attempts > 64 {
        return Err(error(TraceErrorCategory::InvalidValue, line));
    }
    Ok(OperationBudgetV1 {
        deadline_offset_ms,
        max_encoded_bytes,
        max_attempts,
    })
}

fn parse_control(script: &str, drive: &str, line: u16) -> Result<OperationControlV1, TraceError> {
    let directives: Vec<&str> = script.split(';').collect();
    if directives.is_empty() || directives.len() > MAX_CHECKPOINTS {
        return Err(error(TraceErrorCategory::TooManyCheckpoints, line));
    }
    let mut checkpoints = Vec::with_capacity(directives.len());
    for directive in directives {
        let parts: Vec<&str> = directive.split(':').collect();
        checkpoints.push(match parts.as_slice() {
            ["live", monotonic, wall] => {
                let monotonic_advance_ms = parse_u32(monotonic, line)?;
                let wall_advance_seconds = parse_i32(wall, line)?;
                if monotonic_advance_ms > MAX_DEADLINE_OFFSET_MILLISECONDS
                    || wall_advance_seconds.unsigned_abs() > MAX_WALL_ADVANCE_SECONDS as u32
                {
                    return Err(error(TraceErrorCategory::InvalidValue, line));
                }
                CheckpointDirectiveV1::Live {
                    monotonic_advance_ms,
                    wall_advance_seconds,
                }
            }
            ["cancelled"] => CheckpointDirectiveV1::Cancelled,
            ["deadline"] => CheckpointDirectiveV1::DeadlineReached,
            ["wall-unavailable"] => CheckpointDirectiveV1::WallUnavailable,
            _ => return Err(error(TraceErrorCategory::InvalidRecord, line)),
        });
    }
    let drive = match drive {
        "ready" => DriveModeV1::RunToReady,
        "poll-once-drop" => DriveModeV1::PollOnceThenDrop,
        _ => return Err(error(TraceErrorCategory::InvalidValue, line)),
    };
    Ok(OperationControlV1 {
        checkpoints: checkpoints.into_boxed_slice(),
        drive,
    })
}

fn parse_alias_list(
    value: &str,
    known: &BTreeSet<Alias>,
    line: u16,
) -> Result<Box<[Alias]>, TraceError> {
    let values: Vec<&str> = value.split(',').collect();
    if values.is_empty() || values.len() > usize::from(MAX_ACKNOWLEDGEMENT_IDS) {
        return Err(error(TraceErrorCategory::InvalidValue, line));
    }
    let mut aliases = Vec::with_capacity(values.len());
    for value in values {
        let alias = known_alias(value, known, line)?;
        if aliases.contains(&alias) {
            return Err(error(TraceErrorCategory::DuplicateAlias, line));
        }
        aliases.push(alias);
    }
    Ok(aliases.into_boxed_slice())
}

fn parse_item_list(value: &str, line: u16) -> Result<Box<[(Alias, Alias)]>, TraceError> {
    if value == "none" {
        return Ok(Box::new([]));
    }
    let values: Vec<&str> = value.split(',').collect();
    if values.len() > usize::from(MAX_POLL_ENVELOPES) {
        return Err(error(TraceErrorCategory::InvalidValue, line));
    }
    let mut items = Vec::with_capacity(values.len());
    for value in values {
        let pair: Vec<&str> = value.split(':').collect();
        if pair.len() != 2 {
            return Err(error(TraceErrorCategory::InvalidRecord, line));
        }
        items.push((Alias::parse(pair[0], line)?, Alias::parse(pair[1], line)?));
    }
    Ok(items.into_boxed_slice())
}

fn parse_optional_alias(value: &str, line: u16) -> Result<Option<Alias>, TraceError> {
    if value == "none" {
        Ok(None)
    } else {
        Alias::parse(value, line).map(Some)
    }
}

fn parse_optional_known_alias(
    value: &str,
    known: &BTreeSet<Alias>,
    line: u16,
) -> Result<Option<Alias>, TraceError> {
    parse_optional_alias(value, line)?.map_or(Ok(None), |alias| {
        if known.contains(&alias) {
            Ok(Some(alias))
        } else {
            Err(error(TraceErrorCategory::ForwardReference, line))
        }
    })
}

fn known_alias(value: &str, known: &BTreeSet<Alias>, line: u16) -> Result<Alias, TraceError> {
    let alias = Alias::parse(value, line)?;
    if !known.contains(&alias) {
        return Err(error(TraceErrorCategory::ForwardReference, line));
    }
    Ok(alias)
}

fn validate_failure_code(value: &str, line: u16) -> Result<(), TraceError> {
    if matches!(
        value,
        "invalid-authority"
            | "authority-scope-mismatch"
            | "expired-envelope"
            | "envelope-too-large"
            | "idempotency-conflict"
            | "invalid-cursor"
            | "queue-full"
            | "rate-limited"
            | "unavailable"
            | "deadline-exceeded"
            | "cancelled"
            | "corrupt-remote-response"
            | "policy-violation"
            | "misconfigured"
            | "internal"
    ) {
        Ok(())
    } else {
        Err(error(TraceErrorCategory::InvalidValue, line))
    }
}

fn validate_retry(value: &str, line: u16) -> Result<(), TraceError> {
    if matches!(value, "never" | "backoff") {
        return Ok(());
    }
    if let Some(nanoseconds) = value.strip_prefix("after-ns:") {
        let nanoseconds = parse_u64(nanoseconds, line)?;
        if (1..=MAX_RETRY_DELAY_NANOSECONDS).contains(&nanoseconds) {
            return Ok(());
        }
    }
    Err(error(TraceErrorCategory::InvalidValue, line))
}

fn encode_step(step: &TraceStepV1, output: &mut String) {
    output.push_str("step|");
    output.push_str(&step.index.to_string());
    output.push('|');
    encode_action(&step.action, output);
    output.push_str("|expect|");
    encode_expected(&step.expected, output);
    output.push('\n');
}

fn encode_action(action: &TraceActionV1, output: &mut String) {
    match action {
        TraceActionV1::OpenMailbox {
            mailbox,
            lifetime_seconds,
        } => output.push_str(&format!("open-mailbox|{}|{}", mailbox.0, lifetime_seconds)),
        TraceActionV1::ArmDeposit(outcome) => output.push_str(&format!(
            "arm-deposit|{}",
            match outcome {
                DepositOutcomeV1::Deliver => "deliver",
                DepositOutcomeV1::Drop => "drop",
                DepositOutcomeV1::Hold => "hold",
                DepositOutcomeV1::Duplicate => "duplicate",
            }
        )),
        TraceActionV1::ReleaseHeld(index) => {
            output.push_str(&format!("release-held|{index}"));
        }
        TraceActionV1::ReplayStale(delivery) => {
            output.push_str(&format!("replay-stale|{}", delivery.0));
        }
        TraceActionV1::CorruptNextPoll(delivery) => {
            output.push_str(&format!("corrupt-next-poll|{}", delivery.0));
        }
        TraceActionV1::SetAvailability(availability) => output.push_str(&format!(
            "set-availability|{}",
            match availability {
                AvailabilityV1::Available => "available",
                AvailabilityV1::Unavailable => "unavailable",
            }
        )),
        TraceActionV1::LoseNextAcknowledgement(loss) => output.push_str(&format!(
            "lose-next-ack|{}",
            match loss {
                AcknowledgementLossV1::BeforeCommit => "before-commit",
                AcknowledgementLossV1::AfterCommit => "after-commit",
            }
        )),
        TraceActionV1::AdvanceClock {
            monotonic_ms,
            wall_seconds,
        } => output.push_str(&format!("advance-clock|{monotonic_ms}|{wall_seconds}")),
        TraceActionV1::Deposit {
            mailbox,
            envelope,
            budget,
            control,
        } => {
            output.push_str(&format!("deposit|{}|{}|", mailbox.0, envelope.0));
            encode_budget(*budget, output);
            output.push('|');
            encode_control(control, output);
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
            output.push_str(&format!(
                "poll|{}|{}|{}|{}|{}|",
                mailbox.0,
                optional_alias_string(*cursor),
                max_envelopes,
                max_encoded_bytes,
                wait_ms
            ));
            encode_budget(*budget, output);
            output.push('|');
            encode_control(control, output);
        }
        TraceActionV1::Acknowledge {
            mailbox,
            deliveries,
            budget,
            control,
        } => {
            output.push_str(&format!("ack|{}|", mailbox.0));
            encode_aliases(deliveries, output);
            output.push('|');
            encode_budget(*budget, output);
            output.push('|');
            encode_control(control, output);
        }
    }
}

fn encode_budget(budget: OperationBudgetV1, output: &mut String) {
    output.push_str(&format!(
        "{}|{}|{}",
        budget.deadline_offset_ms, budget.max_encoded_bytes, budget.max_attempts
    ));
}

fn encode_control(control: &OperationControlV1, output: &mut String) {
    for (index, checkpoint) in control.checkpoints.iter().enumerate() {
        if index > 0 {
            output.push(';');
        }
        match checkpoint {
            CheckpointDirectiveV1::Live {
                monotonic_advance_ms,
                wall_advance_seconds,
            } => output.push_str(&format!(
                "live:{monotonic_advance_ms}:{wall_advance_seconds}"
            )),
            CheckpointDirectiveV1::Cancelled => output.push_str("cancelled"),
            CheckpointDirectiveV1::DeadlineReached => output.push_str("deadline"),
            CheckpointDirectiveV1::WallUnavailable => output.push_str("wall-unavailable"),
        }
    }
    output.push('|');
    output.push_str(match control.drive {
        DriveModeV1::RunToReady => "ready",
        DriveModeV1::PollOnceThenDrop => "poll-once-drop",
    });
}

fn encode_expected(expected: &ExpectedEventV1, output: &mut String) {
    match expected {
        ExpectedEventV1::MailboxOpened(mailbox) => {
            output.push_str(&format!("mailbox-opened|{}", mailbox.0));
        }
        ExpectedEventV1::FaultApplied => output.push_str("fault-applied"),
        ExpectedEventV1::DepositAccepted(delivery) => {
            output.push_str(&format!("deposit-accepted|{}", delivery.0));
        }
        ExpectedEventV1::PollAccepted { items, cursor } => {
            output.push_str("poll-accepted|");
            if items.is_empty() {
                output.push_str("none");
            } else {
                for (index, (delivery, envelope)) in items.iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    output.push_str(&format!("{}:{}", delivery.0, envelope.0));
                }
            }
            output.push('|');
            output.push_str(&optional_alias_string(*cursor));
        }
        ExpectedEventV1::AcknowledgementAccepted => output.push_str("ack-accepted"),
        ExpectedEventV1::Failed { code, retry } => {
            output.push_str(&format!("failed|{code}|{retry}"));
        }
        ExpectedEventV1::FutureDropped => output.push_str("future-dropped"),
        ExpectedEventV1::Quiescent => output.push_str("quiescent"),
    }
}

fn encode_aliases(aliases: &[Alias], output: &mut String) {
    for (index, alias) in aliases.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str(&alias.0.to_string());
    }
}

fn optional_alias_string(alias: Option<Alias>) -> String {
    match alias {
        Some(alias) => alias.0.to_string(),
        None => "none".to_owned(),
    }
}

fn bounded_positive_u32(value: &str, maximum: u32, line: u16) -> Result<u32, TraceError> {
    let value = parse_u32(value, line)?;
    if value == 0 || value > maximum {
        return Err(error(TraceErrorCategory::InvalidValue, line));
    }
    Ok(value)
}

fn parse_u8(value: &str, line: u16) -> Result<u8, TraceError> {
    parse_unsigned(value, line)
}

fn parse_u16(value: &str, line: u16) -> Result<u16, TraceError> {
    parse_unsigned(value, line)
}

fn parse_u32(value: &str, line: u16) -> Result<u32, TraceError> {
    parse_unsigned(value, line)
}

fn parse_u64(value: &str, line: u16) -> Result<u64, TraceError> {
    parse_unsigned(value, line)
}

fn parse_unsigned<T>(value: &str, line: u16) -> Result<T, TraceError>
where
    T: std::str::FromStr + ToString,
{
    let parsed = value
        .parse::<T>()
        .map_err(|_| error(TraceErrorCategory::InvalidValue, line))?;
    if parsed.to_string() != value {
        return Err(error(TraceErrorCategory::NonCanonical, line));
    }
    Ok(parsed)
}

fn parse_i32(value: &str, line: u16) -> Result<i32, TraceError> {
    let parsed = value
        .parse::<i32>()
        .map_err(|_| error(TraceErrorCategory::InvalidValue, line))?;
    if parsed.to_string() != value {
        return Err(error(TraceErrorCategory::NonCanonical, line));
    }
    Ok(parsed)
}

fn is_canonical_trace_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase()
        || byte.is_ascii_digit()
        || matches!(byte, b'.' | b'/' | b'-' | b'|' | b':' | b';' | b',')
}

fn line_number(index: usize) -> Result<u16, TraceError> {
    u16::try_from(index + 1).map_err(|_| TraceError {
        category: TraceErrorCategory::TraceTooLarge,
        line: None,
    })
}

const fn error(category: TraceErrorCategory, line: u16) -> TraceError {
    TraceError {
        category,
        line: Some(line),
    }
}
