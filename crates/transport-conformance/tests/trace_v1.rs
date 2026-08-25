use session_transport::TransportProfileId;
use transport_conformance::{
    AdverseTraceV1, MAX_TRACE_BYTES, MAX_TRACE_LINE_BYTES, MAX_TRACE_STEPS, TraceErrorCategory,
};

const GOLDEN: &[u8] = include_bytes!("fixtures/adverse-trace-v1.txt");

fn trace(records: &str) -> Vec<u8> {
    format!(
        "session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\n{records}"
    )
    .into_bytes()
}

#[test]
fn golden_v1_trace_round_trips_byte_for_byte() {
    let trace = AdverseTraceV1::parse(GOLDEN).expect("canonical trace");

    assert_eq!(trace.profile(), TransportProfileId::LocalV1);
    assert_eq!(trace.wall_start_unix_seconds(), 1_700_000_000);
    assert_eq!(trace.envelopes().len(), 2);
    assert_eq!(trace.cursors().len(), 1);
    assert_eq!(trace.steps().len(), 11);
    assert_eq!(trace.encode_canonical(), GOLDEN);
}

#[test]
fn parser_rejects_unknown_noncanonical_duplicate_and_forward_referenced_input() {
    let cases: &[(&[u8], TraceErrorCategory)] = &[
        (
            b"session-chat.transport.adverse-trace/v2\n",
            TraceErrorCategory::UnsupportedVersion,
        ),
        (
            b"session-chat.transport.adverse-trace/v1\r\n",
            TraceErrorCategory::NonCanonical,
        ),
        (
            b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\nunknown|value\n",
            TraceErrorCategory::UnknownRecord,
        ),
        (
            b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|01700000000\n",
            TraceErrorCategory::NonCanonical,
        ),
        (
            b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\nenvelope|1|1|1|32|120\nenvelope|1|2|1|32|120\n",
            TraceErrorCategory::DuplicateAlias,
        ),
        (
            b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\ncursor|1|1|8\ncursor|1|2|8\nstep|1|set-availability|available|expect|fault-applied\n",
            TraceErrorCategory::DuplicateAlias,
        ),
        (
            b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\n",
            TraceErrorCategory::InvalidRecord,
        ),
        (
            b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\nstep|1|deposit|1|1|5000|4096|1|live:0:0|ready|expect|deposit-accepted|1\n",
            TraceErrorCategory::ForwardReference,
        ),
        (
            b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\nstep|2|set-availability|available|expect|fault-applied\n",
            TraceErrorCategory::NonContiguousStep,
        ),
        (
            b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\nenvelope|1|1|1|61441|120\nstep|1|set-availability|available|expect|fault-applied\n",
            TraceErrorCategory::InvalidValue,
        ),
        (
            b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\nstep|1|open-mailbox|1|180|expect|mailbox-opened|1\nstep|2|poll|1|none|1|1024|999|5000|4096|1|live:0:0|ready|expect|poll-accepted|none|none\n",
            TraceErrorCategory::InvalidValue,
        ),
        (
            b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\nstep|1|open-mailbox|1|180|expect|mailbox-opened|1\nstep|2|poll|1|none|1|4096|0|5000|1024|1|live:0:0|ready|expect|poll-accepted|none|none\n",
            TraceErrorCategory::InvalidValue,
        ),
    ];

    for (bytes, expected) in cases {
        let failure = AdverseTraceV1::parse(bytes).expect_err("input must fail closed");
        assert_eq!(failure.category(), *expected);
    }
}

#[test]
fn parser_rejects_non_utf8_before_retaining_any_records() {
    let mut bytes =
        b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\n".to_vec();
    bytes.push(0xff);
    bytes.push(b'\n');

    let failure = AdverseTraceV1::parse(&bytes).expect_err("non-UTF-8 trace rejected");
    assert_eq!(failure.category(), TraceErrorCategory::NonCanonical);
    assert_eq!(failure.line(), None);
}

#[test]
fn parser_bounds_each_operation_checkpoint_script() {
    let bytes = b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\nenvelope|1|1|1|32|120\nstep|1|open-mailbox|1|180|expect|mailbox-opened|1\nstep|2|deposit|1|1|5000|4096|1|live:0:0;live:0:0;live:0:0;live:0:0;live:0:0;live:0:0;live:0:0;live:0:0;live:0:0|ready|expect|deposit-accepted|1\n";

    assert_eq!(
        AdverseTraceV1::parse(bytes)
            .expect_err("nine checkpoints exceed the v1 bound")
            .category(),
        TraceErrorCategory::TooManyCheckpoints
    );
}

#[test]
fn parser_enforces_file_line_and_step_bounds_before_retention() {
    let oversized_file = vec![b'a'; MAX_TRACE_BYTES + 1];
    assert_eq!(
        AdverseTraceV1::parse(&oversized_file)
            .expect_err("oversized file")
            .category(),
        TraceErrorCategory::TraceTooLarge
    );

    let mut oversized_line = b"session-chat.transport.adverse-trace/v1\n".to_vec();
    oversized_line.extend(std::iter::repeat_n(b'a', MAX_TRACE_LINE_BYTES + 1));
    oversized_line.push(b'\n');
    assert_eq!(
        AdverseTraceV1::parse(&oversized_line)
            .expect_err("oversized line")
            .category(),
        TraceErrorCategory::LineTooLarge
    );

    let mut too_many_steps =
        b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\n".to_vec();
    for index in 1..=MAX_TRACE_STEPS + 1 {
        too_many_steps.extend_from_slice(
            format!("step|{index}|set-availability|available|expect|fault-applied\n").as_bytes(),
        );
    }
    assert_eq!(
        AdverseTraceV1::parse(&too_many_steps)
            .expect_err("excess steps")
            .category(),
        TraceErrorCategory::TooManySteps
    );
}

#[test]
fn parser_diagnostics_never_echo_the_untrusted_line() {
    let seeded = "SEEDED-CAPABILITY-CIPHERTEXT-CURSOR-IDENTIFIER";
    let bytes = format!(
        "session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\n{seeded}\n"
    );
    let failure = AdverseTraceV1::parse(bytes.as_bytes()).expect_err("unknown seeded record");
    let diagnostics = format!("{failure:?} {failure}");

    assert!(!diagnostics.contains(seeded));
}

#[test]
fn parser_requires_exact_retry_to_reuse_one_bound_delivery_alias() {
    let exact_retry = b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\nenvelope|1|1|1|32|120\nstep|1|open-mailbox|1|180|expect|mailbox-opened|1\nstep|2|deposit|1|1|5000|4096|1|live:0:0;live:0:0|ready|expect|deposit-accepted|1\nstep|3|deposit|1|1|5000|4096|1|live:0:0;live:0:0|ready|expect|deposit-accepted|1\n";
    AdverseTraceV1::parse(exact_retry).expect("exact retry reuses its delivery alias");

    let changed_envelope = b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\nenvelope|1|1|1|32|120\nenvelope|2|2|1|32|120\nstep|1|open-mailbox|1|180|expect|mailbox-opened|1\nstep|2|deposit|1|1|5000|4096|1|live:0:0;live:0:0|ready|expect|deposit-accepted|1\nstep|3|deposit|1|2|5000|4096|1|live:0:0;live:0:0|ready|expect|deposit-accepted|1\n";
    assert_eq!(
        AdverseTraceV1::parse(changed_envelope)
            .expect_err("one delivery alias cannot bind another envelope")
            .category(),
        TraceErrorCategory::InvalidRecord
    );

    let changed_alias = b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\nenvelope|1|1|1|32|120\nstep|1|open-mailbox|1|180|expect|mailbox-opened|1\nstep|2|deposit|1|1|5000|4096|1|live:0:0;live:0:0|ready|expect|deposit-accepted|1\nstep|3|deposit|1|1|5000|4096|1|live:0:0;live:0:0|ready|expect|deposit-accepted|2\n";
    assert_eq!(
        AdverseTraceV1::parse(changed_alias)
            .expect_err("one exact deposit identity cannot mint another alias")
            .category(),
        TraceErrorCategory::InvalidRecord
    );
}

#[test]
fn parser_rejects_the_unreachable_future_pending_expectation() {
    let bytes = b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\nenvelope|1|1|1|32|120\nstep|1|open-mailbox|1|180|expect|mailbox-opened|1\nstep|2|deposit|1|1|5000|4096|1|live:0:0|poll-once-drop|expect|future-pending\n";

    assert_eq!(
        AdverseTraceV1::parse(bytes)
            .expect_err("poll-once-drop has only one terminal dropped outcome")
            .category(),
        TraceErrorCategory::InvalidRecord
    );
}

#[test]
fn parser_preserves_exact_bounded_retry_nanoseconds() {
    let exact = b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\nstep|1|open-mailbox|1|180|expect|mailbox-opened|1\nstep|2|set-availability|unavailable|expect|fault-applied\nstep|3|poll|1|none|1|4096|0|5000|4096|1|live:0:0|ready|expect|failed|unavailable|after-ns:500000000\n";
    let parsed = AdverseTraceV1::parse(exact).expect("subsecond advice is representable exactly");
    assert_eq!(parsed.encode_canonical(), exact);

    let lossy_seconds = b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|1700000000\nstep|1|open-mailbox|1|180|expect|mailbox-opened|1\nstep|2|set-availability|unavailable|expect|fault-applied\nstep|3|poll|1|none|1|4096|0|5000|4096|1|live:0:0|ready|expect|failed|unavailable|after:1\n";
    assert_eq!(
        AdverseTraceV1::parse(lossy_seconds)
            .expect_err("v1 must not accept a lossy retry-delay unit")
            .category(),
        TraceErrorCategory::InvalidValue
    );
}

#[test]
fn every_profile_token_round_trips_without_weakening_profile_selection() {
    for profile in [
        "local",
        "fast",
        "private-interactive",
        "private-mixnet",
        "off-grid",
    ] {
        let bytes = format!(
            "session-chat.transport.adverse-trace/v1\nprofile|{profile}\nwall-start|1700000000\nstep|1|set-availability|available|expect|fault-applied\n"
        );
        let parsed = AdverseTraceV1::parse(bytes.as_bytes()).expect("supported profile");
        assert_eq!(parsed.encode_canonical(), bytes.as_bytes());
    }
}

#[test]
fn parser_rejects_each_bounded_field_and_reference_before_retention() {
    let cases: Vec<(Vec<u8>, TraceErrorCategory, u16)> = vec![
        (
            b"session-chat.transport.adverse-trace/v1\nprofile|unknown\nwall-start|1700000000\nstep|1|set-availability|available|expect|fault-applied\n".to_vec(),
            TraceErrorCategory::InvalidValue,
            2,
        ),
        (
            b"session-chat.transport.adverse-trace/v1\nprofile|local|extra\nwall-start|1700000000\nstep|1|set-availability|available|expect|fault-applied\n".to_vec(),
            TraceErrorCategory::InvalidRecord,
            2,
        ),
        (
            b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall|1700000000\nstep|1|set-availability|available|expect|fault-applied\n".to_vec(),
            TraceErrorCategory::InvalidRecord,
            3,
        ),
        (
            b"session-chat.transport.adverse-trace/v1\nprofile|local\nwall-start|not-a-number\nstep|1|set-availability|available|expect|fault-applied\n".to_vec(),
            TraceErrorCategory::InvalidValue,
            3,
        ),
        (
            trace("envelope|1|1|1|0|120\nstep|1|set-availability|available|expect|fault-applied\n"),
            TraceErrorCategory::InvalidValue,
            4,
        ),
        (
            trace("cursor|1|1|0\nstep|1|set-availability|available|expect|fault-applied\n"),
            TraceErrorCategory::InvalidValue,
            4,
        ),
        (
            trace("step|1|open-mailbox|0|180|expect|mailbox-opened|0\n"),
            TraceErrorCategory::InvalidValue,
            4,
        ),
        (
            trace("step|1|arm-deposit|unknown|expect|fault-applied\n"),
            TraceErrorCategory::InvalidValue,
            4,
        ),
        (
            trace("step|1|set-availability|sometimes|expect|fault-applied\n"),
            TraceErrorCategory::InvalidValue,
            4,
        ),
        (
            trace("step|1|lose-next-ack|during-commit|expect|fault-applied\n"),
            TraceErrorCategory::InvalidValue,
            4,
        ),
        (
            trace("step|1|advance-clock|86400001|0|expect|fault-applied\n"),
            TraceErrorCategory::InvalidValue,
            4,
        ),
        (
            trace("step|1|advance-clock|0|not-a-number|expect|fault-applied\n"),
            TraceErrorCategory::InvalidValue,
            4,
        ),
        (
            trace("step|1|open-mailbox|1|180|expect|mailbox-opened|2\n"),
            TraceErrorCategory::InvalidRecord,
            4,
        ),
        (
            trace("step|1|open-mailbox|1|180|expect|mailbox-opened|1\nstep|2|open-mailbox|1|180|expect|mailbox-opened|1\n"),
            TraceErrorCategory::DuplicateAlias,
            5,
        ),
        (
            trace("envelope|1|1|1|32|120\nstep|1|open-mailbox|1|180|expect|mailbox-opened|1\nstep|2|deposit|1|1|5000|4096|0|live:0:0|ready|expect|failed|internal|never\n"),
            TraceErrorCategory::InvalidValue,
            6,
        ),
        (
            trace("envelope|1|1|1|32|120\nstep|1|open-mailbox|1|180|expect|mailbox-opened|1\nstep|2|deposit|1|1|5000|4096|1|live:120001:0|ready|expect|failed|deadline-exceeded|never\n"),
            TraceErrorCategory::InvalidValue,
            6,
        ),
        (
            trace("envelope|1|1|1|32|120\nstep|1|open-mailbox|1|180|expect|mailbox-opened|1\nstep|2|deposit|1|1|5000|4096|1|alive|ready|expect|failed|internal|never\n"),
            TraceErrorCategory::InvalidRecord,
            6,
        ),
        (
            trace("envelope|1|1|1|32|120\nstep|1|open-mailbox|1|180|expect|mailbox-opened|1\nstep|2|deposit|1|1|5000|4096|1|live:0:0|later|expect|failed|internal|never\n"),
            TraceErrorCategory::InvalidValue,
            6,
        ),
        (
            trace("step|1|open-mailbox|1|180|expect|mailbox-opened|1\nstep|2|poll|1|1|1|4096|0|5000|4096|1|live:0:0|ready|expect|poll-accepted|none|none\n"),
            TraceErrorCategory::ForwardReference,
            5,
        ),
        (
            trace("step|1|open-mailbox|1|180|expect|mailbox-opened|1\nstep|2|poll|1|none|1|4096|0|5000|4096|1|live:0:0|ready|expect|poll-accepted|1:1|none\n"),
            TraceErrorCategory::ForwardReference,
            5,
        ),
        (
            trace("step|1|set-availability|available|expect|failed|not-a-code|never\n"),
            TraceErrorCategory::InvalidValue,
            4,
        ),
        (
            trace("step|1|set-availability|available|expect|failed|internal|after-ns:0\n"),
            TraceErrorCategory::InvalidValue,
            4,
        ),
        (
            trace("step|1|set-availability|available|expect|poll-accepted|1|none\n"),
            TraceErrorCategory::InvalidRecord,
            4,
        ),
    ];

    for (bytes, category, line) in cases {
        let failure = AdverseTraceV1::parse(&bytes).expect_err("input must fail closed");
        assert_eq!(failure.category(), category);
        assert_eq!(failure.line(), Some(line));
    }
}

#[test]
fn acknowledgement_alias_lists_reject_duplicates() {
    let bytes = trace(
        "envelope|1|1|1|32|120\nstep|1|open-mailbox|1|180|expect|mailbox-opened|1\nstep|2|deposit|1|1|5000|4096|1|live:0:0|ready|expect|deposit-accepted|1\nstep|3|ack|1|1,1|5000|4096|1|live:0:0|ready|expect|ack-accepted\n",
    );
    let failure = AdverseTraceV1::parse(&bytes).expect_err("duplicate destructive IDs rejected");
    assert_eq!(failure.category(), TraceErrorCategory::DuplicateAlias);
    assert_eq!(failure.line(), Some(7));
}
