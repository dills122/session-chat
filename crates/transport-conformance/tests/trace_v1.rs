use transport_conformance::{
    AdverseTraceV1, MAX_TRACE_BYTES, MAX_TRACE_LINE_BYTES, MAX_TRACE_STEPS, TraceErrorCategory,
};

const GOLDEN: &[u8] = include_bytes!("fixtures/adverse-trace-v1.txt");

#[test]
fn golden_v1_trace_round_trips_byte_for_byte() {
    let trace = AdverseTraceV1::parse(GOLDEN).expect("canonical trace");

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
