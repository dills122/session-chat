#![forbid(unsafe_code)]

//! Shared, test-only transport conformance traces and runners.

mod trace;

pub use trace::{
    AdverseTraceV1, CursorFixtureV1, EnvelopeFixtureV1, MAX_TRACE_BYTES, MAX_TRACE_LINE_BYTES,
    MAX_TRACE_STEPS, TraceError, TraceErrorCategory, TraceStepV1,
};
