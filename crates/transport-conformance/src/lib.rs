#![forbid(unsafe_code)]

//! Shared, test-only transport conformance traces and runners.

mod lifecycle_provider;
mod trace;

pub use lifecycle_provider::{
    DeterministicAcknowledgementCapabilityV1, DeterministicDepositEndpointV1,
    DeterministicLifecycleProviderV1, DeterministicReceiveCapabilityV1,
    DeterministicRotationCapabilityV1,
};

pub use trace::{
    AcknowledgementLossFaultV1, AdapterControlErrorV1, AdapterSnapshotV1, AdverseTraceAdapterV1,
    AdverseTraceV1, AvailabilityFaultV1, ConformanceFuture, CursorFixtureV1, DepositFaultV1,
    EnvelopeFixtureV1, MAX_TRACE_BYTES, MAX_TRACE_LINE_BYTES, MAX_TRACE_STEPS, RunErrorCategoryV1,
    RunErrorV1, RunReportV1, TraceError, TraceErrorCategory, TraceStepV1,
    run_adverse_trace_twice_v1,
};
