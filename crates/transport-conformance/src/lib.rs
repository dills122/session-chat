#![forbid(unsafe_code)]

//! Shared, test-only transport conformance traces and runners.

mod delivery;
mod lifecycle_provider;
mod receive_owner;
mod trace;

pub use delivery::{
    CONNECTED_DELIVERY_CONFORMANCE_REQUESTS_V1, DeliveryConformanceErrorV1,
    DeliveryConformanceStepV1, run_connected_delivery_conformance_v1,
};

pub use lifecycle_provider::{
    DeterministicAcknowledgementCapabilityV1, DeterministicDepositEndpointV1,
    DeterministicLifecycleProviderV1, DeterministicReceiveCapabilityV1,
    DeterministicRotationCapabilityV1,
};
pub use receive_owner::{
    DeterministicAcknowledgementLeaseV1, DeterministicCommittedReceivePageV1,
    DeterministicReceiveStateErrorV1, DeterministicReceiveStateOwnerV1,
};

pub use trace::{
    AcknowledgementLossFaultV1, AdapterControlErrorV1, AdapterSnapshotV1, AdverseTraceAdapterV1,
    AdverseTraceV1, AvailabilityFaultV1, ConformanceFuture, CursorFixtureV1, DepositFaultV1,
    EnvelopeFixtureV1, MAX_TRACE_BYTES, MAX_TRACE_LINE_BYTES, MAX_TRACE_STEPS, RunErrorCategoryV1,
    RunErrorV1, RunReportV1, TraceError, TraceErrorCategory, TraceStepV1,
    run_adverse_trace_twice_v1,
};
