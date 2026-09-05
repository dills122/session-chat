use std::fmt;

use session_protocol::OpaqueEnvelope;
use session_transport::{
    AcknowledgementRequest, AcknowledgementRight, BoundedDeliveryIds, CanonicalEnvelope,
    DepositRequest, DepositRight, DispatchControl, EnvelopeDelivery, OperationBudget, PollRequest,
    PollWait, ReceiveRight, TransportFailureCode,
};

/// Exact adapter operations exercised by the connected delivery conformance case.
pub const CONNECTED_DELIVERY_CONFORMANCE_REQUESTS_V1: usize = 7;

/// Secret-free step at which the connected delivery conformance case failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryConformanceStepV1 {
    Fixture,
    FirstDeposit,
    DepositRetry,
    IdempotencyConflict,
    FirstPoll,
    FirstAcknowledgement,
    AcknowledgementRetry,
    FinalPoll,
}

/// Context-free connected-delivery conformance failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryConformanceErrorV1 {
    step: DeliveryConformanceStepV1,
}

impl DeliveryConformanceErrorV1 {
    /// Returns the stable step without exposing authority or provider material.
    #[must_use]
    pub const fn step(self) -> DeliveryConformanceStepV1 {
        self.step
    }
}

impl fmt::Display for DeliveryConformanceErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("connected delivery conformance failed")
    }
}

impl std::error::Error for DeliveryConformanceErrorV1 {}

fn failed(step: DeliveryConformanceStepV1) -> DeliveryConformanceErrorV1 {
    DeliveryConformanceErrorV1 { step }
}

/// Runs the common connected-delivery contract against one already-issued mailbox.
///
/// The case proves byte-identical envelope carriage, stable exact retry receipts,
/// conflicting same-ID rejection, polling, exact-set acknowledgement, idempotent
/// acknowledgement retry, and post-acknowledgement absence. The caller owns the
/// provider lifecycle and supplies a fresh finite budget for every operation.
pub async fn run_connected_delivery_conformance_v1<D, B>(
    delivery: &mut D,
    deposit: &DepositRight<D::DepositEndpoint>,
    receive: &ReceiveRight<D::ReceiveCapability>,
    acknowledgement: &AcknowledgementRight<D::AcknowledgementCapability>,
    now_unix_seconds: u64,
    control: &dyn DispatchControl,
    mut budget: B,
) -> Result<(), DeliveryConformanceErrorV1>
where
    D: EnvelopeDelivery,
    B: FnMut() -> OperationBudget,
{
    let expires_at = now_unix_seconds
        .checked_add(120)
        .ok_or_else(|| failed(DeliveryConformanceStepV1::Fixture))?;
    let canonical_bytes = OpaqueEnvelope::new([0x31; 16], expires_at, vec![0x41; 32])
        .and_then(|envelope| envelope.encode_canonical())
        .map_err(|_| failed(DeliveryConformanceStepV1::Fixture))?;

    let first = delivery
        .deposit(
            deposit,
            deposit_request(
                &canonical_bytes,
                budget(),
                DeliveryConformanceStepV1::FirstDeposit,
            )?,
            control,
        )
        .await
        .map_err(|_| failed(DeliveryConformanceStepV1::FirstDeposit))?;
    let delivery_id = *first.delivery_id();

    let retry = delivery
        .deposit(
            deposit,
            deposit_request(
                &canonical_bytes,
                budget(),
                DeliveryConformanceStepV1::DepositRetry,
            )?,
            control,
        )
        .await
        .map_err(|_| failed(DeliveryConformanceStepV1::DepositRetry))?;
    if retry.delivery_id() != &delivery_id {
        return Err(failed(DeliveryConformanceStepV1::DepositRetry));
    }

    let conflicting = CanonicalEnvelope::from_opaque(
        OpaqueEnvelope::new([0x31; 16], expires_at, vec![0x42; 32])
            .map_err(|_| failed(DeliveryConformanceStepV1::Fixture))?,
    )
    .map_err(|_| failed(DeliveryConformanceStepV1::Fixture))?;
    let conflict = delivery
        .deposit(
            deposit,
            DepositRequest::new(conflicting, budget())
                .map_err(|_| failed(DeliveryConformanceStepV1::Fixture))?,
            control,
        )
        .await;
    if conflict.err().map(|failure| failure.code())
        != Some(TransportFailureCode::IdempotencyConflict)
    {
        return Err(failed(DeliveryConformanceStepV1::IdempotencyConflict));
    }

    let batch = delivery
        .poll(receive, poll_request(budget())?, control)
        .await
        .map_err(|_| failed(DeliveryConformanceStepV1::FirstPoll))?;
    if batch.len() != 1
        || batch.items()[0].delivery_id() != &delivery_id
        || batch.items()[0].envelope().as_bytes() != canonical_bytes
    {
        return Err(failed(DeliveryConformanceStepV1::FirstPoll));
    }

    acknowledge(
        delivery,
        acknowledgement,
        delivery_id,
        budget(),
        control,
        DeliveryConformanceStepV1::FirstAcknowledgement,
    )
    .await?;
    acknowledge(
        delivery,
        acknowledgement,
        delivery_id,
        budget(),
        control,
        DeliveryConformanceStepV1::AcknowledgementRetry,
    )
    .await?;

    let final_batch = delivery
        .poll(receive, poll_request(budget())?, control)
        .await
        .map_err(|_| failed(DeliveryConformanceStepV1::FinalPoll))?;
    if !final_batch.is_empty() {
        return Err(failed(DeliveryConformanceStepV1::FinalPoll));
    }
    Ok(())
}

fn deposit_request(
    bytes: &[u8],
    budget: OperationBudget,
    step: DeliveryConformanceStepV1,
) -> Result<DepositRequest, DeliveryConformanceErrorV1> {
    let envelope =
        CanonicalEnvelope::from_canonical_bytes(bytes.to_vec()).map_err(|_| failed(step))?;
    DepositRequest::new(envelope, budget).map_err(|_| failed(step))
}

fn poll_request(budget: OperationBudget) -> Result<PollRequest, DeliveryConformanceErrorV1> {
    PollRequest::new(None, 8, 64 * 1024, PollWait::immediate(), budget)
        .map_err(|_| failed(DeliveryConformanceStepV1::Fixture))
}

async fn acknowledge<D: EnvelopeDelivery>(
    delivery: &mut D,
    authority: &AcknowledgementRight<D::AcknowledgementCapability>,
    delivery_id: session_transport::DeliveryId,
    budget: OperationBudget,
    control: &dyn DispatchControl,
    step: DeliveryConformanceStepV1,
) -> Result<(), DeliveryConformanceErrorV1> {
    let ids = BoundedDeliveryIds::new(vec![delivery_id]).map_err(|_| failed(step))?;
    delivery
        .acknowledge(authority, AcknowledgementRequest::new(ids, budget), control)
        .await
        .map_err(|_| failed(step))?;
    Ok(())
}
