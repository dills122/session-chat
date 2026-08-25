use std::time::Duration;

use session_protocol::{LocalWelcomeDepositEndpoint, MAX_WIRE_OBJECT_BYTES};
use thiserror::Error;

use crate::{
    CanonicalEnvelope, DepositRequest, DepositRight, DispatchControl, EnvelopeDeposit,
    OperationBudget, OutboxPortError, TransportFailure, WelcomeOutboxPort,
};

/// Hard ceiling for one owner lease in the initial local coordinator.
pub const MAX_COORDINATOR_LEASE_SECONDS: u64 = 3_600;

/// Finite policy for one owner lease and one adapter attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoordinatorPolicy {
    operation_timeout: Duration,
    lease_seconds: u64,
    maximum_network_bytes: u64,
}

impl CoordinatorPolicy {
    /// Creates a bounded policy whose operation cannot outlive its owner lease.
    pub fn new(
        operation_timeout: Duration,
        lease_seconds: u64,
        maximum_network_bytes: u64,
    ) -> Result<Self, CoordinatorError> {
        if operation_timeout.is_zero()
            || lease_seconds == 0
            || lease_seconds > MAX_COORDINATOR_LEASE_SECONDS
            || operation_timeout > Duration::from_secs(lease_seconds)
            || maximum_network_bytes == 0
            || maximum_network_bytes > MAX_WIRE_OBJECT_BYTES as u64
        {
            return Err(CoordinatorError::InvalidPolicy);
        }
        Ok(Self {
            operation_timeout,
            lease_seconds,
            maximum_network_bytes,
        })
    }
}

/// One bounded coordinator pass outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatorOutcome {
    /// No owner-store work was eligible at the observed time.
    Idle,
    /// The adapter accepted one exact deposit and the owner recorded it.
    Accepted,
}

/// Stable failures from one coordinator pass.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CoordinatorError {
    #[error("invalid coordinator policy")]
    InvalidPolicy,
    #[error("outbox owner operation failed")]
    OwnerStore(OutboxPortError),
    #[error("owner supplied invalid delivery work")]
    InvalidOwnerWork,
    #[error("transport deposit failed")]
    Transport(TransportFailure),
}

/// Coarse endpoint resolution failure that exposes no route or authority bytes.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EndpointResolutionError {
    #[error("deposit endpoint rejected")]
    Rejected,
}

/// Converts exact encoded destination material into deposit-only adapter authority.
pub trait DepositEndpointResolver<D: EnvelopeDeposit> {
    fn resolve(
        &mut self,
        encoded_endpoint: &[u8],
        now_unix_seconds: u64,
    ) -> Result<DepositRight<D::DepositEndpoint>, EndpointResolutionError>;
}

/// Decoder for the existing canonical LocalV1 transferable Welcome endpoint.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LocalV1DepositEndpointResolver;

impl<D> DepositEndpointResolver<D> for LocalV1DepositEndpointResolver
where
    D: EnvelopeDeposit<DepositEndpoint = LocalWelcomeDepositEndpoint>,
{
    fn resolve(
        &mut self,
        encoded_endpoint: &[u8],
        now_unix_seconds: u64,
    ) -> Result<DepositRight<LocalWelcomeDepositEndpoint>, EndpointResolutionError> {
        let endpoint = LocalWelcomeDepositEndpoint::decode_canonical(encoded_endpoint)
            .map_err(|_| EndpointResolutionError::Rejected)?;
        if endpoint.expires_at_unix_seconds() <= now_unix_seconds {
            return Err(EndpointResolutionError::Rejected);
        }
        Ok(DepositRight::from_provider(endpoint))
    }
}

/// Stateless policy executor over the authoritative owner-store port.
///
/// The returned future must be supervised by the composition root with a
/// timer/cancellation source that wakes it and drops it on expiry. Dropping a
/// pending run drops the adapter future and intentionally leaves the owner
/// lease to its authoritative expiry/recovery rules.
pub struct WelcomeDeliveryCoordinator {
    policy: CoordinatorPolicy,
}

impl WelcomeDeliveryCoordinator {
    #[must_use]
    pub const fn new(policy: CoordinatorPolicy) -> Self {
        Self { policy }
    }

    /// Attempts at most one exact deposit under one owner lease.
    pub async fn run_once<S, R, D>(
        &self,
        store: &mut S,
        resolver: &mut R,
        adapter: &mut D,
        control: &dyn DispatchControl,
    ) -> Result<CoordinatorOutcome, CoordinatorError>
    where
        S: WelcomeOutboxPort,
        D: EnvelopeDeposit,
        R: DepositEndpointResolver<D>,
    {
        let deadline = control
            .monotonic_now()
            .checked_add(self.policy.operation_timeout)
            .ok_or(CoordinatorError::InvalidPolicy)?;
        let budget = OperationBudget::new(deadline, self.policy.maximum_network_bytes, 1)
            .map_err(|_| CoordinatorError::InvalidPolicy)?;
        let observation = control
            .checkpoint(budget)
            .map_err(CoordinatorError::Transport)?;
        let Some(work) = store
            .lease_next(
                observation.wall_now_unix_seconds(),
                self.policy.lease_seconds,
            )
            .map_err(CoordinatorError::OwnerStore)?
        else {
            return Ok(CoordinatorOutcome::Idle);
        };
        let (lease, envelope_bytes, endpoint_bytes, outbox_expiry) = work.into_parts();

        let canonical = match CanonicalEnvelope::from_canonical_bytes(envelope_bytes.to_vec()) {
            Ok(canonical)
                if outbox_expiry > observation.wall_now_unix_seconds()
                    && outbox_expiry <= canonical.expires_at_unix_seconds() =>
            {
                canonical
            }
            _ => return release_invalid(store, lease),
        };
        let endpoint = match resolver.resolve(
            endpoint_bytes.as_slice(),
            observation.wall_now_unix_seconds(),
        ) {
            Ok(endpoint) => endpoint,
            Err(_) => return release_invalid(store, lease),
        };
        let request = match DepositRequest::new(canonical, budget) {
            Ok(request) => request,
            Err(_) => return release_invalid(store, lease),
        };
        if let Err(failure) = control.checkpoint(budget) {
            store
                .report_failed(lease)
                .map_err(CoordinatorError::OwnerStore)?;
            return Err(CoordinatorError::Transport(failure));
        }

        match EnvelopeDeposit::deposit(adapter, &endpoint, request, control).await {
            Ok(_receipt) => {
                let completed_at =
                    control
                        .wall_now_unix_seconds()
                        .ok_or(CoordinatorError::Transport(TransportFailure::new(
                            crate::TransportFailureCode::Internal,
                            crate::RetryAdvice::Never,
                        )))?;
                store
                    .report_accepted(lease, completed_at)
                    .map_err(CoordinatorError::OwnerStore)?;
                Ok(CoordinatorOutcome::Accepted)
            }
            Err(failure) => {
                store
                    .report_failed(lease)
                    .map_err(CoordinatorError::OwnerStore)?;
                Err(CoordinatorError::Transport(failure))
            }
        }
    }
}

fn release_invalid<S: WelcomeOutboxPort>(
    store: &mut S,
    lease: S::Lease,
) -> Result<CoordinatorOutcome, CoordinatorError> {
    store
        .report_failed(lease)
        .map_err(CoordinatorError::OwnerStore)?;
    Err(CoordinatorError::InvalidOwnerWork)
}
