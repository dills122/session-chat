use std::{future::Future, time::Instant};

use crate::{
    AcknowledgementReceipt, AcknowledgementRequest, DepositReceipt, DepositRequest, PollRequest,
    ReceiveBatch, RetryAdvice, TransportFailure, TransportFailureCode,
};

/// One caller-owned observation of the clocks used at an operation checkpoint.
///
/// Monotonic time is used only for the operation budget. Unix wall time is used
/// only for canonical envelope expiry and other externally timestamped values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatchObservation {
    monotonic_now: Instant,
    wall_now_unix_seconds: u64,
}

impl DispatchObservation {
    /// Constructs one caller-owned checkpoint observation.
    ///
    /// Custom controls use this only when overriding [`DispatchControl::checkpoint`]
    /// to provide deterministic virtual time. The control remains responsible
    /// for cancellation, deadline, and wall-clock fail-closed behavior. An
    /// observation grants no mailbox right, profile binding, or mutation
    /// authority.
    #[must_use]
    pub const fn new(monotonic_now: Instant, wall_now_unix_seconds: u64) -> Self {
        Self {
            monotonic_now,
            wall_now_unix_seconds,
        }
    }

    /// Returns the monotonic time observed for the operation budget.
    #[must_use]
    pub const fn monotonic_now(self) -> Instant {
        self.monotonic_now
    }

    /// Returns the local Unix wall time used for externally timestamped values.
    #[must_use]
    pub const fn wall_now_unix_seconds(self) -> u64 {
        self.wall_now_unix_seconds
    }
}

/// Runtime-neutral clock and cancellation observations for one adapter operation.
///
/// The coordinator owns timer and cancellation wakeups. An adapter checks this
/// control before provider entry and after every await or provider boundary. A
/// returned future must not detach adapter-owned work that can outlive its
/// cancellation by drop. A remote deposit may still have completed before a
/// cancellation was observed, so exact idempotency identity remains required.
pub trait DispatchControl: Send + Sync {
    /// Returns the current monotonic time used only for operation deadlines.
    fn monotonic_now(&self) -> Instant;

    /// Returns local Unix wall time used only for externally timestamped values.
    ///
    /// `None` represents a platform clock that could not produce a Unix value;
    /// implementations must not substitute zero or another fabricated time.
    fn wall_now_unix_seconds(&self) -> Option<u64>;

    /// Reports whether the caller has cancelled this operation.
    fn is_cancelled(&self) -> bool;

    /// Fails closed when cancellation or the monotonic deadline has been reached.
    fn checkpoint(
        &self,
        budget: crate::OperationBudget,
    ) -> Result<DispatchObservation, TransportFailure> {
        if self.is_cancelled() {
            return Err(TransportFailure::new(
                TransportFailureCode::Cancelled,
                RetryAdvice::Never,
            ));
        }
        let monotonic_now = self.monotonic_now();
        if monotonic_now >= budget.deadline() {
            return Err(TransportFailure::new(
                TransportFailureCode::DeadlineExceeded,
                RetryAdvice::Never,
            ));
        }
        let wall_now_unix_seconds = self.wall_now_unix_seconds().ok_or_else(|| {
            TransportFailure::new(TransportFailureCode::Internal, RetryAdvice::Never)
        })?;
        Ok(DispatchObservation {
            monotonic_now,
            wall_now_unix_seconds,
        })
    }
}

/// Provider-issued deposit material sealed in a deposit-only operation right.
///
/// The inner value is never returned by this wrapper. Adapters construct it
/// when issuing authority and retain responsibility for making the inner
/// material right-bound and scope-validated. A deposit endpoint may be
/// deliberately transferable, but copying or serializing it must never derive
/// receive or acknowledgement authority. This wrapper prevents direct
/// positional substitution; it cannot repair provider material that can be
/// forged or converted into another right.
///
/// ```compile_fail
/// use session_transport::DepositRight;
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<DepositRight<()>>();
/// ```
///
/// ```compile_fail
/// use session_transport::DepositRight;
/// fn require_clone<T: Clone>() {}
/// require_clone::<DepositRight<()>>();
/// ```
pub struct DepositRight<T>(T);

impl<T> DepositRight<T> {
    /// Tags provider-issued material for the deposit operation only.
    ///
    /// This constructor must be used only by a reviewed adapter issuance path.
    /// Public visibility supports adapters in separate crates; it does not make
    /// caller-created or reminted provider material valid authority.
    #[must_use]
    pub const fn from_provider(value: T) -> Self {
        Self(value)
    }

    /// Borrows the provider-owned material for adapter validation.
    ///
    /// Cloning or serialization policy is provider-specific. Any representation
    /// derived through this borrow must remain deposit-only and exact-scope.
    #[must_use]
    pub const fn provider(&self) -> &T {
        &self.0
    }
}

/// Provider-issued receive material tagged for a receive-only operation right.
///
/// This wrapper prevents direct positional substitution, but the adapter must
/// still make its inner material right-bound and scope-validated. Receive
/// authority should be non-cloneable by default; any exceptional duplication
/// policy requires explicit review and must not derive another right.
///
/// ```compile_fail
/// use session_transport::ReceiveRight;
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<ReceiveRight<()>>();
/// ```
///
/// ```compile_fail
/// use session_transport::ReceiveRight;
/// fn require_clone<T: Clone>() {}
/// require_clone::<ReceiveRight<()>>();
/// ```
pub struct ReceiveRight<T>(T);

impl<T> ReceiveRight<T> {
    /// Tags provider-issued material for the receive operation only.
    ///
    /// This constructor must be used only by a reviewed adapter issuance path.
    #[must_use]
    pub const fn from_provider(value: T) -> Self {
        Self(value)
    }

    /// Borrows the provider-owned material for adapter validation. Provider
    /// duplication policy must not permit derivation of another right.
    #[must_use]
    pub const fn provider(&self) -> &T {
        &self.0
    }
}

/// Provider-issued acknowledgement material tagged for a destructive right.
///
/// This wrapper prevents direct positional substitution, but the adapter must
/// still make its inner material right-bound and scope-validated.
/// Acknowledgement authority should be non-cloneable by default; any
/// exceptional duplication policy requires explicit review and must not derive
/// another right.
///
/// ```compile_fail
/// use session_transport::AcknowledgementRight;
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<AcknowledgementRight<()>>();
/// ```
///
/// ```compile_fail
/// use session_transport::AcknowledgementRight;
/// fn require_clone<T: Clone>() {}
/// require_clone::<AcknowledgementRight<()>>();
/// ```
pub struct AcknowledgementRight<T>(T);

impl<T> AcknowledgementRight<T> {
    /// Tags provider-issued material for the acknowledgement operation only.
    ///
    /// This constructor must be used only by a reviewed adapter issuance path.
    #[must_use]
    pub const fn from_provider(value: T) -> Self {
        Self(value)
    }

    /// Borrows the provider-owned material for adapter validation. Provider
    /// duplication policy must not permit derivation of another right.
    #[must_use]
    pub const fn provider(&self) -> &T {
        &self.0
    }
}

/// Narrow deposit-only dispatch used by sender-side delivery coordinators.
///
/// This contract deliberately grants no poll or acknowledgement operation. A
/// full [`EnvelopeDelivery`] implementation receives this capability through
/// the blanket implementation below, while a sender-only LocalV1 adapter can
/// implement only this smaller surface.
pub trait EnvelopeDeposit: Send {
    type DepositEndpoint: Sync;

    fn deposit<'a>(
        &'a mut self,
        endpoint: &'a DepositRight<Self::DepositEndpoint>,
        request: DepositRequest,
        control: &'a dyn DispatchControl,
    ) -> impl Future<Output = Result<DepositReceipt, TransportFailure>> + Send + 'a;
}

/// Budget-aware provider-neutral dispatch over right-specific mailbox authority.
///
/// This internal Phase 1 boundary uses static dispatch and standard-library
/// futures. It does not select an async runtime or permit network-loaded adapter
/// code. A composition root may select a reviewed provider with a closed enum;
/// it must not silently switch an active session's provider or profile.
///
/// Implementations must not spawn or detach adapter-owned work from the
/// returned future. The caller cancels by signalling the supplied control and
/// dropping the future. Drop must stop further local work and release or abort
/// owned resources; it cannot prove that a remote system did not commit an
/// already-sent operation. Retries therefore preserve the same idempotency
/// identity and never create competing owner-store truth.
///
/// Provider-neutral outer wrappers keep the three method positions distinct,
/// even when an implementation aliases its inner associated types. This is a
/// positional type check, not an authority-issuance proof: every provider must
/// also ensure material for one right cannot derive another right, validate its
/// operation and mailbox scope, and review cloning/serialization policy per
/// right.
///
/// ```compile_fail
/// use session_transport::{DepositRight, DispatchControl, EnvelopeDelivery, PollRequest};
///
/// fn deposit_right_cannot_poll<D: EnvelopeDelivery>(
///     delivery: &mut D,
///     deposit: &DepositRight<D::DepositEndpoint>,
///     request: PollRequest,
///     control: &dyn DispatchControl,
/// ) {
///     let _ = delivery.poll(deposit, request, control);
/// }
/// ```
///
/// ```compile_fail
/// use session_transport::{
///     AcknowledgementRequest, DispatchControl, EnvelopeDelivery, ReceiveRight,
/// };
///
/// fn receive_right_cannot_acknowledge<D: EnvelopeDelivery>(
///     delivery: &mut D,
///     receive: &ReceiveRight<D::ReceiveCapability>,
///     request: AcknowledgementRequest,
///     control: &dyn DispatchControl,
/// ) {
///     let _ = delivery.acknowledge(receive, request, control);
/// }
/// ```
///
/// ```compile_fail
/// use session_transport::{DepositRequest, DispatchControl, EnvelopeDelivery, ReceiveRight};
///
/// fn receive_right_cannot_deposit<D: EnvelopeDelivery>(
///     delivery: &mut D,
///     receive: &ReceiveRight<D::ReceiveCapability>,
///     request: DepositRequest,
///     control: &dyn DispatchControl,
/// ) {
///     let _ = delivery.deposit(receive, request, control);
/// }
/// ```
///
/// ```compile_fail
/// use session_transport::{
///     AcknowledgementRight, DepositRequest, DispatchControl, EnvelopeDelivery,
/// };
///
/// fn acknowledgement_right_cannot_deposit<D: EnvelopeDelivery>(
///     delivery: &mut D,
///     acknowledgement: &AcknowledgementRight<D::AcknowledgementCapability>,
///     request: DepositRequest,
///     control: &dyn DispatchControl,
/// ) {
///     let _ = delivery.deposit(acknowledgement, request, control);
/// }
/// ```
///
/// ```compile_fail
/// use session_transport::{
///     AcknowledgementRight, DispatchControl, EnvelopeDelivery, PollRequest,
/// };
///
/// fn acknowledgement_right_cannot_poll<D: EnvelopeDelivery>(
///     delivery: &mut D,
///     acknowledgement: &AcknowledgementRight<D::AcknowledgementCapability>,
///     request: PollRequest,
///     control: &dyn DispatchControl,
/// ) {
///     let _ = delivery.poll(acknowledgement, request, control);
/// }
/// ```
///
/// ```compile_fail
/// use session_transport::{
///     AcknowledgementRequest, DepositRight, DispatchControl, EnvelopeDelivery,
/// };
///
/// fn deposit_right_cannot_acknowledge<D: EnvelopeDelivery>(
///     delivery: &mut D,
///     deposit: &DepositRight<D::DepositEndpoint>,
///     request: AcknowledgementRequest,
///     control: &dyn DispatchControl,
/// ) {
///     let _ = delivery.acknowledge(deposit, request, control);
/// }
/// ```
///
/// ```compile_fail
/// use session_transport::{DepositRight, DispatchControl, EnvelopeDelivery, PollRequest};
///
/// struct SameProviderMaterial;
///
/// fn aliased_inner_types_still_cannot_cross<D>(
///     delivery: &mut D,
///     deposit: &DepositRight<SameProviderMaterial>,
///     request: PollRequest,
///     control: &dyn DispatchControl,
/// ) where
///     D: EnvelopeDelivery<
///         DepositEndpoint = SameProviderMaterial,
///         ReceiveCapability = SameProviderMaterial,
///     >,
/// {
///     let _ = delivery.poll(deposit, request, control);
/// }
/// ```
///
/// ```compile_fail
/// use session_transport::{
///     AcknowledgementRequest, DeliveryId, DispatchControl, EnvelopeDelivery,
/// };
///
/// fn delivery_id_is_not_authority<D: EnvelopeDelivery>(
///     delivery: &mut D,
///     identifier: &DeliveryId,
///     request: AcknowledgementRequest,
///     control: &dyn DispatchControl,
/// ) {
///     let _ = delivery.acknowledge(identifier, request, control);
/// }
/// ```
///
/// ```compile_fail
/// use session_transport::{
///     AcknowledgementRequest, Cursor, DispatchControl, EnvelopeDelivery,
/// };
///
/// fn cursor_is_not_authority<D: EnvelopeDelivery>(
///     delivery: &mut D,
///     cursor: &Cursor,
///     request: AcknowledgementRequest,
///     control: &dyn DispatchControl,
/// ) {
///     let _ = delivery.acknowledge(cursor, request, control);
/// }
/// ```
///
/// Design sources:
///
/// - <https://doc.rust-lang.org/1.97.1/reference/items/traits.html#dyn-compatibility>
/// - <https://doc.rust-lang.org/1.97.1/std/future/trait.Future.html>
/// - <https://doc.rust-lang.org/1.97.1/std/time/struct.Instant.html>
/// - <https://doc.rust-lang.org/1.97.1/std/time/struct.SystemTime.html>
/// - <https://rust-lang.github.io/async-book/part-guide/more-async-await.html#cancellation>
pub trait EnvelopeDelivery: Send {
    /// Provider-owned sender-facing route and deposit-authority material.
    ///
    /// It must be deposit-bound and scope-validated. Controlled transfer is
    /// allowed but must not derive receive or acknowledgement authority.
    type DepositEndpoint: Sync;
    /// Provider-owned receiver-retained read-authority material.
    ///
    /// It must be receive-bound and scope-validated, and should be non-cloneable
    /// by default.
    type ReceiveCapability: Sync;
    /// Provider-owned destructive acknowledgement-authority material.
    ///
    /// It must be acknowledgement-bound and scope-validated, and should be
    /// non-cloneable by default.
    type AcknowledgementCapability: Sync;

    /// Attempts one bounded deposit without changing profiles or retrying forever.
    fn deposit<'a>(
        &'a mut self,
        endpoint: &'a DepositRight<Self::DepositEndpoint>,
        request: DepositRequest,
        control: &'a dyn DispatchControl,
    ) -> impl Future<Output = Result<DepositReceipt, TransportFailure>> + Send + 'a;

    /// Performs one bounded poll and returns only a validated receive batch.
    fn poll<'a>(
        &'a mut self,
        authority: &'a ReceiveRight<Self::ReceiveCapability>,
        request: PollRequest,
        control: &'a dyn DispatchControl,
    ) -> impl Future<Output = Result<ReceiveBatch, TransportFailure>> + Send + 'a;

    /// Acknowledges an exact bounded identifier set under separate authority.
    fn acknowledge<'a>(
        &'a mut self,
        authority: &'a AcknowledgementRight<Self::AcknowledgementCapability>,
        request: AcknowledgementRequest,
        control: &'a dyn DispatchControl,
    ) -> impl Future<Output = Result<AcknowledgementReceipt, TransportFailure>> + Send + 'a;
}

impl<D: EnvelopeDelivery> EnvelopeDeposit for D {
    type DepositEndpoint = D::DepositEndpoint;

    fn deposit<'a>(
        &'a mut self,
        endpoint: &'a DepositRight<Self::DepositEndpoint>,
        request: DepositRequest,
        control: &'a dyn DispatchControl,
    ) -> impl Future<Output = Result<DepositReceipt, TransportFailure>> + Send + 'a {
        EnvelopeDelivery::deposit(self, endpoint, request, control)
    }
}
