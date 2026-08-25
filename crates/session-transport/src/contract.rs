use std::time::{Duration, Instant};

use session_protocol::OpaqueEnvelope;
use thiserror::Error;

/// Maximum UTF-8 byte length of a local, non-secret adapter identifier.
pub const MAX_ADAPTER_ID_BYTES: usize = 96;
/// Maximum opaque cursor size accepted before adapter dispatch.
pub const MAX_CURSOR_BYTES: usize = 256;
/// Maximum envelopes requested by one generalized poll.
pub const MAX_POLL_ENVELOPES: u16 = 64;
/// Maximum aggregate canonical bytes requested by one generalized poll.
pub const MAX_POLL_ENCODED_BYTES: u32 = 4 * 1024 * 1024;
/// Maximum long-poll wait admitted before the operation deadline is evaluated.
pub const MAX_POLL_WAIT_SECONDS: u64 = 60;
/// Maximum delivery identifiers accepted by one acknowledgement operation.
pub const MAX_ACKNOWLEDGEMENT_IDS: u16 = 64;
/// Global hard ceiling for adapter-provided retry delays.
pub const MAX_RETRY_DELAY_SECONDS: u64 = 3_600;

const ENVELOPE_ID_BYTES: usize = 16;

/// Closed transport profiles accepted by the local version 1 policy boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TransportProfileId {
    /// Deterministic local testing with no network or privacy claim.
    LocalV1,
    /// Low-latency direct or relay delivery with disclosed metadata exposure.
    FastV1,
    /// Low-latency anonymity-network delivery with timing-correlation caveats.
    PrivateInteractiveV1,
    /// Delayed mixnet delivery under a fail-closed private profile.
    PrivateMixnetV1,
    /// Explicit disruption-tolerant delivery with no automatic path change.
    OffGridV1,
}

impl TransportProfileId {
    /// Returns the stable local configuration identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalV1 => "session-chat.transport.local.v1",
            Self::FastV1 => "session-chat.transport.fast.v1",
            Self::PrivateInteractiveV1 => "session-chat.transport.private-interactive.v1",
            Self::PrivateMixnetV1 => "session-chat.transport.private-mixnet.v1",
            Self::OffGridV1 => "session-chat.transport.off-grid.v1",
        }
    }
}

impl TryFrom<&str> for TransportProfileId {
    type Error = TransportContractError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "session-chat.transport.local.v1" => Ok(Self::LocalV1),
            "session-chat.transport.fast.v1" => Ok(Self::FastV1),
            "session-chat.transport.private-interactive.v1" => Ok(Self::PrivateInteractiveV1),
            "session-chat.transport.private-mixnet.v1" => Ok(Self::PrivateMixnetV1),
            "session-chat.transport.off-grid.v1" => Ok(Self::OffGridV1),
            _ => Err(TransportContractError::UnsupportedProfile),
        }
    }
}

/// Validated local implementation identifier used only for binding and diagnostics.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AdapterId(Box<str>);

impl AdapterId {
    /// Validates a bounded lowercase identifier with no route or authority syntax.
    pub fn new(value: &str) -> Result<Self, TransportContractError> {
        let valid_edge = value
            .as_bytes()
            .first()
            .zip(value.as_bytes().last())
            .is_some_and(|(first, last)| {
                first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric()
            });
        let valid_bytes = value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        });
        if value.len() > MAX_ADAPTER_ID_BYTES || !valid_edge || !valid_bytes {
            return Err(TransportContractError::InvalidAdapterId);
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated non-secret local identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Opaque envelope identifier used for deduplication, never as authority.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EnvelopeId([u8; ENVELOPE_ID_BYTES]);

impl EnvelopeId {
    /// Returns the identifier bytes without granting any mailbox right.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ENVELOPE_ID_BYTES] {
        &self.0
    }
}

/// Exact canonical protocol bytes plus validated transport-visible metadata.
///
/// This type intentionally does not implement `Clone`, `Debug`, or `Display` so
/// ciphertext and full envelope identifiers do not enter ordinary diagnostics.
///
/// ```compile_fail
/// use session_transport::CanonicalEnvelope;
///
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<CanonicalEnvelope>();
/// ```
pub struct CanonicalEnvelope {
    bytes: Box<[u8]>,
    envelope_id: EnvelopeId,
    expires_at_unix_seconds: u64,
}

impl CanonicalEnvelope {
    /// Consumes a validated protocol object and retains its one canonical encoding.
    pub fn from_opaque(envelope: OpaqueEnvelope) -> Result<Self, TransportContractError> {
        let bytes = envelope
            .encode_canonical()
            .map_err(|_| TransportContractError::InvalidEnvelope)?;
        Self::from_validated(envelope, bytes)
    }

    /// Validates and takes ownership of exact canonical protocol bytes.
    pub fn from_canonical_bytes(bytes: Vec<u8>) -> Result<Self, TransportContractError> {
        let envelope = OpaqueEnvelope::decode_canonical(&bytes)
            .map_err(|_| TransportContractError::InvalidEnvelope)?;
        Self::from_validated(envelope, bytes)
    }

    fn from_validated(
        envelope: OpaqueEnvelope,
        bytes: Vec<u8>,
    ) -> Result<Self, TransportContractError> {
        if envelope.envelope_id().iter().all(|byte| *byte == 0)
            || envelope.expires_at_unix_seconds() == 0
        {
            return Err(TransportContractError::InvalidEnvelope);
        }
        Ok(Self {
            bytes: bytes.into_boxed_slice(),
            envelope_id: EnvelopeId(*envelope.envelope_id()),
            expires_at_unix_seconds: envelope.expires_at_unix_seconds(),
        })
    }

    /// Returns byte-identical deterministic protocol encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the untrusted identifier used for replay and deduplication.
    #[must_use]
    pub const fn envelope_id(&self) -> &EnvelopeId {
        &self.envelope_id
    }

    /// Returns the protocol-owned absolute expiration time.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }
}

/// Opaque bounded continuation hint that never grants mailbox authority.
///
/// Full cursor bytes intentionally do not implement `Debug` or `Display`.
///
/// ```compile_fail
/// use session_transport::Cursor;
///
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<Cursor>();
/// ```
pub struct Cursor(Box<[u8]>);

impl Cursor {
    /// Takes ownership only after applying the provider-neutral hard bound.
    pub fn new(bytes: Vec<u8>) -> Result<Self, TransportContractError> {
        if bytes.is_empty() || bytes.len() > MAX_CURSOR_BYTES {
            return Err(TransportContractError::InvalidCursor);
        }
        Ok(Self(bytes.into_boxed_slice()))
    }

    /// Borrows the opaque bytes for one adapter operation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Finite work authority for one logical adapter operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationBudget {
    deadline: Instant,
    max_network_bytes: u64,
    max_attempts: u16,
}

impl OperationBudget {
    /// Creates a budget with nonzero byte and attempt limits.
    pub const fn new(
        deadline: Instant,
        max_network_bytes: u64,
        max_attempts: u16,
    ) -> Result<Self, TransportContractError> {
        if max_network_bytes == 0 || max_attempts == 0 {
            return Err(TransportContractError::InvalidOperationBudget);
        }
        Ok(Self {
            deadline,
            max_network_bytes,
            max_attempts,
        })
    }

    /// Returns the caller-owned monotonic deadline.
    #[must_use]
    pub const fn deadline(self) -> Instant {
        self.deadline
    }

    /// Returns the maximum total network bytes allowed for the operation.
    #[must_use]
    pub const fn max_network_bytes(self) -> u64 {
        self.max_network_bytes
    }

    /// Returns the maximum total attempts allowed for the operation.
    #[must_use]
    pub const fn max_attempts(self) -> u16 {
        self.max_attempts
    }
}

/// Bounded wait policy for one generalized poll operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PollWait(Duration);

impl PollWait {
    /// Requests a non-blocking poll.
    #[must_use]
    pub const fn immediate() -> Self {
        Self(Duration::ZERO)
    }

    /// Requests a bounded wait that remains subordinate to the operation deadline.
    pub fn up_to(duration: Duration) -> Result<Self, TransportContractError> {
        if duration < Duration::from_secs(1)
            || duration > Duration::from_secs(MAX_POLL_WAIT_SECONDS)
        {
            return Err(TransportContractError::InvalidPollWait);
        }
        Ok(Self(duration))
    }

    /// Returns zero for an immediate poll or the validated maximum wait.
    #[must_use]
    pub const fn duration(self) -> Duration {
        self.0
    }
}

/// One bounded provider-neutral polling request.
///
/// This type intentionally omits `Debug` because it may own a full cursor.
///
/// ```compile_fail
/// use session_transport::PollRequest;
///
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<PollRequest>();
/// ```
pub struct PollRequest {
    cursor: Option<Cursor>,
    max_envelopes: u16,
    max_encoded_bytes: u32,
    wait: PollWait,
    budget: OperationBudget,
}

impl PollRequest {
    /// Validates count, aggregate bytes, wait, and total-operation work before dispatch.
    pub fn new(
        cursor: Option<Cursor>,
        max_envelopes: u16,
        max_encoded_bytes: u32,
        wait: PollWait,
        budget: OperationBudget,
    ) -> Result<Self, TransportContractError> {
        if max_envelopes == 0
            || max_envelopes > MAX_POLL_ENVELOPES
            || max_encoded_bytes == 0
            || max_encoded_bytes > MAX_POLL_ENCODED_BYTES
            || u64::from(max_encoded_bytes) > budget.max_network_bytes()
        {
            return Err(TransportContractError::InvalidPollRequest);
        }
        Ok(Self {
            cursor,
            max_envelopes,
            max_encoded_bytes,
            wait,
            budget,
        })
    }

    #[must_use]
    pub const fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }

    #[must_use]
    pub const fn max_envelopes(&self) -> u16 {
        self.max_envelopes
    }

    #[must_use]
    pub const fn max_encoded_bytes(&self) -> u32 {
        self.max_encoded_bytes
    }

    #[must_use]
    pub const fn wait(&self) -> PollWait {
        self.wait
    }

    #[must_use]
    pub const fn budget(&self) -> OperationBudget {
        self.budget
    }
}

/// One canonical envelope and the finite work authority for its deposit.
///
/// This type intentionally does not implement `Clone` or diagnostics traits.
///
/// ```compile_fail
/// use session_transport::DepositRequest;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<DepositRequest>();
/// ```
pub struct DepositRequest {
    envelope: CanonicalEnvelope,
    budget: OperationBudget,
}

impl DepositRequest {
    pub fn new(
        envelope: CanonicalEnvelope,
        budget: OperationBudget,
    ) -> Result<Self, TransportContractError> {
        let envelope_bytes = u64::try_from(envelope.as_bytes().len())
            .map_err(|_| TransportContractError::InvalidDepositRequest)?;
        if envelope_bytes > budget.max_network_bytes() {
            return Err(TransportContractError::InvalidDepositRequest);
        }
        Ok(Self { envelope, budget })
    }

    #[must_use]
    pub const fn envelope(&self) -> &CanonicalEnvelope {
        &self.envelope
    }

    #[must_use]
    pub const fn budget(&self) -> OperationBudget {
        self.budget
    }

    #[must_use]
    pub fn into_parts(self) -> (CanonicalEnvelope, OperationBudget) {
        (self.envelope, self.budget)
    }
}

/// Bounded untrusted delivery identifiers; possession grants no mailbox right.
///
/// Full identifier bytes intentionally do not implement `Debug` or `Display`.
///
/// ```compile_fail
/// use session_transport::BoundedDeliveryIds;
///
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<BoundedDeliveryIds>();
/// ```
pub struct BoundedDeliveryIds(Box<[crate::DeliveryId]>);

impl BoundedDeliveryIds {
    pub fn new(ids: Vec<crate::DeliveryId>) -> Result<Self, TransportContractError> {
        if ids.is_empty() || ids.len() > usize::from(MAX_ACKNOWLEDGEMENT_IDS) {
            return Err(TransportContractError::InvalidAcknowledgementBatch);
        }
        Ok(Self(ids.into_boxed_slice()))
    }

    #[must_use]
    pub fn as_slice(&self) -> &[crate::DeliveryId] {
        &self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// One bounded acknowledgement request under separately supplied authority.
pub struct AcknowledgementRequest {
    delivery_ids: BoundedDeliveryIds,
    budget: OperationBudget,
}

impl AcknowledgementRequest {
    #[must_use]
    pub const fn new(delivery_ids: BoundedDeliveryIds, budget: OperationBudget) -> Self {
        Self {
            delivery_ids,
            budget,
        }
    }

    #[must_use]
    pub const fn delivery_ids(&self) -> &BoundedDeliveryIds {
        &self.delivery_ids
    }

    #[must_use]
    pub const fn budget(&self) -> OperationBudget {
        self.budget
    }

    #[must_use]
    pub fn into_parts(self) -> (BoundedDeliveryIds, OperationBudget) {
        (self.delivery_ids, self.budget)
    }
}

/// Non-authorizing result of one accepted deposit attempt.
///
/// This type intentionally omits diagnostics traits because it owns a full
/// delivery identifier.
///
/// ```compile_fail
/// use session_transport::DepositReceipt;
///
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<DepositReceipt>();
/// ```
pub struct DepositReceipt {
    delivery_id: crate::DeliveryId,
}

impl DepositReceipt {
    #[must_use]
    pub const fn accepted(delivery_id: crate::DeliveryId) -> Self {
        Self { delivery_id }
    }

    #[must_use]
    pub const fn delivery_id(&self) -> &crate::DeliveryId {
        &self.delivery_id
    }
}

/// One received canonical envelope paired with its non-authorizing delivery ID.
///
/// This type intentionally omits `Clone`, `Debug`, and `Display` so adapters
/// cannot place ciphertext or full identifiers into ordinary diagnostics.
///
/// ```compile_fail
/// use session_transport::ReceivedCanonicalEnvelope;
///
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<ReceivedCanonicalEnvelope>();
/// ```
pub struct ReceivedCanonicalEnvelope {
    delivery_id: crate::DeliveryId,
    envelope: CanonicalEnvelope,
}

impl ReceivedCanonicalEnvelope {
    #[must_use]
    pub const fn new(delivery_id: crate::DeliveryId, envelope: CanonicalEnvelope) -> Self {
        Self {
            delivery_id,
            envelope,
        }
    }

    #[must_use]
    pub const fn delivery_id(&self) -> &crate::DeliveryId {
        &self.delivery_id
    }

    #[must_use]
    pub const fn envelope(&self) -> &CanonicalEnvelope {
        &self.envelope
    }

    #[must_use]
    pub fn into_parts(self) -> (crate::DeliveryId, CanonicalEnvelope) {
        (self.delivery_id, self.envelope)
    }
}

/// Poll result validated against its originating request and local wall time.
///
/// Empty batches are valid. This type intentionally omits diagnostics traits
/// because it owns canonical ciphertext, delivery identifiers, and a cursor.
///
/// ```compile_fail
/// use session_transport::ReceiveBatch;
///
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<ReceiveBatch>();
/// ```
pub struct ReceiveBatch {
    items: Box<[ReceivedCanonicalEnvelope]>,
    next_cursor: Option<Cursor>,
}

impl ReceiveBatch {
    /// Applies count, aggregate canonical-byte, and post-receive expiry checks.
    pub fn new(
        items: Vec<ReceivedCanonicalEnvelope>,
        next_cursor: Option<Cursor>,
        request: &PollRequest,
        now_unix_seconds: u64,
    ) -> Result<Self, TransportContractError> {
        if items.len() > usize::from(request.max_envelopes()) {
            return Err(TransportContractError::InvalidReceiveBatch);
        }
        let mut encoded_bytes = 0_usize;
        for item in &items {
            if item.envelope().expires_at_unix_seconds() <= now_unix_seconds {
                return Err(TransportContractError::ExpiredReceivedEnvelope);
            }
            encoded_bytes = encoded_bytes
                .checked_add(item.envelope().as_bytes().len())
                .ok_or(TransportContractError::InvalidReceiveBatch)?;
            if encoded_bytes
                > usize::try_from(request.max_encoded_bytes())
                    .map_err(|_| TransportContractError::InvalidReceiveBatch)?
            {
                return Err(TransportContractError::InvalidReceiveBatch);
            }
        }
        Ok(Self {
            items: items.into_boxed_slice(),
            next_cursor,
        })
    }

    #[must_use]
    pub fn items(&self) -> &[ReceivedCanonicalEnvelope] {
        &self.items
    }

    #[must_use]
    pub const fn next_cursor(&self) -> Option<&Cursor> {
        self.next_cursor.as_ref()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    #[must_use]
    pub fn into_parts(self) -> (Box<[ReceivedCanonicalEnvelope]>, Option<Cursor>) {
        (self.items, self.next_cursor)
    }
}

/// Identifier-free normalized acknowledgement outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcknowledgementReceipt(());

impl AcknowledgementReceipt {
    /// Records only that the bounded request was accepted without revealing
    /// which identifiers were already absent or acknowledged.
    #[must_use]
    pub const fn accepted() -> Self {
        Self(())
    }
}

/// Retry delay clamped to the global transport hard ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundedRetryDelay(Duration);

impl BoundedRetryDelay {
    /// Rejects zero or excessive remote retry delays before policy evaluation.
    pub fn new(duration: Duration) -> Result<Self, TransportContractError> {
        if duration.is_zero() || duration > Duration::from_secs(MAX_RETRY_DELAY_SECONDS) {
            return Err(TransportContractError::InvalidRetryDelay);
        }
        Ok(Self(duration))
    }

    /// Returns the already bounded delay.
    #[must_use]
    pub const fn duration(self) -> Duration {
        self.0
    }
}

/// Bounded adapter retry suggestion; the coordinator retains policy authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryAdvice {
    /// The same logical operation must not be retried.
    Never,
    /// Retry only under coordinator-selected bounded backoff.
    Backoff,
    /// Retry no earlier than an already bounded delay.
    After(BoundedRetryDelay),
}

/// Stable, secret-free failure classification at the transport boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TransportFailureCode {
    InvalidAuthority,
    AuthorityScopeMismatch,
    ExpiredEnvelope,
    EnvelopeTooLarge,
    IdempotencyConflict,
    InvalidCursor,
    QueueFull,
    RateLimited,
    Unavailable,
    DeadlineExceeded,
    CorruptRemoteResponse,
    PolicyViolation,
    Misconfigured,
    Internal,
}

/// Context-free transport failure safe for ordinary application errors.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("transport operation failed")]
pub struct TransportFailure {
    code: TransportFailureCode,
    retry: RetryAdvice,
}

impl TransportFailure {
    /// Creates a normalized failure without routes, identifiers, or remote text.
    #[must_use]
    pub const fn new(code: TransportFailureCode, retry: RetryAdvice) -> Self {
        Self { code, retry }
    }

    /// Returns the stable machine-readable category.
    #[must_use]
    pub const fn code(self) -> TransportFailureCode {
        self.code
    }

    /// Returns bounded advice that local policy may ignore or reduce.
    #[must_use]
    pub const fn retry_advice(self) -> RetryAdvice {
        self.retry
    }
}

/// Fail-closed construction errors for generalized transport values.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TransportContractError {
    #[error("unsupported transport profile")]
    UnsupportedProfile,
    #[error("invalid adapter identifier")]
    InvalidAdapterId,
    #[error("invalid canonical envelope")]
    InvalidEnvelope,
    #[error("invalid operation budget")]
    InvalidOperationBudget,
    #[error("invalid transport cursor")]
    InvalidCursor,
    #[error("invalid poll wait")]
    InvalidPollWait,
    #[error("invalid poll request")]
    InvalidPollRequest,
    #[error("invalid deposit request")]
    InvalidDepositRequest,
    #[error("invalid acknowledgement batch")]
    InvalidAcknowledgementBatch,
    #[error("invalid receive batch")]
    InvalidReceiveBatch,
    #[error("received envelope is expired")]
    ExpiredReceivedEnvelope,
    #[error("invalid retry delay")]
    InvalidRetryDelay,
}
