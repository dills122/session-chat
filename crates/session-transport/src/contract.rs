use std::time::{Duration, Instant};

use session_protocol::OpaqueEnvelope;
use thiserror::Error;

/// Maximum UTF-8 byte length of a local, non-secret adapter identifier.
pub const MAX_ADAPTER_ID_BYTES: usize = 96;
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
    #[error("invalid retry delay")]
    InvalidRetryDelay,
}
