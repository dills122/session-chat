#![forbid(unsafe_code)]

//! Right-specific transport contracts and deterministic local adapters.

mod capability;
mod contract;
mod coordinator;
mod dispatch;
mod outbox_port;
mod profile;
mod supervisor;

pub use capability::{
    LocalWelcomeAcknowledgementCapability, LocalWelcomeMailbox, LocalWelcomeReceiveCapability,
};
pub use contract::{
    AcknowledgementReceipt, AcknowledgementRequest, AdapterId, BoundedDeliveryIds,
    BoundedRetryDelay, CanonicalEnvelope, Cursor, DepositReceipt, DepositRequest, EnvelopeId,
    MAX_ACKNOWLEDGEMENT_IDS, MAX_ADAPTER_ID_BYTES, MAX_CURSOR_BYTES, MAX_POLL_ENCODED_BYTES,
    MAX_POLL_ENVELOPES, MAX_POLL_WAIT_SECONDS, MAX_RETRY_DELAY_SECONDS, OperationBudget,
    PollRequest, PollWait, ReceiveBatch, ReceivedCanonicalEnvelope, RetryAdvice,
    TransportContractError, TransportFailure, TransportFailureCode, TransportProfileId,
};
pub use coordinator::{
    CoordinatorError, CoordinatorOutcome, CoordinatorPolicy, DepositEndpointResolver,
    EndpointResolutionError, LocalV1DepositEndpointResolver, MAX_COORDINATOR_LEASE_SECONDS,
    WelcomeDeliveryCoordinator,
};
pub use dispatch::{
    AcknowledgementRight, DepositRight, DispatchControl, DispatchObservation, EnvelopeDelivery,
    EnvelopeDeposit, ReceiveRight,
};
pub use outbox_port::{LeasedWelcome, OutboxPortError, WelcomeOutboxPort};
pub use profile::{
    AdapterExecutionV1, AdapterLimitsV1, AdapterManifestV1, AdapterOperationsV1, AdapterVersionV1,
    BackgroundWorkV1, BindingErrorV1, EgressDeclarationV1, EnforcementModeV1, InternalRetryV1,
    TransportBindingRecordV1, bind_transport_v1,
};
pub use supervisor::{
    BlockingFutureSupervisor, CancellationHandle, SupervisionError, ThreadDispatchControl,
};

use std::{collections::BTreeMap, error::Error};

use aws_lc_rs::{constant_time, digest, rand};
use session_protocol::{DepositCapability, LocalWelcomeDepositEndpoint, OpaqueEnvelope};
use thiserror::Error;
use zeroize::Zeroizing;

const IDENTIFIER_BYTES: usize = 16;
const CAPABILITY_BYTES: usize = 32;
const DIGEST_BYTES: usize = 32;
const CAPABILITY_DIGEST_DOMAIN: &[u8] = b"session-chat/local-mailbox-capability/v1\0";
const ENVELOPE_DIGEST_DOMAIN: &[u8] = b"session-chat/local-mailbox-envelope/v1\0";

/// Explicit lifetime and memory bounds for local Welcome mailboxes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalMailboxPolicy {
    maximum_lifetime_seconds: u64,
    maximum_live_mailboxes: usize,
}

impl LocalMailboxPolicy {
    /// Creates a fail-closed local mailbox policy.
    pub fn new(
        maximum_lifetime_seconds: u64,
        maximum_live_mailboxes: usize,
    ) -> Result<Self, LocalTransportError> {
        if maximum_lifetime_seconds == 0 || maximum_live_mailboxes == 0 {
            return Err(LocalTransportError::InvalidPolicy);
        }
        Ok(Self {
            maximum_lifetime_seconds,
            maximum_live_mailboxes,
        })
    }
}

/// Coarse, secret-free failures from the local transport boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LocalTransportError {
    /// A configured lifetime or capacity was zero.
    #[error("invalid local mailbox policy")]
    InvalidPolicy,
    /// Authority, time, envelope, mailbox state, or idempotency validation failed.
    #[error("local mailbox operation rejected")]
    Rejected,
    /// Creating another live mailbox would exceed the configured bound.
    #[error("local mailbox capacity reached")]
    CapacityExceeded,
    /// The reviewed random provider did not return usable output.
    #[error("local mailbox provider failed")]
    ProviderFailure,
}

/// Untrusted delivery identifier; it conveys no acknowledgement authority.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DeliveryId([u8; IDENTIFIER_BYTES]);

impl DeliveryId {
    /// Creates an untrusted identifier from provider-generated nonzero bytes.
    pub fn from_provider_bytes(bytes: [u8; IDENTIFIER_BYTES]) -> Option<Self> {
        (!bytes.iter().all(|byte| *byte == 0)).then_some(Self(bytes))
    }

    /// Borrows the untrusted identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; IDENTIFIER_BYTES] {
        &self.0
    }
}

/// One received opaque envelope paired with its untrusted delivery identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedEnvelope {
    delivery_id: DeliveryId,
    envelope: OpaqueEnvelope,
}

impl ReceivedEnvelope {
    /// Pairs an untrusted delivery identifier with one bounded opaque envelope.
    #[must_use]
    pub const fn new(delivery_id: DeliveryId, envelope: OpaqueEnvelope) -> Self {
        Self {
            delivery_id,
            envelope,
        }
    }

    /// Returns the identifier used only to select a delivery for acknowledgement.
    #[must_use]
    pub const fn delivery_id(&self) -> &DeliveryId {
        &self.delivery_id
    }

    /// Returns the byte-identical opaque envelope retained by the mailbox.
    #[must_use]
    pub const fn envelope(&self) -> &OpaqueEnvelope {
        &self.envelope
    }
}

/// Provider-neutral operations over right-specific opaque-envelope mailboxes.
///
/// Associated authority types prevent a receive or acknowledgement capability
/// from being supplied to a deposit operation. Implementations remain selected
/// from the compiled, reviewed allowlist; this trait does not permit dynamic or
/// network-loaded transport code.
pub trait EnvelopeTransport {
    /// Sender-facing deposit endpoint for this transport profile.
    type DepositEndpoint;
    /// Receiver-only read authority for this transport profile.
    type ReceiveCapability;
    /// Receiver-only acknowledgement authority for this transport profile.
    type AcknowledgementCapability;
    /// Coarse adapter failure that exposes no capability bytes or plaintext.
    type Error: Error;

    /// Accepts one already bounded opaque envelope for delivery.
    fn deposit(
        &mut self,
        endpoint: &Self::DepositEndpoint,
        envelope: OpaqueEnvelope,
        now_unix_seconds: u64,
    ) -> Result<DeliveryId, Self::Error>;

    /// Reads at most one retained opaque envelope.
    fn receive(
        &mut self,
        authority: &Self::ReceiveCapability,
        now_unix_seconds: u64,
    ) -> Result<Option<ReceivedEnvelope>, Self::Error>;

    /// Deletes or records acknowledgement of one selected delivery.
    fn acknowledge(
        &mut self,
        authority: &Self::AcknowledgementCapability,
        delivery_id: DeliveryId,
        now_unix_seconds: u64,
    ) -> Result<(), Self::Error>;
}

struct AcceptedEnvelope {
    envelope_id: [u8; IDENTIFIER_BYTES],
    envelope_digest: [u8; DIGEST_BYTES],
    delivery_id: DeliveryId,
    envelope: Option<OpaqueEnvelope>,
}

struct LocalMailboxRecord {
    expires_at_unix_seconds: u64,
    deposit_digest: [u8; DIGEST_BYTES],
    receive_digest: [u8; DIGEST_BYTES],
    acknowledgement_digest: [u8; DIGEST_BYTES],
    accepted: Option<AcceptedEnvelope>,
}

/// Bounded, single-process local Welcome mailbox adapter.
pub struct LocalMemoryWelcomeTransport {
    policy: LocalMailboxPolicy,
    transport_instance_id: [u8; IDENTIFIER_BYTES],
    mailboxes: BTreeMap<[u8; IDENTIFIER_BYTES], LocalMailboxRecord>,
}

impl LocalMemoryWelcomeTransport {
    /// Creates an empty transport with a provider-generated instance identifier.
    pub fn new(policy: LocalMailboxPolicy) -> Result<Self, LocalTransportError> {
        Ok(Self {
            policy,
            transport_instance_id: random_nonzero()?,
            mailboxes: BTreeMap::new(),
        })
    }

    /// Creates one single-message mailbox with independent random authorities.
    pub fn create_welcome_mailbox(
        &mut self,
        expires_at_unix_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<LocalWelcomeMailbox, LocalTransportError> {
        let lifetime = expires_at_unix_seconds
            .checked_sub(now_unix_seconds)
            .ok_or(LocalTransportError::Rejected)?;
        if lifetime == 0 || lifetime > self.policy.maximum_lifetime_seconds {
            return Err(LocalTransportError::Rejected);
        }
        let live_count = self
            .mailboxes
            .values()
            .filter(|record| record.expires_at_unix_seconds > now_unix_seconds)
            .count();
        if live_count >= self.policy.maximum_live_mailboxes {
            return Err(LocalTransportError::CapacityExceeded);
        }

        let mailbox_id: [u8; IDENTIFIER_BYTES] = random_nonzero()?;
        if self.mailboxes.contains_key(&mailbox_id) {
            return Err(LocalTransportError::ProviderFailure);
        }
        let deposit_secret = Zeroizing::new(random_nonzero::<CAPABILITY_BYTES>()?);
        let receive_secret = Zeroizing::new(random_nonzero::<CAPABILITY_BYTES>()?);
        let acknowledgement_secret = Zeroizing::new(random_nonzero::<CAPABILITY_BYTES>()?);
        if *deposit_secret == *receive_secret
            || *deposit_secret == *acknowledgement_secret
            || *receive_secret == *acknowledgement_secret
        {
            return Err(LocalTransportError::ProviderFailure);
        }
        let deposit_digest = capability_digest(&deposit_secret[..]);
        let receive_digest = capability_digest(&receive_secret[..]);
        let acknowledgement_digest = capability_digest(&acknowledgement_secret[..]);
        let deposit = LocalWelcomeDepositEndpoint::new(
            self.transport_instance_id,
            mailbox_id,
            DepositCapability::new(*deposit_secret)
                .map_err(|_| LocalTransportError::ProviderFailure)?,
            expires_at_unix_seconds,
        )
        .map_err(|_| LocalTransportError::ProviderFailure)?;
        let receive = LocalWelcomeReceiveCapability::new(
            self.transport_instance_id,
            mailbox_id,
            *receive_secret,
            expires_at_unix_seconds,
        );
        let acknowledgement = LocalWelcomeAcknowledgementCapability::new(
            self.transport_instance_id,
            mailbox_id,
            *acknowledgement_secret,
            expires_at_unix_seconds,
        );

        self.mailboxes
            .retain(|_, record| record.expires_at_unix_seconds > now_unix_seconds);
        self.mailboxes.insert(
            mailbox_id,
            LocalMailboxRecord {
                expires_at_unix_seconds,
                deposit_digest,
                receive_digest,
                acknowledgement_digest,
                accepted: None,
            },
        );
        Ok(LocalWelcomeMailbox::new(deposit, receive, acknowledgement))
    }

    /// Stores one bounded opaque envelope using deposit-only authority.
    pub fn deposit(
        &mut self,
        endpoint: &LocalWelcomeDepositEndpoint,
        envelope: OpaqueEnvelope,
        now_unix_seconds: u64,
    ) -> Result<DeliveryId, LocalTransportError> {
        if endpoint.transport_instance_id() != &self.transport_instance_id
            || endpoint.expires_at_unix_seconds() <= now_unix_seconds
            || envelope.expires_at_unix_seconds() <= now_unix_seconds
            || envelope.expires_at_unix_seconds() > endpoint.expires_at_unix_seconds()
            || envelope.envelope_id().iter().all(|byte| *byte == 0)
        {
            return Err(LocalTransportError::Rejected);
        }
        let record = self
            .mailboxes
            .get_mut(endpoint.mailbox_id())
            .ok_or(LocalTransportError::Rejected)?;
        if record.expires_at_unix_seconds != endpoint.expires_at_unix_seconds()
            || !secret_matches(
                &record.deposit_digest,
                endpoint.deposit_capability().expose_secret(),
            )
        {
            return Err(LocalTransportError::Rejected);
        }
        let encoded = envelope
            .encode_canonical()
            .map_err(|_| LocalTransportError::Rejected)?;
        let envelope_digest = domain_digest(ENVELOPE_DIGEST_DOMAIN, &encoded);
        if let Some(accepted) = &record.accepted {
            if accepted.envelope_id == *envelope.envelope_id()
                && constant_time::verify_slices_are_equal(
                    &accepted.envelope_digest,
                    &envelope_digest,
                )
                .is_ok()
            {
                return Ok(accepted.delivery_id);
            }
            return Err(LocalTransportError::Rejected);
        }
        let delivery_id = DeliveryId(random_nonzero()?);
        record.accepted = Some(AcceptedEnvelope {
            envelope_id: *envelope.envelope_id(),
            envelope_digest,
            delivery_id,
            envelope: Some(envelope),
        });
        Ok(delivery_id)
    }

    /// Reads the one retained envelope using receive-only authority.
    pub fn receive(
        &mut self,
        authority: &LocalWelcomeReceiveCapability,
        now_unix_seconds: u64,
    ) -> Result<Option<ReceivedEnvelope>, LocalTransportError> {
        if authority.transport_instance_id() != &self.transport_instance_id
            || authority.expires_at_unix_seconds() <= now_unix_seconds
        {
            return Err(LocalTransportError::Rejected);
        }
        let record = self
            .mailboxes
            .get_mut(authority.mailbox_id())
            .ok_or(LocalTransportError::Rejected)?;
        if record.expires_at_unix_seconds != authority.expires_at_unix_seconds()
            || !secret_matches(&record.receive_digest, authority.expose_secret())
        {
            return Err(LocalTransportError::Rejected);
        }
        let Some(accepted) = &mut record.accepted else {
            return Ok(None);
        };
        if accepted
            .envelope
            .as_ref()
            .is_some_and(|envelope| envelope.expires_at_unix_seconds() <= now_unix_seconds)
        {
            accepted.envelope = None;
        }
        Ok(accepted.envelope.clone().map(|envelope| ReceivedEnvelope {
            delivery_id: accepted.delivery_id,
            envelope,
        }))
    }

    /// Deletes one selected delivery using acknowledgement-only authority.
    pub fn acknowledge(
        &mut self,
        authority: &LocalWelcomeAcknowledgementCapability,
        delivery_id: DeliveryId,
        now_unix_seconds: u64,
    ) -> Result<(), LocalTransportError> {
        if authority.transport_instance_id() != &self.transport_instance_id
            || authority.expires_at_unix_seconds() <= now_unix_seconds
        {
            return Err(LocalTransportError::Rejected);
        }
        let record = self
            .mailboxes
            .get_mut(authority.mailbox_id())
            .ok_or(LocalTransportError::Rejected)?;
        if record.expires_at_unix_seconds != authority.expires_at_unix_seconds()
            || !secret_matches(&record.acknowledgement_digest, authority.expose_secret())
        {
            return Err(LocalTransportError::Rejected);
        }
        let accepted = record
            .accepted
            .as_mut()
            .ok_or(LocalTransportError::Rejected)?;
        if accepted.delivery_id != delivery_id {
            return Err(LocalTransportError::Rejected);
        }
        accepted.envelope = None;
        Ok(())
    }

    /// Returns the retained mailbox count, including expired entries awaiting pruning.
    #[must_use]
    pub fn mailbox_count(&self) -> usize {
        self.mailboxes.len()
    }
}

impl EnvelopeTransport for LocalMemoryWelcomeTransport {
    type DepositEndpoint = LocalWelcomeDepositEndpoint;
    type ReceiveCapability = LocalWelcomeReceiveCapability;
    type AcknowledgementCapability = LocalWelcomeAcknowledgementCapability;
    type Error = LocalTransportError;

    fn deposit(
        &mut self,
        endpoint: &Self::DepositEndpoint,
        envelope: OpaqueEnvelope,
        now_unix_seconds: u64,
    ) -> Result<DeliveryId, Self::Error> {
        Self::deposit(self, endpoint, envelope, now_unix_seconds)
    }

    fn receive(
        &mut self,
        authority: &Self::ReceiveCapability,
        now_unix_seconds: u64,
    ) -> Result<Option<ReceivedEnvelope>, Self::Error> {
        Self::receive(self, authority, now_unix_seconds)
    }

    fn acknowledge(
        &mut self,
        authority: &Self::AcknowledgementCapability,
        delivery_id: DeliveryId,
        now_unix_seconds: u64,
    ) -> Result<(), Self::Error> {
        Self::acknowledge(self, authority, delivery_id, now_unix_seconds)
    }
}

impl EnvelopeDeposit for LocalMemoryWelcomeTransport {
    type DepositEndpoint = LocalWelcomeDepositEndpoint;

    async fn deposit(
        &mut self,
        endpoint: &DepositRight<Self::DepositEndpoint>,
        request: DepositRequest,
        control: &dyn DispatchControl,
    ) -> Result<DepositReceipt, TransportFailure> {
        let budget = request.budget();
        let observation = control.checkpoint(budget)?;
        let (canonical, _) = request.into_parts();
        if canonical.expires_at_unix_seconds() <= observation.wall_now_unix_seconds()
            || canonical.expires_at_unix_seconds() > endpoint.provider().expires_at_unix_seconds()
        {
            return Err(TransportFailure::new(
                TransportFailureCode::ExpiredEnvelope,
                RetryAdvice::Never,
            ));
        }
        let envelope = OpaqueEnvelope::decode_canonical(canonical.as_bytes()).map_err(|_| {
            TransportFailure::new(
                TransportFailureCode::CorruptRemoteResponse,
                RetryAdvice::Never,
            )
        })?;
        let delivery_id = EnvelopeTransport::deposit(
            self,
            endpoint.provider(),
            envelope,
            observation.wall_now_unix_seconds(),
        )
        .map_err(map_local_dispatch_failure)?;
        control.checkpoint(budget)?;
        Ok(DepositReceipt::accepted(delivery_id))
    }
}

fn map_local_dispatch_failure(failure: LocalTransportError) -> TransportFailure {
    match failure {
        LocalTransportError::InvalidPolicy => {
            TransportFailure::new(TransportFailureCode::Misconfigured, RetryAdvice::Never)
        }
        LocalTransportError::Rejected => {
            TransportFailure::new(TransportFailureCode::InvalidAuthority, RetryAdvice::Never)
        }
        LocalTransportError::CapacityExceeded => {
            TransportFailure::new(TransportFailureCode::QueueFull, RetryAdvice::Backoff)
        }
        LocalTransportError::ProviderFailure => {
            TransportFailure::new(TransportFailureCode::Internal, RetryAdvice::Backoff)
        }
    }
}

fn random_nonzero<const N: usize>() -> Result<[u8; N], LocalTransportError> {
    let mut bytes = [0; N];
    rand::fill(&mut bytes).map_err(|_| LocalTransportError::ProviderFailure)?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(LocalTransportError::ProviderFailure);
    }
    Ok(bytes)
}

fn capability_digest(secret: &[u8]) -> [u8; DIGEST_BYTES] {
    domain_digest(CAPABILITY_DIGEST_DOMAIN, secret)
}

fn domain_digest(domain: &[u8], value: &[u8]) -> [u8; DIGEST_BYTES] {
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(domain);
    context.update(value);
    context
        .finish()
        .as_ref()
        .try_into()
        .expect("SHA-256 has a fixed 32-byte output")
}

fn secret_matches(expected_digest: &[u8; DIGEST_BYTES], secret: &[u8]) -> bool {
    let candidate = capability_digest(secret);
    constant_time::verify_slices_are_equal(expected_digest, &candidate).is_ok()
}
