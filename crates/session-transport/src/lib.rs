#![forbid(unsafe_code)]

//! Right-specific transport contracts and deterministic local adapters.

mod contract;

pub use contract::{
    AdapterId, BoundedRetryDelay, CanonicalEnvelope, EnvelopeId, MAX_ADAPTER_ID_BYTES,
    MAX_RETRY_DELAY_SECONDS, OperationBudget, RetryAdvice, TransportContractError,
    TransportFailure, TransportFailureCode, TransportProfileId,
};

use std::collections::BTreeMap;

use aws_lc_rs::{constant_time, digest, rand};
use session_protocol::{DepositCapability, LocalWelcomeDepositEndpoint, OpaqueEnvelope};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

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

/// One received opaque envelope paired with its untrusted delivery identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedEnvelope {
    delivery_id: DeliveryId,
    envelope: OpaqueEnvelope,
}

impl ReceivedEnvelope {
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

/// Joiner-only authority for reading one local Welcome mailbox.
///
/// This secret-bearing type intentionally does not implement `Clone`, `Debug`,
/// or `Display`.
pub struct LocalWelcomeReceiveCapability {
    transport_instance_id: [u8; IDENTIFIER_BYTES],
    mailbox_id: [u8; IDENTIFIER_BYTES],
    secret: [u8; CAPABILITY_BYTES],
    expires_at_unix_seconds: u64,
}

impl Drop for LocalWelcomeReceiveCapability {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Joiner-only authority for deleting one local Welcome delivery.
///
/// This secret-bearing type intentionally does not implement `Clone`, `Debug`,
/// or `Display`.
pub struct LocalWelcomeAcknowledgementCapability {
    transport_instance_id: [u8; IDENTIFIER_BYTES],
    mailbox_id: [u8; IDENTIFIER_BYTES],
    secret: [u8; CAPABILITY_BYTES],
    expires_at_unix_seconds: u64,
}

impl Drop for LocalWelcomeAcknowledgementCapability {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Fresh local mailbox authorities split by operation.
///
/// Only the deposit endpoint is intended to enter a protected join request.
pub struct LocalWelcomeMailbox {
    deposit: LocalWelcomeDepositEndpoint,
    receive: LocalWelcomeReceiveCapability,
    acknowledgement: LocalWelcomeAcknowledgementCapability,
}

impl LocalWelcomeMailbox {
    /// Separates the sender-facing endpoint from joiner-retained rights.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        LocalWelcomeDepositEndpoint,
        LocalWelcomeReceiveCapability,
        LocalWelcomeAcknowledgementCapability,
    ) {
        (self.deposit, self.receive, self.acknowledgement)
    }
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
        let receive = LocalWelcomeReceiveCapability {
            transport_instance_id: self.transport_instance_id,
            mailbox_id,
            secret: *receive_secret,
            expires_at_unix_seconds,
        };
        let acknowledgement = LocalWelcomeAcknowledgementCapability {
            transport_instance_id: self.transport_instance_id,
            mailbox_id,
            secret: *acknowledgement_secret,
            expires_at_unix_seconds,
        };

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
        Ok(LocalWelcomeMailbox {
            deposit,
            receive,
            acknowledgement,
        })
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
        if authority.transport_instance_id != self.transport_instance_id
            || authority.expires_at_unix_seconds <= now_unix_seconds
        {
            return Err(LocalTransportError::Rejected);
        }
        let record = self
            .mailboxes
            .get_mut(&authority.mailbox_id)
            .ok_or(LocalTransportError::Rejected)?;
        if record.expires_at_unix_seconds != authority.expires_at_unix_seconds
            || !secret_matches(&record.receive_digest, &authority.secret)
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
        if authority.transport_instance_id != self.transport_instance_id
            || authority.expires_at_unix_seconds <= now_unix_seconds
        {
            return Err(LocalTransportError::Rejected);
        }
        let record = self
            .mailboxes
            .get_mut(&authority.mailbox_id)
            .ok_or(LocalTransportError::Rejected)?;
        if record.expires_at_unix_seconds != authority.expires_at_unix_seconds
            || !secret_matches(&record.acknowledgement_digest, &authority.secret)
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
