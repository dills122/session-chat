#![forbid(unsafe_code)]

//! Fault-controlled deterministic memory transport for Phase 1 tests.

use std::collections::{BTreeMap, VecDeque};

use aws_lc_rs::{constant_time, digest, rand};
use session_protocol::OpaqueEnvelope;
use session_transport::{DeliveryId, EnvelopeTransport, ReceivedEnvelope};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const IDENTIFIER_BYTES: usize = 16;
const CAPABILITY_BYTES: usize = 32;
const DIGEST_BYTES: usize = 32;
const DEPOSIT_DOMAIN: &[u8] = b"session-chat/memory-transport/deposit/v1\0";
const RECEIVE_DOMAIN: &[u8] = b"session-chat/memory-transport/receive/v1\0";
const ACKNOWLEDGEMENT_DOMAIN: &[u8] = b"session-chat/memory-transport/ack/v1\0";
const ENVELOPE_DOMAIN: &[u8] = b"session-chat/memory-transport/envelope/v1\0";

/// Explicit lifetime, storage, and retry bounds for deterministic mailboxes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryMailboxPolicy {
    maximum_lifetime_seconds: u64,
    maximum_live_mailboxes: usize,
    maximum_envelopes_per_mailbox: usize,
    maximum_delivery_attempts_per_envelope: usize,
    maximum_scheduled_deliveries_per_mailbox: usize,
}

impl MemoryMailboxPolicy {
    /// Creates a fail-closed deterministic transport policy.
    pub fn new(
        maximum_lifetime_seconds: u64,
        maximum_live_mailboxes: usize,
        maximum_envelopes_per_mailbox: usize,
        maximum_delivery_attempts_per_envelope: usize,
    ) -> Result<Self, MemoryTransportError> {
        if maximum_lifetime_seconds == 0
            || maximum_live_mailboxes == 0
            || maximum_envelopes_per_mailbox == 0
            || maximum_delivery_attempts_per_envelope == 0
        {
            return Err(MemoryTransportError::InvalidPolicy);
        }
        let maximum_scheduled_deliveries_per_mailbox = maximum_envelopes_per_mailbox
            .checked_mul(maximum_delivery_attempts_per_envelope)
            .and_then(|value| value.checked_mul(2))
            .ok_or(MemoryTransportError::InvalidPolicy)?;
        Ok(Self {
            maximum_lifetime_seconds,
            maximum_live_mailboxes,
            maximum_envelopes_per_mailbox,
            maximum_delivery_attempts_per_envelope,
            maximum_scheduled_deliveries_per_mailbox,
        })
    }
}

/// Coarse failures from the deterministic memory transport.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MemoryTransportError {
    /// A policy bound was zero or overflowed its derived queue bound.
    #[error("invalid deterministic memory transport policy")]
    InvalidPolicy,
    /// Authority, time, envelope, mailbox, or idempotency validation failed.
    #[error("deterministic memory transport operation rejected")]
    Rejected,
    /// A mailbox, envelope, attempt, action, or delivery queue bound was reached.
    #[error("deterministic memory transport capacity reached")]
    CapacityExceeded,
    /// The reviewed random provider did not return usable unique output.
    #[error("deterministic memory transport provider failed")]
    ProviderFailure,
}

/// One deterministic outcome applied to the next accepted delivery attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryAction {
    /// Make the delivery visible immediately.
    Deliver,
    /// Accept this attempt without making it visible.
    Drop,
    /// Retain the delivery until the test harness releases it.
    Hold,
    /// Schedule two byte-identical visible copies of the same logical delivery.
    Duplicate,
}

/// Sender-only authority for one deterministic mailbox.
pub struct MemoryDepositEndpoint {
    transport_instance_id: [u8; IDENTIFIER_BYTES],
    mailbox_id: [u8; IDENTIFIER_BYTES],
    secret: [u8; CAPABILITY_BYTES],
    expires_at_unix_seconds: u64,
}

impl Drop for MemoryDepositEndpoint {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Receiver-only read authority for one deterministic mailbox.
pub struct MemoryReceiveCapability {
    transport_instance_id: [u8; IDENTIFIER_BYTES],
    mailbox_id: [u8; IDENTIFIER_BYTES],
    secret: [u8; CAPABILITY_BYTES],
    expires_at_unix_seconds: u64,
}

impl Drop for MemoryReceiveCapability {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Receiver-only acknowledgement authority for one deterministic mailbox.
pub struct MemoryAcknowledgementCapability {
    transport_instance_id: [u8; IDENTIFIER_BYTES],
    mailbox_id: [u8; IDENTIFIER_BYTES],
    secret: [u8; CAPABILITY_BYTES],
    expires_at_unix_seconds: u64,
}

impl Drop for MemoryAcknowledgementCapability {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Fresh deterministic-memory mailbox authorities split by operation.
pub struct MemoryMailbox {
    deposit: MemoryDepositEndpoint,
    receive: MemoryReceiveCapability,
    acknowledgement: MemoryAcknowledgementCapability,
}

impl MemoryMailbox {
    /// Separates the sender-facing endpoint from receiver-retained rights.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        MemoryDepositEndpoint,
        MemoryReceiveCapability,
        MemoryAcknowledgementCapability,
    ) {
        (self.deposit, self.receive, self.acknowledgement)
    }
}

struct AcceptedEnvelope {
    envelope_digest: [u8; DIGEST_BYTES],
    delivery_id: DeliveryId,
    envelope: Option<OpaqueEnvelope>,
    attempts: usize,
}

struct MemoryMailboxRecord {
    expires_at_unix_seconds: u64,
    deposit_digest: [u8; DIGEST_BYTES],
    receive_digest: [u8; DIGEST_BYTES],
    acknowledgement_digest: [u8; DIGEST_BYTES],
    accepted: BTreeMap<[u8; IDENTIFIER_BYTES], AcceptedEnvelope>,
    visible: VecDeque<DeliveryId>,
}

/// Bounded memory transport with explicit deterministic fault controls.
pub struct DeterministicMemoryTransport {
    policy: MemoryMailboxPolicy,
    transport_instance_id: [u8; IDENTIFIER_BYTES],
    mailboxes: BTreeMap<[u8; IDENTIFIER_BYTES], MemoryMailboxRecord>,
    actions: VecDeque<DeliveryAction>,
    held: VecDeque<([u8; IDENTIFIER_BYTES], DeliveryId)>,
}

impl DeterministicMemoryTransport {
    /// Creates an empty adapter with a provider-generated instance identifier.
    pub fn new(policy: MemoryMailboxPolicy) -> Result<Self, MemoryTransportError> {
        Ok(Self {
            policy,
            transport_instance_id: random_nonzero()?,
            mailboxes: BTreeMap::new(),
            actions: VecDeque::new(),
            held: VecDeque::new(),
        })
    }

    /// Queues one outcome for the next otherwise valid delivery attempt.
    pub fn queue_action(&mut self, action: DeliveryAction) -> Result<(), MemoryTransportError> {
        if self.actions.len() >= self.policy.maximum_delivery_attempts_per_envelope {
            return Err(MemoryTransportError::CapacityExceeded);
        }
        self.actions.push_back(action);
        Ok(())
    }

    /// Creates one mailbox with independent provider-generated authorities.
    pub fn create_mailbox(
        &mut self,
        expires_at_unix_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<MemoryMailbox, MemoryTransportError> {
        let lifetime = expires_at_unix_seconds
            .checked_sub(now_unix_seconds)
            .ok_or(MemoryTransportError::Rejected)?;
        if lifetime == 0 || lifetime > self.policy.maximum_lifetime_seconds {
            return Err(MemoryTransportError::Rejected);
        }
        let live_count = self
            .mailboxes
            .values()
            .filter(|record| record.expires_at_unix_seconds > now_unix_seconds)
            .count();
        if live_count >= self.policy.maximum_live_mailboxes {
            return Err(MemoryTransportError::CapacityExceeded);
        }

        let mailbox_id: [u8; IDENTIFIER_BYTES] = random_nonzero()?;
        if self.mailboxes.contains_key(&mailbox_id) {
            return Err(MemoryTransportError::ProviderFailure);
        }
        let deposit_secret = Zeroizing::new(random_nonzero::<CAPABILITY_BYTES>()?);
        let receive_secret = Zeroizing::new(random_nonzero::<CAPABILITY_BYTES>()?);
        let acknowledgement_secret = Zeroizing::new(random_nonzero::<CAPABILITY_BYTES>()?);
        if *deposit_secret == *receive_secret
            || *deposit_secret == *acknowledgement_secret
            || *receive_secret == *acknowledgement_secret
        {
            return Err(MemoryTransportError::ProviderFailure);
        }
        let record = MemoryMailboxRecord {
            expires_at_unix_seconds,
            deposit_digest: domain_digest(DEPOSIT_DOMAIN, &deposit_secret[..]),
            receive_digest: domain_digest(RECEIVE_DOMAIN, &receive_secret[..]),
            acknowledgement_digest: domain_digest(
                ACKNOWLEDGEMENT_DOMAIN,
                &acknowledgement_secret[..],
            ),
            accepted: BTreeMap::new(),
            visible: VecDeque::new(),
        };
        self.mailboxes
            .retain(|_, existing| existing.expires_at_unix_seconds > now_unix_seconds);
        self.held.retain(|(held_mailbox_id, _)| {
            self.mailboxes.contains_key(held_mailbox_id) || held_mailbox_id == &mailbox_id
        });
        self.mailboxes.insert(mailbox_id, record);

        Ok(MemoryMailbox {
            deposit: MemoryDepositEndpoint {
                transport_instance_id: self.transport_instance_id,
                mailbox_id,
                secret: *deposit_secret,
                expires_at_unix_seconds,
            },
            receive: MemoryReceiveCapability {
                transport_instance_id: self.transport_instance_id,
                mailbox_id,
                secret: *receive_secret,
                expires_at_unix_seconds,
            },
            acknowledgement: MemoryAcknowledgementCapability {
                transport_instance_id: self.transport_instance_id,
                mailbox_id,
                secret: *acknowledgement_secret,
                expires_at_unix_seconds,
            },
        })
    }

    /// Releases one held attempt by global deterministic insertion index.
    pub fn release_held(
        &mut self,
        index: usize,
        now_unix_seconds: u64,
    ) -> Result<DeliveryId, MemoryTransportError> {
        let (mailbox_id, delivery_id) = self
            .held
            .get(index)
            .copied()
            .ok_or(MemoryTransportError::Rejected)?;
        let record = self
            .mailboxes
            .get(&mailbox_id)
            .ok_or(MemoryTransportError::Rejected)?;
        if record.expires_at_unix_seconds <= now_unix_seconds
            || !delivery_is_live(record, delivery_id, now_unix_seconds)
        {
            return Err(MemoryTransportError::Rejected);
        }
        self.held.remove(index);
        let record = self
            .mailboxes
            .get_mut(&mailbox_id)
            .ok_or(MemoryTransportError::Rejected)?;
        record.visible.push_back(delivery_id);
        Ok(delivery_id)
    }

    fn schedule(
        &mut self,
        mailbox_id: [u8; IDENTIFIER_BYTES],
        delivery_id: DeliveryId,
        action: DeliveryAction,
    ) -> Result<(), MemoryTransportError> {
        let slots = match action {
            DeliveryAction::Deliver | DeliveryAction::Hold => 1,
            DeliveryAction::Duplicate => 2,
            DeliveryAction::Drop => 0,
        };
        let scheduled = self.scheduled_count(&mailbox_id);
        if scheduled.saturating_add(slots) > self.policy.maximum_scheduled_deliveries_per_mailbox {
            return Err(MemoryTransportError::CapacityExceeded);
        }
        match action {
            DeliveryAction::Deliver => self
                .mailboxes
                .get_mut(&mailbox_id)
                .ok_or(MemoryTransportError::Rejected)?
                .visible
                .push_back(delivery_id),
            DeliveryAction::Drop => {}
            DeliveryAction::Hold => self.held.push_back((mailbox_id, delivery_id)),
            DeliveryAction::Duplicate => {
                let record = self
                    .mailboxes
                    .get_mut(&mailbox_id)
                    .ok_or(MemoryTransportError::Rejected)?;
                record.visible.push_back(delivery_id);
                record.visible.push_back(delivery_id);
            }
        }
        Ok(())
    }

    fn scheduled_count(&self, mailbox_id: &[u8; IDENTIFIER_BYTES]) -> usize {
        let visible = self
            .mailboxes
            .get(mailbox_id)
            .map_or(0, |record| record.visible.len());
        visible
            + self
                .held
                .iter()
                .filter(|(held_mailbox_id, _)| held_mailbox_id == mailbox_id)
                .count()
    }
}

impl EnvelopeTransport for DeterministicMemoryTransport {
    type DepositEndpoint = MemoryDepositEndpoint;
    type ReceiveCapability = MemoryReceiveCapability;
    type AcknowledgementCapability = MemoryAcknowledgementCapability;
    type Error = MemoryTransportError;

    fn deposit(
        &mut self,
        endpoint: &Self::DepositEndpoint,
        envelope: OpaqueEnvelope,
        now_unix_seconds: u64,
    ) -> Result<DeliveryId, Self::Error> {
        if endpoint.transport_instance_id != self.transport_instance_id
            || endpoint.expires_at_unix_seconds <= now_unix_seconds
            || envelope.expires_at_unix_seconds() <= now_unix_seconds
            || envelope.expires_at_unix_seconds() > endpoint.expires_at_unix_seconds
            || envelope.envelope_id().iter().all(|byte| *byte == 0)
        {
            return Err(MemoryTransportError::Rejected);
        }
        let encoded = envelope
            .encode_canonical()
            .map_err(|_| MemoryTransportError::Rejected)?;
        let envelope_digest = domain_digest(ENVELOPE_DOMAIN, &encoded);
        let envelope_id = *envelope.envelope_id();
        let action = self
            .actions
            .front()
            .copied()
            .unwrap_or(DeliveryAction::Deliver);
        let required_slots = match action {
            DeliveryAction::Deliver | DeliveryAction::Hold => 1,
            DeliveryAction::Duplicate => 2,
            DeliveryAction::Drop => 0,
        };
        if self
            .scheduled_count(&endpoint.mailbox_id)
            .saturating_add(required_slots)
            > self.policy.maximum_scheduled_deliveries_per_mailbox
        {
            return Err(MemoryTransportError::CapacityExceeded);
        }

        let delivery_id = {
            let record = self
                .mailboxes
                .get_mut(&endpoint.mailbox_id)
                .ok_or(MemoryTransportError::Rejected)?;
            if record.expires_at_unix_seconds != endpoint.expires_at_unix_seconds
                || !secret_matches(DEPOSIT_DOMAIN, &record.deposit_digest, &endpoint.secret)
            {
                return Err(MemoryTransportError::Rejected);
            }
            if let Some(accepted) = record.accepted.get_mut(&envelope_id) {
                if constant_time::verify_slices_are_equal(
                    &accepted.envelope_digest,
                    &envelope_digest,
                )
                .is_err()
                {
                    return Err(MemoryTransportError::Rejected);
                }
                if accepted.envelope.is_none() {
                    return Ok(accepted.delivery_id);
                }
                if accepted.attempts >= self.policy.maximum_delivery_attempts_per_envelope {
                    return Err(MemoryTransportError::CapacityExceeded);
                }
                accepted.attempts += 1;
                accepted.delivery_id
            } else {
                if record.accepted.len() >= self.policy.maximum_envelopes_per_mailbox {
                    return Err(MemoryTransportError::CapacityExceeded);
                }
                let delivery_id = DeliveryId::from_provider_bytes(random_nonzero()?)
                    .ok_or(MemoryTransportError::ProviderFailure)?;
                if record
                    .accepted
                    .values()
                    .any(|accepted| accepted.delivery_id == delivery_id)
                {
                    return Err(MemoryTransportError::ProviderFailure);
                }
                record.accepted.insert(
                    envelope_id,
                    AcceptedEnvelope {
                        envelope_digest,
                        delivery_id,
                        envelope: Some(envelope),
                        attempts: 1,
                    },
                );
                delivery_id
            }
        };
        if !self.actions.is_empty() {
            self.actions.pop_front();
        }
        self.schedule(endpoint.mailbox_id, delivery_id, action)?;
        Ok(delivery_id)
    }

    fn receive(
        &mut self,
        authority: &Self::ReceiveCapability,
        now_unix_seconds: u64,
    ) -> Result<Option<ReceivedEnvelope>, Self::Error> {
        if authority.transport_instance_id != self.transport_instance_id
            || authority.expires_at_unix_seconds <= now_unix_seconds
        {
            return Err(MemoryTransportError::Rejected);
        }
        let record = self
            .mailboxes
            .get_mut(&authority.mailbox_id)
            .ok_or(MemoryTransportError::Rejected)?;
        if record.expires_at_unix_seconds != authority.expires_at_unix_seconds
            || !secret_matches(RECEIVE_DOMAIN, &record.receive_digest, &authority.secret)
        {
            return Err(MemoryTransportError::Rejected);
        }
        loop {
            let Some(delivery_id) = record.visible.pop_front() else {
                return Ok(None);
            };
            let Some(accepted) = record
                .accepted
                .values_mut()
                .find(|accepted| accepted.delivery_id == delivery_id)
            else {
                continue;
            };
            let Some(envelope) = accepted.envelope.as_ref() else {
                continue;
            };
            if envelope.expires_at_unix_seconds() <= now_unix_seconds {
                accepted.envelope = None;
                record.visible.retain(|candidate| *candidate != delivery_id);
                continue;
            }
            return Ok(Some(ReceivedEnvelope::new(delivery_id, envelope.clone())));
        }
    }

    fn acknowledge(
        &mut self,
        authority: &Self::AcknowledgementCapability,
        delivery_id: DeliveryId,
        now_unix_seconds: u64,
    ) -> Result<(), Self::Error> {
        if authority.transport_instance_id != self.transport_instance_id
            || authority.expires_at_unix_seconds <= now_unix_seconds
        {
            return Err(MemoryTransportError::Rejected);
        }
        {
            let record = self
                .mailboxes
                .get_mut(&authority.mailbox_id)
                .ok_or(MemoryTransportError::Rejected)?;
            if record.expires_at_unix_seconds != authority.expires_at_unix_seconds
                || !secret_matches(
                    ACKNOWLEDGEMENT_DOMAIN,
                    &record.acknowledgement_digest,
                    &authority.secret,
                )
            {
                return Err(MemoryTransportError::Rejected);
            }
            let accepted = record
                .accepted
                .values_mut()
                .find(|accepted| accepted.delivery_id == delivery_id)
                .ok_or(MemoryTransportError::Rejected)?;
            accepted.envelope = None;
            record.visible.retain(|candidate| *candidate != delivery_id);
        }
        self.held.retain(|(mailbox_id, candidate)| {
            mailbox_id != &authority.mailbox_id || *candidate != delivery_id
        });
        Ok(())
    }
}

fn delivery_is_live(
    record: &MemoryMailboxRecord,
    delivery_id: DeliveryId,
    now_unix_seconds: u64,
) -> bool {
    record.accepted.values().any(|accepted| {
        accepted.delivery_id == delivery_id
            && accepted
                .envelope
                .as_ref()
                .is_some_and(|envelope| envelope.expires_at_unix_seconds() > now_unix_seconds)
    })
}

fn random_nonzero<const N: usize>() -> Result<[u8; N], MemoryTransportError> {
    let mut bytes = [0; N];
    rand::fill(&mut bytes).map_err(|_| MemoryTransportError::ProviderFailure)?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(MemoryTransportError::ProviderFailure);
    }
    Ok(bytes)
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

fn secret_matches(domain: &[u8], expected_digest: &[u8; DIGEST_BYTES], secret: &[u8]) -> bool {
    let candidate = domain_digest(domain, secret);
    constant_time::verify_slices_are_equal(expected_digest, &candidate).is_ok()
}
