#![forbid(unsafe_code)]

//! Fault-controlled deterministic memory transport for Phase 1 tests.

use std::collections::{BTreeMap, VecDeque};

use aws_lc_rs::{constant_time, digest, rand};
use session_protocol::OpaqueEnvelope;
use session_transport::{
    AcknowledgementReceipt, AcknowledgementRequest, AcknowledgementRight, CanonicalEnvelope,
    DeliveryId, DepositReceipt, DepositRequest, DepositRight, DispatchControl, EnvelopeDelivery,
    EnvelopeTransport, PollRequest, ReceiveBatch, ReceiveRight, ReceivedCanonicalEnvelope,
    ReceivedEnvelope, RetryAdvice, TransportFailure, TransportFailureCode,
};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const IDENTIFIER_BYTES: usize = 16;
const CAPABILITY_BYTES: usize = 32;
const DIGEST_BYTES: usize = 32;
const DEPOSIT_DOMAIN: &[u8] = b"session-chat/memory-transport/deposit/v1\0";
const RECEIVE_DOMAIN: &[u8] = b"session-chat/memory-transport/receive/v1\0";
const ACKNOWLEDGEMENT_DOMAIN: &[u8] = b"session-chat/memory-transport/ack/v1\0";
const ENVELOPE_DOMAIN: &[u8] = b"session-chat/memory-transport/envelope/v1\0";

/// Maximum lifetime accepted by the deterministic memory-only profile.
pub const MAX_MEMORY_MAILBOX_LIFETIME_SECONDS: u64 = 24 * 60 * 60;
/// Maximum simultaneously live mailboxes accepted by one memory adapter.
pub const MAX_MEMORY_LIVE_MAILBOXES: usize = 64;
/// Maximum logical envelopes retained by one deterministic mailbox.
pub const MAX_MEMORY_ENVELOPES_PER_MAILBOX: usize = 64;
/// Maximum accepted delivery attempts for one logical memory envelope.
pub const MAX_MEMORY_DELIVERY_ATTEMPTS_PER_ENVELOPE: usize = 64;
/// Maximum live canonical envelope bytes retained by one memory mailbox.
pub const MAX_MEMORY_RETAINED_CANONICAL_BYTES_PER_MAILBOX: usize = 4 * 1024 * 1024;

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
            || maximum_lifetime_seconds > MAX_MEMORY_MAILBOX_LIFETIME_SECONDS
            || maximum_live_mailboxes == 0
            || maximum_live_mailboxes > MAX_MEMORY_LIVE_MAILBOXES
            || maximum_envelopes_per_mailbox == 0
            || maximum_envelopes_per_mailbox > MAX_MEMORY_ENVELOPES_PER_MAILBOX
            || maximum_delivery_attempts_per_envelope == 0
            || maximum_delivery_attempts_per_envelope > MAX_MEMORY_DELIVERY_ATTEMPTS_PER_ENVELOPE
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

/// Persistent availability selected by the deterministic adverse controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryAvailability {
    Available,
    Unavailable,
}

/// One-shot acknowledgement-result loss selected by the adverse controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcknowledgementLoss {
    /// Fail before deleting any retained provider state.
    BeforeCommit,
    /// Delete the exact set, then lose the success result.
    AfterCommit,
}

/// Secret-free counts exposed only to deterministic conformance tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryConformanceSnapshot {
    live_envelopes: usize,
    live_encoded_bytes: usize,
    visible_copies: usize,
    held_copies: usize,
    queued_delivery_actions: usize,
    queued_stale_replays: usize,
    corrupt_poll_armed: bool,
    acknowledgement_loss_armed: bool,
    availability: MemoryAvailability,
}

impl MemoryConformanceSnapshot {
    #[must_use]
    pub const fn live_envelopes(self) -> usize {
        self.live_envelopes
    }

    #[must_use]
    pub const fn live_encoded_bytes(self) -> usize {
        self.live_encoded_bytes
    }

    #[must_use]
    pub const fn visible_copies(self) -> usize {
        self.visible_copies
    }

    #[must_use]
    pub const fn held_copies(self) -> usize {
        self.held_copies
    }

    #[must_use]
    pub const fn queued_delivery_actions(self) -> usize {
        self.queued_delivery_actions
    }

    #[must_use]
    pub const fn queued_stale_replays(self) -> usize {
        self.queued_stale_replays
    }

    #[must_use]
    pub const fn corrupt_poll_armed(self) -> bool {
        self.corrupt_poll_armed
    }

    #[must_use]
    pub const fn acknowledgement_loss_armed(self) -> bool {
        self.acknowledgement_loss_armed
    }

    #[must_use]
    pub const fn availability(self) -> MemoryAvailability {
        self.availability
    }
}

/// Sender-only authority for one deterministic mailbox.
///
/// ```compile_fail
/// use transport_memory::MemoryDepositEndpoint;
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<MemoryDepositEndpoint>();
/// ```
///
/// ```compile_fail
/// use transport_memory::MemoryDepositEndpoint;
/// fn require_clone<T: Clone>() {}
/// require_clone::<MemoryDepositEndpoint>();
/// ```
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
///
/// ```compile_fail
/// use transport_memory::MemoryReceiveCapability;
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<MemoryReceiveCapability>();
/// ```
///
/// ```compile_fail
/// use transport_memory::MemoryReceiveCapability;
/// fn require_clone<T: Clone>() {}
/// require_clone::<MemoryReceiveCapability>();
/// ```
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
///
/// ```compile_fail
/// use transport_memory::MemoryAcknowledgementCapability;
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<MemoryAcknowledgementCapability>();
/// ```
///
/// ```compile_fail
/// use transport_memory::MemoryAcknowledgementCapability;
/// fn require_clone<T: Clone>() {}
/// require_clone::<MemoryAcknowledgementCapability>();
/// ```
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

    /// Seals the provider material in non-interchangeable generalized rights.
    #[must_use]
    pub fn into_dispatch_parts(
        self,
    ) -> (
        DepositRight<MemoryDepositEndpoint>,
        ReceiveRight<MemoryReceiveCapability>,
        AcknowledgementRight<MemoryAcknowledgementCapability>,
    ) {
        (
            DepositRight::from_provider(self.deposit),
            ReceiveRight::from_provider(self.receive),
            AcknowledgementRight::from_provider(self.acknowledgement),
        )
    }
}

struct AcceptedEnvelope {
    envelope_digest: [u8; DIGEST_BYTES],
    encoded_len: usize,
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

struct StaleReplay {
    mailbox_id: [u8; IDENTIFIER_BYTES],
    delivery_id: DeliveryId,
    envelope: OpaqueEnvelope,
    encoded_len: usize,
}

#[derive(Clone, Copy)]
struct CorruptPollTarget {
    mailbox_id: [u8; IDENTIFIER_BYTES],
    delivery_id: DeliveryId,
}

/// Bounded memory transport with explicit deterministic fault controls.
pub struct DeterministicMemoryTransport {
    policy: MemoryMailboxPolicy,
    transport_instance_id: [u8; IDENTIFIER_BYTES],
    mailboxes: BTreeMap<[u8; IDENTIFIER_BYTES], MemoryMailboxRecord>,
    actions: VecDeque<DeliveryAction>,
    held: VecDeque<([u8; IDENTIFIER_BYTES], DeliveryId)>,
    stale_replays: VecDeque<StaleReplay>,
    availability: MemoryAvailability,
    corrupt_next_poll: Option<CorruptPollTarget>,
    acknowledgement_loss: Option<AcknowledgementLoss>,
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
            stale_replays: VecDeque::new(),
            availability: MemoryAvailability::Available,
            corrupt_next_poll: None,
            acknowledgement_loss: None,
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

    /// Selects persistent availability without changing queued one-shot faults.
    pub const fn set_availability(&mut self, availability: MemoryAvailability) {
        self.availability = availability;
    }

    /// Arms one normalized corrupt-response result for a known visible delivery.
    pub fn corrupt_next_poll(
        &mut self,
        authority: &ReceiveRight<MemoryReceiveCapability>,
        delivery_id: DeliveryId,
    ) -> Result<(), MemoryTransportError> {
        if self.corrupt_next_poll.is_some() {
            return Err(MemoryTransportError::CapacityExceeded);
        }
        let authority = authority.provider();
        let record = self.fault_mailbox(authority)?;
        let visible = record.visible.contains(&delivery_id);
        let stale_visible = self.stale_replays.iter().any(|replay| {
            replay.mailbox_id == authority.mailbox_id && replay.delivery_id == delivery_id
        });
        if !visible && !stale_visible {
            return Err(MemoryTransportError::Rejected);
        }
        self.corrupt_next_poll = Some(CorruptPollTarget {
            mailbox_id: authority.mailbox_id,
            delivery_id,
        });
        Ok(())
    }

    /// Injects one explicit stale provider replay without restoring accepted state.
    pub fn replay_stale(
        &mut self,
        authority: &ReceiveRight<MemoryReceiveCapability>,
        delivery_id: DeliveryId,
        envelope: OpaqueEnvelope,
    ) -> Result<(), MemoryTransportError> {
        let encoded = envelope
            .encode_canonical()
            .map_err(|_| MemoryTransportError::Rejected)?;
        let digest = domain_digest(ENVELOPE_DOMAIN, &encoded);
        let authority = authority.provider();
        let record = self.fault_mailbox(authority)?;
        record
            .accepted
            .values()
            .find(|accepted| accepted.delivery_id == delivery_id)
            .filter(|accepted| {
                constant_time::verify_slices_are_equal(&accepted.envelope_digest, &digest).is_ok()
            })
            .ok_or(MemoryTransportError::Rejected)?;
        if self.stale_replays.len() >= self.policy.maximum_scheduled_deliveries_per_mailbox {
            return Err(MemoryTransportError::CapacityExceeded);
        }
        let retained_bytes = self
            .stale_replays
            .iter()
            .try_fold(0_usize, |total, replay| {
                total.checked_add(replay.encoded_len)
            })
            .ok_or(MemoryTransportError::CapacityExceeded)?;
        if retained_bytes
            .checked_add(encoded.len())
            .is_none_or(|total| total > MAX_MEMORY_RETAINED_CANONICAL_BYTES_PER_MAILBOX)
        {
            return Err(MemoryTransportError::CapacityExceeded);
        }
        self.stale_replays.push_back(StaleReplay {
            mailbox_id: authority.mailbox_id,
            delivery_id,
            envelope,
            encoded_len: encoded.len(),
        });
        Ok(())
    }

    fn fault_mailbox(
        &self,
        authority: &MemoryReceiveCapability,
    ) -> Result<&MemoryMailboxRecord, MemoryTransportError> {
        let record = self
            .mailboxes
            .get(&authority.mailbox_id)
            .ok_or(MemoryTransportError::Rejected)?;
        if authority.transport_instance_id != self.transport_instance_id
            || record.expires_at_unix_seconds != authority.expires_at_unix_seconds
            || !secret_matches(RECEIVE_DOMAIN, &record.receive_digest, &authority.secret)
        {
            return Err(MemoryTransportError::Rejected);
        }
        Ok(record)
    }

    /// Arms one bounded acknowledgement-result loss.
    pub fn lose_next_acknowledgement(
        &mut self,
        loss: AcknowledgementLoss,
    ) -> Result<(), MemoryTransportError> {
        if self.acknowledgement_loss.is_some() {
            return Err(MemoryTransportError::CapacityExceeded);
        }
        self.acknowledgement_loss = Some(loss);
        Ok(())
    }

    /// Returns only bounded counts and fault enums, never provider identifiers.
    #[must_use]
    pub fn conformance_snapshot(&self) -> MemoryConformanceSnapshot {
        let live_envelopes = self
            .mailboxes
            .values()
            .flat_map(|record| record.accepted.values())
            .filter(|accepted| accepted.envelope.is_some())
            .count();
        let live_encoded_bytes = self
            .mailboxes
            .values()
            .flat_map(|record| record.accepted.values())
            .filter(|accepted| accepted.envelope.is_some())
            .map(|accepted| accepted.encoded_len)
            .sum();
        MemoryConformanceSnapshot {
            live_envelopes,
            live_encoded_bytes,
            visible_copies: self
                .mailboxes
                .values()
                .map(|record| record.visible.len())
                .sum(),
            held_copies: self.held.len(),
            queued_delivery_actions: self.actions.len(),
            queued_stale_replays: self.stale_replays.len(),
            corrupt_poll_armed: self.corrupt_next_poll.is_some(),
            acknowledgement_loss_armed: self.acknowledgement_loss.is_some(),
            availability: self.availability,
        }
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
        self.stale_replays
            .retain(|replay| self.mailboxes.contains_key(&replay.mailbox_id));
        if self
            .corrupt_next_poll
            .is_some_and(|target| !self.mailboxes.contains_key(&target.mailbox_id))
        {
            self.corrupt_next_poll = None;
        }
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
                let retained_encoded_bytes = record
                    .accepted
                    .values()
                    .filter(|accepted| accepted.envelope.is_some())
                    .try_fold(0_usize, |total, accepted| {
                        total.checked_add(accepted.encoded_len)
                    })
                    .ok_or(MemoryTransportError::CapacityExceeded)?;
                if retained_encoded_bytes
                    .checked_add(encoded.len())
                    .is_none_or(|total| total > MAX_MEMORY_RETAINED_CANONICAL_BYTES_PER_MAILBOX)
                {
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
                        encoded_len: encoded.len(),
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
        self.stale_replays.retain(|replay| {
            replay.mailbox_id != authority.mailbox_id || replay.delivery_id != delivery_id
        });
        if self.corrupt_next_poll.is_some_and(|target| {
            target.mailbox_id == authority.mailbox_id && target.delivery_id == delivery_id
        }) {
            self.corrupt_next_poll = None;
        }
        Ok(())
    }
}

impl EnvelopeDelivery for DeterministicMemoryTransport {
    type DepositEndpoint = MemoryDepositEndpoint;
    type ReceiveCapability = MemoryReceiveCapability;
    type AcknowledgementCapability = MemoryAcknowledgementCapability;

    async fn deposit(
        &mut self,
        endpoint: &DepositRight<Self::DepositEndpoint>,
        request: DepositRequest,
        control: &dyn DispatchControl,
    ) -> Result<DepositReceipt, TransportFailure> {
        let endpoint = endpoint.provider();
        let budget = request.budget();
        let observation = control.checkpoint(budget)?;
        let now_unix_seconds = observation.wall_now_unix_seconds();
        if self.availability == MemoryAvailability::Unavailable {
            return Err(transport_failure(TransportFailureCode::Unavailable));
        }
        let (canonical, _) = request.into_parts();
        if canonical.expires_at_unix_seconds() <= now_unix_seconds
            || canonical.expires_at_unix_seconds() > endpoint.expires_at_unix_seconds
        {
            return Err(transport_failure(TransportFailureCode::ExpiredEnvelope));
        }
        let record = self
            .mailboxes
            .get(&endpoint.mailbox_id)
            .ok_or_else(|| transport_failure(TransportFailureCode::InvalidAuthority))?;
        if endpoint.transport_instance_id != self.transport_instance_id
            || endpoint.expires_at_unix_seconds <= now_unix_seconds
            || record.expires_at_unix_seconds != endpoint.expires_at_unix_seconds
            || !secret_matches(DEPOSIT_DOMAIN, &record.deposit_digest, &endpoint.secret)
        {
            return Err(transport_failure(TransportFailureCode::InvalidAuthority));
        }
        let envelope_digest = domain_digest(ENVELOPE_DOMAIN, canonical.as_bytes());
        if record
            .accepted
            .get(canonical.envelope_id().as_bytes())
            .is_some_and(|accepted| {
                constant_time::verify_slices_are_equal(&accepted.envelope_digest, &envelope_digest)
                    .is_err()
            })
        {
            return Err(transport_failure(TransportFailureCode::IdempotencyConflict));
        }
        let envelope = OpaqueEnvelope::decode_canonical(canonical.as_bytes())
            .map_err(|_| transport_failure(TransportFailureCode::CorruptRemoteResponse))?;
        let delivery_id = EnvelopeTransport::deposit(self, endpoint, envelope, now_unix_seconds)
            .map_err(map_memory_failure)?;
        control.checkpoint(budget)?;
        Ok(DepositReceipt::accepted(delivery_id))
    }

    async fn poll(
        &mut self,
        authority: &ReceiveRight<Self::ReceiveCapability>,
        request: PollRequest,
        control: &dyn DispatchControl,
    ) -> Result<ReceiveBatch, TransportFailure> {
        let authority = authority.provider();
        let observation = control.checkpoint(request.budget())?;
        let now_unix_seconds = observation.wall_now_unix_seconds();
        if self.availability == MemoryAvailability::Unavailable {
            return Err(transport_failure(TransportFailureCode::Unavailable));
        }
        let record = self
            .mailboxes
            .get(&authority.mailbox_id)
            .ok_or_else(|| transport_failure(TransportFailureCode::InvalidAuthority))?;
        if authority.transport_instance_id != self.transport_instance_id
            || authority.expires_at_unix_seconds <= now_unix_seconds
            || record.expires_at_unix_seconds != authority.expires_at_unix_seconds
            || !secret_matches(RECEIVE_DOMAIN, &record.receive_digest, &authority.secret)
        {
            return Err(transport_failure(TransportFailureCode::InvalidAuthority));
        }
        if request.cursor().is_some() {
            return Err(transport_failure(TransportFailureCode::InvalidCursor));
        }
        let corrupt_target_is_visible = self.corrupt_next_poll.is_some_and(|target| {
            target.mailbox_id == authority.mailbox_id
                && (record.visible.contains(&target.delivery_id)
                    || self.stale_replays.iter().any(|replay| {
                        replay.mailbox_id == authority.mailbox_id
                            && replay.delivery_id == target.delivery_id
                    }))
        });
        if corrupt_target_is_visible {
            self.corrupt_next_poll = None;
            return Err(transport_failure(
                TransportFailureCode::CorruptRemoteResponse,
            ));
        }

        let mut items: Vec<ReceivedCanonicalEnvelope> =
            Vec::with_capacity(usize::from(request.max_envelopes()));
        let mut consumed_prefix = 0_usize;
        let mut consumed_stale_indices = Vec::new();
        let mut expired_ids = Vec::new();
        let mut encoded_bytes = 0_usize;
        for delivery_id in record
            .visible
            .iter()
            .take(usize::from(request.max_envelopes()))
        {
            consumed_prefix += 1;
            let Some(accepted) = record
                .accepted
                .values()
                .find(|accepted| accepted.delivery_id == *delivery_id)
            else {
                continue;
            };
            let Some(envelope) = accepted.envelope.as_ref() else {
                continue;
            };
            if items.iter().any(|item| item.delivery_id() == delivery_id) {
                continue;
            }
            if envelope.expires_at_unix_seconds() <= now_unix_seconds {
                expired_ids.push(*delivery_id);
                continue;
            }
            let canonical = CanonicalEnvelope::from_opaque(envelope.clone())
                .map_err(|_| transport_failure(TransportFailureCode::CorruptRemoteResponse))?;
            let next_encoded_bytes = encoded_bytes
                .checked_add(canonical.as_bytes().len())
                .ok_or_else(|| transport_failure(TransportFailureCode::EnvelopeTooLarge))?;
            if next_encoded_bytes
                > usize::try_from(request.max_encoded_bytes())
                    .map_err(|_| transport_failure(TransportFailureCode::EnvelopeTooLarge))?
            {
                consumed_prefix -= 1;
                if items.is_empty() {
                    return Err(transport_failure(TransportFailureCode::EnvelopeTooLarge));
                }
                break;
            }
            encoded_bytes = next_encoded_bytes;
            items.push(ReceivedCanonicalEnvelope::new(*delivery_id, canonical));
        }

        if items.len() < usize::from(request.max_envelopes()) {
            for (index, replay) in self.stale_replays.iter().enumerate() {
                if replay.mailbox_id != authority.mailbox_id {
                    continue;
                }
                if items.len() >= usize::from(request.max_envelopes()) {
                    break;
                }
                if replay.envelope.expires_at_unix_seconds() <= now_unix_seconds {
                    consumed_stale_indices.push(index);
                    continue;
                }
                let canonical = CanonicalEnvelope::from_opaque(replay.envelope.clone())
                    .map_err(|_| transport_failure(TransportFailureCode::CorruptRemoteResponse))?;
                if let Some(existing) = items
                    .iter()
                    .find(|item| item.delivery_id() == &replay.delivery_id)
                {
                    if existing.envelope().as_bytes() != canonical.as_bytes() {
                        return Err(transport_failure(
                            TransportFailureCode::CorruptRemoteResponse,
                        ));
                    }
                    consumed_stale_indices.push(index);
                    continue;
                }
                let next_encoded_bytes = encoded_bytes
                    .checked_add(canonical.as_bytes().len())
                    .ok_or_else(|| transport_failure(TransportFailureCode::EnvelopeTooLarge))?;
                if next_encoded_bytes
                    > usize::try_from(request.max_encoded_bytes())
                        .map_err(|_| transport_failure(TransportFailureCode::EnvelopeTooLarge))?
                {
                    if items.is_empty() {
                        return Err(transport_failure(TransportFailureCode::EnvelopeTooLarge));
                    }
                    break;
                }
                encoded_bytes = next_encoded_bytes;
                items.push(ReceivedCanonicalEnvelope::new(
                    replay.delivery_id,
                    canonical,
                ));
                consumed_stale_indices.push(index);
            }
        }

        let final_observation = control.checkpoint(request.budget())?;
        let final_wall_now_unix_seconds =
            now_unix_seconds.max(final_observation.wall_now_unix_seconds());
        items.retain(|item| {
            if item.envelope().expires_at_unix_seconds() <= final_wall_now_unix_seconds {
                expired_ids.push(*item.delivery_id());
                false
            } else {
                true
            }
        });
        let batch = ReceiveBatch::new(items, None, &request, final_wall_now_unix_seconds)
            .map_err(|_| transport_failure(TransportFailureCode::CorruptRemoteResponse))?;
        let record = self
            .mailboxes
            .get_mut(&authority.mailbox_id)
            .ok_or_else(|| transport_failure(TransportFailureCode::Internal))?;
        for _ in 0..consumed_prefix {
            record.visible.pop_front();
        }
        for delivery_id in expired_ids {
            if let Some(accepted) = record
                .accepted
                .values_mut()
                .find(|accepted| accepted.delivery_id == delivery_id)
            {
                accepted.envelope = None;
            }
            if self.corrupt_next_poll.is_some_and(|target| {
                target.mailbox_id == authority.mailbox_id && target.delivery_id == delivery_id
            }) {
                self.corrupt_next_poll = None;
            }
        }
        for index in consumed_stale_indices.into_iter().rev() {
            self.stale_replays.remove(index);
        }
        Ok(batch)
    }

    async fn acknowledge(
        &mut self,
        authority: &AcknowledgementRight<Self::AcknowledgementCapability>,
        request: AcknowledgementRequest,
        control: &dyn DispatchControl,
    ) -> Result<AcknowledgementReceipt, TransportFailure> {
        let authority = authority.provider();
        let observation = control.checkpoint(request.budget())?;
        let now_unix_seconds = observation.wall_now_unix_seconds();
        if self.availability == MemoryAvailability::Unavailable {
            return Err(transport_failure(TransportFailureCode::Unavailable));
        }
        let record = self
            .mailboxes
            .get(&authority.mailbox_id)
            .ok_or_else(|| transport_failure(TransportFailureCode::InvalidAuthority))?;
        if authority.transport_instance_id != self.transport_instance_id
            || authority.expires_at_unix_seconds <= now_unix_seconds
            || record.expires_at_unix_seconds != authority.expires_at_unix_seconds
            || !secret_matches(
                ACKNOWLEDGEMENT_DOMAIN,
                &record.acknowledgement_digest,
                &authority.secret,
            )
        {
            return Err(transport_failure(TransportFailureCode::InvalidAuthority));
        }
        let final_observation = control.checkpoint(request.budget())?;
        let final_wall_now_unix_seconds =
            now_unix_seconds.max(final_observation.wall_now_unix_seconds());
        let record = self
            .mailboxes
            .get(&authority.mailbox_id)
            .ok_or_else(|| transport_failure(TransportFailureCode::InvalidAuthority))?;
        if authority.expires_at_unix_seconds <= final_wall_now_unix_seconds
            || record.expires_at_unix_seconds != authority.expires_at_unix_seconds
            || !secret_matches(
                ACKNOWLEDGEMENT_DOMAIN,
                &record.acknowledgement_digest,
                &authority.secret,
            )
        {
            return Err(transport_failure(TransportFailureCode::InvalidAuthority));
        }
        let acknowledgement_loss = self.acknowledgement_loss.take();
        if acknowledgement_loss == Some(AcknowledgementLoss::BeforeCommit) {
            return Err(transport_failure(TransportFailureCode::Unavailable));
        }
        let (delivery_ids, _) = request.into_parts();
        let record = self
            .mailboxes
            .get_mut(&authority.mailbox_id)
            .ok_or_else(|| transport_failure(TransportFailureCode::Internal))?;
        for delivery_id in delivery_ids.as_slice() {
            if let Some(accepted) = record
                .accepted
                .values_mut()
                .find(|accepted| accepted.delivery_id == *delivery_id)
            {
                accepted.envelope = None;
            }
            record.visible.retain(|candidate| candidate != delivery_id);
        }
        self.held.retain(|(mailbox_id, candidate)| {
            mailbox_id != &authority.mailbox_id || !delivery_ids.as_slice().contains(candidate)
        });
        self.stale_replays.retain(|replay| {
            replay.mailbox_id != authority.mailbox_id
                || !delivery_ids.as_slice().contains(&replay.delivery_id)
        });
        if self.corrupt_next_poll.is_some_and(|target| {
            target.mailbox_id == authority.mailbox_id
                && delivery_ids.as_slice().contains(&target.delivery_id)
        }) {
            self.corrupt_next_poll = None;
        }
        if acknowledgement_loss == Some(AcknowledgementLoss::AfterCommit) {
            return Err(transport_failure(TransportFailureCode::Unavailable));
        }
        Ok(AcknowledgementReceipt::accepted())
    }
}

fn transport_failure(code: TransportFailureCode) -> TransportFailure {
    TransportFailure::new(code, RetryAdvice::Never)
}

fn map_memory_failure(failure: MemoryTransportError) -> TransportFailure {
    let code = match failure {
        MemoryTransportError::InvalidPolicy => TransportFailureCode::Misconfigured,
        MemoryTransportError::CapacityExceeded => TransportFailureCode::QueueFull,
        MemoryTransportError::Rejected | MemoryTransportError::ProviderFailure => {
            TransportFailureCode::Internal
        }
    };
    transport_failure(code)
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
