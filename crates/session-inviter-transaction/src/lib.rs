#![forbid(unsafe_code)]

//! Bounded conformance model for ADR 0008's inviter-local join transaction.

use std::{collections::BTreeMap, sync::Arc};

use session_protocol::{LocalWelcomeDepositEndpoint, OpaqueEnvelope};
use thiserror::Error;
use zeroize::Zeroize;

/// Fixed identifier size used by transaction, invitation, and request IDs.
pub const IDENTIFIER_BYTES: usize = 16;
/// Exact signed-invitation generation token size.
pub const INVITATION_GENERATION_BYTES: usize = 64;
/// Exact canonical-request fingerprint size.
pub const REQUEST_FINGERPRINT_BYTES: usize = 32;
const HARD_MAXIMUM_TRANSACTIONS: usize = 4_096;
const HARD_MAXIMUM_GROUP_ID_BYTES: usize = 255;
const HARD_MAXIMUM_APPROVAL_BYTES: usize = 4_096;
const HARD_MAXIMUM_MLS_STATE_BYTES: usize = 2_097_152;
const HARD_MAXIMUM_WELCOME_BYTES: usize = 65_536;
const HARD_MAXIMUM_ENDPOINT_BYTES: usize = 4_096;
const HARD_MAXIMUM_DELIVERY_ATTEMPTS: u32 = 32;
const HARD_MAXIMUM_LEASE_SECONDS: u64 = 3_600;

/// Explicit resource limits for the conformance model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionPolicy {
    maximum_transactions: usize,
    maximum_group_id_bytes: usize,
    maximum_approval_bytes: usize,
    maximum_mls_state_bytes: usize,
    maximum_welcome_bytes: usize,
    maximum_endpoint_bytes: usize,
    maximum_delivery_attempts: u32,
    maximum_lease_seconds: u64,
}

impl TransactionPolicy {
    /// Constructs a policy, rejecting zero limits.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        maximum_transactions: usize,
        maximum_group_id_bytes: usize,
        maximum_approval_bytes: usize,
        maximum_mls_state_bytes: usize,
        maximum_welcome_bytes: usize,
        maximum_endpoint_bytes: usize,
        maximum_delivery_attempts: u32,
        maximum_lease_seconds: u64,
    ) -> Result<Self, TransactionError> {
        if maximum_transactions == 0
            || maximum_group_id_bytes == 0
            || maximum_approval_bytes == 0
            || maximum_mls_state_bytes == 0
            || maximum_welcome_bytes == 0
            || maximum_endpoint_bytes == 0
            || maximum_delivery_attempts == 0
            || maximum_lease_seconds == 0
            || maximum_transactions > HARD_MAXIMUM_TRANSACTIONS
            || maximum_group_id_bytes > HARD_MAXIMUM_GROUP_ID_BYTES
            || maximum_approval_bytes > HARD_MAXIMUM_APPROVAL_BYTES
            || maximum_mls_state_bytes > HARD_MAXIMUM_MLS_STATE_BYTES
            || maximum_welcome_bytes > HARD_MAXIMUM_WELCOME_BYTES
            || maximum_endpoint_bytes > HARD_MAXIMUM_ENDPOINT_BYTES
            || maximum_delivery_attempts > HARD_MAXIMUM_DELIVERY_ATTEMPTS
            || maximum_lease_seconds > HARD_MAXIMUM_LEASE_SECONDS
        {
            return Err(TransactionError::InvalidInput);
        }
        Ok(Self {
            maximum_transactions,
            maximum_group_id_bytes,
            maximum_approval_bytes,
            maximum_mls_state_bytes,
            maximum_welcome_bytes,
            maximum_endpoint_bytes,
            maximum_delivery_attempts,
            maximum_lease_seconds,
        })
    }
}

/// Exact pre-existing reservation that a commit must consume.
pub struct ReservedInvitation {
    invitation_id: [u8; IDENTIFIER_BYTES],
    invitation_generation: [u8; INVITATION_GENERATION_BYTES],
    join_request_id: [u8; IDENTIFIER_BYTES],
    expires_at_unix_seconds: u64,
}

impl ReservedInvitation {
    /// Constructs one exact invitation-generation reservation.
    pub fn new(
        invitation_id: [u8; IDENTIFIER_BYTES],
        invitation_generation: [u8; INVITATION_GENERATION_BYTES],
        join_request_id: [u8; IDENTIFIER_BYTES],
        expires_at_unix_seconds: u64,
    ) -> Result<Self, TransactionError> {
        if all_zero(&invitation_id)
            || all_zero(&invitation_generation)
            || all_zero(&join_request_id)
            || expires_at_unix_seconds == 0
        {
            return Err(TransactionError::InvalidInput);
        }
        Ok(Self {
            invitation_id,
            invitation_generation,
            join_request_id,
            expires_at_unix_seconds,
        })
    }
}

/// Complete secret-bearing input to one inviter-local atomic commit.
pub struct InviterJoinCommit {
    transaction_id: [u8; IDENTIFIER_BYTES],
    invitation_id: [u8; IDENTIFIER_BYTES],
    invitation_generation: [u8; INVITATION_GENERATION_BYTES],
    join_request_id: [u8; IDENTIFIER_BYTES],
    request_fingerprint: [u8; REQUEST_FINGERPRINT_BYTES],
    group_id: Vec<u8>,
    epoch_before: u64,
    epoch_after: u64,
    approval_record: Vec<u8>,
    mls_state: Vec<u8>,
    welcome_envelope: Vec<u8>,
    deposit_endpoint: Vec<u8>,
    outbox_expires_at_unix_seconds: u64,
}

impl Drop for InviterJoinCommit {
    fn drop(&mut self) {
        self.request_fingerprint.zeroize();
        self.approval_record.zeroize();
        self.mls_state.zeroize();
        self.welcome_envelope.zeroize();
        self.deposit_endpoint.zeroize();
    }
}

impl InviterJoinCommit {
    /// Constructs a commit input. Store-specific bounds are checked at commit.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        transaction_id: [u8; IDENTIFIER_BYTES],
        invitation_id: [u8; IDENTIFIER_BYTES],
        invitation_generation: [u8; INVITATION_GENERATION_BYTES],
        join_request_id: [u8; IDENTIFIER_BYTES],
        request_fingerprint: [u8; REQUEST_FINGERPRINT_BYTES],
        group_id: Vec<u8>,
        epoch_before: u64,
        epoch_after: u64,
        approval_record: Vec<u8>,
        mls_state: Vec<u8>,
        welcome_envelope: Vec<u8>,
        deposit_endpoint: Vec<u8>,
        outbox_expires_at_unix_seconds: u64,
    ) -> Self {
        Self {
            transaction_id,
            invitation_id,
            invitation_generation,
            join_request_id,
            request_fingerprint,
            group_id,
            epoch_before,
            epoch_after,
            approval_record,
            mls_state,
            welcome_envelope,
            deposit_endpoint,
            outbox_expires_at_unix_seconds,
        }
    }
}

/// Observable commit result for safe retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitOutcome {
    /// This invocation atomically installed the record.
    Committed,
    /// An exact prior invocation already installed the record.
    AlreadyCommitted,
}

/// Secret-free invitation lifecycle view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvitationState {
    /// The exact reservation still exists.
    Reserved,
    /// The exact reservation was atomically consumed.
    Consumed,
}

/// Secret-free outbox lifecycle view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboxState {
    /// Committed and awaiting a delivery worker.
    Pending,
    /// Temporarily leased to one delivery worker.
    Leased,
    /// Delivery completed.
    Delivered,
    /// The configured delivery-attempt bound was reached without acceptance.
    AttemptsExhausted,
}

/// Secret-free recovery view for one transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionView {
    /// Committed post-Add epoch.
    pub epoch_after: u64,
    /// Current Welcome outbox state.
    pub outbox_state: OutboxState,
    /// Number of delivery leases issued.
    pub delivery_attempts: u32,
}

/// Opaque authority for reporting one leased delivery result.
pub struct DeliveryLease {
    store_scope: Arc<()>,
    transaction_id: [u8; IDENTIFIER_BYTES],
    lease_sequence: u64,
}

/// Borrowed secret-bearing payload available only under an exact live lease.
pub struct DeliveryPayload<'a> {
    /// Byte-identical encrypted Welcome envelope.
    pub welcome_envelope: &'a [u8],
    /// Byte-identical deposit-only endpoint.
    pub deposit_endpoint: &'a [u8],
}

/// Deterministic failure points used to prove recovery semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitFault {
    /// No injected failure.
    None,
    /// Fail after validating the reservation.
    AfterReservationCheck,
    /// Fail after validating replay uniqueness.
    AfterReplayCheck,
    /// Fail after staging approval state.
    AfterApprovalStaging,
    /// Fail after staging MLS state.
    AfterMlsStaging,
    /// Fail after staging Welcome outbox state.
    AfterOutboxStaging,
    /// Commit succeeded, but its response was lost.
    AfterCommit,
}

/// Coarse, secret-free transaction failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TransactionError {
    /// An identifier, bound, timestamp, or epoch invariant was invalid.
    #[error("transaction input rejected")]
    InvalidInput,
    /// Retaining another transaction would exceed the configured bound.
    #[error("transaction capacity reached")]
    CapacityExceeded,
    /// A reservation did not name the exact current invitation generation.
    #[error("reservation rejected")]
    ReservationMismatch,
    /// An identifier was reused with different content or authority.
    #[error("transaction conflict")]
    Conflict,
    /// The invitation or outbox has expired.
    #[error("transaction state expired")]
    Expired,
    /// No pending delivery could be leased or completed.
    #[error("delivery unavailable")]
    DeliveryUnavailable,
    /// A delivery result did not carry the exact live lease.
    #[error("delivery lease rejected")]
    LeaseMismatch,
    /// The configured delivery-attempt bound was reached.
    #[error("delivery attempts exhausted")]
    AttemptsExhausted,
    /// A deterministic pre-commit failure was injected.
    #[error("injected transaction failure")]
    InjectedFailure,
    /// The commit response was lost; recover by transaction ID.
    #[error("transaction outcome unknown")]
    OutcomeUnknown,
}

/// Bounded in-memory conformance model. This type is not durable storage.
pub struct InMemoryInviterJoinStore {
    policy: TransactionPolicy,
    lease_scope: Arc<()>,
    next_lease_sequence: u64,
    reservations: BTreeMap<[u8; IDENTIFIER_BYTES], ReservationRecord>,
    commits: BTreeMap<[u8; IDENTIFIER_BYTES], CommittedRecord>,
}

struct ReservationRecord {
    invitation_generation: [u8; INVITATION_GENERATION_BYTES],
    join_request_id: [u8; IDENTIFIER_BYTES],
    expires_at_unix_seconds: u64,
}

struct CommittedRecord {
    invitation_id: [u8; IDENTIFIER_BYTES],
    invitation_generation: [u8; INVITATION_GENERATION_BYTES],
    join_request_id: [u8; IDENTIFIER_BYTES],
    request_fingerprint: [u8; REQUEST_FINGERPRINT_BYTES],
    group_id: Vec<u8>,
    epoch_before: u64,
    epoch_after: u64,
    approval_record: Vec<u8>,
    mls_state: Vec<u8>,
    welcome_envelope: Vec<u8>,
    deposit_endpoint: Vec<u8>,
    outbox_expires_at_unix_seconds: u64,
    outbox: StoredOutboxState,
    delivery_attempts: u32,
}

impl CommittedRecord {
    fn matches(&self, commit: &InviterJoinCommit) -> bool {
        self.invitation_id == commit.invitation_id
            && self.invitation_generation == commit.invitation_generation
            && self.join_request_id == commit.join_request_id
            && self.request_fingerprint == commit.request_fingerprint
            && self.group_id == commit.group_id
            && self.epoch_before == commit.epoch_before
            && self.epoch_after == commit.epoch_after
            && self.approval_record == commit.approval_record
            && self.mls_state == commit.mls_state
            && self.welcome_envelope == commit.welcome_envelope
            && self.deposit_endpoint == commit.deposit_endpoint
            && self.outbox_expires_at_unix_seconds == commit.outbox_expires_at_unix_seconds
    }
}

impl Drop for CommittedRecord {
    fn drop(&mut self) {
        self.request_fingerprint.zeroize();
        self.approval_record.zeroize();
        self.mls_state.zeroize();
        self.welcome_envelope.zeroize();
        self.deposit_endpoint.zeroize();
    }
}

#[derive(Clone, Copy)]
enum StoredOutboxState {
    Pending,
    Leased {
        lease_sequence: u64,
        expires_at_unix_seconds: u64,
    },
    Delivered {
        lease_sequence: u64,
    },
    AttemptsExhausted,
}

impl InMemoryInviterJoinStore {
    /// Creates an empty conformance model.
    #[must_use]
    pub fn new(policy: TransactionPolicy) -> Self {
        Self {
            policy,
            lease_scope: Arc::new(()),
            next_lease_sequence: 1,
            reservations: BTreeMap::new(),
            commits: BTreeMap::new(),
        }
    }

    /// Seeds the exact reservation created by the admission state machine.
    pub fn seed_reservation(
        &mut self,
        reservation: ReservedInvitation,
        now_unix_seconds: u64,
    ) -> Result<(), TransactionError> {
        if self
            .commits
            .values()
            .any(|record| record.invitation_id == reservation.invitation_id)
        {
            return Err(TransactionError::Conflict);
        }
        if reservation.expires_at_unix_seconds <= now_unix_seconds {
            return Err(TransactionError::Expired);
        }
        let replaces_expired = self
            .reservations
            .get(&reservation.invitation_id)
            .is_some_and(|current| current.expires_at_unix_seconds <= now_unix_seconds);
        if self.reservations.contains_key(&reservation.invitation_id) && !replaces_expired {
            return Err(TransactionError::Conflict);
        }
        if !replaces_expired && self.reservations.len() >= self.policy.maximum_transactions {
            return Err(TransactionError::CapacityExceeded);
        }
        if replaces_expired
            && self
                .reservations
                .get(&reservation.invitation_id)
                .is_some_and(|current| {
                    current.invitation_generation == reservation.invitation_generation
                })
        {
            return Err(TransactionError::Conflict);
        }
        self.reservations.insert(
            reservation.invitation_id,
            ReservationRecord {
                invitation_generation: reservation.invitation_generation,
                join_request_id: reservation.join_request_id,
                expires_at_unix_seconds: reservation.expires_at_unix_seconds,
            },
        );
        Ok(())
    }

    /// Attempts one atomic commit with an optional deterministic fault.
    pub fn commit_with_fault(
        &mut self,
        commit: &InviterJoinCommit,
        now_unix_seconds: u64,
        fault: CommitFault,
    ) -> Result<CommitOutcome, TransactionError> {
        self.validate_commit(commit)?;

        if let Some(record) = self.commits.get(&commit.transaction_id) {
            return if record.matches(commit) {
                Ok(CommitOutcome::AlreadyCommitted)
            } else {
                Err(TransactionError::Conflict)
            };
        }
        if commit.outbox_expires_at_unix_seconds <= now_unix_seconds {
            return Err(TransactionError::Expired);
        }
        if self.commits.len() >= self.policy.maximum_transactions {
            return Err(TransactionError::CapacityExceeded);
        }

        let reservation = self
            .reservations
            .get(&commit.invitation_id)
            .ok_or(TransactionError::ReservationMismatch)?;
        if reservation.invitation_generation != commit.invitation_generation
            || reservation.join_request_id != commit.join_request_id
        {
            return Err(TransactionError::ReservationMismatch);
        }
        if reservation.expires_at_unix_seconds <= now_unix_seconds {
            return Err(TransactionError::Expired);
        }
        fail_at(fault, CommitFault::AfterReservationCheck)?;

        if self.commits.values().any(|record| {
            (record.invitation_id == commit.invitation_id
                && record.invitation_generation == commit.invitation_generation)
                || record.join_request_id == commit.join_request_id
        }) {
            return Err(TransactionError::Conflict);
        }
        fail_at(fault, CommitFault::AfterReplayCheck)?;
        fail_at(fault, CommitFault::AfterApprovalStaging)?;
        fail_at(fault, CommitFault::AfterMlsStaging)?;
        fail_at(fault, CommitFault::AfterOutboxStaging)?;

        let record = CommittedRecord {
            invitation_id: commit.invitation_id,
            invitation_generation: commit.invitation_generation,
            join_request_id: commit.join_request_id,
            request_fingerprint: commit.request_fingerprint,
            group_id: commit.group_id.clone(),
            epoch_before: commit.epoch_before,
            epoch_after: commit.epoch_after,
            approval_record: commit.approval_record.clone(),
            mls_state: commit.mls_state.clone(),
            welcome_envelope: commit.welcome_envelope.clone(),
            deposit_endpoint: commit.deposit_endpoint.clone(),
            outbox_expires_at_unix_seconds: commit.outbox_expires_at_unix_seconds,
            outbox: StoredOutboxState::Pending,
            delivery_attempts: 0,
        };
        self.reservations.remove(&commit.invitation_id);
        self.commits.insert(commit.transaction_id, record);

        if fault == CommitFault::AfterCommit {
            Err(TransactionError::OutcomeUnknown)
        } else {
            Ok(CommitOutcome::Committed)
        }
    }

    /// Returns the invitation lifecycle for a retained invitation.
    #[must_use]
    pub fn invitation_state(
        &self,
        invitation_id: &[u8; IDENTIFIER_BYTES],
    ) -> Option<InvitationState> {
        if self.reservations.contains_key(invitation_id) {
            Some(InvitationState::Reserved)
        } else if self
            .commits
            .values()
            .any(|record| &record.invitation_id == invitation_id)
        {
            Some(InvitationState::Consumed)
        } else {
            None
        }
    }

    /// Recovers a secret-free committed transaction view.
    #[must_use]
    pub fn recover(&self, transaction_id: &[u8; IDENTIFIER_BYTES]) -> Option<TransactionView> {
        self.commits
            .get(transaction_id)
            .map(|record| TransactionView {
                epoch_after: record.epoch_after,
                outbox_state: match record.outbox {
                    StoredOutboxState::Pending => OutboxState::Pending,
                    StoredOutboxState::Leased { .. } => OutboxState::Leased,
                    StoredOutboxState::Delivered { .. } => OutboxState::Delivered,
                    StoredOutboxState::AttemptsExhausted => OutboxState::AttemptsExhausted,
                },
                delivery_attempts: record.delivery_attempts,
            })
    }

    /// Lists bounded, non-expired outbox work that can be leased now.
    #[must_use]
    pub fn pending_transaction_ids(&self, now_unix_seconds: u64) -> Vec<[u8; IDENTIFIER_BYTES]> {
        self.commits
            .iter()
            .filter_map(|(transaction_id, record)| {
                if record.outbox_expires_at_unix_seconds <= now_unix_seconds {
                    return None;
                }
                if record.delivery_attempts >= self.policy.maximum_delivery_attempts {
                    return None;
                }
                match record.outbox {
                    StoredOutboxState::Pending => Some(*transaction_id),
                    StoredOutboxState::Leased {
                        expires_at_unix_seconds,
                        ..
                    } if expires_at_unix_seconds <= now_unix_seconds => Some(*transaction_id),
                    StoredOutboxState::Leased { .. }
                    | StoredOutboxState::Delivered { .. }
                    | StoredOutboxState::AttemptsExhausted => None,
                }
            })
            .collect()
    }

    /// Leases one pending Welcome for a bounded delivery attempt.
    pub fn lease_delivery(
        &mut self,
        transaction_id: [u8; IDENTIFIER_BYTES],
        now_unix_seconds: u64,
        lease_seconds: u64,
    ) -> Result<DeliveryLease, TransactionError> {
        if all_zero(&transaction_id)
            || lease_seconds == 0
            || lease_seconds > self.policy.maximum_lease_seconds
        {
            return Err(TransactionError::InvalidInput);
        }
        let lease_expires_at = now_unix_seconds
            .checked_add(lease_seconds)
            .ok_or(TransactionError::InvalidInput)?;
        let record = self
            .commits
            .get_mut(&transaction_id)
            .ok_or(TransactionError::DeliveryUnavailable)?;
        if record.outbox_expires_at_unix_seconds <= now_unix_seconds
            || lease_expires_at > record.outbox_expires_at_unix_seconds
        {
            return Err(TransactionError::Expired);
        }
        if matches!(record.outbox, StoredOutboxState::AttemptsExhausted) {
            return Err(TransactionError::AttemptsExhausted);
        }

        let available = match record.outbox {
            StoredOutboxState::Pending => true,
            StoredOutboxState::Leased {
                expires_at_unix_seconds,
                ..
            } => expires_at_unix_seconds <= now_unix_seconds,
            StoredOutboxState::Delivered { .. } | StoredOutboxState::AttemptsExhausted => false,
        };
        if !available {
            return Err(TransactionError::DeliveryUnavailable);
        }
        if record.delivery_attempts >= self.policy.maximum_delivery_attempts {
            record.outbox = StoredOutboxState::AttemptsExhausted;
            return Err(TransactionError::AttemptsExhausted);
        }
        let lease_sequence = self.next_lease_sequence;
        self.next_lease_sequence = self
            .next_lease_sequence
            .checked_add(1)
            .ok_or(TransactionError::DeliveryUnavailable)?;
        record.delivery_attempts += 1;
        record.outbox = StoredOutboxState::Leased {
            lease_sequence,
            expires_at_unix_seconds: lease_expires_at,
        };
        Ok(DeliveryLease {
            store_scope: Arc::clone(&self.lease_scope),
            transaction_id,
            lease_sequence,
        })
    }

    /// Borrows the exact payload selected by a live lease.
    pub fn delivery_payload(
        &self,
        lease: &DeliveryLease,
        now_unix_seconds: u64,
    ) -> Result<DeliveryPayload<'_>, TransactionError> {
        self.require_local_lease(lease)?;
        let record = self
            .commits
            .get(&lease.transaction_id)
            .ok_or(TransactionError::LeaseMismatch)?;
        if record.outbox_expires_at_unix_seconds <= now_unix_seconds {
            return Err(TransactionError::Expired);
        }
        match record.outbox {
            StoredOutboxState::Leased {
                lease_sequence,
                expires_at_unix_seconds,
            } if lease_sequence == lease.lease_sequence
                && expires_at_unix_seconds > now_unix_seconds =>
            {
                Ok(DeliveryPayload {
                    welcome_envelope: &record.welcome_envelope,
                    deposit_endpoint: &record.deposit_endpoint,
                })
            }
            _ => Err(TransactionError::LeaseMismatch),
        }
    }

    /// Reports a failed attempt, returning the Welcome to pending.
    pub fn fail_delivery(&mut self, lease: &DeliveryLease) -> Result<(), TransactionError> {
        self.require_local_lease(lease)?;
        let record = self
            .commits
            .get_mut(&lease.transaction_id)
            .ok_or(TransactionError::LeaseMismatch)?;
        match record.outbox {
            StoredOutboxState::Leased { lease_sequence, .. }
                if lease_sequence == lease.lease_sequence =>
            {
                record.outbox = if record.delivery_attempts >= self.policy.maximum_delivery_attempts
                {
                    StoredOutboxState::AttemptsExhausted
                } else {
                    StoredOutboxState::Pending
                };
                Ok(())
            }
            _ => Err(TransactionError::LeaseMismatch),
        }
    }

    /// Reports successful delivery idempotently for the exact lease.
    pub fn complete_delivery(
        &mut self,
        lease: &DeliveryLease,
        now_unix_seconds: u64,
    ) -> Result<(), TransactionError> {
        self.require_local_lease(lease)?;
        let record = self
            .commits
            .get_mut(&lease.transaction_id)
            .ok_or(TransactionError::LeaseMismatch)?;
        match record.outbox {
            StoredOutboxState::Leased {
                lease_sequence,
                expires_at_unix_seconds,
            } if lease_sequence == lease.lease_sequence
                && expires_at_unix_seconds > now_unix_seconds
                && record.outbox_expires_at_unix_seconds > now_unix_seconds =>
            {
                record.outbox = StoredOutboxState::Delivered { lease_sequence };
                Ok(())
            }
            StoredOutboxState::Delivered { lease_sequence }
                if lease_sequence == lease.lease_sequence =>
            {
                Ok(())
            }
            _ => Err(TransactionError::LeaseMismatch),
        }
    }

    /// Returns the number of committed transactions.
    #[must_use]
    pub fn committed_count(&self) -> usize {
        self.commits.len()
    }

    fn validate_commit(&self, commit: &InviterJoinCommit) -> Result<(), TransactionError> {
        if all_zero(&commit.transaction_id)
            || all_zero(&commit.invitation_id)
            || all_zero(&commit.invitation_generation)
            || all_zero(&commit.join_request_id)
            || all_zero(&commit.request_fingerprint)
            || commit.group_id.is_empty()
            || commit.group_id.len() > self.policy.maximum_group_id_bytes
            || commit.approval_record.is_empty()
            || commit.approval_record.len() > self.policy.maximum_approval_bytes
            || commit.mls_state.is_empty()
            || commit.mls_state.len() > self.policy.maximum_mls_state_bytes
            || commit.welcome_envelope.is_empty()
            || commit.welcome_envelope.len() > self.policy.maximum_welcome_bytes
            || commit.deposit_endpoint.is_empty()
            || commit.deposit_endpoint.len() > self.policy.maximum_endpoint_bytes
            || commit.epoch_before.checked_add(1) != Some(commit.epoch_after)
        {
            return Err(TransactionError::InvalidInput);
        }
        let envelope = OpaqueEnvelope::decode_canonical(&commit.welcome_envelope)
            .map_err(|_| TransactionError::InvalidInput)?;
        let endpoint = LocalWelcomeDepositEndpoint::decode_canonical(&commit.deposit_endpoint)
            .map_err(|_| TransactionError::InvalidInput)?;
        if all_zero(envelope.envelope_id())
            || commit.outbox_expires_at_unix_seconds > envelope.expires_at_unix_seconds()
            || envelope.expires_at_unix_seconds() > endpoint.expires_at_unix_seconds()
        {
            return Err(TransactionError::InvalidInput);
        }
        Ok(())
    }

    fn require_local_lease(&self, lease: &DeliveryLease) -> Result<(), TransactionError> {
        if Arc::ptr_eq(&self.lease_scope, &lease.store_scope) {
            Ok(())
        } else {
            Err(TransactionError::LeaseMismatch)
        }
    }
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn fail_at(actual: CommitFault, expected: CommitFault) -> Result<(), TransactionError> {
    if actual == expected {
        Err(TransactionError::InjectedFailure)
    } else {
        Ok(())
    }
}
