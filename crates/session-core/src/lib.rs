#![forbid(unsafe_code)]

//! Invitation and session state machines for Session Chat 2.0.

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use session_protocol::{CapabilityInvitationClaims, SignedCapabilityInvitation, WireError};
use thiserror::Error;

const INVITATION_ID_BYTES: usize = 16;
const JOIN_REQUEST_ID_BYTES: usize = 16;

/// Explicit time and memory bounds for inviter-owned capability invitations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvitationPolicy {
    maximum_lifetime_seconds: u64,
    maximum_future_skew_seconds: u64,
    maximum_live_invitations: usize,
}

impl InvitationPolicy {
    /// Creates a fail-closed policy with caller-selected realm limits.
    pub fn new(
        maximum_lifetime_seconds: u64,
        maximum_future_skew_seconds: u64,
        maximum_live_invitations: usize,
    ) -> Result<Self, InvitationLifecycleError> {
        if maximum_lifetime_seconds == 0 {
            return Err(InvitationLifecycleError::InvalidMaximumLifetime);
        }
        if maximum_live_invitations == 0 {
            return Err(InvitationLifecycleError::InvalidCapacity);
        }

        Ok(Self {
            maximum_lifetime_seconds,
            maximum_future_skew_seconds,
            maximum_live_invitations,
        })
    }
}

/// Public, non-secret view of an inviter-owned invitation's lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvitationLifecycle {
    /// The invitation can be reserved by one fully validated admission request.
    Available,
    /// One admission request owns the invitation while approval/membership proceeds.
    Reserved,
    /// A successful membership transition permanently used the invitation.
    Consumed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoredInvitationLifecycle {
    Available,
    Reserved {
        join_request_id: [u8; JOIN_REQUEST_ID_BYTES],
    },
    Consumed,
}

/// A capability invitation created through the inviter-owned registry.
///
/// This object contains a bearer capability, does not implement `Debug` or
/// `Clone`, and must not enter logs or transport metadata.
#[derive(Eq, PartialEq)]
pub struct IssuedCapabilityInvitation(SignedCapabilityInvitation);

impl IssuedCapabilityInvitation {
    /// Returns the locally issued invitation identifier.
    #[must_use]
    pub const fn invitation_id(&self) -> &[u8; INVITATION_ID_BYTES] {
        self.0.invitation_id()
    }

    /// Encodes the secret-bearing descriptor for deliberate publication.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, WireError> {
        self.0.encode_canonical()
    }

    /// Borrows the signed protocol object.
    #[must_use]
    pub const fn invitation(&self) -> &SignedCapabilityInvitation {
        &self.0
    }
}

/// An authenticated and time-valid descriptor that has not changed lifecycle state.
///
/// Validation alone does not prove local issuance, capability possession,
/// admission policy, approval, or MLS membership. This secret-bearing object
/// intentionally does not implement `Debug` or `Clone`.
#[derive(Eq, PartialEq)]
pub struct ValidatedCapabilityInvitation(SignedCapabilityInvitation);

impl ValidatedCapabilityInvitation {
    /// Returns the authenticated invitation identifier.
    #[must_use]
    pub const fn invitation_id(&self) -> &[u8; INVITATION_ID_BYTES] {
        self.0.invitation_id()
    }

    /// Returns the descriptor's absolute expiration time.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.0.expires_at_unix_seconds()
    }

    /// Borrows the verified protocol object for admission verification.
    #[must_use]
    pub const fn invitation(&self) -> &SignedCapabilityInvitation {
        &self.0
    }
}

/// Opaque authority to complete or release one invitation reservation.
///
/// Construction is restricted to `InvitationRegistry::reserve_after_admission`.
#[derive(Eq, PartialEq)]
pub struct InvitationReservation {
    invitation_id: [u8; INVITATION_ID_BYTES],
    join_request_id: [u8; JOIN_REQUEST_ID_BYTES],
    record_signature: [u8; 64],
}

struct InvitationRecord {
    expires_at_unix_seconds: u64,
    inviter_verifying_key: [u8; 32],
    signature: [u8; 64],
    lifecycle: StoredInvitationLifecycle,
}

impl InvitationRecord {
    fn matches(&self, invitation: &SignedCapabilityInvitation) -> bool {
        self.expires_at_unix_seconds == invitation.expires_at_unix_seconds()
            && self.inviter_verifying_key == *invitation.inviter_verifying_key()
            && self.signature == *invitation.signature()
    }
}

/// Bounded, single-process inviter-owned invitation lifecycle state.
pub struct InvitationRegistry {
    policy: InvitationPolicy,
    records: BTreeMap<[u8; INVITATION_ID_BYTES], InvitationRecord>,
}

impl InvitationRegistry {
    /// Creates an empty registry using explicit realm policy.
    #[must_use]
    pub const fn new(policy: InvitationPolicy) -> Self {
        Self {
            policy,
            records: BTreeMap::new(),
        }
    }

    /// Signs and records a locally issued invitation as available.
    ///
    /// Expired records are pruned only as part of successful issuance. Remote
    /// descriptors cannot create registry state through this API.
    pub fn issue(
        &mut self,
        claims: CapabilityInvitationClaims,
        signing_key: &SigningKey,
        now_unix_seconds: u64,
    ) -> Result<IssuedCapabilityInvitation, InvitationLifecycleError> {
        let invitation = SignedCapabilityInvitation::sign(claims, signing_key)?;
        self.validate_time(&invitation, now_unix_seconds)?;

        let invitation_id = *invitation.invitation_id();
        if self
            .records
            .get(&invitation_id)
            .is_some_and(|record| record.expires_at_unix_seconds > now_unix_seconds)
        {
            return Err(InvitationLifecycleError::DuplicateInvitationId);
        }

        let live_count = self
            .records
            .values()
            .filter(|record| record.expires_at_unix_seconds > now_unix_seconds)
            .count();
        if live_count >= self.policy.maximum_live_invitations {
            return Err(InvitationLifecycleError::CapacityExceeded {
                maximum: self.policy.maximum_live_invitations,
            });
        }

        self.records
            .retain(|_, record| record.expires_at_unix_seconds > now_unix_seconds);
        self.records.insert(
            invitation_id,
            InvitationRecord {
                expires_at_unix_seconds: invitation.expires_at_unix_seconds(),
                inviter_verifying_key: *invitation.inviter_verifying_key(),
                signature: *invitation.signature(),
                lifecycle: StoredInvitationLifecycle::Available,
            },
        );

        Ok(IssuedCapabilityInvitation(invitation))
    }

    /// Authenticates and time-validates an attacker-controlled descriptor.
    ///
    /// This operation is deliberately read-only. It does not reserve or consume
    /// inviter-owned state and is safe to retry.
    pub fn validate_descriptor(
        &self,
        encoded_invitation: &[u8],
        now_unix_seconds: u64,
    ) -> Result<ValidatedCapabilityInvitation, InvitationLifecycleError> {
        let invitation = SignedCapabilityInvitation::decode_and_verify(encoded_invitation)?;
        self.validate_time(&invitation, now_unix_seconds)?;
        Ok(ValidatedCapabilityInvitation(invitation))
    }

    /// Reserves a locally issued invitation for one validated admission request.
    ///
    /// The caller must invoke this only after capability/admission verification,
    /// KeyPackage binding validation, and replay checks succeed. Reservation is
    /// not approval or membership and can be released after rejection or failure.
    pub fn reserve_after_admission(
        &mut self,
        invitation: &ValidatedCapabilityInvitation,
        join_request_id: [u8; JOIN_REQUEST_ID_BYTES],
        now_unix_seconds: u64,
    ) -> Result<InvitationReservation, InvitationLifecycleError> {
        if join_request_id.iter().all(|byte| *byte == 0) {
            return Err(InvitationLifecycleError::ZeroJoinRequestId);
        }
        self.validate_time(invitation.invitation(), now_unix_seconds)?;

        let invitation_id = *invitation.invitation_id();
        let record = self
            .records
            .get_mut(&invitation_id)
            .ok_or(InvitationLifecycleError::UnknownInvitation)?;
        if !record.matches(invitation.invitation()) {
            return Err(InvitationLifecycleError::DescriptorMismatch);
        }

        match record.lifecycle {
            StoredInvitationLifecycle::Available => {
                record.lifecycle = StoredInvitationLifecycle::Reserved { join_request_id };
                Ok(InvitationReservation {
                    invitation_id,
                    join_request_id,
                    record_signature: record.signature,
                })
            }
            StoredInvitationLifecycle::Reserved { .. } => {
                Err(InvitationLifecycleError::AlreadyReserved)
            }
            StoredInvitationLifecycle::Consumed => Err(InvitationLifecycleError::AlreadyConsumed),
        }
    }

    /// Releases a matching reservation after rejection or a failed state transition.
    pub fn release(
        &mut self,
        reservation: InvitationReservation,
        now_unix_seconds: u64,
    ) -> Result<(), InvitationLifecycleError> {
        let record = self.current_record_mut(reservation.invitation_id, now_unix_seconds)?;
        if record.signature != reservation.record_signature {
            return Err(InvitationLifecycleError::ReservationMismatch);
        }
        match record.lifecycle {
            StoredInvitationLifecycle::Reserved { join_request_id }
                if join_request_id == reservation.join_request_id =>
            {
                record.lifecycle = StoredInvitationLifecycle::Available;
                Ok(())
            }
            StoredInvitationLifecycle::Reserved { .. } => {
                Err(InvitationLifecycleError::ReservationMismatch)
            }
            StoredInvitationLifecycle::Available => Err(InvitationLifecycleError::NotReserved),
            StoredInvitationLifecycle::Consumed => Err(InvitationLifecycleError::AlreadyConsumed),
        }
    }

    /// Consumes a matching reservation after a successful membership transition.
    ///
    /// Persistent implementations must commit this transition atomically with
    /// the MLS state change, request replay and approval/result state, and
    /// queued Welcome outbox work with an idempotency key. Network delivery
    /// from that committed outbox is separately retryable.
    pub fn consume_after_membership(
        &mut self,
        reservation: InvitationReservation,
        now_unix_seconds: u64,
    ) -> Result<(), InvitationLifecycleError> {
        let record = self.current_record_mut(reservation.invitation_id, now_unix_seconds)?;
        if record.signature != reservation.record_signature {
            return Err(InvitationLifecycleError::ReservationMismatch);
        }
        match record.lifecycle {
            StoredInvitationLifecycle::Reserved { join_request_id }
                if join_request_id == reservation.join_request_id =>
            {
                record.lifecycle = StoredInvitationLifecycle::Consumed;
                Ok(())
            }
            StoredInvitationLifecycle::Reserved { .. } => {
                Err(InvitationLifecycleError::ReservationMismatch)
            }
            StoredInvitationLifecycle::Available => Err(InvitationLifecycleError::NotReserved),
            StoredInvitationLifecycle::Consumed => Err(InvitationLifecycleError::AlreadyConsumed),
        }
    }

    /// Returns a non-secret lifecycle view for a retained local invitation.
    #[must_use]
    pub fn lifecycle(
        &self,
        invitation_id: &[u8; INVITATION_ID_BYTES],
    ) -> Option<InvitationLifecycle> {
        self.records
            .get(invitation_id)
            .map(|record| match record.lifecycle {
                StoredInvitationLifecycle::Available => InvitationLifecycle::Available,
                StoredInvitationLifecycle::Reserved { .. } => InvitationLifecycle::Reserved,
                StoredInvitationLifecycle::Consumed => InvitationLifecycle::Consumed,
            })
    }

    /// Returns the retained local-record count, including expired records awaiting pruning.
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    fn current_record_mut(
        &mut self,
        invitation_id: [u8; INVITATION_ID_BYTES],
        now_unix_seconds: u64,
    ) -> Result<&mut InvitationRecord, InvitationLifecycleError> {
        let record = self
            .records
            .get_mut(&invitation_id)
            .ok_or(InvitationLifecycleError::UnknownInvitation)?;
        if record.expires_at_unix_seconds <= now_unix_seconds {
            return Err(InvitationLifecycleError::Expired {
                expires_at: record.expires_at_unix_seconds,
                now: now_unix_seconds,
            });
        }
        Ok(record)
    }

    fn validate_time(
        &self,
        invitation: &SignedCapabilityInvitation,
        now_unix_seconds: u64,
    ) -> Result<(), InvitationLifecycleError> {
        let latest_allowed =
            now_unix_seconds.saturating_add(self.policy.maximum_future_skew_seconds);
        if invitation.issued_at_unix_seconds() > latest_allowed {
            return Err(InvitationLifecycleError::IssuedTooFarInFuture {
                issued_at: invitation.issued_at_unix_seconds(),
                latest_allowed,
            });
        }

        if invitation.expires_at_unix_seconds() <= now_unix_seconds {
            return Err(InvitationLifecycleError::Expired {
                expires_at: invitation.expires_at_unix_seconds(),
                now: now_unix_seconds,
            });
        }

        let lifetime = invitation
            .expires_at_unix_seconds()
            .saturating_sub(invitation.issued_at_unix_seconds());
        if lifetime > self.policy.maximum_lifetime_seconds {
            return Err(InvitationLifecycleError::LifetimeExceedsPolicy {
                actual_seconds: lifetime,
                maximum_seconds: self.policy.maximum_lifetime_seconds,
            });
        }

        Ok(())
    }
}

/// Fail-closed errors from invitation validation and lifecycle transitions.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum InvitationLifecycleError {
    /// The signed wire object failed canonical parsing or authentication.
    #[error("invitation protocol validation failed: {0}")]
    Protocol(#[from] WireError),

    /// The configured maximum lifetime cannot be zero.
    #[error("maximum invitation lifetime must be greater than zero")]
    InvalidMaximumLifetime,

    /// A bounded registry must retain at least one invitation.
    #[error("invitation registry capacity must be greater than zero")]
    InvalidCapacity,

    /// The descriptor was issued beyond configured clock-skew tolerance.
    #[error("invitation issue time {issued_at} is later than allowed time {latest_allowed}")]
    IssuedTooFarInFuture { issued_at: u64, latest_allowed: u64 },

    /// Expiration is exclusive, so equality with current time is expired.
    #[error("invitation expired at {expires_at}; current time is {now}")]
    Expired { expires_at: u64, now: u64 },

    /// The signed interval exceeds realm policy.
    #[error("invitation lifetime {actual_seconds} exceeds maximum {maximum_seconds}")]
    LifetimeExceedsPolicy {
        actual_seconds: u64,
        maximum_seconds: u64,
    },

    /// A still-live locally issued invitation already uses the identifier.
    #[error("a live locally issued invitation already uses this identifier")]
    DuplicateInvitationId,

    /// Retaining another live local invitation would exceed the configured bound.
    #[error("invitation registry reached capacity {maximum}")]
    CapacityExceeded { maximum: usize },

    /// No inviter-owned state exists for this descriptor.
    #[error("invitation was not issued by this local registry")]
    UnknownInvitation,

    /// A descriptor reused a local identifier but did not match the issued object.
    #[error("descriptor does not match the locally issued invitation")]
    DescriptorMismatch,

    /// Join-request identifiers reserve the all-zero value.
    #[error("join request id must not be all zero")]
    ZeroJoinRequestId,

    /// Another request already owns the invitation reservation.
    #[error("invitation is already reserved")]
    AlreadyReserved,

    /// A successful membership transition already consumed the invitation.
    #[error("invitation has already been consumed")]
    AlreadyConsumed,

    /// The provided reservation does not own the current request or record instance.
    #[error("reservation does not match the current invitation instance and join request")]
    ReservationMismatch,

    /// The invitation has no active reservation to release or consume.
    #[error("invitation is not reserved")]
    NotReserved,
}
