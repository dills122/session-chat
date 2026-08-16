#![forbid(unsafe_code)]

//! Invitation and session state machines for Session Chat 2.0.

use std::collections::BTreeMap;

use session_protocol::{SignedCapabilityInvitation, WireError};
use thiserror::Error;

/// Explicit time and memory bounds for capability-invitation acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvitationAcceptancePolicy {
    maximum_lifetime_seconds: u64,
    maximum_future_skew_seconds: u64,
    maximum_consumed_invitations: usize,
}

impl InvitationAcceptancePolicy {
    /// Creates a fail-closed policy with caller-selected realm limits.
    pub fn new(
        maximum_lifetime_seconds: u64,
        maximum_future_skew_seconds: u64,
        maximum_consumed_invitations: usize,
    ) -> Result<Self, InvitationAcceptanceError> {
        if maximum_lifetime_seconds == 0 {
            return Err(InvitationAcceptanceError::InvalidMaximumLifetime);
        }
        if maximum_consumed_invitations == 0 {
            return Err(InvitationAcceptanceError::InvalidCapacity);
        }

        Ok(Self {
            maximum_lifetime_seconds,
            maximum_future_skew_seconds,
            maximum_consumed_invitations,
        })
    }
}

/// An authenticated, time-valid invitation whose identifier is now consumed.
#[derive(Clone, Eq, PartialEq)]
pub struct AcceptedCapabilityInvitation(SignedCapabilityInvitation);

impl AcceptedCapabilityInvitation {
    /// Returns the consumed invitation identifier.
    #[must_use]
    pub const fn invitation_id(&self) -> &[u8; 16] {
        self.0.invitation_id()
    }

    /// Returns the accepted invitation's absolute expiration time.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.0.expires_at_unix_seconds()
    }

    /// Borrows the verified protocol object for the next state-machine step.
    #[must_use]
    pub const fn invitation(&self) -> &SignedCapabilityInvitation {
        &self.0
    }
}

/// Bounded, single-process replay state for Phase 1 capability invitations.
pub struct InvitationRegistry {
    policy: InvitationAcceptancePolicy,
    consumed_until: BTreeMap<[u8; 16], u64>,
}

impl InvitationRegistry {
    /// Creates an empty registry using explicit realm policy.
    #[must_use]
    pub const fn new(policy: InvitationAcceptancePolicy) -> Self {
        Self {
            policy,
            consumed_until: BTreeMap::new(),
        }
    }

    /// Authenticates, validates, and atomically consumes one invitation.
    ///
    /// No registry mutation occurs on failure. Expired replay entries are
    /// pruned only as part of a successful insertion.
    pub fn accept(
        &mut self,
        encoded_invitation: &[u8],
        now_unix_seconds: u64,
    ) -> Result<AcceptedCapabilityInvitation, InvitationAcceptanceError> {
        let invitation = SignedCapabilityInvitation::decode_and_verify(encoded_invitation)?;
        self.validate_time(&invitation, now_unix_seconds)?;

        let invitation_id = *invitation.invitation_id();
        if self
            .consumed_until
            .get(&invitation_id)
            .is_some_and(|expires_at| *expires_at > now_unix_seconds)
        {
            return Err(InvitationAcceptanceError::AlreadyConsumed);
        }

        let active_count = self
            .consumed_until
            .values()
            .filter(|expires_at| **expires_at > now_unix_seconds)
            .count();
        if active_count >= self.policy.maximum_consumed_invitations {
            return Err(InvitationAcceptanceError::CapacityExceeded {
                maximum: self.policy.maximum_consumed_invitations,
            });
        }

        self.consumed_until
            .retain(|_, expires_at| *expires_at > now_unix_seconds);
        self.consumed_until
            .insert(invitation_id, invitation.expires_at_unix_seconds());

        Ok(AcceptedCapabilityInvitation(invitation))
    }

    /// Returns the currently retained replay-entry count, including entries
    /// that await pruning during the next successful acceptance.
    #[must_use]
    pub fn consumed_count(&self) -> usize {
        self.consumed_until.len()
    }

    fn validate_time(
        &self,
        invitation: &SignedCapabilityInvitation,
        now_unix_seconds: u64,
    ) -> Result<(), InvitationAcceptanceError> {
        let latest_allowed =
            now_unix_seconds.saturating_add(self.policy.maximum_future_skew_seconds);
        if invitation.issued_at_unix_seconds() > latest_allowed {
            return Err(InvitationAcceptanceError::IssuedTooFarInFuture {
                issued_at: invitation.issued_at_unix_seconds(),
                latest_allowed,
            });
        }

        if invitation.expires_at_unix_seconds() <= now_unix_seconds {
            return Err(InvitationAcceptanceError::Expired {
                expires_at: invitation.expires_at_unix_seconds(),
                now: now_unix_seconds,
            });
        }

        let lifetime = invitation
            .expires_at_unix_seconds()
            .saturating_sub(invitation.issued_at_unix_seconds());
        if lifetime > self.policy.maximum_lifetime_seconds {
            return Err(InvitationAcceptanceError::LifetimeExceedsPolicy {
                actual_seconds: lifetime,
                maximum_seconds: self.policy.maximum_lifetime_seconds,
            });
        }

        Ok(())
    }
}

/// Fail-closed errors from invitation authentication and one-time consumption.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum InvitationAcceptanceError {
    /// The signed wire object failed canonical parsing or authentication.
    #[error("invitation protocol validation failed: {0}")]
    Protocol(#[from] WireError),

    /// The configured maximum lifetime cannot be zero.
    #[error("maximum invitation lifetime must be greater than zero")]
    InvalidMaximumLifetime,

    /// A bounded registry must retain at least one replay entry.
    #[error("invitation replay capacity must be greater than zero")]
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

    /// The invitation identifier already has a live consumption record.
    #[error("invitation has already been consumed")]
    AlreadyConsumed,

    /// Retaining another live replay record would exceed the configured bound.
    #[error("invitation replay registry reached capacity {maximum}")]
    CapacityExceeded { maximum: usize },
}
