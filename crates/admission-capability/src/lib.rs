#![forbid(unsafe_code)]

//! Capability admission for the local protected-join profile.

use session_crypto_hpke::OpenedCapabilityJoinRequest;
use session_crypto_mls::{KeyPackageReference, ValidatedKeyPackage, create_key_package_validator};
use thiserror::Error;

const IDENTIFIER_BYTES: usize = 16;
const FIXED_KEY_BYTES: usize = 32;

/// Explicit time and memory bounds for capability admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityAdmissionPolicy {
    maximum_request_lifetime_seconds: u64,
    maximum_future_skew_seconds: u64,
    maximum_pending_requests: usize,
}

impl CapabilityAdmissionPolicy {
    /// Creates a fail-closed in-memory admission policy.
    pub fn new(
        maximum_request_lifetime_seconds: u64,
        maximum_future_skew_seconds: u64,
        maximum_pending_requests: usize,
    ) -> Result<Self, CapabilityAdmissionError> {
        if maximum_request_lifetime_seconds == 0 || maximum_pending_requests == 0 {
            return Err(CapabilityAdmissionError::InvalidPolicy);
        }
        Ok(Self {
            maximum_request_lifetime_seconds,
            maximum_future_skew_seconds,
            maximum_pending_requests,
        })
    }
}

/// Coarse failures from the capability-admission boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CapabilityAdmissionError {
    /// A configured lifetime or capacity was zero.
    #[error("invalid capability-admission policy")]
    InvalidPolicy,
    /// Authentication, time, KeyPackage, or binding validation failed.
    #[error("capability admission rejected")]
    Rejected,
    /// The request identifier or nonce is already pending for this generation.
    #[error("capability admission replay rejected")]
    Replay,
    /// Retaining another pending request would exceed the configured bound.
    #[error("capability admission capacity reached")]
    CapacityExceeded,
    /// The released value no longer owns the retained replay reservation.
    #[error("capability admission reservation mismatch")]
    ReservationMismatch,
}

#[derive(Eq, PartialEq)]
struct ReplayGeneration {
    invitation_id: [u8; IDENTIFIER_BYTES],
    join_challenge: [u8; FIXED_KEY_BYTES],
    invitation_key_id: [u8; IDENTIFIER_BYTES],
    intended_verifier: [u8; FIXED_KEY_BYTES],
}

struct PendingReplay {
    generation: ReplayGeneration,
    join_request_id: [u8; IDENTIFIER_BYTES],
    request_nonce: [u8; FIXED_KEY_BYTES],
    expires_at_unix_seconds: u64,
    reservation_id: u64,
}

/// In-memory verifier and bounded replay reservation state for capability mode.
pub struct CapabilityAdmissionVerifier {
    policy: CapabilityAdmissionPolicy,
    pending: Vec<PendingReplay>,
    next_reservation_id: u64,
}

impl CapabilityAdmissionVerifier {
    /// Creates an empty verifier with explicit bounds.
    #[must_use]
    pub const fn new(policy: CapabilityAdmissionPolicy) -> Self {
        Self {
            policy,
            pending: Vec::new(),
            next_reservation_id: 1,
        }
    }

    /// Validates one HPKE-authenticated request and reserves its replay values.
    ///
    /// Every automated check completes before replay state mutates.
    pub fn verify_and_reserve(
        &mut self,
        opened: OpenedCapabilityJoinRequest,
        now_unix_seconds: u64,
    ) -> Result<VerifiedCapabilityAdmission, CapabilityAdmissionError> {
        let request = opened.request();
        let latest_issue = now_unix_seconds.saturating_add(self.policy.maximum_future_skew_seconds);
        let lifetime = request
            .expires_at_unix_seconds()
            .checked_sub(request.issued_at_unix_seconds())
            .ok_or(CapabilityAdmissionError::Rejected)?;
        if request.issued_at_unix_seconds() > latest_issue
            || request.expires_at_unix_seconds() <= now_unix_seconds
            || lifetime > self.policy.maximum_request_lifetime_seconds
        {
            return Err(CapabilityAdmissionError::Rejected);
        }

        let validated = create_key_package_validator()
            .validate_key_package(request.key_package(), now_unix_seconds)
            .map_err(|_| CapabilityAdmissionError::Rejected)?;
        if request.key_package_reference() != validated.key_package_reference()
            || request.credential_identity() != validated.credential_identity()
            || request.leaf_signature_key() != validated.leaf_signature_key()
        {
            return Err(CapabilityAdmissionError::Rejected);
        }

        let generation = ReplayGeneration {
            invitation_id: *request.invitation_id(),
            join_challenge: *request.join_challenge(),
            invitation_key_id: *request.invitation_key_id(),
            intended_verifier: *request.intended_verifier(),
        };
        let join_request_id = *request.join_request_id();
        let request_nonce = *request.request_nonce();
        if self.pending.iter().any(|entry| {
            entry.expires_at_unix_seconds > now_unix_seconds
                && entry.generation == generation
                && (entry.join_request_id == join_request_id
                    || entry.request_nonce == request_nonce)
        }) {
            return Err(CapabilityAdmissionError::Replay);
        }

        let live_count = self
            .pending
            .iter()
            .filter(|entry| entry.expires_at_unix_seconds > now_unix_seconds)
            .count();
        if live_count >= self.policy.maximum_pending_requests {
            return Err(CapabilityAdmissionError::CapacityExceeded);
        }
        let reservation_id = self.next_reservation_id;
        let next_reservation_id = reservation_id
            .checked_add(1)
            .ok_or(CapabilityAdmissionError::CapacityExceeded)?;
        self.pending
            .retain(|entry| entry.expires_at_unix_seconds > now_unix_seconds);
        self.pending.push(PendingReplay {
            generation,
            join_request_id,
            request_nonce,
            expires_at_unix_seconds: request.expires_at_unix_seconds(),
            reservation_id,
        });
        self.next_reservation_id = next_reservation_id;

        Ok(VerifiedCapabilityAdmission {
            opened,
            validated,
            reservation_id,
        })
    }

    /// Returns the bounded count of retained replay reservations.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Releases one matching replay reservation after rejection or abandonment.
    pub fn release(
        &mut self,
        verified: VerifiedCapabilityAdmission,
    ) -> Result<(), CapabilityAdmissionError> {
        let request = verified.opened.request();
        let position = self.pending.iter().position(|entry| {
            entry.reservation_id == verified.reservation_id
                && entry.generation.invitation_id == *request.invitation_id()
                && entry.generation.join_challenge == *request.join_challenge()
                && entry.generation.invitation_key_id == *request.invitation_key_id()
                && entry.generation.intended_verifier == *request.intended_verifier()
                && entry.join_request_id == *request.join_request_id()
                && entry.request_nonce == *request.request_nonce()
        });
        let position = position.ok_or(CapabilityAdmissionError::ReservationMismatch)?;
        self.pending.remove(position);
        Ok(())
    }
}

/// One-shot admission value owning the HPKE proof and exact validated KeyPackage.
pub struct VerifiedCapabilityAdmission {
    opened: OpenedCapabilityJoinRequest,
    validated: ValidatedKeyPackage,
    reservation_id: u64,
}

impl VerifiedCapabilityAdmission {
    /// Returns the invitation identifier authenticated by HPKE.
    #[must_use]
    pub const fn invitation_id(&self) -> &[u8; IDENTIFIER_BYTES] {
        self.opened.request().invitation_id()
    }

    /// Returns the replay identifier reserved by this value.
    #[must_use]
    pub const fn join_request_id(&self) -> &[u8; IDENTIFIER_BYTES] {
        self.opened.request().join_request_id()
    }

    /// Returns the canonical reference of the exact owned KeyPackage.
    #[must_use]
    pub const fn key_package_reference(&self) -> &KeyPackageReference {
        self.validated.key_package_reference()
    }
}
