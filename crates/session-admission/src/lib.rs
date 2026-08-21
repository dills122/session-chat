#![forbid(unsafe_code)]

//! Provider-neutral admission and approval contracts.

use std::{error::Error, fmt};

/// Byte length of an invitation or join-request identifier.
pub const ADMISSION_IDENTIFIER_BYTES: usize = 16;
/// Byte length of the canonical MLS KeyPackage reference in the Phase 1 suite.
pub const KEY_PACKAGE_REFERENCE_BYTES: usize = 32;

/// Admission mechanism that produced one pending approval request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionMethod {
    /// Possession of the invitation-scoped secret capability was verified.
    SecretCapability,
}

/// Human or headless policy decision for one already verified request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalDecision {
    /// Continue with the exact provider-owned admission authority.
    Approve,
    /// Reject the request and release its provider-owned reservations.
    Reject,
}

/// Coarse failure from the provider-neutral admission contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionContractError {
    /// A required identifier, KeyPackage reference, or expiration was zero.
    InvalidContext,
}

impl fmt::Display for AdmissionContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid admission approval context")
    }
}

impl Error for AdmissionContractError {}

/// Non-authorizing metadata shown to an approval policy or user interface.
///
/// This value deliberately carries no admission proof, bearer capability,
/// parsed KeyPackage, invitation reservation, replay authority, or membership
/// authority. Approving a copied or reconstructed context grants nothing; the
/// concrete provider must consume its original one-shot value.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ApprovalContext {
    method: AdmissionMethod,
    invitation_id: [u8; ADMISSION_IDENTIFIER_BYTES],
    join_request_id: [u8; ADMISSION_IDENTIFIER_BYTES],
    key_package_reference: [u8; KEY_PACKAGE_REFERENCE_BYTES],
    expires_at_unix_seconds: u64,
}

impl ApprovalContext {
    /// Creates display-only approval metadata after structural validation.
    pub fn new(
        method: AdmissionMethod,
        invitation_id: [u8; ADMISSION_IDENTIFIER_BYTES],
        join_request_id: [u8; ADMISSION_IDENTIFIER_BYTES],
        key_package_reference: [u8; KEY_PACKAGE_REFERENCE_BYTES],
        expires_at_unix_seconds: u64,
    ) -> Result<Self, AdmissionContractError> {
        if invitation_id == [0; ADMISSION_IDENTIFIER_BYTES]
            || join_request_id == [0; ADMISSION_IDENTIFIER_BYTES]
            || key_package_reference == [0; KEY_PACKAGE_REFERENCE_BYTES]
            || expires_at_unix_seconds == 0
        {
            return Err(AdmissionContractError::InvalidContext);
        }
        Ok(Self {
            method,
            invitation_id,
            join_request_id,
            key_package_reference,
            expires_at_unix_seconds,
        })
    }

    /// Returns the evidence mechanism already verified by the provider.
    #[must_use]
    pub const fn method(&self) -> AdmissionMethod {
        self.method
    }

    /// Returns the invitation identifier awaiting a decision.
    #[must_use]
    pub const fn invitation_id(&self) -> &[u8; ADMISSION_IDENTIFIER_BYTES] {
        &self.invitation_id
    }

    /// Returns the join-request identifier awaiting a decision.
    #[must_use]
    pub const fn join_request_id(&self) -> &[u8; ADMISSION_IDENTIFIER_BYTES] {
        &self.join_request_id
    }

    /// Returns the exact KeyPackage reference already bound by the provider.
    #[must_use]
    pub const fn key_package_reference(&self) -> &[u8; KEY_PACKAGE_REFERENCE_BYTES] {
        &self.key_package_reference
    }

    /// Returns the request expiration that must be rechecked before mutation.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }
}

impl fmt::Debug for ApprovalContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalContext")
            .field("method", &self.method)
            .field("expires_at_unix_seconds", &self.expires_at_unix_seconds)
            .finish_non_exhaustive()
    }
}

/// Provider-neutral observation of one pending admission request.
///
/// The trait is object-safe for a future composition root. It exposes only a
/// display-only [`ApprovalContext`]; provider-specific verified evidence and
/// exact membership authority remain concrete, linear, and non-cloneable.
pub trait PendingAdmission {
    /// Returns non-authorizing metadata for an approval decision.
    fn approval_context(&self) -> ApprovalContext;
}
