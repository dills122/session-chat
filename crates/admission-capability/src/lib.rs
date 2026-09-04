#![forbid(unsafe_code)]

//! Capability admission for the local protected-join profile.

use session_admission::{AdmissionMethod, ApprovalContext, PendingAdmission};
use session_core::{InvitationRegistry, InvitationReservation, ValidatedCapabilityInvitationV2};
use session_crypto_hpke::OpenedCapabilityJoinRequest;
use session_crypto_mls::{
    CommittedAddition, KeyPackageReference, PreparedAddition, SessionMlsConfig, SessionMlsGroup,
    ValidatedKeyPackage, create_key_package_validator,
};
use session_protocol::LocalWelcomeDepositEndpoint;
use thiserror::Error;

/// Backward-compatible name for the shared provider-neutral approval decision.
pub use session_admission::ApprovalDecision as ManualApprovalDecision;

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

#[derive(Clone, Eq, PartialEq)]
struct ReplayGeneration {
    invitation_id: [u8; IDENTIFIER_BYTES],
    join_challenge: [u8; FIXED_KEY_BYTES],
    invitation_key_id: [u8; IDENTIFIER_BYTES],
    intended_verifier: [u8; FIXED_KEY_BYTES],
}

#[derive(Clone, Eq, PartialEq)]
struct ReplayReservation {
    generation: ReplayGeneration,
    join_request_id: [u8; IDENTIFIER_BYTES],
    request_nonce: [u8; FIXED_KEY_BYTES],
    reservation_id: u64,
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
            || request.response_endpoint().expires_at_unix_seconds() <= now_unix_seconds
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
        let reservation = ReplayReservation {
            generation: generation.clone(),
            join_request_id,
            request_nonce,
            reservation_id,
        };
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
            reservation,
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
        self.remove_reservation(&verified.reservation)
    }

    /// Binds automated admission to the exact locally issued v2 invitation.
    ///
    /// Any binding or registry failure releases the verifier-owned replay
    /// reservation before returning a coarse rejection.
    pub fn reserve_v2_for_approval(
        &mut self,
        registry: &mut InvitationRegistry,
        invitation: &ValidatedCapabilityInvitationV2,
        verified: VerifiedCapabilityAdmission,
        now_unix_seconds: u64,
    ) -> Result<PendingCapabilityApproval, CapabilityAdmissionError> {
        if self.reservation_position(&verified.reservation).is_none() {
            return Err(CapabilityAdmissionError::ReservationMismatch);
        }
        let request = verified.opened.request();
        let signed = invitation.invitation();
        if request.invitation_id() != signed.invitation_id()
            || request.join_challenge() != signed.join_challenge()
            || request.invitation_key_id() != signed.invitation_key_id()
            || request.intended_verifier() != signed.inviter_verifying_key()
            || verified.opened.invitation_signature() != signed.signature()
        {
            self.remove_reservation(&verified.reservation)?;
            return Err(CapabilityAdmissionError::Rejected);
        }
        let approval_context = match ApprovalContext::new(
            AdmissionMethod::SecretCapability,
            *verified.invitation_id(),
            *verified.join_request_id(),
            *verified.key_package_reference(),
            request.expires_at_unix_seconds(),
        ) {
            Ok(context) => context,
            Err(_) => {
                self.remove_reservation(&verified.reservation)?;
                return Err(CapabilityAdmissionError::Rejected);
            }
        };
        let invitation_reservation = match registry.reserve_v2_after_admission(
            invitation,
            *verified.join_request_id(),
            now_unix_seconds,
        ) {
            Ok(reservation) => reservation,
            Err(_) => {
                self.remove_reservation(&verified.reservation)?;
                return Err(CapabilityAdmissionError::Rejected);
            }
        };
        Ok(PendingCapabilityApproval {
            verified,
            invitation_reservation,
            approval_context,
        })
    }

    /// Applies one explicit simulated manual-approval decision.
    ///
    /// Rejection releases both state machines. Approval produces the only value
    /// accepted by the cross-state MLS preparation API.
    pub fn decide_v2(
        &mut self,
        registry: &mut InvitationRegistry,
        pending: PendingCapabilityApproval,
        decision: ManualApprovalDecision,
        now_unix_seconds: u64,
    ) -> Result<CapabilityApprovalOutcome, CapabilityAdmissionError> {
        if self
            .reservation_position(&pending.verified.reservation)
            .is_none()
        {
            return Err(CapabilityAdmissionError::ReservationMismatch);
        }
        match decision {
            ManualApprovalDecision::Reject => {
                self.release_pending(registry, pending, now_unix_seconds)?;
                Ok(CapabilityApprovalOutcome::Rejected)
            }
            ManualApprovalDecision::Approve => {
                if pending.verified.opened.request().expires_at_unix_seconds() <= now_unix_seconds
                    || pending
                        .verified
                        .opened
                        .request()
                        .response_endpoint()
                        .expires_at_unix_seconds()
                        <= now_unix_seconds
                    || registry
                        .validate_reservation(&pending.invitation_reservation, now_unix_seconds)
                        .is_err()
                {
                    let _ = self.release_pending(registry, pending, now_unix_seconds);
                    return Err(CapabilityAdmissionError::Rejected);
                }
                Ok(CapabilityApprovalOutcome::Approved(Box::new(
                    ApprovedCapabilityAdmission {
                        verified: pending.verified,
                        invitation_reservation: pending.invitation_reservation,
                    },
                )))
            }
        }
    }

    /// Prepares MLS Add from the exact explicitly approved cross-state value.
    pub fn prepare_approved_add<'verifier, 'registry, 'group, C: SessionMlsConfig>(
        &'verifier mut self,
        registry: &'registry mut InvitationRegistry,
        approved: Box<ApprovedCapabilityAdmission>,
        group: &'group mut SessionMlsGroup<C>,
        now_unix_seconds: u64,
    ) -> Result<
        PreparedApprovedCapabilityAddition<'verifier, 'registry, 'group, C>,
        CapabilityAdmissionError,
    > {
        let ApprovedCapabilityAdmission {
            verified,
            invitation_reservation,
        } = *approved;
        if self.reservation_position(&verified.reservation).is_none() {
            return Err(CapabilityAdmissionError::ReservationMismatch);
        }
        let request_expires_at_unix_seconds = verified.opened.request().expires_at_unix_seconds();
        if verified.opened.request().expires_at_unix_seconds() <= now_unix_seconds
            || verified
                .opened
                .request()
                .response_endpoint()
                .expires_at_unix_seconds()
                <= now_unix_seconds
            || registry
                .validate_reservation(&invitation_reservation, now_unix_seconds)
                .is_err()
        {
            let _ = registry.release(invitation_reservation, now_unix_seconds);
            let _ = self.remove_reservation(&verified.reservation);
            return Err(CapabilityAdmissionError::Rejected);
        }
        let VerifiedCapabilityAdmission {
            opened,
            validated,
            reservation,
        } = verified;
        let response_endpoint = opened.into_request().into_response_endpoint();
        match group.prepare_add(validated, now_unix_seconds) {
            Ok(inner) => Ok(PreparedApprovedCapabilityAddition {
                verifier: Some(self),
                registry: Some(registry),
                inner: Some(inner),
                replay_reservation: reservation,
                invitation_reservation: Some(invitation_reservation),
                now_unix_seconds,
                request_expires_at_unix_seconds,
                response_endpoint: Some(response_endpoint),
                preserve_states: false,
            }),
            Err(_) => {
                let _ = registry.release(invitation_reservation, now_unix_seconds);
                self.remove_reservation(&reservation)?;
                Err(CapabilityAdmissionError::Rejected)
            }
        }
    }

    fn remove_reservation(
        &mut self,
        reservation: &ReplayReservation,
    ) -> Result<(), CapabilityAdmissionError> {
        let position = self
            .reservation_position(reservation)
            .ok_or(CapabilityAdmissionError::ReservationMismatch)?;
        self.pending.remove(position);
        Ok(())
    }

    fn reservation_position(&self, reservation: &ReplayReservation) -> Option<usize> {
        self.pending.iter().position(|entry| {
            entry.reservation_id == reservation.reservation_id
                && entry.generation == reservation.generation
                && entry.join_request_id == reservation.join_request_id
                && entry.request_nonce == reservation.request_nonce
        })
    }

    fn release_pending(
        &mut self,
        registry: &mut InvitationRegistry,
        pending: PendingCapabilityApproval,
        now_unix_seconds: u64,
    ) -> Result<(), CapabilityAdmissionError> {
        let invitation_result = registry.release(pending.invitation_reservation, now_unix_seconds);
        let replay_result = self.remove_reservation(&pending.verified.reservation);
        if invitation_result.is_err() || replay_result.is_err() {
            return Err(CapabilityAdmissionError::ReservationMismatch);
        }
        Ok(())
    }
}

/// One-shot admission value owning the HPKE proof and exact validated KeyPackage.
pub struct VerifiedCapabilityAdmission {
    opened: OpenedCapabilityJoinRequest,
    validated: ValidatedKeyPackage,
    reservation: ReplayReservation,
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

/// Result of consuming one pending approval value.
#[must_use]
pub enum CapabilityApprovalOutcome {
    /// Exact admission authority that may enter MLS preparation once.
    Approved(Box<ApprovedCapabilityAdmission>),
    /// The request was rejected and both reservations were released.
    Rejected,
}

/// Exact automated admission plus inviter-owned invitation reservation awaiting approval.
#[must_use]
pub struct PendingCapabilityApproval {
    verified: VerifiedCapabilityAdmission,
    invitation_reservation: InvitationReservation,
    approval_context: ApprovalContext,
}

impl PendingCapabilityApproval {
    /// Returns the exact invitation identifier awaiting approval.
    #[must_use]
    pub const fn invitation_id(&self) -> &[u8; IDENTIFIER_BYTES] {
        self.verified.invitation_id()
    }

    /// Returns the exact request identifier awaiting approval.
    #[must_use]
    pub const fn join_request_id(&self) -> &[u8; IDENTIFIER_BYTES] {
        self.verified.join_request_id()
    }
}

impl PendingAdmission for PendingCapabilityApproval {
    fn approval_context(&self) -> ApprovalContext {
        self.approval_context
    }
}

/// One-shot approved authority for the exact invitation, request, and KeyPackage.
#[must_use]
pub struct ApprovedCapabilityAdmission {
    verified: VerifiedCapabilityAdmission,
    invitation_reservation: InvitationReservation,
}

impl ApprovedCapabilityAdmission {
    /// Returns the exact KeyPackage reference authorized for MLS Add.
    #[must_use]
    pub const fn key_package_reference(&self) -> &KeyPackageReference {
        self.verified.key_package_reference()
    }
}

/// Pending approved MLS Add coupled to invitation and replay reservations.
pub struct PreparedApprovedCapabilityAddition<'verifier, 'registry, 'group, C: SessionMlsConfig> {
    verifier: Option<&'verifier mut CapabilityAdmissionVerifier>,
    registry: Option<&'registry mut InvitationRegistry>,
    inner: Option<PreparedAddition<'group, C>>,
    replay_reservation: ReplayReservation,
    invitation_reservation: Option<InvitationReservation>,
    now_unix_seconds: u64,
    request_expires_at_unix_seconds: u64,
    response_endpoint: Option<LocalWelcomeDepositEndpoint>,
    preserve_states: bool,
}

impl<'verifier, 'registry, C: SessionMlsConfig>
    PreparedApprovedCapabilityAddition<'verifier, 'registry, '_, C>
{
    /// Returns the exact admitted KeyPackage reference targeted by the Welcome.
    #[must_use]
    pub fn key_package_reference(&self) -> &KeyPackageReference {
        self.inner
            .as_ref()
            .expect("prepared addition exists until apply")
            .key_package_reference()
    }

    /// Observes that preparation has not advanced the group epoch.
    #[must_use]
    pub fn current_group_epoch(&self) -> u64 {
        self.inner
            .as_ref()
            .expect("prepared addition exists until apply")
            .current_group_epoch()
    }

    /// Applies MLS Add and consumes the exact invitation reservation in memory.
    ///
    /// Durable composition roots must use [`Self::apply_awaiting_durability`]
    /// instead so an ambiguous owner-store outcome cannot be mistaken for a
    /// proven commit or rollback.
    pub fn apply(
        self,
        now_unix_seconds: u64,
    ) -> Result<CommittedCapabilityJoin, CapabilityAdmissionError> {
        self.apply_awaiting_durability(now_unix_seconds)?
            .finalize_committed()
    }

    /// Applies the exact approved MLS Add while preserving both admission
    /// reservations until the owner-store result is resolved.
    ///
    /// The returned one-shot value deliberately has no automatic rollback on
    /// drop: a lost or ambiguous SQL commit result must remain fail-closed.
    /// Callers may expose the Welcome only after the durable transaction is
    /// recovered as committed and [`AppliedCapabilityJoinAwaitingDurability::finalize_committed`]
    /// succeeds.
    pub fn apply_awaiting_durability(
        mut self,
        now_unix_seconds: u64,
    ) -> Result<
        AppliedCapabilityJoinAwaitingDurability<'verifier, 'registry>,
        CapabilityAdmissionError,
    > {
        self.now_unix_seconds = now_unix_seconds;
        if self.request_expires_at_unix_seconds <= now_unix_seconds
            || self
                .response_endpoint
                .as_ref()
                .is_none_or(|endpoint| endpoint.expires_at_unix_seconds() <= now_unix_seconds)
        {
            return Err(CapabilityAdmissionError::Rejected);
        }
        let invitation_reservation = self
            .invitation_reservation
            .as_ref()
            .expect("prepared invitation reservation exists until apply");
        self.registry
            .as_deref()
            .expect("prepared registry borrow exists until apply")
            .validate_reservation(invitation_reservation, now_unix_seconds)
            .map_err(|_| CapabilityAdmissionError::Rejected)?;
        let inner = self
            .inner
            .take()
            .expect("prepared MLS addition exists until apply");
        let committed = inner
            .apply()
            .map_err(|_| CapabilityAdmissionError::Rejected)?;
        self.preserve_states = true;
        let invitation_reservation = self
            .invitation_reservation
            .take()
            .expect("prepared invitation reservation exists after MLS apply");
        let response_endpoint = self
            .response_endpoint
            .take()
            .expect("prepared response endpoint exists after MLS apply");
        let verifier = self
            .verifier
            .take()
            .expect("prepared verifier borrow exists after MLS apply");
        let registry = self
            .registry
            .take()
            .expect("prepared registry borrow exists after MLS apply");
        Ok(AppliedCapabilityJoinAwaitingDurability {
            verifier,
            registry,
            committed,
            response_endpoint,
            replay_reservation: self.replay_reservation.clone(),
            invitation_reservation,
            applied_at_unix_seconds: now_unix_seconds,
        })
    }
}

/// Applied MLS result whose owner-store transaction is not yet resolved.
///
/// Dropping this value preserves both in-memory admission reservations. This
/// is intentional fail-closed behavior for crash and ambiguous-commit paths.
#[must_use = "resolve the durable commit before exposing or discarding this MLS result"]
pub struct AppliedCapabilityJoinAwaitingDurability<'verifier, 'registry> {
    verifier: &'verifier mut CapabilityAdmissionVerifier,
    registry: &'registry mut InvitationRegistry,
    committed: CommittedAddition,
    response_endpoint: LocalWelcomeDepositEndpoint,
    replay_reservation: ReplayReservation,
    invitation_reservation: InvitationReservation,
    applied_at_unix_seconds: u64,
}

impl<'verifier, 'registry> AppliedCapabilityJoinAwaitingDurability<'verifier, 'registry> {
    /// Returns the exact admitted KeyPackage reference targeted by the Welcome.
    #[must_use]
    pub fn key_package_reference(&self) -> &KeyPackageReference {
        self.committed.key_package_reference()
    }

    /// Borrows the MLS Commit that must be included in the durable owner write.
    #[must_use]
    pub fn commit(&self) -> &session_crypto_mls::MlsWireMessage {
        self.committed.commit()
    }

    /// Borrows the encrypted Welcome that must be queued byte-exactly.
    #[must_use]
    pub fn welcome(&self) -> &session_crypto_mls::WelcomeMessage {
        self.committed.welcome()
    }

    /// Borrows the authenticated deposit-only response endpoint.
    #[must_use]
    pub fn response_endpoint(&self) -> &LocalWelcomeDepositEndpoint {
        &self.response_endpoint
    }

    /// Transfers the provider-applied Add to a durable authorization owner.
    ///
    /// The returned settlement value keeps the in-memory invitation and replay
    /// shadows reserved until the durable owner proves the exact transaction
    /// committed or uncommitted. This process therefore cannot reuse either
    /// value while the storage result is unresolved.
    #[must_use = "persist the exact provider-applied Add through the durable authorization owner"]
    pub fn into_durable_owner_parts(
        self,
    ) -> (
        CommittedAddition,
        LocalWelcomeDepositEndpoint,
        DurableCapabilityShadowSettlement<'verifier, 'registry>,
    ) {
        let Self {
            verifier,
            registry,
            committed,
            response_endpoint,
            replay_reservation,
            invitation_reservation,
            applied_at_unix_seconds,
        } = self;
        (
            committed,
            response_endpoint,
            DurableCapabilityShadowSettlement {
                verifier,
                registry,
                replay_reservation,
                invitation_reservation,
                applied_at_unix_seconds,
            },
        )
    }

    /// Returns the current in-memory invitation shadow without mutation.
    #[must_use]
    pub fn invitation_lifecycle(&self) -> Option<session_core::InvitationLifecycle> {
        let invitation_id = &self.replay_reservation.generation.invitation_id;
        self.registry.lifecycle(invitation_id)
    }

    /// Reflects a recovered committed owner-store transaction in the in-memory
    /// invitation shadow and returns the delivery material.
    pub fn finalize_committed(self) -> Result<CommittedCapabilityJoin, CapabilityAdmissionError> {
        self.registry
            .consume_after_membership(self.invitation_reservation, self.applied_at_unix_seconds)
            .map_err(|_| CapabilityAdmissionError::ReservationMismatch)?;
        Ok(CommittedCapabilityJoin {
            committed: self.committed,
            response_endpoint: self.response_endpoint,
        })
    }

    /// Releases both admission reservations after the owner store proves that
    /// no MLS membership transaction committed.
    ///
    /// The caller must discard the transiently advanced group and reload it
    /// from the authoritative owner store before another membership attempt.
    pub fn release_proven_uncommitted(self) -> Result<(), CapabilityAdmissionError> {
        let invitation_result = self
            .registry
            .release(self.invitation_reservation, self.applied_at_unix_seconds);
        let replay_result = self.verifier.remove_reservation(&self.replay_reservation);
        if invitation_result.is_err() || replay_result.is_err() {
            return Err(CapabilityAdmissionError::ReservationMismatch);
        }
        Ok(())
    }
}

/// Provider-owned in-memory shadows awaiting an exact durable-owner outcome.
///
/// This value carries no MLS Add or Welcome authority. It can only mirror a
/// proven durable result into the provider's bounded in-memory state.
#[must_use = "settle provider shadows after resolving the durable owner outcome"]
pub struct DurableCapabilityShadowSettlement<'verifier, 'registry> {
    verifier: &'verifier mut CapabilityAdmissionVerifier,
    registry: &'registry mut InvitationRegistry,
    replay_reservation: ReplayReservation,
    invitation_reservation: InvitationReservation,
    applied_at_unix_seconds: u64,
}

impl DurableCapabilityShadowSettlement<'_, '_> {
    /// Reflects a proven durable commit in the inviter's in-memory invitation shadow.
    pub fn finalize_committed(self) -> Result<(), CapabilityAdmissionError> {
        self.registry
            .consume_after_membership(self.invitation_reservation, self.applied_at_unix_seconds)
            .map_err(|_| CapabilityAdmissionError::ReservationMismatch)
    }

    /// Releases both provider shadows after durable recovery proves no commit.
    pub fn release_proven_uncommitted(self) -> Result<(), CapabilityAdmissionError> {
        let invitation_result = self
            .registry
            .release(self.invitation_reservation, self.applied_at_unix_seconds);
        let replay_result = self.verifier.remove_reservation(&self.replay_reservation);
        if invitation_result.is_err() || replay_result.is_err() {
            return Err(CapabilityAdmissionError::ReservationMismatch);
        }
        Ok(())
    }
}

/// Applied in-memory capability join plus its authenticated deposit-only endpoint.
pub struct CommittedCapabilityJoin {
    committed: CommittedAddition,
    response_endpoint: LocalWelcomeDepositEndpoint,
}

impl CommittedCapabilityJoin {
    /// Returns the reference checked against the encrypted Welcome recipients.
    #[must_use]
    pub const fn key_package_reference(&self) -> &KeyPackageReference {
        self.committed.key_package_reference()
    }

    /// Borrows the MLS Commit for future durable local persistence.
    #[must_use]
    pub const fn commit(&self) -> &session_crypto_mls::MlsWireMessage {
        self.committed.commit()
    }

    /// Borrows the encrypted MLS Welcome to frame for delivery.
    #[must_use]
    pub const fn welcome(&self) -> &session_crypto_mls::WelcomeMessage {
        self.committed.welcome()
    }

    /// Borrows the only mailbox authority returned to the inviter.
    #[must_use]
    pub const fn response_endpoint(&self) -> &LocalWelcomeDepositEndpoint {
        &self.response_endpoint
    }

    /// Separates the committed MLS result from its deposit-only destination.
    #[must_use]
    pub fn into_parts(self) -> (CommittedAddition, LocalWelcomeDepositEndpoint) {
        (self.committed, self.response_endpoint)
    }
}

impl<C: SessionMlsConfig> Drop for PreparedApprovedCapabilityAddition<'_, '_, '_, C> {
    fn drop(&mut self) {
        if !self.preserve_states {
            drop(self.inner.take());
            if let Some(reservation) = self.invitation_reservation.take()
                && let Some(registry) = self.registry.as_deref_mut()
            {
                let _ = registry.release(reservation, self.now_unix_seconds);
            }
            if let Some(verifier) = self.verifier.as_deref_mut() {
                let _ = verifier.remove_reservation(&self.replay_reservation);
            }
        }
    }
}
