use std::future::Future;

use thiserror::Error;

use crate::{
    AcknowledgementRight, Cursor, DepositRight, DispatchControl, OperationBudget, ReceiveRight,
    TransportFailure, TransportProfileId,
};

/// Byte length of a provider-generated mailbox continuity identifier.
pub const MAILBOX_CONTINUITY_ID_BYTES: usize = 16;
/// Byte length of a caller-generated idempotent rotation identifier.
pub const ROTATION_ID_BYTES: usize = 16;
/// Byte length of configuration and receive-scope fingerprints.
pub const MAILBOX_SCOPE_FINGERPRINT_BYTES: usize = 32;

/// Non-secret configuration binding used to invalidate foreign cursor state.
///
/// The full value intentionally omits ordinary diagnostics because it can
/// correlate local configuration state across operations.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BindingFingerprint([u8; MAILBOX_SCOPE_FINGERPRINT_BYTES]);

impl BindingFingerprint {
    /// Accepts one already-derived, nonzero configuration fingerprint.
    pub fn from_bytes(
        bytes: [u8; MAILBOX_SCOPE_FINGERPRINT_BYTES],
    ) -> Result<Self, MailboxLifecycleContractError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(MailboxLifecycleContractError::InvalidBindingFingerprint);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; MAILBOX_SCOPE_FINGERPRINT_BYTES] {
        &self.0
    }
}

/// Opaque provider-generated continuity identifier; possession grants no right.
///
/// The full identifier intentionally omits `Debug` and `Display`.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MailboxContinuityId([u8; MAILBOX_CONTINUITY_ID_BYTES]);

impl MailboxContinuityId {
    pub fn from_provider_bytes(
        bytes: [u8; MAILBOX_CONTINUITY_ID_BYTES],
    ) -> Result<Self, MailboxLifecycleContractError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(MailboxLifecycleContractError::InvalidContinuityId);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; MAILBOX_CONTINUITY_ID_BYTES] {
        &self.0
    }
}

/// Monotonic, nonzero mailbox generation within one continuity identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MailboxGeneration(u64);

impl MailboxGeneration {
    pub const fn new(value: u64) -> Result<Self, MailboxLifecycleContractError> {
        if value == 0 {
            return Err(MailboxLifecycleContractError::InvalidGeneration);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn successor(self) -> Result<Self, MailboxLifecycleContractError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(MailboxLifecycleContractError::GenerationExhausted),
        }
    }
}

/// Non-authorizing digest of one provider-defined receive scope.
///
/// This value intentionally omits ordinary diagnostics.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ReceiveScopeFingerprint([u8; MAILBOX_SCOPE_FINGERPRINT_BYTES]);

impl ReceiveScopeFingerprint {
    pub fn from_bytes(
        bytes: [u8; MAILBOX_SCOPE_FINGERPRINT_BYTES],
    ) -> Result<Self, MailboxLifecycleContractError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(MailboxLifecycleContractError::InvalidReceiveScope);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; MAILBOX_SCOPE_FINGERPRINT_BYTES] {
        &self.0
    }
}

/// Version of the opaque provider cursor encoding persisted by the owner.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CursorSchemaVersion(u16);

impl CursorSchemaVersion {
    pub const fn new(value: u16) -> Result<Self, MailboxLifecycleContractError> {
        if value == 0 {
            return Err(MailboxLifecycleContractError::InvalidCursorSchema);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Declared persistence semantics for opaque provider cursors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CursorPersistenceV1 {
    /// The owner persists cursors and binds resume to a provider-state epoch.
    OwnerBoundRestartableProviderEpoch,
}

/// Declared mailbox-generation semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxGenerationPolicyV1 {
    /// Generations increase monotonically and are never reused in a continuity.
    MonotonicNonReused,
}

/// Declared reusable-mailbox rotation semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxRotationPolicyV1 {
    /// Rotation uses predecessor CAS with bounded routine drain and no
    /// compromise overlap.
    CompareAndSwapBoundedRoutineDrain,
}

/// Declared portable acknowledgement scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcknowledgementScopeV1 {
    /// One exact bounded set of distinct IDs under generation-scoped authority.
    ExactSetPerGeneration,
}

/// Declared owner of durable receive progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveStateOwnershipV1 {
    /// A separate owner atomically commits progress; the adapter cannot do so.
    ExternalAtomicOwner,
}

/// Non-secret lifecycle declaration required from a reusable provider.
///
/// This is separate from the LocalV1 adapter manifest because LocalV1 remains
/// cursorless and implements no rotation. P1-5 providers expose this complete
/// declaration before issuance or delivery is composed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleProviderContractV1 {
    profile: TransportProfileId,
    cursor_schema: CursorSchemaVersion,
    maximum_routine_drain_seconds: u64,
}

impl LifecycleProviderContractV1 {
    pub const fn new(
        profile: TransportProfileId,
        cursor_schema: CursorSchemaVersion,
        maximum_routine_drain_seconds: u64,
    ) -> Result<Self, MailboxLifecycleContractError> {
        if matches!(profile, TransportProfileId::LocalV1) {
            return Err(MailboxLifecycleContractError::UnsupportedLifecycleProfile);
        }
        if maximum_routine_drain_seconds == 0 {
            return Err(MailboxLifecycleContractError::InvalidLifecycleDeclaration);
        }
        Ok(Self {
            profile,
            cursor_schema,
            maximum_routine_drain_seconds,
        })
    }

    /// Returns the one nonlocal semantic profile this declaration describes.
    ///
    /// This value does not enable or bind that profile; the separately reviewed
    /// profile binder retains that responsibility.
    #[must_use]
    pub const fn profile(self) -> TransportProfileId {
        self.profile
    }

    #[must_use]
    pub const fn cursor_schema(self) -> CursorSchemaVersion {
        self.cursor_schema
    }

    #[must_use]
    pub const fn cursor_persistence(self) -> CursorPersistenceV1 {
        CursorPersistenceV1::OwnerBoundRestartableProviderEpoch
    }

    #[must_use]
    pub const fn generation_policy(self) -> MailboxGenerationPolicyV1 {
        MailboxGenerationPolicyV1::MonotonicNonReused
    }

    #[must_use]
    pub const fn rotation_policy(self) -> MailboxRotationPolicyV1 {
        MailboxRotationPolicyV1::CompareAndSwapBoundedRoutineDrain
    }

    #[must_use]
    pub const fn maximum_routine_drain_seconds(self) -> u64 {
        self.maximum_routine_drain_seconds
    }

    /// Validates the declared routine-drain bound at provider entry.
    pub fn validate_rotation_request(
        self,
        request: &RotationRequestV1,
        now_unix_seconds: u64,
    ) -> Result<(), MailboxLifecycleContractError> {
        if now_unix_seconds == 0
            || request.predecessor().expires_at_unix_seconds() <= now_unix_seconds
            || request.successor_expires_at_unix_seconds() <= now_unix_seconds
            || request.predecessor().profile() != self.profile
            || request.predecessor().cursor_schema() != self.cursor_schema
        {
            return Err(MailboxLifecycleContractError::ProviderResultMismatch);
        }
        if let RotationModeV1::Routine {
            drain_predecessor_until_unix_seconds,
        } = request.mode()
            && (drain_predecessor_until_unix_seconds <= now_unix_seconds
                || drain_predecessor_until_unix_seconds.saturating_sub(now_unix_seconds)
                    > self.maximum_routine_drain_seconds)
        {
            return Err(MailboxLifecycleContractError::InvalidRotation);
        }
        Ok(())
    }

    /// Validates that one issuance request names this exact declaration.
    pub fn validate_issue_request(
        self,
        request: &MailboxIssueRequestV1,
        now_unix_seconds: u64,
    ) -> Result<(), MailboxLifecycleContractError> {
        if now_unix_seconds == 0
            || request.expires_at_unix_seconds() <= now_unix_seconds
            || request.profile() != self.profile
        {
            return Err(MailboxLifecycleContractError::ProviderResultMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn acknowledgement_scope(self) -> AcknowledgementScopeV1 {
        AcknowledgementScopeV1::ExactSetPerGeneration
    }

    #[must_use]
    pub const fn receive_state_ownership(self) -> ReceiveStateOwnershipV1 {
        ReceiveStateOwnershipV1::ExternalAtomicOwner
    }
}

/// Nonzero provider-state epoch used to invalidate restored or reset cursors.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderStateEpoch(u64);

impl ProviderStateEpoch {
    pub const fn new(value: u64) -> Result<Self, MailboxLifecycleContractError> {
        if value == 0 {
            return Err(MailboxLifecycleContractError::InvalidProviderStateEpoch);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Complete non-authorizing binding required to persist or resume one cursor.
///
/// Cursors matching only a subset of these fields are invalid. The value omits
/// ordinary diagnostics because it contains full continuity and scope values.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CursorBindingV1 {
    profile: TransportProfileId,
    binding_fingerprint: BindingFingerprint,
    continuity_id: MailboxContinuityId,
    generation: MailboxGeneration,
    receive_scope: ReceiveScopeFingerprint,
    cursor_schema: CursorSchemaVersion,
    provider_state_epoch: ProviderStateEpoch,
    expires_at_unix_seconds: u64,
}

impl CursorBindingV1 {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        profile: TransportProfileId,
        binding_fingerprint: BindingFingerprint,
        continuity_id: MailboxContinuityId,
        generation: MailboxGeneration,
        receive_scope: ReceiveScopeFingerprint,
        cursor_schema: CursorSchemaVersion,
        provider_state_epoch: ProviderStateEpoch,
        expires_at_unix_seconds: u64,
    ) -> Result<Self, MailboxLifecycleContractError> {
        if matches!(profile, TransportProfileId::LocalV1) {
            return Err(MailboxLifecycleContractError::UnsupportedLifecycleProfile);
        }
        if expires_at_unix_seconds == 0 {
            return Err(MailboxLifecycleContractError::InvalidExpiry);
        }
        Ok(Self {
            profile,
            binding_fingerprint,
            continuity_id,
            generation,
            receive_scope,
            cursor_schema,
            provider_state_epoch,
            expires_at_unix_seconds,
        })
    }

    #[must_use]
    pub const fn profile(self) -> TransportProfileId {
        self.profile
    }

    #[must_use]
    pub const fn binding_fingerprint(&self) -> &BindingFingerprint {
        &self.binding_fingerprint
    }

    #[must_use]
    pub const fn continuity_id(&self) -> &MailboxContinuityId {
        &self.continuity_id
    }

    #[must_use]
    pub const fn generation(self) -> MailboxGeneration {
        self.generation
    }

    #[must_use]
    pub const fn receive_scope(&self) -> &ReceiveScopeFingerprint {
        &self.receive_scope
    }

    #[must_use]
    pub const fn cursor_schema(self) -> CursorSchemaVersion {
        self.cursor_schema
    }

    #[must_use]
    pub const fn provider_state_epoch(self) -> ProviderStateEpoch {
        self.provider_state_epoch
    }

    #[must_use]
    pub const fn expires_at_unix_seconds(self) -> u64 {
        self.expires_at_unix_seconds
    }
}

/// One opaque cursor bound to every state component required for safe resume.
///
/// This type intentionally does not implement `Clone`, `Debug`, or `Display`.
pub struct BoundCursorV1 {
    cursor: Cursor,
    binding: CursorBindingV1,
}

impl BoundCursorV1 {
    #[must_use]
    pub const fn new(cursor: Cursor, binding: CursorBindingV1) -> Self {
        Self { cursor, binding }
    }

    #[must_use]
    pub const fn cursor(&self) -> &Cursor {
        &self.cursor
    }

    #[must_use]
    pub const fn binding(&self) -> &CursorBindingV1 {
        &self.binding
    }

    #[must_use]
    pub fn into_parts(self) -> (Cursor, CursorBindingV1) {
        (self.cursor, self.binding)
    }
}

/// Provider-issued rotation material tagged for the rotation operation only.
///
/// ```compile_fail
/// use session_transport::RotationRight;
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<RotationRight<()>>();
/// ```
///
/// ```compile_fail
/// use session_transport::RotationRight;
/// fn require_clone<T: Clone>() {}
/// require_clone::<RotationRight<()>>();
/// ```
///
/// ```compile_fail
/// use session_transport::{
///     DepositRequest, DispatchControl, EnvelopeDelivery, RotationRight,
/// };
///
/// fn rotation_is_not_deposit_authority<D: EnvelopeDelivery>(
///     delivery: &mut D,
///     rotation: &RotationRight<D::DepositEndpoint>,
///     request: DepositRequest,
///     control: &dyn DispatchControl,
/// ) {
///     let _ = delivery.deposit(rotation, request, control);
/// }
/// ```
pub struct RotationRight<T>(T);

impl<T> RotationRight<T> {
    /// Tags provider-issued material for mailbox rotation only.
    #[must_use]
    pub const fn from_provider(value: T) -> Self {
        Self(value)
    }

    /// Borrows provider-owned rotation material for exact-scope validation.
    #[must_use]
    pub const fn provider(&self) -> &T {
        &self.0
    }
}

/// Four independent provider rights issued for one exact mailbox generation.
///
/// The set intentionally omits cloning and ordinary diagnostics. Provider
/// implementations remain responsible for generating non-derivable material.
pub struct MailboxAuthoritySetV1<D, R, A, O> {
    binding: CursorBindingV1,
    deposit: DepositRight<D>,
    receive: ReceiveRight<R>,
    acknowledgement: AcknowledgementRight<A>,
    rotation: RotationRight<O>,
}

impl<D, R, A, O> MailboxAuthoritySetV1<D, R, A, O> {
    #[must_use]
    pub const fn from_provider(
        binding: CursorBindingV1,
        deposit: DepositRight<D>,
        receive: ReceiveRight<R>,
        acknowledgement: AcknowledgementRight<A>,
        rotation: RotationRight<O>,
    ) -> Self {
        Self {
            binding,
            deposit,
            receive,
            acknowledgement,
            rotation,
        }
    }

    #[must_use]
    pub const fn binding(&self) -> &CursorBindingV1 {
        &self.binding
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        CursorBindingV1,
        DepositRight<D>,
        ReceiveRight<R>,
        AcknowledgementRight<A>,
        RotationRight<O>,
    ) {
        (
            self.binding,
            self.deposit,
            self.receive,
            self.acknowledgement,
            self.rotation,
        )
    }
}

/// Bounded request for fresh, independently generated mailbox authority.
pub struct MailboxIssueRequestV1 {
    profile: TransportProfileId,
    binding_fingerprint: BindingFingerprint,
    expires_at_unix_seconds: u64,
    budget: OperationBudget,
}

impl MailboxIssueRequestV1 {
    pub const fn new(
        profile: TransportProfileId,
        binding_fingerprint: BindingFingerprint,
        expires_at_unix_seconds: u64,
        budget: OperationBudget,
    ) -> Result<Self, MailboxLifecycleContractError> {
        if matches!(profile, TransportProfileId::LocalV1) {
            return Err(MailboxLifecycleContractError::UnsupportedLifecycleProfile);
        }
        if expires_at_unix_seconds == 0 {
            return Err(MailboxLifecycleContractError::InvalidExpiry);
        }
        Ok(Self {
            profile,
            binding_fingerprint,
            expires_at_unix_seconds,
            budget,
        })
    }

    #[must_use]
    pub const fn profile(&self) -> TransportProfileId {
        self.profile
    }

    #[must_use]
    pub const fn binding_fingerprint(&self) -> &BindingFingerprint {
        &self.binding_fingerprint
    }

    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    #[must_use]
    pub const fn budget(&self) -> OperationBudget {
        self.budget
    }
}

/// Fresh mailbox authority validated against its exact issuance request.
pub struct MailboxIssueResultV1<D, R, A, O> {
    lifecycle_contract: LifecycleProviderContractV1,
    authorities: MailboxAuthoritySetV1<D, R, A, O>,
}

/// Normalized result of one bounded mailbox issuance operation.
pub type MailboxIssueOutcomeV1<D, R, A, O> =
    Result<MailboxIssueResultV1<D, R, A, O>, TransportFailure>;

impl<D, R, A, O> MailboxIssueResultV1<D, R, A, O> {
    pub fn new(
        lifecycle_contract: LifecycleProviderContractV1,
        request: MailboxIssueRequestV1,
        authorities: MailboxAuthoritySetV1<D, R, A, O>,
        now_unix_seconds: u64,
    ) -> Result<Self, MailboxLifecycleContractError> {
        lifecycle_contract.validate_issue_request(&request, now_unix_seconds)?;
        let binding = authorities.binding();
        if binding.profile() != request.profile
            || binding.binding_fingerprint() != &request.binding_fingerprint
            || binding.cursor_schema() != lifecycle_contract.cursor_schema()
            || binding.expires_at_unix_seconds() != request.expires_at_unix_seconds
        {
            return Err(MailboxLifecycleContractError::ProviderResultMismatch);
        }
        Ok(Self {
            lifecycle_contract,
            authorities,
        })
    }

    #[must_use]
    pub const fn lifecycle_contract(&self) -> LifecycleProviderContractV1 {
        self.lifecycle_contract
    }

    #[must_use]
    pub const fn authorities(&self) -> &MailboxAuthoritySetV1<D, R, A, O> {
        &self.authorities
    }

    #[must_use]
    pub fn into_authorities(self) -> MailboxAuthoritySetV1<D, R, A, O> {
        self.authorities
    }
}

/// Opaque, non-authorizing identifier for idempotent rotation recovery.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RotationId([u8; ROTATION_ID_BYTES]);

impl RotationId {
    pub fn from_provider_bytes(
        bytes: [u8; ROTATION_ID_BYTES],
    ) -> Result<Self, MailboxLifecycleContractError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(MailboxLifecycleContractError::InvalidRotationId);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ROTATION_ID_BYTES] {
        &self.0
    }
}

/// Closed predecessor-overlap policy for one mailbox rotation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RotationModeV1 {
    /// Permit bounded draining of the predecessor until the stated time.
    Routine {
        drain_predecessor_until_unix_seconds: u64,
    },
    /// Retire the predecessor immediately and accept possible message loss.
    Compromise,
}

/// Exact compare-and-swap request for one successor mailbox generation.
pub struct RotationRequestV1 {
    rotation_id: RotationId,
    predecessor: CursorBindingV1,
    successor_generation: MailboxGeneration,
    mode: RotationModeV1,
    successor_expires_at_unix_seconds: u64,
    budget: OperationBudget,
}

impl RotationRequestV1 {
    pub const fn new(
        rotation_id: RotationId,
        predecessor: CursorBindingV1,
        mode: RotationModeV1,
        successor_expires_at_unix_seconds: u64,
        budget: OperationBudget,
    ) -> Result<Self, MailboxLifecycleContractError> {
        if successor_expires_at_unix_seconds == 0 {
            return Err(MailboxLifecycleContractError::InvalidRotation);
        }
        if let RotationModeV1::Routine {
            drain_predecessor_until_unix_seconds,
        } = mode
            && (drain_predecessor_until_unix_seconds == 0
                || drain_predecessor_until_unix_seconds > predecessor.expires_at_unix_seconds
                || drain_predecessor_until_unix_seconds >= successor_expires_at_unix_seconds)
        {
            return Err(MailboxLifecycleContractError::InvalidRotation);
        }
        let successor_generation = match predecessor.generation.successor() {
            Ok(generation) => generation,
            Err(error) => return Err(error),
        };
        Ok(Self {
            rotation_id,
            predecessor,
            successor_generation,
            mode,
            successor_expires_at_unix_seconds,
            budget,
        })
    }

    #[must_use]
    pub const fn rotation_id(&self) -> &RotationId {
        &self.rotation_id
    }

    #[must_use]
    pub const fn predecessor(&self) -> &CursorBindingV1 {
        &self.predecessor
    }

    #[must_use]
    pub const fn successor_generation(&self) -> MailboxGeneration {
        self.successor_generation
    }

    #[must_use]
    pub const fn mode(&self) -> RotationModeV1 {
        self.mode
    }

    #[must_use]
    pub const fn successor_expires_at_unix_seconds(&self) -> u64 {
        self.successor_expires_at_unix_seconds
    }

    #[must_use]
    pub const fn budget(&self) -> OperationBudget {
        self.budget
    }
}

/// Successor authority validated against one exact rotation request.
pub struct MailboxRotationResultV1<D, R, A, O> {
    lifecycle_contract: LifecycleProviderContractV1,
    rotation_id: RotationId,
    predecessor_generation: MailboxGeneration,
    mode: RotationModeV1,
    authorities: MailboxAuthoritySetV1<D, R, A, O>,
}

/// Normalized result of one bounded mailbox rotation operation.
pub type MailboxRotationOutcomeV1<D, R, A, O> =
    Result<MailboxRotationResultV1<D, R, A, O>, TransportFailure>;

impl<D, R, A, O> MailboxRotationResultV1<D, R, A, O> {
    pub fn new(
        lifecycle_contract: LifecycleProviderContractV1,
        request: RotationRequestV1,
        authorities: MailboxAuthoritySetV1<D, R, A, O>,
        now_unix_seconds: u64,
    ) -> Result<Self, MailboxLifecycleContractError> {
        lifecycle_contract.validate_rotation_request(&request, now_unix_seconds)?;
        let successor = authorities.binding();
        let predecessor = request.predecessor();
        if successor.profile() != lifecycle_contract.profile()
            || successor.binding_fingerprint() != predecessor.binding_fingerprint()
            || successor.continuity_id() != predecessor.continuity_id()
            || successor.generation() != request.successor_generation()
            || successor.receive_scope() == predecessor.receive_scope()
            || successor.cursor_schema() != predecessor.cursor_schema()
            || successor.provider_state_epoch() != predecessor.provider_state_epoch()
            || successor.expires_at_unix_seconds() != request.successor_expires_at_unix_seconds()
        {
            return Err(MailboxLifecycleContractError::ProviderResultMismatch);
        }
        Ok(Self {
            lifecycle_contract,
            rotation_id: request.rotation_id,
            predecessor_generation: predecessor.generation(),
            mode: request.mode,
            authorities,
        })
    }

    #[must_use]
    pub const fn lifecycle_contract(&self) -> LifecycleProviderContractV1 {
        self.lifecycle_contract
    }

    #[must_use]
    pub const fn rotation_id(&self) -> &RotationId {
        &self.rotation_id
    }

    #[must_use]
    pub const fn predecessor_generation(&self) -> MailboxGeneration {
        self.predecessor_generation
    }

    #[must_use]
    pub const fn mode(&self) -> RotationModeV1 {
        self.mode
    }

    #[must_use]
    pub const fn authorities(&self) -> &MailboxAuthoritySetV1<D, R, A, O> {
        &self.authorities
    }

    #[must_use]
    pub fn into_authorities(self) -> MailboxAuthoritySetV1<D, R, A, O> {
        self.authorities
    }
}

/// Provider-neutral issuance and compare-and-swap mailbox rotation contract.
///
/// Implementations must issue independent material for all four rights and
/// bind it to the exact returned generation. Rotation validates the supplied
/// rotation right, predecessor binding, and idempotency identifier. An exact
/// retry returns the same successor; stale or competing requests fail closed.
///
/// A receive right cannot be substituted for the rotation right:
///
/// ```compile_fail
/// use session_transport::{
///     DispatchControl, MailboxLifecycle, ReceiveRight, RotationRequestV1,
/// };
///
/// fn receive_is_not_rotation_authority<P: MailboxLifecycle>(
///     provider: &mut P,
///     receive: &ReceiveRight<P::RotationCapability>,
///     request: RotationRequestV1,
///     control: &dyn DispatchControl,
/// ) {
///     let expected_contract = provider.lifecycle_contract();
///     let _ = provider.rotate(expected_contract, receive, request, control);
/// }
/// ```
///
/// A bound cursor is continuation state, not rotation authority:
///
/// ```compile_fail
/// use session_transport::{
///     BoundCursorV1, DispatchControl, MailboxLifecycle, RotationRequestV1,
/// };
///
/// fn cursor_is_not_rotation_authority<P: MailboxLifecycle>(
///     provider: &mut P,
///     cursor: &BoundCursorV1,
///     request: RotationRequestV1,
///     control: &dyn DispatchControl,
/// ) {
///     let expected_contract = provider.lifecycle_contract();
///     let _ = provider.rotate(expected_contract, cursor, request, control);
/// }
/// ```
pub trait MailboxLifecycle: Send {
    type DepositEndpoint: Sync;
    type ReceiveCapability: Sync;
    type AcknowledgementCapability: Sync;
    type RotationCapability: Sync;

    /// Declares the complete reusable-mailbox semantics before provider use.
    fn lifecycle_contract(&self) -> LifecycleProviderContractV1;

    /// Issues against the exact declaration observed by the composition root.
    fn issue<'a>(
        &'a mut self,
        expected_contract: LifecycleProviderContractV1,
        request: MailboxIssueRequestV1,
        control: &'a dyn DispatchControl,
    ) -> impl Future<
        Output = MailboxIssueOutcomeV1<
            Self::DepositEndpoint,
            Self::ReceiveCapability,
            Self::AcknowledgementCapability,
            Self::RotationCapability,
        >,
    > + Send
    + 'a;

    /// Rotates against the exact declaration observed by the composition root.
    fn rotate<'a>(
        &'a mut self,
        expected_contract: LifecycleProviderContractV1,
        authority: &'a RotationRight<Self::RotationCapability>,
        request: RotationRequestV1,
        control: &'a dyn DispatchControl,
    ) -> impl Future<
        Output = MailboxRotationOutcomeV1<
            Self::DepositEndpoint,
            Self::ReceiveCapability,
            Self::AcknowledgementCapability,
            Self::RotationCapability,
        >,
    > + Send
    + 'a;
}

/// Closed lifecycle behavior vocabulary consumed by the P1-5 conformance provider.
///
/// These tokens define the positive, restart, resynchronization, rotation, and
/// stale-state cases that a deterministic cursor-bearing provider must expose.
/// P1-5 may add an authority/resource matrix around these cases, but it cannot
/// silently omit or reinterpret one of them.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LifecycleConformanceCaseV1 {
    IssueFreshGeneration,
    PersistBeforeAcknowledge,
    CursorAdvance,
    CursorlessCheckpointAdvance,
    LoadCommittedCheckpoint,
    CursorOverlapDeduplicated,
    RestartResume,
    RecoverCommittedAcknowledgement,
    RecoverAcknowledgementAfterLeaseCrash,
    AcceptAcknowledgement,
    ReleaseAmbiguousAcknowledgement,
    ExplicitResynchronization,
    RecordExplicitResynchronization,
    RoutineRotation,
    CompromiseRotation,
    ExactRotationRetry,
    RejectCrossRightAuthority,
    RejectWrongProfileCursor,
    RejectWrongBindingCursor,
    RejectWrongContinuityCursor,
    RejectStaleGenerationCursor,
    RejectWrongReceiveScopeCursor,
    RejectWrongCursorSchema,
    RejectWrongProviderStateEpoch,
    RejectExpiredCursor,
    RejectStaleCheckpoint,
    RejectOutcomeCardinalityMismatch,
    RejectChangedAcknowledgementIntent,
    RejectMismatchedReceivePageBinding,
    RejectWrongCursorPosition,
    RejectDuplicateDeliveryId,
    RejectForgedCommitEvidence,
    RejectExpiredReceiveOwnerOperation,
    RejectExpiredIssuance,
    RejectForeignReceiveBinding,
    RejectStaleRotation,
    RejectCompetingRotation,
    RejectGenerationExhaustion,
}

impl LifecycleConformanceCaseV1 {
    const REQUIRED: [Self; 38] = [
        Self::IssueFreshGeneration,
        Self::PersistBeforeAcknowledge,
        Self::CursorAdvance,
        Self::CursorlessCheckpointAdvance,
        Self::LoadCommittedCheckpoint,
        Self::CursorOverlapDeduplicated,
        Self::RestartResume,
        Self::RecoverCommittedAcknowledgement,
        Self::RecoverAcknowledgementAfterLeaseCrash,
        Self::AcceptAcknowledgement,
        Self::ReleaseAmbiguousAcknowledgement,
        Self::ExplicitResynchronization,
        Self::RecordExplicitResynchronization,
        Self::RoutineRotation,
        Self::CompromiseRotation,
        Self::ExactRotationRetry,
        Self::RejectCrossRightAuthority,
        Self::RejectWrongProfileCursor,
        Self::RejectWrongBindingCursor,
        Self::RejectWrongContinuityCursor,
        Self::RejectStaleGenerationCursor,
        Self::RejectWrongReceiveScopeCursor,
        Self::RejectWrongCursorSchema,
        Self::RejectWrongProviderStateEpoch,
        Self::RejectExpiredCursor,
        Self::RejectStaleCheckpoint,
        Self::RejectOutcomeCardinalityMismatch,
        Self::RejectChangedAcknowledgementIntent,
        Self::RejectMismatchedReceivePageBinding,
        Self::RejectWrongCursorPosition,
        Self::RejectDuplicateDeliveryId,
        Self::RejectForgedCommitEvidence,
        Self::RejectExpiredReceiveOwnerOperation,
        Self::RejectExpiredIssuance,
        Self::RejectForeignReceiveBinding,
        Self::RejectStaleRotation,
        Self::RejectCompetingRotation,
        Self::RejectGenerationExhaustion,
    ];

    #[must_use]
    pub const fn required() -> &'static [Self] {
        &Self::REQUIRED
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IssueFreshGeneration => "issue-fresh-generation",
            Self::PersistBeforeAcknowledge => "persist-before-acknowledge",
            Self::CursorAdvance => "cursor-advance",
            Self::CursorlessCheckpointAdvance => "cursorless-checkpoint-advance",
            Self::LoadCommittedCheckpoint => "load-committed-checkpoint",
            Self::CursorOverlapDeduplicated => "cursor-overlap-deduplicated",
            Self::RestartResume => "restart-resume",
            Self::RecoverCommittedAcknowledgement => "recover-committed-acknowledgement",
            Self::RecoverAcknowledgementAfterLeaseCrash => {
                "recover-acknowledgement-after-lease-crash"
            }
            Self::AcceptAcknowledgement => "accept-acknowledgement",
            Self::ReleaseAmbiguousAcknowledgement => "release-ambiguous-acknowledgement",
            Self::ExplicitResynchronization => "explicit-resynchronization",
            Self::RecordExplicitResynchronization => "record-explicit-resynchronization",
            Self::RoutineRotation => "routine-rotation",
            Self::CompromiseRotation => "compromise-rotation",
            Self::ExactRotationRetry => "exact-rotation-retry",
            Self::RejectCrossRightAuthority => "reject-cross-right-authority",
            Self::RejectWrongProfileCursor => "reject-wrong-profile-cursor",
            Self::RejectWrongBindingCursor => "reject-wrong-binding-cursor",
            Self::RejectWrongContinuityCursor => "reject-wrong-continuity-cursor",
            Self::RejectStaleGenerationCursor => "reject-stale-generation-cursor",
            Self::RejectWrongReceiveScopeCursor => "reject-wrong-receive-scope-cursor",
            Self::RejectWrongCursorSchema => "reject-wrong-cursor-schema",
            Self::RejectWrongProviderStateEpoch => "reject-wrong-provider-state-epoch",
            Self::RejectExpiredCursor => "reject-expired-cursor",
            Self::RejectStaleCheckpoint => "reject-stale-checkpoint",
            Self::RejectOutcomeCardinalityMismatch => "reject-outcome-cardinality-mismatch",
            Self::RejectChangedAcknowledgementIntent => "reject-changed-acknowledgement-intent",
            Self::RejectMismatchedReceivePageBinding => "reject-mismatched-receive-page-binding",
            Self::RejectWrongCursorPosition => "reject-wrong-cursor-position",
            Self::RejectDuplicateDeliveryId => "reject-duplicate-delivery-id",
            Self::RejectForgedCommitEvidence => "reject-forged-commit-evidence",
            Self::RejectExpiredReceiveOwnerOperation => "reject-expired-receive-owner-operation",
            Self::RejectExpiredIssuance => "reject-expired-issuance",
            Self::RejectForeignReceiveBinding => "reject-foreign-receive-binding",
            Self::RejectStaleRotation => "reject-stale-rotation",
            Self::RejectCompetingRotation => "reject-competing-rotation",
            Self::RejectGenerationExhaustion => "reject-generation-exhaustion",
        }
    }
}

impl TryFrom<&str> for LifecycleConformanceCaseV1 {
    type Error = LifecycleConformanceContractError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::REQUIRED
            .iter()
            .copied()
            .find(|case| case.as_str() == value)
            .ok_or(LifecycleConformanceContractError::UnsupportedCase)
    }
}

/// Fail-closed parsing error for the versioned conformance vocabulary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LifecycleConformanceContractError {
    #[error("unsupported mailbox lifecycle conformance case")]
    UnsupportedCase,
}

/// Fail-closed construction errors for lifecycle and cursor bindings.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MailboxLifecycleContractError {
    #[error("invalid transport binding fingerprint")]
    InvalidBindingFingerprint,
    #[error("invalid mailbox continuity identifier")]
    InvalidContinuityId,
    #[error("invalid mailbox generation")]
    InvalidGeneration,
    #[error("mailbox generation exhausted")]
    GenerationExhausted,
    #[error("invalid receive scope fingerprint")]
    InvalidReceiveScope,
    #[error("invalid cursor schema version")]
    InvalidCursorSchema,
    #[error("invalid provider state epoch")]
    InvalidProviderStateEpoch,
    #[error("invalid mailbox expiry")]
    InvalidExpiry,
    #[error("invalid mailbox lifecycle declaration")]
    InvalidLifecycleDeclaration,
    #[error("transport profile does not support reusable mailbox lifecycle")]
    UnsupportedLifecycleProfile,
    #[error("invalid mailbox rotation identifier")]
    InvalidRotationId,
    #[error("invalid mailbox rotation request")]
    InvalidRotation,
    #[error("mailbox provider result does not match the exact request")]
    ProviderResultMismatch,
}
