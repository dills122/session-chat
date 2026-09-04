use std::future::Future;

use session_transport::{
    AcknowledgementRight, BindingFingerprint, CursorBindingV1, CursorSchemaVersion, DepositRight,
    DispatchControl, LifecycleProviderContractV1, MailboxAuthoritySetV1, MailboxContinuityId,
    MailboxGeneration, MailboxIssueOutcomeV1, MailboxIssueRequestV1, MailboxIssueResultV1,
    MailboxLifecycle, MailboxRotationOutcomeV1, MailboxRotationResultV1, ProviderStateEpoch,
    ReceiveRight, ReceiveScopeFingerprint, RetryAdvice, RotationId, RotationModeV1,
    RotationRequestV1, RotationRight, TransportFailure, TransportFailureCode, TransportProfileId,
};

const CURSOR_SCHEMA_V1: u16 = 1;
const PROVIDER_STATE_EPOCH_V1: u64 = 1;
const MAXIMUM_ROUTINE_DRAIN_SECONDS: u64 = 300;

/// Deterministic, publish-disabled reusable-mailbox lifecycle provider.
///
/// This provider exists only to exercise the shared lifecycle contract. It
/// performs no network I/O and its predictable authority bytes are unsuitable
/// for production use.
pub struct DeterministicLifecycleProviderV1 {
    contract: LifecycleProviderContractV1,
    next_material: u8,
    generations: Vec<GenerationMaterial>,
    active: Vec<CursorBindingV1>,
    rotations: Vec<RotationRecord>,
}

/// Provider-private deposit material for the deterministic conformance model.
pub struct DeterministicDepositEndpointV1 {
    _token: [u8; 32],
}

/// Provider-private receive material for the deterministic conformance model.
pub struct DeterministicReceiveCapabilityV1 {
    _token: [u8; 32],
}

/// Provider-private acknowledgement material for the deterministic model.
pub struct DeterministicAcknowledgementCapabilityV1 {
    _token: [u8; 32],
}

/// Provider-private rotation material for the deterministic conformance model.
pub struct DeterministicRotationCapabilityV1 {
    binding: CursorBindingV1,
    token: [u8; 32],
}

#[derive(Clone, Copy)]
struct GenerationMaterial {
    binding: CursorBindingV1,
    deposit: [u8; 32],
    receive: [u8; 32],
    acknowledgement: [u8; 32],
    rotation: [u8; 32],
}

#[derive(Clone, Copy)]
struct RotationRecord {
    rotation_id: RotationId,
    predecessor: CursorBindingV1,
    mode: RotationModeV1,
    successor_expires_at_unix_seconds: u64,
    successor: GenerationMaterial,
}

impl DeterministicLifecycleProviderV1 {
    #[must_use]
    pub fn new() -> Self {
        Self {
            contract: LifecycleProviderContractV1::new(
                TransportProfileId::FastV1,
                CursorSchemaVersion::new(CURSOR_SCHEMA_V1).expect("nonzero cursor schema"),
                MAXIMUM_ROUTINE_DRAIN_SECONDS,
            )
            .expect("deterministic lifecycle declaration is valid"),
            next_material: 1,
            generations: Vec::new(),
            active: Vec::new(),
            rotations: Vec::new(),
        }
    }

    fn issue_now(
        &mut self,
        expected_contract: LifecycleProviderContractV1,
        request: MailboxIssueRequestV1,
        control: &dyn DispatchControl,
    ) -> MailboxIssueOutcomeV1<
        DeterministicDepositEndpointV1,
        DeterministicReceiveCapabilityV1,
        DeterministicAcknowledgementCapabilityV1,
        DeterministicRotationCapabilityV1,
    > {
        let observation = control.checkpoint(request.budget())?;
        if expected_contract != self.contract
            || self
                .contract
                .validate_issue_request(&request, observation.wall_now_unix_seconds())
                .is_err()
        {
            return Err(failure(TransportFailureCode::PolicyViolation));
        }

        let continuity_material = self.take_material()?;
        let continuity_id = MailboxContinuityId::from_provider_bytes([continuity_material; 16])
            .map_err(|_| failure(TransportFailureCode::Internal))?;
        let material = self.fresh_generation(
            *request.binding_fingerprint(),
            continuity_id,
            MailboxGeneration::new(1).map_err(|_| failure(TransportFailureCode::Internal))?,
            request.expires_at_unix_seconds(),
        )?;
        let authorities = authorities(material);
        let result = MailboxIssueResultV1::new(
            self.contract,
            request,
            authorities,
            observation.wall_now_unix_seconds(),
        )
        .map_err(|_| failure(TransportFailureCode::Internal))?;
        self.generations.push(material);
        self.active.push(material.binding);
        Ok(result)
    }

    fn rotate_now(
        &mut self,
        expected_contract: LifecycleProviderContractV1,
        authority: &RotationRight<DeterministicRotationCapabilityV1>,
        request: RotationRequestV1,
        control: &dyn DispatchControl,
    ) -> MailboxRotationOutcomeV1<
        DeterministicDepositEndpointV1,
        DeterministicReceiveCapabilityV1,
        DeterministicAcknowledgementCapabilityV1,
        DeterministicRotationCapabilityV1,
    > {
        let observation = control.checkpoint(request.budget())?;
        if expected_contract != self.contract
            || self
                .contract
                .validate_rotation_request(&request, observation.wall_now_unix_seconds())
                .is_err()
        {
            return Err(failure(TransportFailureCode::PolicyViolation));
        }

        let predecessor = *request.predecessor();
        let authority = authority.provider();
        let known_predecessor = self
            .generations
            .iter()
            .find(|material| material.binding == predecessor)
            .copied();
        if authority.binding != predecessor
            || known_predecessor
                .map(|material| material.rotation != authority.token)
                .unwrap_or(true)
        {
            return Err(failure(TransportFailureCode::InvalidAuthority));
        }

        if let Some(record) = self
            .rotations
            .iter()
            .find(|record| record.rotation_id == *request.rotation_id())
            .copied()
        {
            if record.predecessor != predecessor
                || record.mode != request.mode()
                || record.successor_expires_at_unix_seconds
                    != request.successor_expires_at_unix_seconds()
            {
                return Err(failure(TransportFailureCode::IdempotencyConflict));
            }
            return MailboxRotationResultV1::new(
                self.contract,
                request,
                authorities(record.successor),
                observation.wall_now_unix_seconds(),
            )
            .map_err(|_| failure(TransportFailureCode::Internal));
        }

        let active_index = self
            .active
            .iter()
            .position(|binding| binding.continuity_id() == predecessor.continuity_id())
            .ok_or_else(|| failure(TransportFailureCode::AuthorityScopeMismatch))?;
        if self.active[active_index] != predecessor {
            return Err(failure(TransportFailureCode::AuthorityScopeMismatch));
        }

        let successor = self.fresh_generation(
            *predecessor.binding_fingerprint(),
            *predecessor.continuity_id(),
            request.successor_generation(),
            request.successor_expires_at_unix_seconds(),
        )?;
        let record = RotationRecord {
            rotation_id: *request.rotation_id(),
            predecessor,
            mode: request.mode(),
            successor_expires_at_unix_seconds: request.successor_expires_at_unix_seconds(),
            successor,
        };
        let result = MailboxRotationResultV1::new(
            self.contract,
            request,
            authorities(successor),
            observation.wall_now_unix_seconds(),
        )
        .map_err(|_| failure(TransportFailureCode::Internal))?;
        self.generations.push(successor);
        self.active[active_index] = successor.binding;
        self.rotations.push(record);
        Ok(result)
    }

    fn fresh_generation(
        &mut self,
        binding_fingerprint: BindingFingerprint,
        continuity_id: MailboxContinuityId,
        generation: MailboxGeneration,
        expires_at_unix_seconds: u64,
    ) -> Result<GenerationMaterial, TransportFailure> {
        let receive_scope = ReceiveScopeFingerprint::from_bytes([self.take_material()?; 32])
            .map_err(|_| failure(TransportFailureCode::Internal))?;
        let binding = CursorBindingV1::new(
            self.contract.profile(),
            binding_fingerprint,
            continuity_id,
            generation,
            receive_scope,
            self.contract.cursor_schema(),
            ProviderStateEpoch::new(PROVIDER_STATE_EPOCH_V1)
                .map_err(|_| failure(TransportFailureCode::Internal))?,
            expires_at_unix_seconds,
        )
        .map_err(|_| failure(TransportFailureCode::Internal))?;
        Ok(GenerationMaterial {
            binding,
            deposit: [self.take_material()?; 32],
            receive: [self.take_material()?; 32],
            acknowledgement: [self.take_material()?; 32],
            rotation: [self.take_material()?; 32],
        })
    }

    fn take_material(&mut self) -> Result<u8, TransportFailure> {
        let material = self.next_material;
        self.next_material = self
            .next_material
            .checked_add(1)
            .ok_or_else(|| failure(TransportFailureCode::QueueFull))?;
        Ok(material)
    }
}

impl Default for DeterministicLifecycleProviderV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl MailboxLifecycle for DeterministicLifecycleProviderV1 {
    type DepositEndpoint = DeterministicDepositEndpointV1;
    type ReceiveCapability = DeterministicReceiveCapabilityV1;
    type AcknowledgementCapability = DeterministicAcknowledgementCapabilityV1;
    type RotationCapability = DeterministicRotationCapabilityV1;

    fn lifecycle_contract(&self) -> LifecycleProviderContractV1 {
        self.contract
    }

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
    + 'a {
        std::future::ready(self.issue_now(expected_contract, request, control))
    }

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
    + 'a {
        std::future::ready(self.rotate_now(expected_contract, authority, request, control))
    }
}

fn authorities(
    material: GenerationMaterial,
) -> MailboxAuthoritySetV1<
    DeterministicDepositEndpointV1,
    DeterministicReceiveCapabilityV1,
    DeterministicAcknowledgementCapabilityV1,
    DeterministicRotationCapabilityV1,
> {
    MailboxAuthoritySetV1::from_provider(
        material.binding,
        DepositRight::from_provider(DeterministicDepositEndpointV1 {
            _token: material.deposit,
        }),
        ReceiveRight::from_provider(DeterministicReceiveCapabilityV1 {
            _token: material.receive,
        }),
        AcknowledgementRight::from_provider(DeterministicAcknowledgementCapabilityV1 {
            _token: material.acknowledgement,
        }),
        RotationRight::from_provider(DeterministicRotationCapabilityV1 {
            binding: material.binding,
            token: material.rotation,
        }),
    )
}

const fn failure(code: TransportFailureCode) -> TransportFailure {
    TransportFailure::new(code, RetryAdvice::Never)
}
