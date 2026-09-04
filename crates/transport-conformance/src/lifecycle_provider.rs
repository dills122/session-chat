use std::future::Future;

use session_transport::{
    AcknowledgementReceipt, AcknowledgementRequest, AcknowledgementRight, BindingFingerprint,
    CanonicalEnvelope, Cursor, CursorBindingV1, CursorSchemaVersion, DeliveryId, DepositReceipt,
    DepositRequest, DepositRight, DispatchControl, EnvelopeDelivery, EnvelopeId,
    LifecycleProviderContractV1, MailboxAuthoritySetV1, MailboxContinuityId, MailboxGeneration,
    MailboxIssueOutcomeV1, MailboxIssueRequestV1, MailboxIssueResultV1, MailboxLifecycle,
    MailboxRotationOutcomeV1, MailboxRotationResultV1, PollRequest, ProviderStateEpoch,
    ReceiveBatch, ReceiveRight, ReceiveScopeFingerprint, ReceivedCanonicalEnvelope, RetryAdvice,
    RotationId, RotationModeV1, RotationRequestV1, RotationRight, TransportFailure,
    TransportFailureCode, TransportProfileId,
};

const CURSOR_SCHEMA_V1: u16 = 1;
const PROVIDER_STATE_EPOCH_V1: u64 = 1;
const MAXIMUM_ROUTINE_DRAIN_SECONDS: u64 = 300;
const MAX_ENVELOPES_PER_GENERATION: usize = 64;

/// Deterministic, publish-disabled reusable-mailbox lifecycle provider.
///
/// This provider exists only to exercise the shared lifecycle contract. It
/// performs no network I/O and its predictable authority bytes are unsuitable
/// for production use.
pub struct DeterministicLifecycleProviderV1 {
    contract: LifecycleProviderContractV1,
    next_material: u8,
    next_delivery_sequence: u64,
    mailboxes: Vec<MailboxState>,
    active: Vec<CursorBindingV1>,
    rotations: Vec<RotationRecord>,
}

/// Provider-private deposit material for the deterministic conformance model.
pub struct DeterministicDepositEndpointV1 {
    binding: CursorBindingV1,
    token: [u8; 32],
}

/// Provider-private receive material for the deterministic conformance model.
pub struct DeterministicReceiveCapabilityV1 {
    binding: CursorBindingV1,
    token: [u8; 32],
}

/// Provider-private acknowledgement material for the deterministic model.
pub struct DeterministicAcknowledgementCapabilityV1 {
    binding: CursorBindingV1,
    token: [u8; 32],
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

struct MailboxState {
    material: GenerationMaterial,
    retire_at_unix_seconds: Option<u64>,
    deliveries: Vec<StoredDelivery>,
}

struct StoredDelivery {
    sequence: u64,
    delivery_id: DeliveryId,
    envelope_id: EnvelopeId,
    canonical_bytes: Box<[u8]>,
    expires_at_unix_seconds: u64,
    acknowledged: bool,
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
            next_delivery_sequence: 1,
            mailboxes: Vec::new(),
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
        self.mailboxes.push(MailboxState {
            material,
            retire_at_unix_seconds: None,
            deliveries: Vec::new(),
        });
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
            .mailboxes
            .iter()
            .find(|mailbox| mailbox.material.binding == predecessor)
            .map(|mailbox| mailbox.material);
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
        let predecessor_mailbox = self
            .mailboxes
            .iter_mut()
            .find(|mailbox| mailbox.material.binding == predecessor)
            .ok_or_else(|| failure(TransportFailureCode::Internal))?;
        predecessor_mailbox.retire_at_unix_seconds = Some(match request_mode(record.mode) {
            Some(drain) => drain,
            None => observation.wall_now_unix_seconds(),
        });
        self.mailboxes.push(MailboxState {
            material: successor,
            retire_at_unix_seconds: None,
            deliveries: Vec::new(),
        });
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

    fn mailbox_index(
        &self,
        binding: CursorBindingV1,
        token: &[u8; 32],
        expected_token: impl FnOnce(&GenerationMaterial) -> &[u8; 32],
        now_unix_seconds: u64,
    ) -> Result<usize, TransportFailure> {
        let index = self
            .mailboxes
            .iter()
            .position(|mailbox| mailbox.material.binding == binding)
            .ok_or_else(|| failure(TransportFailureCode::InvalidAuthority))?;
        let mailbox = &self.mailboxes[index];
        if expected_token(&mailbox.material) != token
            || binding.expires_at_unix_seconds() <= now_unix_seconds
            || mailbox
                .retire_at_unix_seconds
                .is_some_and(|retire_at| retire_at <= now_unix_seconds)
        {
            return Err(failure(TransportFailureCode::InvalidAuthority));
        }
        Ok(index)
    }

    fn deposit_now(
        &mut self,
        endpoint: &DepositRight<DeterministicDepositEndpointV1>,
        request: DepositRequest,
        control: &dyn DispatchControl,
    ) -> Result<DepositReceipt, TransportFailure> {
        let first = control.checkpoint(request.budget())?;
        let endpoint = endpoint.provider();
        let mut mailbox_index = self.mailbox_index(
            endpoint.binding,
            &endpoint.token,
            |material| &material.deposit,
            first.wall_now_unix_seconds(),
        )?;
        if request.envelope().expires_at_unix_seconds() <= first.wall_now_unix_seconds() {
            return Err(failure(TransportFailureCode::ExpiredEnvelope));
        }
        if let Some(existing) = self.mailboxes[mailbox_index]
            .deliveries
            .iter()
            .find(|delivery| delivery.envelope_id == *request.envelope().envelope_id())
        {
            return if existing.canonical_bytes.as_ref() == request.envelope().as_bytes() {
                Ok(DepositReceipt::accepted(existing.delivery_id))
            } else {
                Err(failure(TransportFailureCode::IdempotencyConflict))
            };
        }

        let final_observation = control.checkpoint(request.budget())?;
        mailbox_index = self.mailbox_index(
            endpoint.binding,
            &endpoint.token,
            |material| &material.deposit,
            final_observation.wall_now_unix_seconds(),
        )?;
        if request.envelope().expires_at_unix_seconds() <= final_observation.wall_now_unix_seconds()
        {
            return Err(failure(TransportFailureCode::ExpiredEnvelope));
        }
        if self.mailboxes[mailbox_index].deliveries.len() >= MAX_ENVELOPES_PER_GENERATION {
            return Err(failure(TransportFailureCode::QueueFull));
        }

        let sequence = self.next_delivery_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| failure(TransportFailureCode::QueueFull))?;
        let mut delivery_id_bytes = [0_u8; 16];
        delivery_id_bytes[0] = 0xd1;
        delivery_id_bytes[8..].copy_from_slice(&sequence.to_be_bytes());
        let delivery_id = DeliveryId::from_provider_bytes(delivery_id_bytes)
            .ok_or_else(|| failure(TransportFailureCode::Internal))?;
        let (envelope, _) = request.into_parts();
        let stored = StoredDelivery {
            sequence,
            delivery_id,
            envelope_id: *envelope.envelope_id(),
            canonical_bytes: envelope.as_bytes().to_vec().into_boxed_slice(),
            expires_at_unix_seconds: envelope.expires_at_unix_seconds(),
            acknowledged: false,
        };
        self.next_delivery_sequence = next_sequence;
        self.mailboxes[mailbox_index].deliveries.push(stored);
        Ok(DepositReceipt::accepted(delivery_id))
    }

    fn poll_now(
        &mut self,
        authority: &ReceiveRight<DeterministicReceiveCapabilityV1>,
        request: PollRequest,
        control: &dyn DispatchControl,
    ) -> Result<ReceiveBatch, TransportFailure> {
        let first = control.checkpoint(request.budget())?;
        let authority = authority.provider();
        let mut mailbox_index = self.mailbox_index(
            authority.binding,
            &authority.token,
            |material| &material.receive,
            first.wall_now_unix_seconds(),
        )?;
        let requested_cursor = decode_cursor(request.cursor())?;
        let maximum_sequence = self.mailboxes[mailbox_index]
            .deliveries
            .last()
            .map(|delivery| delivery.sequence)
            .unwrap_or(0);
        if requested_cursor > maximum_sequence {
            return Err(failure(TransportFailureCode::InvalidCursor));
        }

        let final_observation = control.checkpoint(request.budget())?;
        mailbox_index = self.mailbox_index(
            authority.binding,
            &authority.token,
            |material| &material.receive,
            final_observation.wall_now_unix_seconds(),
        )?;
        let now = first
            .wall_now_unix_seconds()
            .max(final_observation.wall_now_unix_seconds());
        let mut encoded_bytes = 0_usize;
        let mut last_cursor = requested_cursor;
        let mut items = Vec::new();
        for delivery in self.mailboxes[mailbox_index]
            .deliveries
            .iter()
            .filter(|delivery| {
                delivery.sequence > requested_cursor
                    && !delivery.acknowledged
                    && delivery.expires_at_unix_seconds > now
            })
        {
            if items.len() >= usize::from(request.max_envelopes()) {
                break;
            }
            let next_bytes = encoded_bytes
                .checked_add(delivery.canonical_bytes.len())
                .ok_or_else(|| failure(TransportFailureCode::EnvelopeTooLarge))?;
            if next_bytes
                > usize::try_from(request.max_encoded_bytes())
                    .map_err(|_| failure(TransportFailureCode::EnvelopeTooLarge))?
            {
                if items.is_empty() {
                    return Err(failure(TransportFailureCode::EnvelopeTooLarge));
                }
                break;
            }
            let envelope =
                CanonicalEnvelope::from_canonical_bytes(delivery.canonical_bytes.to_vec())
                    .map_err(|_| failure(TransportFailureCode::CorruptRemoteResponse))?;
            encoded_bytes = next_bytes;
            last_cursor = delivery.sequence;
            items.push(ReceivedCanonicalEnvelope::new(
                delivery.delivery_id,
                envelope,
            ));
        }
        let next_cursor = (last_cursor != 0)
            .then(|| Cursor::new(last_cursor.to_be_bytes().to_vec()))
            .transpose()
            .map_err(|_| failure(TransportFailureCode::Internal))?;
        ReceiveBatch::new(items, next_cursor, &request, now)
            .map_err(|_| failure(TransportFailureCode::CorruptRemoteResponse))
    }

    fn acknowledge_now(
        &mut self,
        authority: &AcknowledgementRight<DeterministicAcknowledgementCapabilityV1>,
        request: AcknowledgementRequest,
        control: &dyn DispatchControl,
    ) -> Result<AcknowledgementReceipt, TransportFailure> {
        let first = control.checkpoint(request.budget())?;
        let authority = authority.provider();
        self.mailbox_index(
            authority.binding,
            &authority.token,
            |material| &material.acknowledgement,
            first.wall_now_unix_seconds(),
        )?;
        let final_observation = control.checkpoint(request.budget())?;
        let mailbox_index = self.mailbox_index(
            authority.binding,
            &authority.token,
            |material| &material.acknowledgement,
            final_observation.wall_now_unix_seconds(),
        )?;
        let (delivery_ids, _) = request.into_parts();
        for delivery in &mut self.mailboxes[mailbox_index].deliveries {
            if delivery_ids.as_slice().contains(&delivery.delivery_id) {
                delivery.acknowledged = true;
            }
        }
        Ok(AcknowledgementReceipt::accepted())
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

impl EnvelopeDelivery for DeterministicLifecycleProviderV1 {
    type DepositEndpoint = DeterministicDepositEndpointV1;
    type ReceiveCapability = DeterministicReceiveCapabilityV1;
    type AcknowledgementCapability = DeterministicAcknowledgementCapabilityV1;

    fn deposit<'a>(
        &'a mut self,
        endpoint: &'a DepositRight<Self::DepositEndpoint>,
        request: DepositRequest,
        control: &'a dyn DispatchControl,
    ) -> impl Future<Output = Result<DepositReceipt, TransportFailure>> + Send + 'a {
        std::future::ready(self.deposit_now(endpoint, request, control))
    }

    fn poll<'a>(
        &'a mut self,
        authority: &'a ReceiveRight<Self::ReceiveCapability>,
        request: PollRequest,
        control: &'a dyn DispatchControl,
    ) -> impl Future<Output = Result<ReceiveBatch, TransportFailure>> + Send + 'a {
        std::future::ready(self.poll_now(authority, request, control))
    }

    fn acknowledge<'a>(
        &'a mut self,
        authority: &'a AcknowledgementRight<Self::AcknowledgementCapability>,
        request: AcknowledgementRequest,
        control: &'a dyn DispatchControl,
    ) -> impl Future<Output = Result<AcknowledgementReceipt, TransportFailure>> + Send + 'a {
        std::future::ready(self.acknowledge_now(authority, request, control))
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
            binding: material.binding,
            token: material.deposit,
        }),
        ReceiveRight::from_provider(DeterministicReceiveCapabilityV1 {
            binding: material.binding,
            token: material.receive,
        }),
        AcknowledgementRight::from_provider(DeterministicAcknowledgementCapabilityV1 {
            binding: material.binding,
            token: material.acknowledgement,
        }),
        RotationRight::from_provider(DeterministicRotationCapabilityV1 {
            binding: material.binding,
            token: material.rotation,
        }),
    )
}

fn decode_cursor(cursor: Option<&Cursor>) -> Result<u64, TransportFailure> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    let bytes: [u8; 8] = cursor
        .as_bytes()
        .try_into()
        .map_err(|_| failure(TransportFailureCode::InvalidCursor))?;
    let sequence = u64::from_be_bytes(bytes);
    if sequence == 0 {
        return Err(failure(TransportFailureCode::InvalidCursor));
    }
    Ok(sequence)
}

const fn request_mode(mode: RotationModeV1) -> Option<u64> {
    match mode {
        RotationModeV1::Routine {
            drain_predecessor_until_unix_seconds,
        } => Some(drain_predecessor_until_unix_seconds),
        RotationModeV1::Compromise => None,
    }
}

const fn failure(code: TransportFailureCode) -> TransportFailure {
    TransportFailure::new(code, RetryAdvice::Never)
}
