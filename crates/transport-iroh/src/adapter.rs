use std::{
    collections::BTreeMap,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use aws_lc_rs::{constant_time, digest, hmac, rand};
use minicbor::{Decoder, Encoder};
use session_transport::{
    AcknowledgementReceipt, AcknowledgementRequest, AcknowledgementRight, AdapterExecutionV1,
    AdapterId, AdapterLimitsV1, AdapterManifestV1, AdapterOperationsV1, AdapterVersionV1,
    BackgroundWorkV1, BindingErrorV1, CanonicalEnvelope, Cursor, DeliveryId, DepositReceipt,
    DepositRequest, DepositRight, DispatchControl, EgressDeclarationV1, EnvelopeDelivery,
    InternalRetryV1, PollRequest, ReceiveBatch, ReceiveRight, ReceivedCanonicalEnvelope,
    RetryAdvice, TransportFailure, TransportFailureCode, TransportProfileId,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{FastEndpointId, IrohFastError, IrohFastLink};

const WIRE_VERSION: u16 = 1;
const OP_DEPOSIT: u8 = 1;
const OP_POLL: u8 = 2;
const OP_ACKNOWLEDGE: u8 = 3;
const OUTER_FIELDS: u64 = 5;
const RESPONSE_FIELDS: u64 = 4;
const MAILBOX_ID_BYTES: usize = 16;
const CAPABILITY_BYTES: usize = 32;
const CURSOR_POSITION_BYTES: usize = 8;
const CURSOR_TAG_BYTES: usize = 32;
const CURSOR_BYTES: usize = CURSOR_POSITION_BYTES + CURSOR_TAG_BYTES;
const FRAME_PREFIX_BYTES: usize = 4;
const POLL_PROTOCOL_OVERHEAD_BYTES: u64 = 4 * 1024;
const DEPOSIT_DOMAIN: &[u8] = b"session-chat/iroh-fast/deposit/v1\0";
const RECEIVE_DOMAIN: &[u8] = b"session-chat/iroh-fast/receive/v1\0";
const ACKNOWLEDGEMENT_DOMAIN: &[u8] = b"session-chat/iroh-fast/acknowledgement/v1\0";
const CURSOR_DOMAIN: &[u8] = b"session-chat/iroh-fast/cursor/v1\0";
const ENVELOPE_DOMAIN: &[u8] = b"session-chat/iroh-fast/envelope/v1\0";

/// Maximum lifetime accepted by the connected Fast mailbox laboratory.
pub const MAX_FAST_MAILBOX_LIFETIME_SECONDS: u64 = 24 * 60 * 60;
/// Maximum mailboxes retained by one connected Fast mailbox service.
pub const MAX_FAST_LIVE_MAILBOXES: usize = 64;
/// Maximum envelopes retained by one connected Fast mailbox.
pub const MAX_FAST_ENVELOPES_PER_MAILBOX: usize = 64;
/// Maximum aggregate canonical bytes retained by one connected Fast mailbox.
pub const MAX_FAST_RETAINED_BYTES_PER_MAILBOX: usize = 4 * 1024 * 1024;
/// Maximum canonical envelope bytes returned by one connected Fast poll.
pub const MAX_FAST_BATCH_CANONICAL_BYTES: u32 = 192 * 1024;
/// Maximum requests served on one connected Fast stream.
pub const MAX_FAST_REQUESTS_PER_CONNECTION: usize = 1_024;

/// Explicit volatile-mailbox resource bounds for the connected Fast adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FastMailboxPolicy {
    maximum_lifetime_seconds: u64,
    maximum_live_mailboxes: usize,
    maximum_envelopes_per_mailbox: usize,
    maximum_retained_bytes_per_mailbox: usize,
}

impl FastMailboxPolicy {
    /// Constructs a policy inside the crate-wide hard ceilings.
    pub fn new(
        maximum_lifetime_seconds: u64,
        maximum_live_mailboxes: usize,
        maximum_envelopes_per_mailbox: usize,
        maximum_retained_bytes_per_mailbox: usize,
    ) -> Result<Self, IrohFastError> {
        if maximum_lifetime_seconds == 0
            || maximum_lifetime_seconds > MAX_FAST_MAILBOX_LIFETIME_SECONDS
            || maximum_live_mailboxes == 0
            || maximum_live_mailboxes > MAX_FAST_LIVE_MAILBOXES
            || maximum_envelopes_per_mailbox == 0
            || maximum_envelopes_per_mailbox > MAX_FAST_ENVELOPES_PER_MAILBOX
            || maximum_retained_bytes_per_mailbox == 0
            || maximum_retained_bytes_per_mailbox > MAX_FAST_RETAINED_BYTES_PER_MAILBOX
        {
            return Err(IrohFastError::InvalidBound);
        }
        Ok(Self {
            maximum_lifetime_seconds,
            maximum_live_mailboxes,
            maximum_envelopes_per_mailbox,
            maximum_retained_bytes_per_mailbox,
        })
    }
}

/// Transferable deposit-only authority for one connected Fast mailbox.
pub struct FastDepositEndpoint {
    server: FastEndpointId,
    mailbox_id: [u8; MAILBOX_ID_BYTES],
    secret: [u8; CAPABILITY_BYTES],
    expires_at_unix_seconds: u64,
}

impl Clone for FastDepositEndpoint {
    fn clone(&self) -> Self {
        Self {
            server: self.server,
            mailbox_id: self.mailbox_id,
            secret: self.secret,
            expires_at_unix_seconds: self.expires_at_unix_seconds,
        }
    }
}

impl Drop for FastDepositEndpoint {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Receiver-only authority for one connected Fast mailbox.
pub struct FastReceiveCapability {
    server: FastEndpointId,
    mailbox_id: [u8; MAILBOX_ID_BYTES],
    secret: [u8; CAPABILITY_BYTES],
    expires_at_unix_seconds: u64,
}

impl Drop for FastReceiveCapability {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Destructive acknowledgement authority for one connected Fast mailbox.
pub struct FastAcknowledgementCapability {
    server: FastEndpointId,
    mailbox_id: [u8; MAILBOX_ID_BYTES],
    secret: [u8; CAPABILITY_BYTES],
    expires_at_unix_seconds: u64,
}

impl Drop for FastAcknowledgementCapability {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Fresh connected-mailbox authorities separated by operation.
pub struct FastMailboxAuthorities {
    deposit: FastDepositEndpoint,
    receive: FastReceiveCapability,
    acknowledgement: FastAcknowledgementCapability,
}

impl FastMailboxAuthorities {
    /// Seals the provider material in the provider-neutral right wrappers.
    #[must_use]
    pub fn into_dispatch_parts(
        self,
    ) -> (
        DepositRight<FastDepositEndpoint>,
        ReceiveRight<FastReceiveCapability>,
        AcknowledgementRight<FastAcknowledgementCapability>,
    ) {
        (
            DepositRight::from_provider(self.deposit),
            ReceiveRight::from_provider(self.receive),
            AcknowledgementRight::from_provider(self.acknowledgement),
        )
    }
}

struct StoredEnvelope {
    digest: [u8; 32],
    canonical: Box<[u8]>,
    expires_at_unix_seconds: u64,
    delivery_id: DeliveryId,
    acknowledged: bool,
}

struct MailboxRecord {
    expires_at_unix_seconds: u64,
    deposit_digest: [u8; 32],
    receive_digest: [u8; 32],
    acknowledgement_digest: [u8; 32],
    cursor_key: [u8; CAPABILITY_BYTES],
    order: Vec<[u8; MAILBOX_ID_BYTES]>,
    envelopes: BTreeMap<[u8; MAILBOX_ID_BYTES], StoredEnvelope>,
    retained_bytes: usize,
}

impl Drop for MailboxRecord {
    fn drop(&mut self) {
        self.cursor_key.zeroize();
    }
}

/// Online, volatile peer service used by the connected Iroh Fast adapter.
///
/// The service owns bounded in-memory delivery state only. Closing or crashing
/// it loses that state, so it cannot satisfy an offline-mailbox or durability
/// claim.
pub struct IrohFastMailboxService {
    policy: FastMailboxPolicy,
    mailboxes: BTreeMap<[u8; MAILBOX_ID_BYTES], MailboxRecord>,
}

impl IrohFastMailboxService {
    /// Creates an empty volatile service.
    #[must_use]
    pub const fn new(policy: FastMailboxPolicy) -> Self {
        Self {
            policy,
            mailboxes: BTreeMap::new(),
        }
    }

    /// Issues fresh, independent rights for one online mailbox.
    pub fn issue_mailbox(
        &mut self,
        server: FastEndpointId,
        expires_at_unix_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<FastMailboxAuthorities, IrohFastError> {
        let lifetime = expires_at_unix_seconds
            .checked_sub(now_unix_seconds)
            .ok_or(IrohFastError::InvalidBound)?;
        if lifetime == 0 || lifetime > self.policy.maximum_lifetime_seconds {
            return Err(IrohFastError::InvalidBound);
        }
        self.mailboxes
            .retain(|_, mailbox| mailbox.expires_at_unix_seconds > now_unix_seconds);
        if self.mailboxes.len() >= self.policy.maximum_live_mailboxes {
            return Err(IrohFastError::EndpointUnavailable);
        }

        let mailbox_id = random_nonzero()?;
        if self.mailboxes.contains_key(&mailbox_id) {
            return Err(IrohFastError::EndpointUnavailable);
        }
        let mut deposit = random_nonzero()?;
        let mut receive = random_nonzero()?;
        let mut acknowledgement = random_nonzero()?;
        if deposit == receive || deposit == acknowledgement || receive == acknowledgement {
            deposit.zeroize();
            receive.zeroize();
            acknowledgement.zeroize();
            return Err(IrohFastError::EndpointUnavailable);
        }
        let cursor_key = random_nonzero()?;
        self.mailboxes.insert(
            mailbox_id,
            MailboxRecord {
                expires_at_unix_seconds,
                deposit_digest: capability_digest(DEPOSIT_DOMAIN, &deposit),
                receive_digest: capability_digest(RECEIVE_DOMAIN, &receive),
                acknowledgement_digest: capability_digest(ACKNOWLEDGEMENT_DOMAIN, &acknowledgement),
                cursor_key,
                order: Vec::new(),
                envelopes: BTreeMap::new(),
                retained_bytes: 0,
            },
        );
        Ok(FastMailboxAuthorities {
            deposit: FastDepositEndpoint {
                server,
                mailbox_id,
                secret: deposit,
                expires_at_unix_seconds,
            },
            receive: FastReceiveCapability {
                server,
                mailbox_id,
                secret: receive,
                expires_at_unix_seconds,
            },
            acknowledgement: FastAcknowledgementCapability {
                server,
                mailbox_id,
                secret: acknowledgement,
                expires_at_unix_seconds,
            },
        })
    }

    /// Serves an exact bounded number of sequential requests and then closes.
    pub async fn serve_requests(
        mut self,
        mut link: IrohFastLink,
        maximum_requests: usize,
        operation_duration: Duration,
    ) -> Result<(), IrohFastError> {
        if maximum_requests == 0 || maximum_requests > MAX_FAST_REQUESTS_PER_CONNECTION {
            return Err(IrohFastError::InvalidBound);
        }
        for _ in 0..maximum_requests {
            let deadline = Instant::now()
                .checked_add(operation_duration)
                .ok_or(IrohFastError::InvalidBound)?;
            let request = Zeroizing::new(
                link.receive_frame(remaining_service_duration(deadline)?)
                    .await?,
            );
            let now = unix_now()?;
            let response = self.process_request(&request, now)?;
            link.send_frame(&response, remaining_service_duration(deadline)?)
                .await?;
        }
        link.close(operation_duration).await
    }

    fn process_request(
        &mut self,
        bytes: &[u8],
        now_unix_seconds: u64,
    ) -> Result<Vec<u8>, IrohFastError> {
        let request = WireRequest::decode(bytes)?;
        let operation = request.operation;
        let result = match operation {
            OP_DEPOSIT => self.process_deposit(request, now_unix_seconds),
            OP_POLL => self.process_poll(request, now_unix_seconds),
            OP_ACKNOWLEDGE => self.process_acknowledgement(request, now_unix_seconds),
            _ => return Err(IrohFastError::FrameRejected),
        };
        match result {
            Ok(payload) => encode_response(operation, 0, &payload),
            Err(code) => encode_response(operation, status_for(code), &[]),
        }
    }

    fn process_deposit(
        &mut self,
        request: WireRequest,
        now_unix_seconds: u64,
    ) -> Result<Vec<u8>, TransportFailureCode> {
        let maximum_envelopes = self.policy.maximum_envelopes_per_mailbox;
        let maximum_retained_bytes = self.policy.maximum_retained_bytes_per_mailbox;
        let mailbox = self.authorize(
            &request,
            now_unix_seconds,
            |record| &record.deposit_digest,
            DEPOSIT_DOMAIN,
        )?;
        let canonical = CanonicalEnvelope::from_canonical_bytes(request.payload.to_vec())
            .map_err(|_| TransportFailureCode::CorruptRemoteResponse)?;
        if canonical.expires_at_unix_seconds() <= now_unix_seconds
            || canonical.expires_at_unix_seconds() > mailbox.expires_at_unix_seconds
        {
            return Err(TransportFailureCode::ExpiredEnvelope);
        }
        let envelope_id = *canonical.envelope_id().as_bytes();
        let envelope_digest = domain_digest(ENVELOPE_DOMAIN, canonical.as_bytes());
        if let Some(existing) = mailbox.envelopes.get(&envelope_id) {
            if constant_time::verify_slices_are_equal(&existing.digest, &envelope_digest).is_err() {
                return Err(TransportFailureCode::IdempotencyConflict);
            }
            return Ok(existing.delivery_id.as_bytes().to_vec());
        }
        if mailbox.envelopes.len() >= maximum_envelopes {
            return Err(TransportFailureCode::QueueFull);
        }
        let retained_bytes = mailbox
            .retained_bytes
            .checked_add(canonical.as_bytes().len())
            .ok_or(TransportFailureCode::QueueFull)?;
        if retained_bytes > maximum_retained_bytes {
            return Err(TransportFailureCode::QueueFull);
        }
        let delivery_id = DeliveryId::from_provider_bytes(
            random_nonzero().map_err(|_| TransportFailureCode::Internal)?,
        )
        .ok_or(TransportFailureCode::Internal)?;
        if mailbox
            .envelopes
            .values()
            .any(|stored| stored.delivery_id == delivery_id)
        {
            return Err(TransportFailureCode::Internal);
        }
        mailbox.order.push(envelope_id);
        mailbox.retained_bytes = retained_bytes;
        mailbox.envelopes.insert(
            envelope_id,
            StoredEnvelope {
                digest: envelope_digest,
                canonical: canonical.as_bytes().into(),
                expires_at_unix_seconds: canonical.expires_at_unix_seconds(),
                delivery_id,
                acknowledged: false,
            },
        );
        Ok(delivery_id.as_bytes().to_vec())
    }

    fn process_poll(
        &mut self,
        request: WireRequest,
        now_unix_seconds: u64,
    ) -> Result<Vec<u8>, TransportFailureCode> {
        let poll = decode_poll_payload(&request.payload)?;
        let mailbox = self.authorize(
            &request,
            now_unix_seconds,
            |record| &record.receive_digest,
            RECEIVE_DOMAIN,
        )?;
        let start = match poll.cursor {
            Some(cursor) => decode_cursor(mailbox, &cursor)?,
            None => 0,
        };
        if start > mailbox.order.len() {
            return Err(TransportFailureCode::InvalidCursor);
        }
        let mut selected = Vec::new();
        let mut encoded_bytes = 0_usize;
        let mut position = start;
        while position < mailbox.order.len() && selected.len() < usize::from(poll.maximum_envelopes)
        {
            let envelope_id = mailbox.order[position];
            let stored = mailbox
                .envelopes
                .get(&envelope_id)
                .ok_or(TransportFailureCode::Internal)?;
            if !stored.acknowledged && stored.expires_at_unix_seconds > now_unix_seconds {
                let next_size = encoded_bytes
                    .checked_add(stored.canonical.len())
                    .ok_or(TransportFailureCode::EnvelopeTooLarge)?;
                if next_size
                    > usize::try_from(poll.maximum_bytes)
                        .map_err(|_| TransportFailureCode::EnvelopeTooLarge)?
                {
                    if selected.is_empty() {
                        return Err(TransportFailureCode::EnvelopeTooLarge);
                    }
                    break;
                }
                encoded_bytes = next_size;
                selected.push((stored.delivery_id, stored.canonical.as_ref()));
            }
            position += 1;
        }
        let next_cursor =
            (position < mailbox.order.len()).then(|| encode_cursor(mailbox, position));
        encode_poll_response(&selected, next_cursor.as_deref())
            .map_err(|_| TransportFailureCode::Internal)
    }

    fn process_acknowledgement(
        &mut self,
        request: WireRequest,
        now_unix_seconds: u64,
    ) -> Result<Vec<u8>, TransportFailureCode> {
        let ids = decode_acknowledgement_payload(&request.payload)?;
        let mailbox = self.authorize(
            &request,
            now_unix_seconds,
            |record| &record.acknowledgement_digest,
            ACKNOWLEDGEMENT_DOMAIN,
        )?;
        if ids.iter().any(|delivery_id| {
            !mailbox
                .envelopes
                .values()
                .any(|stored| stored.delivery_id == *delivery_id)
        }) {
            return Err(TransportFailureCode::AuthorityScopeMismatch);
        }
        for delivery_id in ids {
            let stored = mailbox
                .envelopes
                .values_mut()
                .find(|stored| stored.delivery_id == delivery_id)
                .ok_or(TransportFailureCode::Internal)?;
            if !stored.acknowledged {
                mailbox.retained_bytes = mailbox
                    .retained_bytes
                    .checked_sub(stored.canonical.len())
                    .ok_or(TransportFailureCode::Internal)?;
                stored.canonical = Box::new([]);
                stored.acknowledged = true;
            }
        }
        Ok(Vec::new())
    }

    fn authorize<'a>(
        &'a mut self,
        request: &WireRequest,
        now_unix_seconds: u64,
        expected_digest: impl FnOnce(&MailboxRecord) -> &[u8; 32],
        domain: &[u8],
    ) -> Result<&'a mut MailboxRecord, TransportFailureCode> {
        let mailbox = self
            .mailboxes
            .get_mut(&request.mailbox_id)
            .ok_or(TransportFailureCode::InvalidAuthority)?;
        if mailbox.expires_at_unix_seconds <= now_unix_seconds
            || constant_time::verify_slices_are_equal(
                expected_digest(mailbox),
                &capability_digest(domain, &request.secret[..]),
            )
            .is_err()
        {
            return Err(TransportFailureCode::InvalidAuthority);
        }
        Ok(mailbox)
    }
}

/// Connected client-side implementation of the common delivery contract.
pub struct IrohFastDelivery {
    link: IrohFastLink,
}

impl IrohFastDelivery {
    /// Returns the exact non-secret capability declaration for FastV1 binding.
    pub fn manifest() -> Result<AdapterManifestV1, BindingErrorV1> {
        AdapterManifestV1::new(
            1,
            AdapterId::new("session-chat.adapter.iroh-fast.v1")
                .map_err(|_| BindingErrorV1::InvalidManifest)?,
            AdapterVersionV1::new(env!("CARGO_PKG_VERSION"))?,
            TransportProfileId::FastV1,
            AdapterLimitsV1::new(
                u32::try_from(session_protocol::MAX_WIRE_OBJECT_BYTES)
                    .map_err(|_| BindingErrorV1::InvalidManifest)?,
                MAX_FAST_BATCH_CANONICAL_BYTES,
                session_transport::MAX_POLL_ENVELOPES,
                u16::try_from(CURSOR_BYTES).map_err(|_| BindingErrorV1::InvalidManifest)?,
            )?,
            AdapterOperationsV1::DepositPollAcknowledge,
            InternalRetryV1::CoordinatorOnly,
            EgressDeclarationV1::AmbientNetwork,
            BackgroundWorkV1::Declared,
            AdapterExecutionV1::InProcess,
            1,
        )
    }

    /// Binds delivery operations to one authenticated connected peer.
    ///
    /// The exact frame ceiling is part of the FastV1 manifest and must match
    /// the connected link before the adapter can advertise that declaration.
    pub fn new(link: IrohFastLink) -> Result<Self, IrohFastError> {
        if link.maximum_frame_bytes() != crate::MAX_FAST_FRAME_BYTES {
            return Err(IrohFastError::InvalidBound);
        }
        Ok(Self { link })
    }

    /// Returns the authenticated service endpoint for local policy checks.
    #[must_use]
    pub fn remote_id(&self) -> FastEndpointId {
        self.link.remote_id()
    }

    /// Finishes the connected adapter and verifies clean peer shutdown.
    pub async fn close(self, duration: Duration) -> Result<(), IrohFastError> {
        self.link.close(duration).await
    }

    async fn round_trip(
        &mut self,
        request: Zeroizing<Vec<u8>>,
        budget: session_transport::OperationBudget,
        control: &dyn DispatchControl,
    ) -> Result<WireResponse, TransportFailure> {
        let first = control.checkpoint(budget)?;
        let request_network_bytes = request
            .len()
            .checked_add(FRAME_PREFIX_BYTES)
            .ok_or_else(|| failure(TransportFailureCode::EnvelopeTooLarge))?;
        let request_network_bytes = u64::try_from(request_network_bytes)
            .map_err(|_| failure(TransportFailureCode::EnvelopeTooLarge))?;
        if request_network_bytes >= budget.max_network_bytes() {
            return Err(failure(TransportFailureCode::EnvelopeTooLarge));
        }
        self.link
            .send_frame(&request, remaining_duration(first.monotonic_now(), budget)?)
            .await
            .map_err(map_link_failure)?;
        let second = control.checkpoint(budget)?;
        let remaining_bytes = budget
            .max_network_bytes()
            .checked_sub(request_network_bytes)
            .and_then(|remaining| remaining.checked_sub(FRAME_PREFIX_BYTES as u64))
            .ok_or_else(|| failure(TransportFailureCode::EnvelopeTooLarge))?;
        let response_ceiling = usize::try_from(remaining_bytes)
            .unwrap_or(usize::MAX)
            .min(self.link.maximum_frame_bytes());
        if response_ceiling == 0 {
            return Err(failure(TransportFailureCode::EnvelopeTooLarge));
        }
        let response = self
            .link
            .receive_frame_bounded(
                remaining_duration(second.monotonic_now(), budget)?,
                response_ceiling,
            )
            .await
            .map_err(map_link_failure)?;
        control.checkpoint(budget)?;
        WireResponse::decode(&response).inspect_err(|_| {
            self.link.poison();
        })
    }

    fn validate_scope(
        &self,
        server: FastEndpointId,
        expires_at_unix_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<(), TransportFailure> {
        if server != self.link.remote_id() {
            return Err(failure(TransportFailureCode::AuthorityScopeMismatch));
        }
        if expires_at_unix_seconds <= now_unix_seconds {
            return Err(failure(TransportFailureCode::InvalidAuthority));
        }
        Ok(())
    }

    fn validate_response(
        &mut self,
        response: &WireResponse,
        expected_operation: u8,
    ) -> Result<(), TransportFailure> {
        if response.operation != expected_operation
            || (response.status != 0 && !response.payload.is_empty())
        {
            self.link.poison();
            return Err(failure(TransportFailureCode::CorruptRemoteResponse));
        }
        if response.status == 0 {
            return Ok(());
        }
        match code_for_status(response.status) {
            Ok(code) => Err(remote_failure(code)),
            Err(error) => {
                self.link.poison();
                Err(error)
            }
        }
    }
}

impl EnvelopeDelivery for IrohFastDelivery {
    type DepositEndpoint = FastDepositEndpoint;
    type ReceiveCapability = FastReceiveCapability;
    type AcknowledgementCapability = FastAcknowledgementCapability;

    async fn deposit(
        &mut self,
        endpoint: &DepositRight<Self::DepositEndpoint>,
        request: DepositRequest,
        control: &dyn DispatchControl,
    ) -> Result<DepositReceipt, TransportFailure> {
        let endpoint = endpoint.provider();
        let observation = control.checkpoint(request.budget())?;
        self.validate_scope(
            endpoint.server,
            endpoint.expires_at_unix_seconds,
            observation.wall_now_unix_seconds(),
        )?;
        if request.envelope().expires_at_unix_seconds() <= observation.wall_now_unix_seconds()
            || request.envelope().expires_at_unix_seconds() > endpoint.expires_at_unix_seconds
        {
            return Err(failure(TransportFailureCode::ExpiredEnvelope));
        }
        let wire = Zeroizing::new(WireRequest::encode(
            OP_DEPOSIT,
            &endpoint.mailbox_id,
            &endpoint.secret,
            request.envelope().as_bytes(),
        )?);
        let response = self.round_trip(wire, request.budget(), control).await?;
        self.validate_response(&response, OP_DEPOSIT)?;
        let Some(delivery_id) =
            fixed_array::<16>(&response.payload).and_then(DeliveryId::from_provider_bytes)
        else {
            self.link.poison();
            return Err(failure(TransportFailureCode::CorruptRemoteResponse));
        };
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
        self.validate_scope(
            authority.server,
            authority.expires_at_unix_seconds,
            observation.wall_now_unix_seconds(),
        )?;
        let payload = encode_poll_request(&request)?;
        let wire = Zeroizing::new(WireRequest::encode(
            OP_POLL,
            &authority.mailbox_id,
            &authority.secret,
            &payload,
        )?);
        let response = self.round_trip(wire, request.budget(), control).await?;
        self.validate_response(&response, OP_POLL)?;
        let (items, next_cursor) = match decode_poll_response(&response.payload) {
            Ok(decoded) => decoded,
            Err(error) => {
                self.link.poison();
                return Err(error);
            }
        };
        let final_observation = control.checkpoint(request.budget())?;
        match ReceiveBatch::new(
            items,
            next_cursor,
            &request,
            final_observation.wall_now_unix_seconds(),
        ) {
            Ok(batch) => Ok(batch),
            Err(_) => {
                self.link.poison();
                Err(failure(TransportFailureCode::CorruptRemoteResponse))
            }
        }
    }

    async fn acknowledge(
        &mut self,
        authority: &AcknowledgementRight<Self::AcknowledgementCapability>,
        request: AcknowledgementRequest,
        control: &dyn DispatchControl,
    ) -> Result<AcknowledgementReceipt, TransportFailure> {
        let authority = authority.provider();
        let observation = control.checkpoint(request.budget())?;
        self.validate_scope(
            authority.server,
            authority.expires_at_unix_seconds,
            observation.wall_now_unix_seconds(),
        )?;
        let payload = encode_acknowledgement_request(&request)?;
        let wire = Zeroizing::new(WireRequest::encode(
            OP_ACKNOWLEDGE,
            &authority.mailbox_id,
            &authority.secret,
            &payload,
        )?);
        let response = self.round_trip(wire, request.budget(), control).await?;
        self.validate_response(&response, OP_ACKNOWLEDGE)?;
        if !response.payload.is_empty() {
            self.link.poison();
            return Err(failure(TransportFailureCode::CorruptRemoteResponse));
        }
        Ok(AcknowledgementReceipt::accepted())
    }
}

struct WireRequest {
    operation: u8,
    mailbox_id: [u8; MAILBOX_ID_BYTES],
    secret: Zeroizing<[u8; CAPABILITY_BYTES]>,
    payload: Box<[u8]>,
}

impl WireRequest {
    fn encode(
        operation: u8,
        mailbox_id: &[u8; MAILBOX_ID_BYTES],
        secret: &[u8; CAPABILITY_BYTES],
        payload: &[u8],
    ) -> Result<Vec<u8>, TransportFailure> {
        let mut encoder = Encoder::new(Vec::with_capacity(payload.len() + 64));
        encoder
            .array(OUTER_FIELDS)
            .and_then(|encoder| encoder.u16(WIRE_VERSION))
            .and_then(|encoder| encoder.u8(operation))
            .and_then(|encoder| encoder.bytes(mailbox_id))
            .and_then(|encoder| encoder.bytes(secret))
            .and_then(|encoder| encoder.bytes(payload))
            .map_err(|_| failure(TransportFailureCode::Internal))?;
        Ok(encoder.into_writer())
    }

    fn decode(bytes: &[u8]) -> Result<Self, IrohFastError> {
        let mut decoder = Decoder::new(bytes);
        require_array(&mut decoder, OUTER_FIELDS)?;
        if decoder.u16().map_err(|_| IrohFastError::FrameRejected)? != WIRE_VERSION {
            return Err(IrohFastError::FrameRejected);
        }
        let operation = decoder.u8().map_err(|_| IrohFastError::FrameRejected)?;
        let mailbox_id = fixed_array(decoder.bytes().map_err(|_| IrohFastError::FrameRejected)?)
            .ok_or(IrohFastError::FrameRejected)?;
        let secret = fixed_array(decoder.bytes().map_err(|_| IrohFastError::FrameRejected)?)
            .ok_or(IrohFastError::FrameRejected)?;
        let payload = decoder
            .bytes()
            .map_err(|_| IrohFastError::FrameRejected)?
            .to_vec()
            .into_boxed_slice();
        reject_trailing(&decoder, bytes)?;
        let request = Self {
            operation,
            mailbox_id,
            secret: Zeroizing::new(secret),
            payload,
        };
        let canonical = Self::encode(
            request.operation,
            &request.mailbox_id,
            &request.secret,
            &request.payload,
        )
        .map_err(|_| IrohFastError::FrameRejected)?;
        if canonical != bytes {
            return Err(IrohFastError::FrameRejected);
        }
        Ok(request)
    }
}

struct WireResponse {
    operation: u8,
    status: u16,
    payload: Box<[u8]>,
}

impl WireResponse {
    fn decode(bytes: &[u8]) -> Result<Self, TransportFailure> {
        let mut decoder = Decoder::new(bytes);
        require_array_transport(&mut decoder, RESPONSE_FIELDS)?;
        if decoder
            .u16()
            .map_err(|_| failure(TransportFailureCode::CorruptRemoteResponse))?
            != WIRE_VERSION
        {
            return Err(failure(TransportFailureCode::CorruptRemoteResponse));
        }
        let operation = decoder
            .u8()
            .map_err(|_| failure(TransportFailureCode::CorruptRemoteResponse))?;
        let status = decoder
            .u16()
            .map_err(|_| failure(TransportFailureCode::CorruptRemoteResponse))?;
        let payload = decoder
            .bytes()
            .map_err(|_| failure(TransportFailureCode::CorruptRemoteResponse))?
            .to_vec()
            .into_boxed_slice();
        if decoder.position() != bytes.len() {
            return Err(failure(TransportFailureCode::CorruptRemoteResponse));
        }
        let canonical = encode_response(operation, status, &payload)
            .map_err(|_| failure(TransportFailureCode::CorruptRemoteResponse))?;
        if canonical != bytes {
            return Err(failure(TransportFailureCode::CorruptRemoteResponse));
        }
        Ok(Self {
            operation,
            status,
            payload,
        })
    }
}

fn encode_response(operation: u8, status: u16, payload: &[u8]) -> Result<Vec<u8>, IrohFastError> {
    let mut encoder = Encoder::new(Vec::with_capacity(payload.len() + 16));
    encoder
        .array(RESPONSE_FIELDS)
        .and_then(|encoder| encoder.u16(WIRE_VERSION))
        .and_then(|encoder| encoder.u8(operation))
        .and_then(|encoder| encoder.u16(status))
        .and_then(|encoder| encoder.bytes(payload))
        .map_err(|_| IrohFastError::FrameRejected)?;
    Ok(encoder.into_writer())
}

fn encode_poll_request(request: &PollRequest) -> Result<Vec<u8>, TransportFailure> {
    let cursor = request.cursor().map_or(&[][..], Cursor::as_bytes);
    let operation_ceiling = request
        .budget()
        .max_network_bytes()
        .checked_sub(POLL_PROTOCOL_OVERHEAD_BYTES)
        .and_then(|bytes| u32::try_from(bytes).ok())
        .ok_or_else(|| failure(TransportFailureCode::EnvelopeTooLarge))?;
    let maximum_bytes = request
        .max_encoded_bytes()
        .min(operation_ceiling)
        .min(MAX_FAST_BATCH_CANONICAL_BYTES);
    if maximum_bytes == 0 {
        return Err(failure(TransportFailureCode::EnvelopeTooLarge));
    }
    encode_poll_payload(
        cursor,
        request.max_envelopes(),
        maximum_bytes,
        request.wait().duration().as_secs(),
    )
}

fn encode_poll_payload(
    cursor: &[u8],
    maximum_envelopes: u16,
    maximum_bytes: u32,
    wait_seconds: u64,
) -> Result<Vec<u8>, TransportFailure> {
    let mut encoder = Encoder::new(Vec::with_capacity(cursor.len() + 32));
    encoder
        .array(4)
        .and_then(|encoder| encoder.bytes(cursor))
        .and_then(|encoder| encoder.u16(maximum_envelopes))
        .and_then(|encoder| encoder.u32(maximum_bytes))
        .and_then(|encoder| encoder.u64(wait_seconds))
        .map_err(|_| failure(TransportFailureCode::Internal))?;
    Ok(encoder.into_writer())
}

struct DecodedPollRequest {
    cursor: Option<Box<[u8]>>,
    maximum_envelopes: u16,
    maximum_bytes: u32,
}

fn decode_poll_payload(bytes: &[u8]) -> Result<DecodedPollRequest, TransportFailureCode> {
    let mut decoder = Decoder::new(bytes);
    if decoder.array().ok() != Some(Some(4)) {
        return Err(TransportFailureCode::CorruptRemoteResponse);
    }
    let raw_cursor = decoder
        .bytes()
        .map_err(|_| TransportFailureCode::CorruptRemoteResponse)?;
    if !raw_cursor.is_empty() && raw_cursor.len() != CURSOR_BYTES {
        return Err(TransportFailureCode::InvalidCursor);
    }
    let cursor = (!raw_cursor.is_empty()).then(|| raw_cursor.to_vec().into_boxed_slice());
    let maximum_envelopes = decoder
        .u16()
        .map_err(|_| TransportFailureCode::CorruptRemoteResponse)?;
    let maximum_bytes = decoder
        .u32()
        .map_err(|_| TransportFailureCode::CorruptRemoteResponse)?;
    let wait_seconds = decoder
        .u64()
        .map_err(|_| TransportFailureCode::CorruptRemoteResponse)?;
    if decoder.position() != bytes.len()
        || maximum_envelopes == 0
        || maximum_envelopes > session_transport::MAX_POLL_ENVELOPES
        || maximum_bytes == 0
        || maximum_bytes > session_transport::MAX_POLL_ENCODED_BYTES
        || wait_seconds > session_transport::MAX_POLL_WAIT_SECONDS
    {
        return Err(TransportFailureCode::CorruptRemoteResponse);
    }
    let canonical = encode_poll_payload(raw_cursor, maximum_envelopes, maximum_bytes, wait_seconds)
        .map_err(|_| TransportFailureCode::CorruptRemoteResponse)?;
    if canonical != bytes {
        return Err(TransportFailureCode::CorruptRemoteResponse);
    }
    Ok(DecodedPollRequest {
        cursor,
        maximum_envelopes,
        maximum_bytes,
    })
}

fn encode_poll_response(
    items: &[(DeliveryId, &[u8])],
    next_cursor: Option<&[u8]>,
) -> Result<Vec<u8>, IrohFastError> {
    let cursor = next_cursor.unwrap_or(&[]);
    let count = u64::try_from(items.len()).map_err(|_| IrohFastError::FrameRejected)?;
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(2)
        .and_then(|encoder| encoder.array(count))
        .map_err(|_| IrohFastError::FrameRejected)?;
    for (delivery_id, canonical) in items {
        encoder
            .array(2)
            .and_then(|encoder| encoder.bytes(delivery_id.as_bytes()))
            .and_then(|encoder| encoder.bytes(canonical))
            .map_err(|_| IrohFastError::FrameRejected)?;
    }
    encoder
        .bytes(cursor)
        .map_err(|_| IrohFastError::FrameRejected)?;
    Ok(encoder.into_writer())
}

fn decode_poll_response(
    bytes: &[u8],
) -> Result<(Vec<ReceivedCanonicalEnvelope>, Option<Cursor>), TransportFailure> {
    let mut decoder = Decoder::new(bytes);
    require_array_transport(&mut decoder, 2)?;
    let count = decoder
        .array()
        .map_err(|_| failure(TransportFailureCode::CorruptRemoteResponse))?
        .ok_or_else(|| failure(TransportFailureCode::CorruptRemoteResponse))?;
    if count > u64::from(session_transport::MAX_POLL_ENVELOPES) {
        return Err(failure(TransportFailureCode::CorruptRemoteResponse));
    }
    let capacity =
        usize::try_from(count).map_err(|_| failure(TransportFailureCode::CorruptRemoteResponse))?;
    let mut items = Vec::with_capacity(capacity);
    for _ in 0..count {
        require_array_transport(&mut decoder, 2)?;
        let delivery_id = fixed_array::<16>(
            decoder
                .bytes()
                .map_err(|_| failure(TransportFailureCode::CorruptRemoteResponse))?,
        )
        .and_then(DeliveryId::from_provider_bytes)
        .ok_or_else(|| failure(TransportFailureCode::CorruptRemoteResponse))?;
        let canonical = decoder
            .bytes()
            .map_err(|_| failure(TransportFailureCode::CorruptRemoteResponse))?;
        let envelope = CanonicalEnvelope::from_canonical_bytes(canonical.to_vec())
            .map_err(|_| failure(TransportFailureCode::CorruptRemoteResponse))?;
        items.push(ReceivedCanonicalEnvelope::new(delivery_id, envelope));
    }
    let cursor = decoder
        .bytes()
        .map_err(|_| failure(TransportFailureCode::CorruptRemoteResponse))?;
    let next_cursor = if cursor.is_empty() {
        None
    } else {
        Some(
            Cursor::new(cursor.to_vec())
                .map_err(|_| failure(TransportFailureCode::CorruptRemoteResponse))?,
        )
    };
    if decoder.position() != bytes.len() {
        return Err(failure(TransportFailureCode::CorruptRemoteResponse));
    }
    let canonical_items = items
        .iter()
        .map(|item| (*item.delivery_id(), item.envelope().as_bytes()))
        .collect::<Vec<_>>();
    let canonical =
        encode_poll_response(&canonical_items, next_cursor.as_ref().map(Cursor::as_bytes))
            .map_err(|_| failure(TransportFailureCode::CorruptRemoteResponse))?;
    if canonical != bytes {
        return Err(failure(TransportFailureCode::CorruptRemoteResponse));
    }
    Ok((items, next_cursor))
}

fn encode_acknowledgement_request(
    request: &AcknowledgementRequest,
) -> Result<Vec<u8>, TransportFailure> {
    encode_acknowledgement_ids(request.delivery_ids().as_slice())
        .map_err(|_| failure(TransportFailureCode::Internal))
}

fn decode_acknowledgement_payload(bytes: &[u8]) -> Result<Vec<DeliveryId>, TransportFailureCode> {
    let mut decoder = Decoder::new(bytes);
    let count = decoder
        .array()
        .map_err(|_| TransportFailureCode::CorruptRemoteResponse)?
        .ok_or(TransportFailureCode::CorruptRemoteResponse)?;
    if count == 0 || count > u64::from(session_transport::MAX_ACKNOWLEDGEMENT_IDS) {
        return Err(TransportFailureCode::CorruptRemoteResponse);
    }
    let mut ids = Vec::with_capacity(
        usize::try_from(count).map_err(|_| TransportFailureCode::CorruptRemoteResponse)?,
    );
    for _ in 0..count {
        let id = fixed_array::<16>(
            decoder
                .bytes()
                .map_err(|_| TransportFailureCode::CorruptRemoteResponse)?,
        )
        .and_then(DeliveryId::from_provider_bytes)
        .ok_or(TransportFailureCode::CorruptRemoteResponse)?;
        if ids.contains(&id) {
            return Err(TransportFailureCode::CorruptRemoteResponse);
        }
        ids.push(id);
    }
    if decoder.position() != bytes.len() {
        return Err(TransportFailureCode::CorruptRemoteResponse);
    }
    let canonical = encode_acknowledgement_ids(&ids)
        .map_err(|_| TransportFailureCode::CorruptRemoteResponse)?;
    if canonical != bytes {
        return Err(TransportFailureCode::CorruptRemoteResponse);
    }
    Ok(ids)
}

fn encode_acknowledgement_ids(ids: &[DeliveryId]) -> Result<Vec<u8>, IrohFastError> {
    let count = u64::try_from(ids.len()).map_err(|_| IrohFastError::FrameRejected)?;
    let mut encoder = Encoder::new(Vec::with_capacity(ids.len() * 18));
    encoder
        .array(count)
        .map_err(|_| IrohFastError::FrameRejected)?;
    for delivery_id in ids {
        encoder
            .bytes(delivery_id.as_bytes())
            .map_err(|_| IrohFastError::FrameRejected)?;
    }
    Ok(encoder.into_writer())
}

fn encode_cursor(mailbox: &MailboxRecord, position: usize) -> Box<[u8]> {
    let position = u64::try_from(position).expect("mailbox bound fits u64");
    let position_bytes = position.to_be_bytes();
    let mut authenticated = Vec::with_capacity(CURSOR_DOMAIN.len() + 16 + 8);
    authenticated.extend_from_slice(CURSOR_DOMAIN);
    authenticated.extend_from_slice(&position_bytes);
    let key = hmac::Key::new(hmac::HMAC_SHA256, &mailbox.cursor_key);
    let tag = hmac::sign(&key, &authenticated);
    let mut cursor = Vec::with_capacity(CURSOR_BYTES);
    cursor.extend_from_slice(&position_bytes);
    cursor.extend_from_slice(tag.as_ref());
    cursor.into_boxed_slice()
}

fn decode_cursor(mailbox: &MailboxRecord, cursor: &[u8]) -> Result<usize, TransportFailureCode> {
    if cursor.len() != CURSOR_BYTES {
        return Err(TransportFailureCode::InvalidCursor);
    }
    let position_bytes = fixed_array::<CURSOR_POSITION_BYTES>(&cursor[..CURSOR_POSITION_BYTES])
        .ok_or(TransportFailureCode::InvalidCursor)?;
    let mut authenticated = Vec::with_capacity(CURSOR_DOMAIN.len() + 8);
    authenticated.extend_from_slice(CURSOR_DOMAIN);
    authenticated.extend_from_slice(&position_bytes);
    let key = hmac::Key::new(hmac::HMAC_SHA256, &mailbox.cursor_key);
    hmac::verify(&key, &authenticated, &cursor[CURSOR_POSITION_BYTES..])
        .map_err(|_| TransportFailureCode::InvalidCursor)?;
    usize::try_from(u64::from_be_bytes(position_bytes))
        .map_err(|_| TransportFailureCode::InvalidCursor)
}

fn capability_digest(domain: &[u8], secret: &[u8]) -> [u8; 32] {
    domain_digest(domain, secret)
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(domain);
    context.update(bytes);
    let digest = context.finish();
    let mut result = [0; 32];
    result.copy_from_slice(digest.as_ref());
    result
}

fn random_nonzero<const N: usize>() -> Result<[u8; N], IrohFastError> {
    let mut bytes = [0_u8; N];
    rand::fill(&mut bytes).map_err(|_| IrohFastError::EndpointUnavailable)?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(IrohFastError::EndpointUnavailable);
    }
    Ok(bytes)
}

fn remaining_duration(
    now: std::time::Instant,
    budget: session_transport::OperationBudget,
) -> Result<Duration, TransportFailure> {
    budget
        .deadline()
        .checked_duration_since(now)
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| failure(TransportFailureCode::DeadlineExceeded))
}

fn unix_now() -> Result<u64, IrohFastError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| IrohFastError::EndpointUnavailable)
        .map(|duration| duration.as_secs())
}

fn remaining_service_duration(deadline: Instant) -> Result<Duration, IrohFastError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(IrohFastError::DeadlineExceeded)
}

fn map_link_failure(error: IrohFastError) -> TransportFailure {
    match error {
        IrohFastError::DeadlineExceeded => failure(TransportFailureCode::DeadlineExceeded),
        IrohFastError::FrameRejected | IrohFastError::InvalidBound => {
            failure(TransportFailureCode::CorruptRemoteResponse)
        }
        IrohFastError::PeerRejected => failure(TransportFailureCode::AuthorityScopeMismatch),
        IrohFastError::EndpointUnavailable | IrohFastError::ConnectionUnavailable => {
            retryable_failure(TransportFailureCode::Unavailable)
        }
    }
}

fn failure(code: TransportFailureCode) -> TransportFailure {
    TransportFailure::new(code, RetryAdvice::Never)
}

fn retryable_failure(code: TransportFailureCode) -> TransportFailure {
    TransportFailure::new(code, RetryAdvice::Backoff)
}

fn remote_failure(code: TransportFailureCode) -> TransportFailure {
    match code {
        TransportFailureCode::QueueFull
        | TransportFailureCode::RateLimited
        | TransportFailureCode::Unavailable
        | TransportFailureCode::Internal => retryable_failure(code),
        _ => failure(code),
    }
}

fn status_for(code: TransportFailureCode) -> u16 {
    match code {
        TransportFailureCode::InvalidAuthority => 1,
        TransportFailureCode::AuthorityScopeMismatch => 2,
        TransportFailureCode::ExpiredEnvelope => 3,
        TransportFailureCode::EnvelopeTooLarge => 4,
        TransportFailureCode::IdempotencyConflict => 5,
        TransportFailureCode::InvalidCursor => 6,
        TransportFailureCode::QueueFull => 7,
        TransportFailureCode::RateLimited => 8,
        TransportFailureCode::Unavailable => 9,
        TransportFailureCode::DeadlineExceeded => 10,
        TransportFailureCode::Cancelled => 11,
        TransportFailureCode::CorruptRemoteResponse => 12,
        TransportFailureCode::PolicyViolation => 13,
        TransportFailureCode::Misconfigured => 14,
        TransportFailureCode::Internal => 15,
        _ => 15,
    }
}

fn code_for_status(status: u16) -> Result<TransportFailureCode, TransportFailure> {
    match status {
        1 => Ok(TransportFailureCode::InvalidAuthority),
        2 => Ok(TransportFailureCode::AuthorityScopeMismatch),
        3 => Ok(TransportFailureCode::ExpiredEnvelope),
        4 => Ok(TransportFailureCode::EnvelopeTooLarge),
        5 => Ok(TransportFailureCode::IdempotencyConflict),
        6 => Ok(TransportFailureCode::InvalidCursor),
        7 => Ok(TransportFailureCode::QueueFull),
        8 => Ok(TransportFailureCode::RateLimited),
        9 => Ok(TransportFailureCode::Unavailable),
        10 => Ok(TransportFailureCode::DeadlineExceeded),
        11 => Ok(TransportFailureCode::Cancelled),
        12 => Ok(TransportFailureCode::CorruptRemoteResponse),
        13 => Ok(TransportFailureCode::PolicyViolation),
        14 => Ok(TransportFailureCode::Misconfigured),
        15 => Ok(TransportFailureCode::Internal),
        _ => Err(failure(TransportFailureCode::CorruptRemoteResponse)),
    }
}

fn require_array(decoder: &mut Decoder<'_>, fields: u64) -> Result<(), IrohFastError> {
    if decoder.array().map_err(|_| IrohFastError::FrameRejected)? == Some(fields) {
        Ok(())
    } else {
        Err(IrohFastError::FrameRejected)
    }
}

fn require_array_transport(decoder: &mut Decoder<'_>, fields: u64) -> Result<(), TransportFailure> {
    if decoder
        .array()
        .map_err(|_| failure(TransportFailureCode::CorruptRemoteResponse))?
        == Some(fields)
    {
        Ok(())
    } else {
        Err(failure(TransportFailureCode::CorruptRemoteResponse))
    }
}

fn reject_trailing(decoder: &Decoder<'_>, bytes: &[u8]) -> Result<(), IrohFastError> {
    if decoder.position() == bytes.len() {
        Ok(())
    } else {
        Err(IrohFastError::FrameRejected)
    }
}

fn fixed_array<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    let mut result = [0_u8; N];
    (bytes.len() == N).then(|| {
        result.copy_from_slice(bytes);
        result
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_rejects_zero_and_excessive_bounds() {
        assert_eq!(
            FastMailboxPolicy::new(0, 1, 1, 1),
            Err(IrohFastError::InvalidBound)
        );
        assert_eq!(
            FastMailboxPolicy::new(
                MAX_FAST_MAILBOX_LIFETIME_SECONDS,
                MAX_FAST_LIVE_MAILBOXES,
                MAX_FAST_ENVELOPES_PER_MAILBOX,
                MAX_FAST_RETAINED_BYTES_PER_MAILBOX,
            ),
            Ok(FastMailboxPolicy {
                maximum_lifetime_seconds: MAX_FAST_MAILBOX_LIFETIME_SECONDS,
                maximum_live_mailboxes: MAX_FAST_LIVE_MAILBOXES,
                maximum_envelopes_per_mailbox: MAX_FAST_ENVELOPES_PER_MAILBOX,
                maximum_retained_bytes_per_mailbox: MAX_FAST_RETAINED_BYTES_PER_MAILBOX,
            })
        );
    }

    #[test]
    fn cursor_is_scope_authenticated() {
        let mailbox = MailboxRecord {
            expires_at_unix_seconds: 10,
            deposit_digest: [1; 32],
            receive_digest: [2; 32],
            acknowledgement_digest: [3; 32],
            cursor_key: [4; 32],
            order: Vec::new(),
            envelopes: BTreeMap::new(),
            retained_bytes: 0,
        };
        let cursor = encode_cursor(&mailbox, 7);
        assert_eq!(decode_cursor(&mailbox, &cursor), Ok(7));
        let mut corrupt = cursor.to_vec();
        corrupt[9] ^= 1;
        assert_eq!(
            decode_cursor(&mailbox, &corrupt),
            Err(TransportFailureCode::InvalidCursor)
        );
    }

    #[test]
    fn request_wire_rejects_wrong_version_trailing_and_noncanonical_encodings() {
        let mailbox_id = [0x11; MAILBOX_ID_BYTES];
        let secret = [0x22; CAPABILITY_BYTES];
        let encoded = WireRequest::encode(OP_POLL, &mailbox_id, &secret, &[0x33])
            .expect("encode canonical request");
        assert!(WireRequest::decode(&encoded).is_ok());

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            WireRequest::decode(&trailing).err(),
            Some(IrohFastError::FrameRejected)
        );

        let mut wrong_version = Encoder::new(Vec::new());
        wrong_version
            .array(OUTER_FIELDS)
            .and_then(|encoder| encoder.u16(WIRE_VERSION + 1))
            .and_then(|encoder| encoder.u8(OP_POLL))
            .and_then(|encoder| encoder.bytes(&mailbox_id))
            .and_then(|encoder| encoder.bytes(&secret))
            .and_then(|encoder| encoder.bytes(&[0x33]))
            .expect("encode wrong-version request");
        assert_eq!(
            WireRequest::decode(&wrong_version.into_writer()).err(),
            Some(IrohFastError::FrameRejected)
        );

        assert_eq!(encoded[1], WIRE_VERSION as u8);
        let mut noncanonical = Vec::with_capacity(encoded.len() + 1);
        noncanonical.push(encoded[0]);
        noncanonical.extend_from_slice(&[0x18, WIRE_VERSION as u8]);
        noncanonical.extend_from_slice(&encoded[2..]);
        assert_eq!(
            WireRequest::decode(&noncanonical).err(),
            Some(IrohFastError::FrameRejected)
        );
    }
}
