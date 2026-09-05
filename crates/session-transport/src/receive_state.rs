use std::error::Error;

use thiserror::Error;

use crate::{
    BoundCursorV1, BoundedDeliveryIds, Cursor, CursorBindingV1, OperationBudget, PollRequest,
    PollWait, ReceiveBatch, ReceivedCanonicalEnvelope,
};

/// Nonzero compare-and-swap revision of one durable receive checkpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReceiveCheckpointRevision(u64);

impl ReceiveCheckpointRevision {
    pub const fn new(value: u64) -> Result<Self, ReceiveStateContractError> {
        if value == 0 {
            return Err(ReceiveStateContractError::InvalidCheckpointRevision);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn successor(self) -> Result<Self, ReceiveStateContractError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(ReceiveStateContractError::CheckpointRevisionExhausted),
        }
    }
}

/// Exact non-authorizing checkpoint identity carried through one provider poll.
///
/// This marker binds the returned page to the mailbox generation and owner CAS
/// revision that originated the request. It intentionally omits diagnostics.
#[derive(Clone, Eq, PartialEq)]
pub struct ReceivePollBindingV1 {
    binding: CursorBindingV1,
    revision: ReceiveCheckpointRevision,
    position: ReceivePollPositionBindingV1,
}

impl ReceivePollBindingV1 {
    /// Exact mailbox generation that an external provider must match to receive authority.
    pub const fn binding(&self) -> &CursorBindingV1 {
        &self.binding
    }

    fn from_checkpoint(checkpoint: &ReceiveCheckpointV1) -> Self {
        let position = match &checkpoint.position {
            ReceiveCheckpointPositionV1::NewGeneration => {
                ReceivePollPositionBindingV1::NewGeneration
            }
            ReceiveCheckpointPositionV1::Resume(cursor) => ReceivePollPositionBindingV1::Resume(
                cursor.cursor().as_bytes().to_vec().into_boxed_slice(),
            ),
            ReceiveCheckpointPositionV1::CommittedPageWithoutCursor => {
                ReceivePollPositionBindingV1::CommittedPageWithoutCursor
            }
            ReceiveCheckpointPositionV1::ExplicitResynchronization(reason) => {
                ReceivePollPositionBindingV1::ExplicitResynchronization(*reason)
            }
        };
        Self {
            binding: checkpoint.binding,
            revision: checkpoint.revision,
            position,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
enum ReceivePollPositionBindingV1 {
    NewGeneration,
    Resume(Box<[u8]>),
    CommittedPageWithoutCursor,
    ExplicitResynchronization(ResynchronizationReasonV1),
}

/// Closed reason for deliberately restarting a cursor-bearing poll at `None`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResynchronizationReasonV1 {
    /// The provider rejected the exact persisted cursor as invalid.
    InvalidCursor,
    /// The provider declared an incompatible state reset or epoch change.
    ProviderStateReset,
}

enum ReceiveCheckpointPositionV1 {
    NewGeneration,
    Resume(BoundCursorV1),
    CommittedPageWithoutCursor,
    ExplicitResynchronization(ResynchronizationReasonV1),
}

/// Owner-provided compare-and-swap checkpoint for one bounded poll.
///
/// `cursor=None` distinguishes a fresh generation, a committed successor
/// revision without a continuation cursor, and an explicitly recorded
/// resynchronization. A resumed cursor must match the complete live binding and
/// remain unexpired. This value contains full cursor/scope state and therefore
/// intentionally omits `Clone`, `Debug`, and `Display`.
pub struct ReceiveCheckpointV1 {
    binding: CursorBindingV1,
    revision: ReceiveCheckpointRevision,
    position: ReceiveCheckpointPositionV1,
}

impl ReceiveCheckpointV1 {
    pub const fn new_generation(
        binding: CursorBindingV1,
        revision: ReceiveCheckpointRevision,
        now_unix_seconds: u64,
    ) -> Result<Self, ReceiveStateContractError> {
        if binding.expires_at_unix_seconds() <= now_unix_seconds {
            return Err(ReceiveStateContractError::ExpiredCursorBinding);
        }
        Ok(Self {
            binding,
            revision,
            position: ReceiveCheckpointPositionV1::NewGeneration,
        })
    }

    pub fn resume(
        expected_binding: CursorBindingV1,
        cursor: BoundCursorV1,
        revision: ReceiveCheckpointRevision,
        now_unix_seconds: u64,
    ) -> Result<Self, ReceiveStateContractError> {
        if cursor.binding() != &expected_binding {
            return Err(ReceiveStateContractError::CursorBindingMismatch);
        }
        if expected_binding.expires_at_unix_seconds() <= now_unix_seconds {
            return Err(ReceiveStateContractError::ExpiredCursorBinding);
        }
        Ok(Self {
            binding: expected_binding,
            revision,
            position: ReceiveCheckpointPositionV1::Resume(cursor),
        })
    }

    /// Reconstructs a resynchronization checkpoint only after the owner has
    /// durably committed the corresponding [`ResynchronizationRequestV1`].
    ///
    /// This constructor exists for owner implementations in separate crates;
    /// ordinary callers obtain this value from
    /// [`ReceiveStateOwnerPort::record_resynchronization`].
    pub const fn from_recorded_resynchronization(
        binding: CursorBindingV1,
        revision: ReceiveCheckpointRevision,
        reason: ResynchronizationReasonV1,
        now_unix_seconds: u64,
    ) -> Result<Self, ReceiveStateContractError> {
        if binding.expires_at_unix_seconds() <= now_unix_seconds {
            return Err(ReceiveStateContractError::ExpiredCursorBinding);
        }
        Ok(Self {
            binding,
            revision,
            position: ReceiveCheckpointPositionV1::ExplicitResynchronization(reason),
        })
    }

    /// Reconstructs a committed successor revision when the provider returned
    /// no continuation cursor.
    pub const fn committed_page_without_cursor(
        binding: CursorBindingV1,
        revision: ReceiveCheckpointRevision,
        now_unix_seconds: u64,
    ) -> Result<Self, ReceiveStateContractError> {
        if binding.expires_at_unix_seconds() <= now_unix_seconds {
            return Err(ReceiveStateContractError::ExpiredCursorBinding);
        }
        Ok(Self {
            binding,
            revision,
            position: ReceiveCheckpointPositionV1::CommittedPageWithoutCursor,
        })
    }

    /// Returns the exact persisted cursor only for a validated resume.
    #[must_use]
    pub const fn poll_cursor(&self) -> Option<&Cursor> {
        match &self.position {
            ReceiveCheckpointPositionV1::Resume(cursor) => Some(cursor.cursor()),
            ReceiveCheckpointPositionV1::NewGeneration
            | ReceiveCheckpointPositionV1::CommittedPageWithoutCursor
            | ReceiveCheckpointPositionV1::ExplicitResynchronization(_) => None,
        }
    }

    #[must_use]
    pub const fn is_explicit_resynchronization(&self) -> bool {
        matches!(
            self.position,
            ReceiveCheckpointPositionV1::ExplicitResynchronization(_)
        )
    }

    #[must_use]
    pub const fn resynchronization_reason(&self) -> Option<ResynchronizationReasonV1> {
        match self.position {
            ReceiveCheckpointPositionV1::ExplicitResynchronization(reason) => Some(reason),
            ReceiveCheckpointPositionV1::NewGeneration
            | ReceiveCheckpointPositionV1::Resume(_)
            | ReceiveCheckpointPositionV1::CommittedPageWithoutCursor => None,
        }
    }

    #[must_use]
    pub const fn is_committed_page_without_cursor(&self) -> bool {
        matches!(
            self.position,
            ReceiveCheckpointPositionV1::CommittedPageWithoutCursor
        )
    }

    #[must_use]
    pub const fn binding(&self) -> &CursorBindingV1 {
        &self.binding
    }

    #[must_use]
    pub const fn revision(&self) -> ReceiveCheckpointRevision {
        self.revision
    }

    /// Creates the only poll request whose result may advance this checkpoint.
    ///
    /// The exact binding and CAS revision are copied into the request and then
    /// into `ReceiveBatch` by its validating constructor.
    pub fn poll_request(
        &self,
        max_envelopes: u16,
        max_encoded_bytes: u32,
        wait: PollWait,
        budget: OperationBudget,
        now_unix_seconds: u64,
    ) -> Result<PollRequest, ReceiveStateContractError> {
        self.ensure_live(now_unix_seconds)?;
        let cursor = self
            .poll_cursor()
            .map(|cursor| Cursor::new(cursor.as_bytes().to_vec()))
            .transpose()
            .map_err(|_| ReceiveStateContractError::InvalidReceivePage)?;
        PollRequest::new(cursor, max_envelopes, max_encoded_bytes, wait, budget)
            .map(|request| request.bind_receive_checkpoint(self.poll_binding()))
            .map_err(|_| ReceiveStateContractError::InvalidReceivePage)
    }

    pub(crate) const fn ensure_live(
        &self,
        now_unix_seconds: u64,
    ) -> Result<(), ReceiveStateContractError> {
        if self.binding.expires_at_unix_seconds() <= now_unix_seconds {
            return Err(ReceiveStateContractError::ExpiredCursorBinding);
        }
        Ok(())
    }

    fn poll_binding(&self) -> ReceivePollBindingV1 {
        ReceivePollBindingV1::from_checkpoint(self)
    }
}

/// Owner-CAS request to persist an explicit cursor resynchronization.
///
/// The expected checkpoint is consumed so the owner can compare its complete
/// binding, revision, position, and cursor before advancing to the successor
/// cursorless resynchronization state.
pub struct ResynchronizationRequestV1 {
    expected_checkpoint: ReceiveCheckpointV1,
    reason: ResynchronizationReasonV1,
    successor_revision: ReceiveCheckpointRevision,
}

impl ResynchronizationRequestV1 {
    pub fn new(
        expected_checkpoint: ReceiveCheckpointV1,
        reason: ResynchronizationReasonV1,
        now_unix_seconds: u64,
    ) -> Result<Self, ReceiveStateContractError> {
        expected_checkpoint.ensure_live(now_unix_seconds)?;
        let successor_revision = expected_checkpoint.revision().successor()?;
        Ok(Self {
            expected_checkpoint,
            reason,
            successor_revision,
        })
    }

    #[must_use]
    pub const fn expected_checkpoint(&self) -> &ReceiveCheckpointV1 {
        &self.expected_checkpoint
    }

    #[must_use]
    pub const fn reason(&self) -> ResynchronizationReasonV1 {
        self.reason
    }

    #[must_use]
    pub const fn successor_revision(&self) -> ReceiveCheckpointRevision {
        self.successor_revision
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ReceiveCheckpointV1,
        ResynchronizationReasonV1,
        ReceiveCheckpointRevision,
    ) {
        (
            self.expected_checkpoint,
            self.reason,
            self.successor_revision,
        )
    }
}

/// One owner-atomic transition containing the complete validated poll page.
///
/// The owner must compare-and-swap `expected_checkpoint`, retain each canonical
/// envelope or its durable deduplication result, persist the exact
/// acknowledgement intent, and advance to `next_cursor` or a cursorless
/// successor revision in one transaction. The adapter never receives this
/// value and cannot commit owner state.
pub struct ReceivePageCommitV1 {
    expected_checkpoint: ReceiveCheckpointV1,
    items: Box<[ReceivedCanonicalEnvelope]>,
    next_cursor: Option<BoundCursorV1>,
    acknowledgement_intent: Option<BoundedDeliveryIds>,
}

impl ReceivePageCommitV1 {
    pub fn new(
        expected_checkpoint: ReceiveCheckpointV1,
        batch: ReceiveBatch,
    ) -> Result<Self, ReceiveStateContractError> {
        let expected_poll_binding = expected_checkpoint.poll_binding();
        if batch.receive_binding() != Some(&expected_poll_binding) {
            return Err(ReceiveStateContractError::ReceivePageBindingMismatch);
        }
        let binding = *expected_checkpoint.binding();
        let (items, next_cursor) = batch.into_parts();
        let acknowledgement_intent = if items.is_empty() {
            None
        } else {
            let identifiers = items.iter().map(|item| *item.delivery_id()).collect();
            Some(
                BoundedDeliveryIds::new(identifiers)
                    .map_err(|_| ReceiveStateContractError::InvalidReceivePage)?,
            )
        };
        Ok(Self {
            expected_checkpoint,
            items,
            next_cursor: next_cursor.map(|cursor| BoundCursorV1::new(cursor, binding)),
            acknowledgement_intent,
        })
    }

    #[must_use]
    pub const fn expected_checkpoint(&self) -> &ReceiveCheckpointV1 {
        &self.expected_checkpoint
    }

    #[must_use]
    pub fn items(&self) -> &[ReceivedCanonicalEnvelope] {
        &self.items
    }

    #[must_use]
    pub const fn next_cursor(&self) -> Option<&BoundCursorV1> {
        self.next_cursor.as_ref()
    }

    #[must_use]
    pub const fn acknowledgement_intent(&self) -> Option<&BoundedDeliveryIds> {
        self.acknowledgement_intent.as_ref()
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ReceiveCheckpointV1,
        Box<[ReceivedCanonicalEnvelope]>,
        Option<BoundCursorV1>,
        Option<BoundedDeliveryIds>,
    ) {
        (
            self.expected_checkpoint,
            self.items,
            self.next_cursor,
            self.acknowledgement_intent,
        )
    }
}

/// Durable per-envelope result produced by the receive-state owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeduplicationOutcomeV1 {
    /// The canonical envelope was new and retained by the owner.
    Stored,
    /// The exact envelope was already durably retained or processed.
    Duplicate,
}

/// Owner-defined opaque evidence returned only by an atomic page commit.
///
/// The port chooses the concrete type. Callers can inspect non-secret commit
/// metadata but cannot construct, disassemble, or splice the owner token through
/// this contract.
///
/// ```compile_fail
/// use session_transport::{
///     BoundedDeliveryIds, CommittedReceivePageV1, CursorBindingV1,
///     DeduplicationOutcomeV1, ReceiveCheckpointRevision, ReceiveStateOwnerPort,
/// };
///
/// struct ForeignCommit;
/// impl CommittedReceivePageV1 for ForeignCommit {
///     fn checkpoint_revision(&self) -> ReceiveCheckpointRevision { todo!() }
///     fn binding(&self) -> &CursorBindingV1 { todo!() }
///     fn deduplication_outcomes(&self) -> &[DeduplicationOutcomeV1] { todo!() }
///     fn acknowledgement_intent(&self) -> Option<&BoundedDeliveryIds> { None }
/// }
///
/// fn foreign_commit_cannot_lease<O: ReceiveStateOwnerPort>(
///     owner: &mut O,
///     foreign: ForeignCommit,
/// ) {
///     let _ = owner.lease_acknowledgement(foreign, 1);
/// }
/// ```
pub trait CommittedReceivePageV1 {
    fn checkpoint_revision(&self) -> ReceiveCheckpointRevision;
    fn binding(&self) -> &CursorBindingV1;
    fn deduplication_outcomes(&self) -> &[DeduplicationOutcomeV1];
    fn acknowledgement_intent(&self) -> Option<&BoundedDeliveryIds>;
}

/// Exact persisted acknowledgement work leased only after page commit.
pub trait AcknowledgementLeaseV1 {
    fn binding(&self) -> &CursorBindingV1;
    fn delivery_ids(&self) -> &BoundedDeliveryIds;
}

/// Sole owner of durable receive checkpoints and acknowledgement scheduling.
///
/// `commit_receive_page` is one atomic compare-and-swap transition and receives
/// explicit wall time for a final live-binding check. Only its opaque associated
/// `CommittedPage` may be passed to `lease_acknowledgement`, making
/// persist-before-acknowledge the shape of the immediate path. Leasing also
/// receives explicit wall time. After restart,
/// `load_checkpoint` reconstructs the latest committed cursor state for an
/// exact live binding without transferring ownership of the durable record.
/// `recover_acknowledgement` receives explicit wall time and may lease only an
/// intent already persisted under the complete live binding. Implementations
/// accept/release only the exact
/// owner-issued lease. An adapter implements neither this port nor any method
/// that can advance the owner checkpoint.
pub trait ReceiveStateOwnerPort {
    type Error: Error;
    type CommittedPage: CommittedReceivePageV1;
    type AcknowledgementLease: AcknowledgementLeaseV1;

    /// Loads the latest committed checkpoint for one exact live binding.
    ///
    /// Implementations must reconstruct this value from owner state, reject
    /// foreign or expired bindings, and never return a checkpoint older than
    /// the current compare-and-swap revision.
    fn load_checkpoint(
        &mut self,
        binding: &CursorBindingV1,
        now_unix_seconds: u64,
    ) -> Result<Option<ReceiveCheckpointV1>, Self::Error>;

    /// Atomically records an explicit resynchronization before polling at none.
    ///
    /// Implementations compare-and-swap the complete expected checkpoint,
    /// persist the reason at the successor revision, and only then return the
    /// pollable checkpoint. A crash before commit leaves the predecessor intact;
    /// a crash after commit is recovered through `load_checkpoint`.
    fn record_resynchronization(
        &mut self,
        request: ResynchronizationRequestV1,
        now_unix_seconds: u64,
    ) -> Result<ReceiveCheckpointV1, Self::Error>;

    fn commit_receive_page(
        &mut self,
        transition: ReceivePageCommitV1,
        now_unix_seconds: u64,
    ) -> Result<Self::CommittedPage, Self::Error>;

    fn lease_acknowledgement(
        &mut self,
        committed: Self::CommittedPage,
        now_unix_seconds: u64,
    ) -> Result<Option<Self::AcknowledgementLease>, Self::Error>;

    /// Recovers previously committed acknowledgement work after restart.
    ///
    /// Implementations must return only an exact intent durably committed
    /// under `binding`; this method cannot create new acknowledgement work.
    fn recover_acknowledgement(
        &mut self,
        binding: &CursorBindingV1,
        now_unix_seconds: u64,
    ) -> Result<Option<Self::AcknowledgementLease>, Self::Error>;

    fn accept_acknowledgement(
        &mut self,
        lease: Self::AcknowledgementLease,
    ) -> Result<(), Self::Error>;

    fn release_acknowledgement(
        &mut self,
        lease: Self::AcknowledgementLease,
    ) -> Result<(), Self::Error>;
}

/// Fail-closed construction errors for owner receive-state transitions.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ReceiveStateContractError {
    #[error("invalid receive checkpoint revision")]
    InvalidCheckpointRevision,
    #[error("receive checkpoint revision exhausted")]
    CheckpointRevisionExhausted,
    #[error("cursor binding does not match the receive checkpoint")]
    CursorBindingMismatch,
    #[error("receive page does not match the originating checkpoint")]
    ReceivePageBindingMismatch,
    #[error("cursor binding is expired")]
    ExpiredCursorBinding,
    #[error("invalid receive page transition")]
    InvalidReceivePage,
    #[error("deduplication outcome count does not match receive page")]
    DeduplicationOutcomeCardinalityMismatch,
}
