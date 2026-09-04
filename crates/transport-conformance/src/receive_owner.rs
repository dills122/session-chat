use std::{collections::BTreeMap, error::Error, fmt};

use session_transport::{
    AcknowledgementLeaseV1, BoundCursorV1, BoundedDeliveryIds, CommittedReceivePageV1, Cursor,
    CursorBindingV1, DeduplicationOutcomeV1, DeliveryId, ReceiveCheckpointRevision,
    ReceiveCheckpointV1, ReceivePageCommitV1, ReceiveStateOwnerPort, ResynchronizationReasonV1,
    ResynchronizationRequestV1,
};

/// Context-free failure from the deterministic receive-state owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeterministicReceiveStateErrorV1;

impl fmt::Display for DeterministicReceiveStateErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("deterministic receive-state transition failed")
    }
}

impl Error for DeterministicReceiveStateErrorV1 {}

/// Opaque commit evidence issued by [`DeterministicReceiveStateOwnerV1`].
pub struct DeterministicCommittedReceivePageV1 {
    nonce: u64,
    revision: ReceiveCheckpointRevision,
    binding: CursorBindingV1,
    outcomes: Box<[DeduplicationOutcomeV1]>,
    acknowledgement_intent: Option<BoundedDeliveryIds>,
}

impl CommittedReceivePageV1 for DeterministicCommittedReceivePageV1 {
    fn checkpoint_revision(&self) -> ReceiveCheckpointRevision {
        self.revision
    }

    fn binding(&self) -> &CursorBindingV1 {
        &self.binding
    }

    fn deduplication_outcomes(&self) -> &[DeduplicationOutcomeV1] {
        &self.outcomes
    }

    fn acknowledgement_intent(&self) -> Option<&BoundedDeliveryIds> {
        self.acknowledgement_intent.as_ref()
    }
}

/// Exact acknowledgement lease issued by the deterministic owner.
pub struct DeterministicAcknowledgementLeaseV1 {
    binding: CursorBindingV1,
    delivery_ids: BoundedDeliveryIds,
}

impl AcknowledgementLeaseV1 for DeterministicAcknowledgementLeaseV1 {
    fn binding(&self) -> &CursorBindingV1 {
        &self.binding
    }

    fn delivery_ids(&self) -> &BoundedDeliveryIds {
        &self.delivery_ids
    }
}

enum PersistedCheckpointPosition {
    Resume(Box<[u8]>),
    CommittedPageWithoutCursor,
    ExplicitResynchronization(ResynchronizationReasonV1),
}

struct PersistedCheckpoint {
    binding: CursorBindingV1,
    revision: ReceiveCheckpointRevision,
    position: PersistedCheckpointPosition,
}

struct CommitEvidence {
    nonce: u64,
    revision: ReceiveCheckpointRevision,
    binding: CursorBindingV1,
    delivery_ids: Box<[DeliveryId]>,
}

struct LeaseEvidence {
    binding: CursorBindingV1,
    delivery_ids: Box<[DeliveryId]>,
}

/// Bounded in-memory owner model for receive checkpoints and acknowledgement work.
///
/// `restart` preserves only modeled durable state and discards live leases and
/// immediate commit handles. The model retains canonical bytes solely to prove
/// exact duplicate overlap; it intentionally implements no storage durability
/// or product transport.
pub struct DeterministicReceiveStateOwnerV1 {
    next_commit_nonce: u64,
    stored: BTreeMap<DeliveryId, Box<[u8]>>,
    checkpoint: Option<PersistedCheckpoint>,
    recoverable: Option<(CursorBindingV1, BoundedDeliveryIds)>,
    valid_commit: Option<CommitEvidence>,
    leased: Option<LeaseEvidence>,
}

impl DeterministicReceiveStateOwnerV1 {
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_commit_nonce: 1,
            stored: BTreeMap::new(),
            checkpoint: None,
            recoverable: None,
            valid_commit: None,
            leased: None,
        }
    }

    /// Simulates a process restart while preserving modeled durable state.
    #[must_use]
    pub fn restart(mut self) -> Self {
        self.valid_commit = None;
        self.leased = None;
        self
    }

    fn checkpoint_matches(&self, checkpoint: &ReceiveCheckpointV1) -> bool {
        self.checkpoint.as_ref().is_some_and(|persisted| {
            if persisted.binding != *checkpoint.binding()
                || persisted.revision != checkpoint.revision()
            {
                return false;
            }
            match &persisted.position {
                PersistedCheckpointPosition::Resume(cursor) => checkpoint
                    .poll_cursor()
                    .is_some_and(|candidate| candidate.as_bytes() == cursor.as_ref()),
                PersistedCheckpointPosition::CommittedPageWithoutCursor => {
                    checkpoint.is_committed_page_without_cursor()
                }
                PersistedCheckpointPosition::ExplicitResynchronization(reason) => {
                    checkpoint.resynchronization_reason() == Some(*reason)
                }
            }
        })
    }

    fn validate_lease(
        &self,
        lease: &DeterministicAcknowledgementLeaseV1,
    ) -> Result<(), DeterministicReceiveStateErrorV1> {
        self.leased
            .as_ref()
            .filter(|expected| {
                expected.binding == lease.binding
                    && expected.delivery_ids.as_ref() == lease.delivery_ids.as_slice()
            })
            .map(|_| ())
            .ok_or(DeterministicReceiveStateErrorV1)
    }
}

impl Default for DeterministicReceiveStateOwnerV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl ReceiveStateOwnerPort for DeterministicReceiveStateOwnerV1 {
    type Error = DeterministicReceiveStateErrorV1;
    type CommittedPage = DeterministicCommittedReceivePageV1;
    type AcknowledgementLease = DeterministicAcknowledgementLeaseV1;

    fn load_checkpoint(
        &mut self,
        binding: &CursorBindingV1,
        now_unix_seconds: u64,
    ) -> Result<Option<ReceiveCheckpointV1>, Self::Error> {
        if binding.expires_at_unix_seconds() <= now_unix_seconds {
            return Err(DeterministicReceiveStateErrorV1);
        }
        self.checkpoint
            .as_ref()
            .filter(|persisted| persisted.binding == *binding)
            .map(|persisted| {
                let checkpoint = match &persisted.position {
                    PersistedCheckpointPosition::Resume(cursor) => {
                        let cursor = Cursor::new(cursor.to_vec())
                            .map_err(|_| DeterministicReceiveStateErrorV1)?;
                        ReceiveCheckpointV1::resume(
                            persisted.binding,
                            BoundCursorV1::new(cursor, persisted.binding),
                            persisted.revision,
                            now_unix_seconds,
                        )
                    }
                    PersistedCheckpointPosition::CommittedPageWithoutCursor => {
                        ReceiveCheckpointV1::committed_page_without_cursor(
                            persisted.binding,
                            persisted.revision,
                            now_unix_seconds,
                        )
                    }
                    PersistedCheckpointPosition::ExplicitResynchronization(reason) => {
                        ReceiveCheckpointV1::from_recorded_resynchronization(
                            persisted.binding,
                            persisted.revision,
                            *reason,
                            now_unix_seconds,
                        )
                    }
                };
                checkpoint.map_err(|_| DeterministicReceiveStateErrorV1)
            })
            .transpose()
    }

    fn record_resynchronization(
        &mut self,
        request: ResynchronizationRequestV1,
        now_unix_seconds: u64,
    ) -> Result<ReceiveCheckpointV1, Self::Error> {
        if request
            .expected_checkpoint()
            .binding()
            .expires_at_unix_seconds()
            <= now_unix_seconds
            || !self.checkpoint_matches(request.expected_checkpoint())
            || self.recoverable.is_some()
            || self.leased.is_some()
        {
            return Err(DeterministicReceiveStateErrorV1);
        }
        let (expected, reason, successor_revision) = request.into_parts();
        let binding = *expected.binding();
        self.checkpoint = Some(PersistedCheckpoint {
            binding,
            revision: successor_revision,
            position: PersistedCheckpointPosition::ExplicitResynchronization(reason),
        });
        ReceiveCheckpointV1::from_recorded_resynchronization(
            binding,
            successor_revision,
            reason,
            now_unix_seconds,
        )
        .map_err(|_| DeterministicReceiveStateErrorV1)
    }

    fn commit_receive_page(
        &mut self,
        transition: ReceivePageCommitV1,
        now_unix_seconds: u64,
    ) -> Result<Self::CommittedPage, Self::Error> {
        let expected = transition.expected_checkpoint();
        if expected.binding().expires_at_unix_seconds() <= now_unix_seconds
            || self.recoverable.is_some()
            || self.leased.is_some()
            || self
                .checkpoint
                .as_ref()
                .is_some_and(|_| !self.checkpoint_matches(expected))
        {
            return Err(DeterministicReceiveStateErrorV1);
        }

        let next_revision = expected
            .revision()
            .successor()
            .map_err(|_| DeterministicReceiveStateErrorV1)?;
        let mut additions = Vec::new();
        let outcomes = transition
            .items()
            .iter()
            .map(|item| match self.stored.get(item.delivery_id()) {
                Some(bytes) if bytes.as_ref() == item.envelope().as_bytes() => {
                    Ok(DeduplicationOutcomeV1::Duplicate)
                }
                Some(_) => Err(DeterministicReceiveStateErrorV1),
                None => {
                    additions.push((
                        *item.delivery_id(),
                        item.envelope().as_bytes().to_vec().into_boxed_slice(),
                    ));
                    Ok(DeduplicationOutcomeV1::Stored)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        let delivery_ids = transition
            .items()
            .iter()
            .map(|item| *item.delivery_id())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let binding = *expected.binding();
        let nonce = self.next_commit_nonce;
        let next_commit_nonce = self
            .next_commit_nonce
            .checked_add(1)
            .ok_or(DeterministicReceiveStateErrorV1)?;
        let (_expected, _items, next_cursor, acknowledgement_intent) = transition.into_parts();

        for (delivery_id, bytes) in additions {
            self.stored.insert(delivery_id, bytes);
        }
        self.next_commit_nonce = next_commit_nonce;
        self.checkpoint = Some(PersistedCheckpoint {
            binding,
            revision: next_revision,
            position: next_cursor.map_or(
                PersistedCheckpointPosition::CommittedPageWithoutCursor,
                |cursor| {
                    PersistedCheckpointPosition::Resume(
                        cursor.cursor().as_bytes().to_vec().into_boxed_slice(),
                    )
                },
            ),
        });
        self.recoverable = acknowledgement_intent
            .as_ref()
            .map(|ids| copy_ids(ids).map(|copied| (binding, copied)))
            .transpose()?;
        self.valid_commit = Some(CommitEvidence {
            nonce,
            revision: next_revision,
            binding,
            delivery_ids: delivery_ids.clone(),
        });
        Ok(DeterministicCommittedReceivePageV1 {
            nonce,
            revision: next_revision,
            binding,
            outcomes: outcomes.into_boxed_slice(),
            acknowledgement_intent,
        })
    }

    fn lease_acknowledgement(
        &mut self,
        committed: Self::CommittedPage,
        now_unix_seconds: u64,
    ) -> Result<Option<Self::AcknowledgementLease>, Self::Error> {
        if committed.binding.expires_at_unix_seconds() <= now_unix_seconds {
            return Err(DeterministicReceiveStateErrorV1);
        }
        let delivery_ids = committed
            .acknowledgement_intent
            .as_ref()
            .map(|ids| ids.as_slice())
            .unwrap_or_default();
        if !self.valid_commit.as_ref().is_some_and(|evidence| {
            evidence.nonce == committed.nonce
                && evidence.revision == committed.revision
                && evidence.binding == committed.binding
                && evidence.delivery_ids.as_ref() == delivery_ids
        }) || self.leased.is_some()
        {
            return Err(DeterministicReceiveStateErrorV1);
        }
        self.valid_commit = None;
        let Some(delivery_ids) = committed.acknowledgement_intent else {
            return Ok(None);
        };
        let lease_copy = copy_ids(&delivery_ids)?;
        self.leased = Some(LeaseEvidence {
            binding: committed.binding,
            delivery_ids: delivery_ids.as_slice().to_vec().into_boxed_slice(),
        });
        Ok(Some(DeterministicAcknowledgementLeaseV1 {
            binding: committed.binding,
            delivery_ids: lease_copy,
        }))
    }

    fn recover_acknowledgement(
        &mut self,
        binding: &CursorBindingV1,
        now_unix_seconds: u64,
    ) -> Result<Option<Self::AcknowledgementLease>, Self::Error> {
        if binding.expires_at_unix_seconds() <= now_unix_seconds || self.leased.is_some() {
            return Err(DeterministicReceiveStateErrorV1);
        }
        let Some((persisted_binding, delivery_ids)) = self
            .recoverable
            .as_ref()
            .filter(|(persisted_binding, _)| persisted_binding == binding)
        else {
            return Ok(None);
        };
        let lease_ids = copy_ids(delivery_ids)?;
        self.leased = Some(LeaseEvidence {
            binding: *persisted_binding,
            delivery_ids: delivery_ids.as_slice().to_vec().into_boxed_slice(),
        });
        Ok(Some(DeterministicAcknowledgementLeaseV1 {
            binding: *persisted_binding,
            delivery_ids: lease_ids,
        }))
    }

    fn accept_acknowledgement(
        &mut self,
        lease: Self::AcknowledgementLease,
    ) -> Result<(), Self::Error> {
        self.validate_lease(&lease)?;
        if !self.recoverable.as_ref().is_some_and(|(binding, ids)| {
            *binding == lease.binding && ids.as_slice() == lease.delivery_ids.as_slice()
        }) {
            return Err(DeterministicReceiveStateErrorV1);
        }
        self.recoverable = None;
        self.leased = None;
        Ok(())
    }

    fn release_acknowledgement(
        &mut self,
        lease: Self::AcknowledgementLease,
    ) -> Result<(), Self::Error> {
        self.validate_lease(&lease)?;
        self.leased = None;
        Ok(())
    }
}

fn copy_ids(
    delivery_ids: &BoundedDeliveryIds,
) -> Result<BoundedDeliveryIds, DeterministicReceiveStateErrorV1> {
    BoundedDeliveryIds::new(delivery_ids.as_slice().to_vec())
        .map_err(|_| DeterministicReceiveStateErrorV1)
}
