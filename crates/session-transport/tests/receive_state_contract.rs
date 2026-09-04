use std::{
    error::Error,
    fmt,
    time::{Duration, Instant},
};

use session_protocol::OpaqueEnvelope;
use session_transport::{
    AcknowledgementLeaseV1, BindingFingerprint, BoundCursorV1, BoundedDeliveryIds,
    CanonicalEnvelope, CommittedReceivePageV1, Cursor, CursorBindingV1, CursorSchemaVersion,
    DeduplicationOutcomeV1, DeliveryId, MailboxContinuityId, MailboxGeneration, OperationBudget,
    PollWait, ProviderStateEpoch, ReceiveBatch, ReceiveCheckpointRevision, ReceiveCheckpointV1,
    ReceivePageCommitV1, ReceiveScopeFingerprint, ReceiveStateContractError, ReceiveStateOwnerPort,
    ReceivedCanonicalEnvelope, ResynchronizationReasonV1, ResynchronizationRequestV1,
    TransportProfileId,
};

const NOW: u64 = 1_700_000_000;

fn binding(generation: u64, fingerprint: u8) -> CursorBindingV1 {
    binding_until(generation, fingerprint, NOW + 600)
}

fn binding_until(
    generation: u64,
    fingerprint: u8,
    expires_at_unix_seconds: u64,
) -> CursorBindingV1 {
    CursorBindingV1::new(
        TransportProfileId::FastV1,
        BindingFingerprint::from_bytes([fingerprint; 32]).expect("binding fingerprint"),
        MailboxContinuityId::from_provider_bytes([0x22; 16]).expect("continuity ID"),
        MailboxGeneration::new(generation).expect("generation"),
        ReceiveScopeFingerprint::from_bytes([0x33; 32]).expect("receive scope"),
        CursorSchemaVersion::new(1).expect("cursor schema"),
        ProviderStateEpoch::new(5).expect("provider epoch"),
        expires_at_unix_seconds,
    )
    .expect("cursor binding")
}

fn batch(checkpoint: &ReceiveCheckpointV1, next_cursor: Option<Vec<u8>>) -> ReceiveBatch {
    let budget =
        OperationBudget::new(Instant::now() + Duration::from_secs(30), 4_096, 1).expect("budget");
    let request = checkpoint
        .poll_request(2, 4_096, PollWait::immediate(), budget, NOW)
        .expect("checkpoint-bound poll request");
    let items = [0x41_u8, 0x42]
        .into_iter()
        .map(|value| {
            ReceivedCanonicalEnvelope::new(
                DeliveryId::from_provider_bytes([value; 16]).expect("delivery ID"),
                CanonicalEnvelope::from_opaque(
                    OpaqueEnvelope::new([value; 16], NOW + 300, vec![value; 32])
                        .expect("opaque envelope"),
                )
                .expect("canonical envelope"),
            )
        })
        .collect();
    ReceiveBatch::new(
        items,
        next_cursor.map(|bytes| Cursor::new(bytes).expect("bounded cursor")),
        &request,
        NOW,
    )
    .expect("valid receive batch")
}

#[test]
fn fresh_generation_is_an_explicit_cursorless_initial_state() {
    let revision = ReceiveCheckpointRevision::new(1).expect("revision");
    let fresh = ReceiveCheckpointV1::new_generation(binding(1, 0x11), revision, NOW)
        .expect("live fresh checkpoint");
    assert!(fresh.poll_cursor().is_none());
    assert!(!fresh.is_explicit_resynchronization());
}

#[test]
fn restart_resume_requires_the_exact_live_cursor_binding() {
    let exact = binding(3, 0x11);
    let cursor = BoundCursorV1::new(Cursor::new(vec![0x51; 16]).expect("cursor"), exact);
    let resumed = ReceiveCheckpointV1::resume(
        exact,
        cursor,
        ReceiveCheckpointRevision::new(8).expect("revision"),
        NOW,
    )
    .expect("matching live cursor");
    assert_eq!(
        resumed.poll_cursor().expect("resume cursor").as_bytes(),
        &[0x51; 16]
    );

    let foreign = BoundCursorV1::new(
        Cursor::new(vec![0x52; 16]).expect("cursor"),
        binding(3, 0x12),
    );
    assert_eq!(
        ReceiveCheckpointV1::resume(
            exact,
            foreign,
            ReceiveCheckpointRevision::new(8).expect("revision"),
            NOW,
        )
        .err(),
        Some(ReceiveStateContractError::CursorBindingMismatch)
    );

    let expired_binding = CursorBindingV1::new(
        TransportProfileId::FastV1,
        BindingFingerprint::from_bytes([0x11; 32]).expect("binding fingerprint"),
        MailboxContinuityId::from_provider_bytes([0x22; 16]).expect("continuity ID"),
        MailboxGeneration::new(3).expect("generation"),
        ReceiveScopeFingerprint::from_bytes([0x33; 32]).expect("receive scope"),
        CursorSchemaVersion::new(1).expect("cursor schema"),
        ProviderStateEpoch::new(5).expect("provider epoch"),
        NOW,
    )
    .expect("expired binding shape remains valid");
    let expired = BoundCursorV1::new(
        Cursor::new(vec![0x53; 16]).expect("cursor"),
        expired_binding,
    );
    assert_eq!(
        ReceiveCheckpointV1::resume(
            expired_binding,
            expired,
            ReceiveCheckpointRevision::new(8).expect("revision"),
            NOW,
        )
        .err(),
        Some(ReceiveStateContractError::ExpiredCursorBinding)
    );
}

#[test]
fn page_commit_derives_exact_acknowledgement_intent_and_binds_the_next_cursor() {
    let exact = binding(2, 0x61);
    let checkpoint = ReceiveCheckpointV1::new_generation(
        exact,
        ReceiveCheckpointRevision::new(4).expect("revision"),
        NOW,
    )
    .expect("checkpoint");
    let receive_batch = batch(&checkpoint, Some(vec![0x62; 16]));
    let transition =
        ReceivePageCommitV1::new(checkpoint, receive_batch).expect("atomic owner transition");

    assert_eq!(transition.items().len(), 2);
    assert_eq!(
        transition
            .acknowledgement_intent()
            .expect("exact intent")
            .len(),
        2
    );
    assert!(
        transition
            .next_cursor()
            .expect("bound next cursor")
            .binding()
            == &exact
    );
    assert_eq!(transition.expected_checkpoint().revision().get(), 4);
}

#[test]
fn committed_page_rejects_deduplication_outcome_cardinality_mismatch() {
    let exact = binding(2, 0x63);
    let checkpoint = ReceiveCheckpointV1::new_generation(
        exact,
        ReceiveCheckpointRevision::new(4).expect("revision"),
        NOW,
    )
    .expect("checkpoint");
    let receive_batch = batch(&checkpoint, Some(vec![0x64; 16]));
    let transition = ReceivePageCommitV1::new(checkpoint, receive_batch).expect("page transition");
    let mut owner = ModelOwner {
        return_short_outcome_set: true,
        ..ModelOwner::default()
    };

    assert!(owner.commit_receive_page(transition, NOW).is_err());
}

#[derive(Debug)]
struct ModelError;

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("model receive-state error")
    }
}

impl Error for ModelError {}

struct ModelCommitted {
    nonce: u64,
    revision: ReceiveCheckpointRevision,
    binding: CursorBindingV1,
    outcomes: Box<[DeduplicationOutcomeV1]>,
    acknowledgement_intent: Option<BoundedDeliveryIds>,
}

impl CommittedReceivePageV1 for ModelCommitted {
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

struct ModelLease {
    binding: CursorBindingV1,
    ids: BoundedDeliveryIds,
}

enum ModelCheckpointPosition {
    Resume(Vec<u8>),
    CommittedPageWithoutCursor,
    ExplicitResynchronization(ResynchronizationReasonV1),
}

impl AcknowledgementLeaseV1 for ModelLease {
    fn binding(&self) -> &CursorBindingV1 {
        &self.binding
    }

    fn delivery_ids(&self) -> &BoundedDeliveryIds {
        &self.ids
    }
}

#[derive(Default)]
struct ModelOwner {
    commits: usize,
    accepted: usize,
    return_short_outcome_set: bool,
    recoverable: Option<(CursorBindingV1, BoundedDeliveryIds)>,
    checkpoint: Option<(
        CursorBindingV1,
        ReceiveCheckpointRevision,
        ModelCheckpointPosition,
    )>,
    current_revision: Option<ReceiveCheckpointRevision>,
    valid_commit: Option<(
        u64,
        ReceiveCheckpointRevision,
        CursorBindingV1,
        Vec<DeliveryId>,
    )>,
    leased_acknowledgement: Option<(CursorBindingV1, Vec<DeliveryId>)>,
}

impl ModelOwner {
    fn restart(self) -> Self {
        Self {
            commits: 0,
            accepted: 0,
            return_short_outcome_set: self.return_short_outcome_set,
            recoverable: self.recoverable,
            checkpoint: self.checkpoint,
            current_revision: self.current_revision,
            valid_commit: self.valid_commit,
            leased_acknowledgement: None,
        }
    }

    fn checkpoint_matches(&self, checkpoint: &ReceiveCheckpointV1) -> bool {
        self.checkpoint
            .as_ref()
            .is_some_and(|(binding, revision, position)| {
                if binding != checkpoint.binding() || *revision != checkpoint.revision() {
                    return false;
                }
                match position {
                    ModelCheckpointPosition::Resume(cursor) => checkpoint
                        .poll_cursor()
                        .is_some_and(|expected| expected.as_bytes() == cursor),
                    ModelCheckpointPosition::CommittedPageWithoutCursor => {
                        checkpoint.is_committed_page_without_cursor()
                    }
                    ModelCheckpointPosition::ExplicitResynchronization(reason) => {
                        checkpoint.resynchronization_reason() == Some(*reason)
                    }
                }
            })
    }
}

impl ReceiveStateOwnerPort for ModelOwner {
    type Error = ModelError;
    type CommittedPage = ModelCommitted;
    type AcknowledgementLease = ModelLease;

    fn commit_receive_page(
        &mut self,
        transition: ReceivePageCommitV1,
        now_unix_seconds: u64,
    ) -> Result<Self::CommittedPage, Self::Error> {
        if transition
            .expected_checkpoint()
            .binding()
            .expires_at_unix_seconds()
            <= now_unix_seconds
        {
            return Err(ModelError);
        }
        if self
            .current_revision
            .is_some_and(|revision| revision != transition.expected_checkpoint().revision())
        {
            return Err(ModelError);
        }
        if self.checkpoint.is_some() && !self.checkpoint_matches(transition.expected_checkpoint()) {
            return Err(ModelError);
        }
        let next_revision = transition
            .expected_checkpoint()
            .revision()
            .successor()
            .expect("next revision");
        let mut outcomes = vec![DeduplicationOutcomeV1::Stored; transition.items().len()];
        if self.return_short_outcome_set {
            outcomes.pop();
        }
        if outcomes.len() != transition.items().len() {
            return Err(ModelError);
        }
        let nonce = u64::try_from(self.commits).expect("bounded model commits") + 1;
        let persisted_ids: Vec<_> = transition
            .items()
            .iter()
            .map(|item| *item.delivery_id())
            .collect();
        let recoverable_ids = (!persisted_ids.is_empty())
            .then(|| BoundedDeliveryIds::new(persisted_ids.clone()).expect("bounded receive page"));
        let binding = *transition.expected_checkpoint().binding();
        let revision = next_revision;
        let (_expected, _items, next_cursor, acknowledgement_intent) = transition.into_parts();
        self.commits += 1;
        self.current_revision = Some(next_revision);
        let position = next_cursor.map_or(
            ModelCheckpointPosition::CommittedPageWithoutCursor,
            |cursor| ModelCheckpointPosition::Resume(cursor.cursor().as_bytes().to_vec()),
        );
        self.checkpoint = Some((binding, next_revision, position));
        self.recoverable = recoverable_ids.map(|ids| (binding, ids));
        self.valid_commit = Some((nonce, revision, binding, persisted_ids));
        Ok(ModelCommitted {
            nonce,
            revision,
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
            return Err(ModelError);
        }
        let committed_ids: Vec<_> = committed
            .acknowledgement_intent
            .as_ref()
            .map(|ids| ids.as_slice().to_vec())
            .unwrap_or_default();
        if !self
            .valid_commit
            .as_ref()
            .is_some_and(|(nonce, revision, binding, ids)| {
                *nonce == committed.nonce
                    && *revision == committed.revision
                    && binding == &committed.binding
                    && ids == &committed_ids
            })
        {
            return Err(ModelError);
        }
        self.valid_commit = None;
        self.leased_acknowledgement =
            (!committed_ids.is_empty()).then_some((committed.binding, committed_ids));
        Ok(committed.acknowledgement_intent.map(|ids| ModelLease {
            binding: committed.binding,
            ids,
        }))
    }

    fn recover_acknowledgement(
        &mut self,
        binding: &CursorBindingV1,
        now_unix_seconds: u64,
    ) -> Result<Option<Self::AcknowledgementLease>, Self::Error> {
        if binding.expires_at_unix_seconds() <= now_unix_seconds {
            return Err(ModelError);
        }
        if self.leased_acknowledgement.is_some() {
            return Err(ModelError);
        }
        if !self
            .recoverable
            .as_ref()
            .is_some_and(|(persisted_binding, _)| persisted_binding == binding)
        {
            return Ok(None);
        }
        let Some((persisted_binding, ids)) = self.recoverable.as_ref() else {
            return Ok(None);
        };
        let copied_ids =
            BoundedDeliveryIds::new(ids.as_slice().to_vec()).map_err(|_| ModelError)?;
        self.leased_acknowledgement = Some((*persisted_binding, ids.as_slice().to_vec()));
        Ok(Some(ModelLease {
            binding: *persisted_binding,
            ids: copied_ids,
        }))
    }

    fn load_checkpoint(
        &mut self,
        binding: &CursorBindingV1,
        now_unix_seconds: u64,
    ) -> Result<Option<ReceiveCheckpointV1>, Self::Error> {
        self.checkpoint
            .as_ref()
            .filter(|(persisted_binding, _, _)| persisted_binding == binding)
            .map(|(persisted_binding, revision, position)| {
                match position {
                    ModelCheckpointPosition::Resume(cursor) => ReceiveCheckpointV1::resume(
                        *persisted_binding,
                        BoundCursorV1::new(
                            Cursor::new(cursor.clone()).expect("persisted cursor"),
                            *persisted_binding,
                        ),
                        *revision,
                        now_unix_seconds,
                    ),
                    ModelCheckpointPosition::CommittedPageWithoutCursor => {
                        ReceiveCheckpointV1::committed_page_without_cursor(
                            *persisted_binding,
                            *revision,
                            now_unix_seconds,
                        )
                    }
                    ModelCheckpointPosition::ExplicitResynchronization(reason) => {
                        ReceiveCheckpointV1::from_recorded_resynchronization(
                            *persisted_binding,
                            *revision,
                            *reason,
                            now_unix_seconds,
                        )
                    }
                }
                .map_err(|_| ModelError)
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
        {
            return Err(ModelError);
        }
        let (expected, reason, successor_revision) = request.into_parts();
        let binding = *expected.binding();
        self.current_revision = Some(successor_revision);
        self.checkpoint = Some((
            binding,
            successor_revision,
            ModelCheckpointPosition::ExplicitResynchronization(reason),
        ));
        ReceiveCheckpointV1::from_recorded_resynchronization(
            binding,
            successor_revision,
            reason,
            now_unix_seconds,
        )
        .map_err(|_| ModelError)
    }

    fn accept_acknowledgement(
        &mut self,
        lease: Self::AcknowledgementLease,
    ) -> Result<(), Self::Error> {
        if !self
            .leased_acknowledgement
            .as_ref()
            .is_some_and(|(binding, ids)| {
                binding == &lease.binding && ids.as_slice() == lease.ids.as_slice()
            })
        {
            return Err(ModelError);
        }
        if self.recoverable.as_ref().is_some_and(|(binding, ids)| {
            binding == &lease.binding && ids.as_slice() == lease.ids.as_slice()
        }) {
            self.recoverable = None;
        }
        self.leased_acknowledgement = None;
        self.accepted += 1;
        Ok(())
    }

    fn release_acknowledgement(
        &mut self,
        lease: Self::AcknowledgementLease,
    ) -> Result<(), Self::Error> {
        if !self
            .leased_acknowledgement
            .as_ref()
            .is_some_and(|(binding, ids)| {
                binding == &lease.binding && ids.as_slice() == lease.ids.as_slice()
            })
        {
            return Err(ModelError);
        }
        self.leased_acknowledgement = None;
        Ok(())
    }
}

#[test]
fn acknowledgement_can_be_leased_only_from_a_committed_owner_result() {
    let exact = binding(2, 0x71);
    let checkpoint = ReceiveCheckpointV1::new_generation(
        exact,
        ReceiveCheckpointRevision::new(1).expect("revision"),
        NOW,
    )
    .expect("checkpoint");
    let receive_batch = batch(&checkpoint, None);
    let transition = ReceivePageCommitV1::new(checkpoint, receive_batch).expect("transition");
    let mut owner = ModelOwner::default();

    let committed = owner
        .commit_receive_page(transition, NOW)
        .expect("atomic commit");
    assert_eq!(
        committed.deduplication_outcomes(),
        [DeduplicationOutcomeV1::Stored; 2]
    );
    let committed_ids = committed
        .acknowledgement_intent()
        .expect("committed exact intent")
        .as_slice();
    assert_eq!(committed_ids[0].as_bytes(), &[0x41; 16]);
    assert_eq!(committed_ids[1].as_bytes(), &[0x42; 16]);
    let lease = owner
        .lease_acknowledgement(committed, NOW)
        .expect("lease lookup")
        .expect("persisted exact intent");
    assert_eq!(lease.delivery_ids().len(), 2);
    owner
        .accept_acknowledgement(lease)
        .expect("terminal acknowledgement");

    assert_eq!(owner.commits, 1);
    assert_eq!(owner.accepted, 1);
}

#[test]
fn persisted_acknowledgement_can_be_recovered_after_restart() {
    let exact = binding(2, 0x72);
    let checkpoint = ReceiveCheckpointV1::new_generation(
        exact,
        ReceiveCheckpointRevision::new(1).expect("revision"),
        NOW,
    )
    .expect("checkpoint");
    let receive_batch = batch(&checkpoint, None);
    let transition = ReceivePageCommitV1::new(checkpoint, receive_batch).expect("transition");
    let mut owner = ModelOwner::default();

    let _committed = owner
        .commit_receive_page(transition, NOW)
        .expect("atomic commit before restart");
    let mut owner = owner.restart();
    let recovered = owner
        .recover_acknowledgement(&exact, NOW)
        .expect("recovery lookup")
        .expect("persisted exact intent");

    assert!(recovered.binding() == &exact);
    assert_eq!(recovered.delivery_ids().len(), 2);
}

#[test]
fn recovered_acknowledgement_survives_crash_and_ambiguous_release() {
    let exact = binding(2, 0x78);
    let checkpoint = ReceiveCheckpointV1::new_generation(
        exact,
        ReceiveCheckpointRevision::new(1).expect("revision"),
        NOW,
    )
    .expect("checkpoint");
    let receive_batch = batch(&checkpoint, None);
    let transition = ReceivePageCommitV1::new(checkpoint, receive_batch).expect("transition");
    let mut owner = ModelOwner::default();
    let _committed = owner.commit_receive_page(transition, NOW).expect("commit");

    let mut owner = owner.restart();
    let abandoned = owner
        .recover_acknowledgement(&exact, NOW)
        .expect("recovery")
        .expect("durable intent");
    let mut owner = owner.restart();
    drop(abandoned);
    let released = owner
        .recover_acknowledgement(&exact, NOW)
        .expect("post-crash recovery")
        .expect("intent survived crash");
    owner
        .release_acknowledgement(released)
        .expect("ambiguous release");
    let accepted = owner
        .recover_acknowledgement(&exact, NOW)
        .expect("post-release recovery")
        .expect("intent survived release");
    owner
        .accept_acknowledgement(accepted)
        .expect("terminal acceptance");
    assert!(
        owner
            .recover_acknowledgement(&exact, NOW)
            .expect("terminal lookup")
            .is_none()
    );
}

#[test]
fn ambiguous_acknowledgement_release_remains_recoverable_until_acceptance() {
    let exact = binding(2, 0x75);
    let checkpoint = ReceiveCheckpointV1::new_generation(
        exact,
        ReceiveCheckpointRevision::new(1).expect("revision"),
        NOW,
    )
    .expect("checkpoint");
    let receive_batch = batch(&checkpoint, None);
    let transition = ReceivePageCommitV1::new(checkpoint, receive_batch).expect("transition");
    let mut owner = ModelOwner::default();
    let committed = owner.commit_receive_page(transition, NOW).expect("commit");

    let lease = owner
        .lease_acknowledgement(committed, NOW)
        .expect("immediate lease")
        .expect("persisted intent");
    owner
        .release_acknowledgement(lease)
        .expect("ambiguous result release");
    let recovered = owner
        .recover_acknowledgement(&exact, NOW)
        .expect("recovery lookup")
        .expect("released intent remains recoverable");
    owner
        .accept_acknowledgement(recovered)
        .expect("terminal acceptance");

    assert!(
        owner
            .recover_acknowledgement(&exact, NOW)
            .expect("terminal recovery lookup")
            .is_none()
    );
    assert_eq!(owner.accepted, 1);
}

#[test]
fn foreign_receive_binding_rejects_without_consuming_owner_state() {
    let exact = binding(2, 0x76);
    let foreign = binding(2, 0x77);
    let checkpoint = ReceiveCheckpointV1::new_generation(
        exact,
        ReceiveCheckpointRevision::new(1).expect("revision"),
        NOW,
    )
    .expect("checkpoint");
    let receive_batch = batch(&checkpoint, Some(vec![0xa1; 16]));
    let transition = ReceivePageCommitV1::new(checkpoint, receive_batch).expect("transition");
    let mut owner = ModelOwner::default();
    let _committed = owner.commit_receive_page(transition, NOW).expect("commit");

    assert!(
        owner
            .load_checkpoint(&foreign, NOW)
            .expect("foreign checkpoint lookup")
            .is_none()
    );
    assert!(
        owner
            .recover_acknowledgement(&foreign, NOW)
            .expect("foreign acknowledgement lookup")
            .is_none()
    );

    assert!(
        owner
            .load_checkpoint(&exact, NOW)
            .expect("exact checkpoint lookup")
            .is_some()
    );
    assert!(
        owner
            .recover_acknowledgement(&exact, NOW)
            .expect("exact acknowledgement lookup")
            .is_some()
    );
}

#[test]
fn committed_cursor_advances_across_pages_and_reloads_after_restart() {
    let exact = binding(2, 0x73);
    let checkpoint = ReceiveCheckpointV1::new_generation(
        exact,
        ReceiveCheckpointRevision::new(1).expect("revision"),
        NOW,
    )
    .expect("checkpoint");
    let first_batch = batch(&checkpoint, Some(vec![0x81; 16]));
    let first = ReceivePageCommitV1::new(checkpoint, first_batch).expect("first page transition");
    let mut owner = ModelOwner::default();

    let _first_commit = owner.commit_receive_page(first, NOW).expect("first commit");
    let mut owner = owner.restart();
    let resumed = owner
        .load_checkpoint(&exact, NOW)
        .expect("checkpoint lookup")
        .expect("committed checkpoint");
    assert_eq!(resumed.revision().get(), 2);
    assert_eq!(
        resumed.poll_cursor().expect("first cursor").as_bytes(),
        &[0x81; 16]
    );

    let second_batch = batch(&resumed, Some(vec![0x82; 16]));
    let second = ReceivePageCommitV1::new(resumed, second_batch).expect("second page transition");
    let _second_commit = owner
        .commit_receive_page(second, NOW)
        .expect("second commit");
    let advanced = owner
        .load_checkpoint(&exact, NOW)
        .expect("checkpoint lookup")
        .expect("advanced checkpoint");
    assert_eq!(advanced.revision().get(), 3);
    assert_eq!(
        advanced.poll_cursor().expect("second cursor").as_bytes(),
        &[0x82; 16]
    );
}

#[test]
fn stale_checkpoint_cas_rejects_without_advancing_owner_state() {
    let exact = binding(2, 0x74);
    let first_checkpoint = ReceiveCheckpointV1::new_generation(
        exact,
        ReceiveCheckpointRevision::new(1).expect("revision"),
        NOW,
    )
    .expect("checkpoint");
    let first_batch = batch(&first_checkpoint, Some(vec![0x91; 16]));
    let first =
        ReceivePageCommitV1::new(first_checkpoint, first_batch).expect("first page transition");
    let mut owner = ModelOwner::default();
    let _first_commit = owner.commit_receive_page(first, NOW).expect("first commit");

    let stale_checkpoint = ReceiveCheckpointV1::new_generation(
        exact,
        ReceiveCheckpointRevision::new(1).expect("stale revision"),
        NOW,
    )
    .expect("stale checkpoint shape");
    let stale_batch = batch(&stale_checkpoint, Some(vec![0x92; 16]));
    let stale = ReceivePageCommitV1::new(stale_checkpoint, stale_batch).expect("stale page shape");
    assert!(owner.commit_receive_page(stale, NOW).is_err());

    let unchanged = owner
        .load_checkpoint(&exact, NOW)
        .expect("checkpoint lookup")
        .expect("original checkpoint");
    assert_eq!(unchanged.revision().get(), 2);
    assert_eq!(
        unchanged.poll_cursor().expect("original cursor").as_bytes(),
        &[0x91; 16]
    );
    assert_eq!(owner.commits, 1);
}

#[test]
fn receive_page_rejects_cross_mailbox_and_cross_generation_commit() {
    let mailbox_a = binding(2, 0x81);
    let checkpoint_a = ReceiveCheckpointV1::new_generation(
        mailbox_a,
        ReceiveCheckpointRevision::new(4).expect("revision"),
        NOW,
    )
    .expect("mailbox A checkpoint");
    let batch_a = batch(&checkpoint_a, Some(vec![0xa1; 16]));

    let mailbox_b = binding(2, 0x82);
    let checkpoint_b = ReceiveCheckpointV1::new_generation(
        mailbox_b,
        ReceiveCheckpointRevision::new(4).expect("revision"),
        NOW,
    )
    .expect("mailbox B checkpoint");
    assert_eq!(
        ReceivePageCommitV1::new(checkpoint_b, batch_a).err(),
        Some(ReceiveStateContractError::ReceivePageBindingMismatch)
    );

    let generation_two = ReceiveCheckpointV1::new_generation(
        mailbox_a,
        ReceiveCheckpointRevision::new(4).expect("revision"),
        NOW,
    )
    .expect("generation two checkpoint");
    let generation_two_batch = batch(&generation_two, Some(vec![0xa2; 16]));
    let generation_three = ReceiveCheckpointV1::new_generation(
        binding(3, 0x81),
        ReceiveCheckpointRevision::new(4).expect("revision"),
        NOW,
    )
    .expect("generation three checkpoint");
    assert_eq!(
        ReceivePageCommitV1::new(generation_three, generation_two_batch).err(),
        Some(ReceiveStateContractError::ReceivePageBindingMismatch)
    );

    let cursor_a = ReceiveCheckpointV1::resume(
        mailbox_a,
        BoundCursorV1::new(Cursor::new(vec![0xb1; 16]).expect("cursor A"), mailbox_a),
        ReceiveCheckpointRevision::new(7).expect("revision"),
        NOW,
    )
    .expect("cursor A checkpoint");
    let cursor_a_batch = batch(&cursor_a, Some(vec![0xb3; 16]));
    let cursor_b = ReceiveCheckpointV1::resume(
        mailbox_a,
        BoundCursorV1::new(Cursor::new(vec![0xb2; 16]).expect("cursor B"), mailbox_a),
        ReceiveCheckpointRevision::new(7).expect("revision"),
        NOW,
    )
    .expect("cursor B checkpoint");
    assert_eq!(
        ReceivePageCommitV1::new(cursor_b, cursor_a_batch).err(),
        Some(ReceiveStateContractError::ReceivePageBindingMismatch)
    );

    let fresh = ReceiveCheckpointV1::new_generation(
        mailbox_a,
        ReceiveCheckpointRevision::new(8).expect("revision"),
        NOW,
    )
    .expect("fresh checkpoint");
    let fresh_batch = batch(&fresh, None);
    let committed_cursorless = ReceiveCheckpointV1::committed_page_without_cursor(
        mailbox_a,
        ReceiveCheckpointRevision::new(8).expect("revision"),
        NOW,
    )
    .expect("cursorless committed checkpoint");
    assert_eq!(
        ReceivePageCommitV1::new(committed_cursorless, fresh_batch).err(),
        Some(ReceiveStateContractError::ReceivePageBindingMismatch)
    );
}

#[test]
fn cursorless_commit_reloads_and_remains_cas_advanceable_after_restart() {
    let exact = binding(2, 0x83);
    let checkpoint = ReceiveCheckpointV1::new_generation(
        exact,
        ReceiveCheckpointRevision::new(1).expect("revision"),
        NOW,
    )
    .expect("checkpoint");
    let first_batch = batch(&checkpoint, None);
    let first = ReceivePageCommitV1::new(checkpoint, first_batch).expect("first transition");
    let mut owner = ModelOwner::default();
    let _first_commit = owner.commit_receive_page(first, NOW).expect("first commit");

    let mut owner = owner.restart();
    let reloaded = owner
        .load_checkpoint(&exact, NOW)
        .expect("checkpoint lookup")
        .expect("cursorless committed checkpoint");
    assert_eq!(reloaded.revision().get(), 2);
    assert!(reloaded.poll_cursor().is_none());
    assert!(reloaded.is_committed_page_without_cursor());

    let second_batch = batch(&reloaded, None);
    let second = ReceivePageCommitV1::new(reloaded, second_batch).expect("second transition");
    let _second_commit = owner
        .commit_receive_page(second, NOW)
        .expect("second commit");
    let advanced = owner
        .load_checkpoint(&exact, NOW)
        .expect("checkpoint lookup")
        .expect("advanced cursorless checkpoint");
    assert_eq!(advanced.revision().get(), 3);
    assert!(advanced.is_committed_page_without_cursor());
}

#[test]
fn resynchronization_is_owner_committed_before_cursorless_poll_and_survives_restart() {
    let exact = binding(2, 0x87);
    let checkpoint = ReceiveCheckpointV1::new_generation(
        exact,
        ReceiveCheckpointRevision::new(1).expect("revision"),
        NOW,
    )
    .expect("checkpoint");
    let first_batch = batch(&checkpoint, Some(vec![0xc1; 16]));
    let first = ReceivePageCommitV1::new(checkpoint, first_batch).expect("first transition");
    let mut owner = ModelOwner::default();
    let _committed = owner.commit_receive_page(first, NOW).expect("first commit");
    let persisted = owner
        .load_checkpoint(&exact, NOW)
        .expect("load")
        .expect("cursor checkpoint");
    let request =
        ResynchronizationRequestV1::new(persisted, ResynchronizationReasonV1::InvalidCursor, NOW)
            .expect("resynchronization request");
    let recorded = owner
        .record_resynchronization(request, NOW)
        .expect("owner CAS record");
    assert_eq!(recorded.revision().get(), 3);
    assert_eq!(
        recorded.resynchronization_reason(),
        Some(ResynchronizationReasonV1::InvalidCursor)
    );

    let stale = ReceiveCheckpointV1::resume(
        exact,
        BoundCursorV1::new(Cursor::new(vec![0xc1; 16]).expect("old cursor"), exact),
        ReceiveCheckpointRevision::new(2).expect("old revision"),
        NOW,
    )
    .expect("stale predecessor shape");
    let stale_request =
        ResynchronizationRequestV1::new(stale, ResynchronizationReasonV1::ProviderStateReset, NOW)
            .expect("stale request shape");
    assert!(owner.record_resynchronization(stale_request, NOW).is_err());

    let mut owner = owner.restart();
    let reloaded = owner
        .load_checkpoint(&exact, NOW)
        .expect("restart load")
        .expect("recorded resynchronization");
    assert_eq!(reloaded.revision().get(), 3);
    assert!(reloaded.poll_cursor().is_none());
    assert!(reloaded.is_explicit_resynchronization());
}

#[test]
fn forged_or_rebound_commit_evidence_cannot_lease_acknowledgement() {
    let exact = binding(2, 0x84);
    let checkpoint = ReceiveCheckpointV1::new_generation(
        exact,
        ReceiveCheckpointRevision::new(1).expect("revision"),
        NOW,
    )
    .expect("checkpoint");
    let receive_batch = batch(&checkpoint, None);
    let transition = ReceivePageCommitV1::new(checkpoint, receive_batch).expect("transition");
    let mut owner = ModelOwner::default();
    let committed = owner.commit_receive_page(transition, NOW).expect("commit");

    let rebound = ModelCommitted {
        nonce: committed.nonce,
        revision: committed.revision,
        binding: binding(2, 0x85),
        outcomes: committed.outcomes,
        acknowledgement_intent: committed.acknowledgement_intent,
    };
    assert!(owner.lease_acknowledgement(rebound, NOW).is_err());

    let uncommitted = ModelCommitted {
        nonce: u64::MAX,
        revision: ReceiveCheckpointRevision::new(2).expect("revision"),
        binding: exact,
        outcomes: Box::new([]),
        acknowledgement_intent: None,
    };
    assert!(owner.lease_acknowledgement(uncommitted, NOW).is_err());
}

#[test]
fn expiry_between_poll_commit_and_restart_recovery_fails_closed() {
    let exact = binding_until(2, 0x86, NOW + 1);
    let checkpoint = ReceiveCheckpointV1::new_generation(
        exact,
        ReceiveCheckpointRevision::new(1).expect("revision"),
        NOW,
    )
    .expect("checkpoint");
    let receive_batch = batch(&checkpoint, None);
    let transition = ReceivePageCommitV1::new(checkpoint, receive_batch).expect("transition");
    let mut owner = ModelOwner::default();
    assert!(owner.commit_receive_page(transition, NOW + 1).is_err());
    assert_eq!(owner.commits, 0);

    let checkpoint = ReceiveCheckpointV1::new_generation(
        exact,
        ReceiveCheckpointRevision::new(1).expect("revision"),
        NOW,
    )
    .expect("checkpoint");
    let receive_batch = batch(&checkpoint, None);
    let transition = ReceivePageCommitV1::new(checkpoint, receive_batch).expect("transition");
    let _committed = owner.commit_receive_page(transition, NOW).expect("commit");
    assert!(owner.recover_acknowledgement(&exact, NOW + 1).is_err());
    assert!(owner.load_checkpoint(&exact, NOW + 1).is_err());
}

#[test]
fn checkpoint_revision_fails_closed_at_zero_and_exhaustion() {
    assert_eq!(
        ReceiveCheckpointRevision::new(0),
        Err(ReceiveStateContractError::InvalidCheckpointRevision)
    );
    assert_eq!(
        ReceiveCheckpointRevision::new(u64::MAX)
            .expect("terminal revision")
            .successor(),
        Err(ReceiveStateContractError::CheckpointRevisionExhausted)
    );
}
