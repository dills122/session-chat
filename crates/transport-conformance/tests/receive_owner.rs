use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use session_protocol::OpaqueEnvelope;
use session_transport::{
    AcknowledgementLeaseV1, BindingFingerprint, CanonicalEnvelope, CommittedReceivePageV1, Cursor,
    DeduplicationOutcomeV1, DeliveryId, DispatchControl, MailboxIssueRequestV1, MailboxLifecycle,
    OperationBudget, PollWait, ReceiveBatch, ReceiveCheckpointRevision, ReceiveCheckpointV1,
    ReceivePageCommitV1, ReceiveStateOwnerPort, ReceivedCanonicalEnvelope,
    ResynchronizationReasonV1, ResynchronizationRequestV1, TransportProfileId,
};
use transport_conformance::{DeterministicLifecycleProviderV1, DeterministicReceiveStateOwnerV1};

const NOW: u64 = 1_700_000_000;

struct FixedControl {
    monotonic: Instant,
}

impl DispatchControl for FixedControl {
    fn monotonic_now(&self) -> Instant {
        self.monotonic
    }

    fn wall_now_unix_seconds(&self) -> Option<u64> {
        Some(NOW)
    }

    fn is_cancelled(&self) -> bool {
        false
    }
}

fn operation() -> (FixedControl, OperationBudget) {
    let monotonic = Instant::now();
    (
        FixedControl { monotonic },
        OperationBudget::new(monotonic + Duration::from_secs(30), 65_536, 1)
            .expect("bounded operation"),
    )
}

fn ready<T>(future: impl Future<Output = T>) -> T {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("deterministic lifecycle operation must be immediately ready"),
    }
}

fn issued_binding(fingerprint: u8) -> session_transport::CursorBindingV1 {
    let mut provider = DeterministicLifecycleProviderV1::new();
    let contract = provider.lifecycle_contract();
    let (control, budget) = operation();
    let request = MailboxIssueRequestV1::new(
        TransportProfileId::FastV1,
        BindingFingerprint::from_bytes([fingerprint; 32]).expect("binding fingerprint"),
        NOW + 600,
        budget,
    )
    .expect("issue request");
    *ready(provider.issue(contract, request, &control))
        .expect("issued mailbox")
        .authorities()
        .binding()
}

fn batch(
    checkpoint: &ReceiveCheckpointV1,
    values: &[u8],
    next_cursor: Option<Vec<u8>>,
) -> ReceiveBatch {
    let (_, budget) = operation();
    let request = checkpoint
        .poll_request(8, 65_536, PollWait::immediate(), budget, NOW)
        .expect("checkpoint-bound poll request");
    let items = values
        .iter()
        .map(|value| {
            ReceivedCanonicalEnvelope::new(
                DeliveryId::from_provider_bytes([*value; 16]).expect("delivery ID"),
                CanonicalEnvelope::from_opaque(
                    OpaqueEnvelope::new([*value; 16], NOW + 300, vec![*value; 32])
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
fn owner_persists_cursor_and_acknowledgement_before_restart_recovery() {
    let binding = issued_binding(0x11);
    let checkpoint = ReceiveCheckpointV1::new_generation(
        binding,
        ReceiveCheckpointRevision::new(1).expect("revision"),
        NOW,
    )
    .expect("fresh checkpoint");
    let received = batch(&checkpoint, &[0x31, 0x32], Some(vec![0x71; 16]));
    let transition = ReceivePageCommitV1::new(checkpoint, received).expect("page transition");
    let mut owner = DeterministicReceiveStateOwnerV1::new();
    let committed = owner
        .commit_receive_page(transition, NOW)
        .expect("atomic page commit");

    assert_eq!(
        committed.deduplication_outcomes(),
        [
            DeduplicationOutcomeV1::Stored,
            DeduplicationOutcomeV1::Stored
        ]
    );
    let mut owner = owner.restart();
    let resumed = owner
        .load_checkpoint(&binding, NOW)
        .expect("load checkpoint")
        .expect("persisted checkpoint");
    assert_eq!(resumed.revision().get(), 2);
    assert_eq!(
        resumed.poll_cursor().expect("cursor").as_bytes(),
        &[0x71; 16]
    );

    let lease = owner
        .recover_acknowledgement(&binding, NOW)
        .expect("recover acknowledgement")
        .expect("durable acknowledgement intent");
    assert_eq!(lease.delivery_ids().len(), 2);
    owner
        .release_acknowledgement(lease)
        .expect("ambiguous acknowledgement release");

    let mut owner = owner.restart();
    let lease = owner
        .recover_acknowledgement(&binding, NOW)
        .expect("recover acknowledgement after another restart")
        .expect("intent survives ambiguous release");
    owner
        .accept_acknowledgement(lease)
        .expect("terminal acknowledgement acceptance");
    let mut owner = owner.restart();
    assert!(
        owner
            .recover_acknowledgement(&binding, NOW)
            .expect("accepted intent is terminal")
            .is_none()
    );
}

#[test]
fn owner_deduplicates_cursor_overlap_and_records_resynchronization() {
    let binding = issued_binding(0x11);
    let initial = ReceiveCheckpointV1::new_generation(
        binding,
        ReceiveCheckpointRevision::new(1).expect("revision"),
        NOW,
    )
    .expect("fresh checkpoint");
    let received = batch(&initial, &[0x41], Some(vec![0x72; 16]));
    let first = ReceivePageCommitV1::new(initial, received).expect("first page");
    let mut owner = DeterministicReceiveStateOwnerV1::new();
    let committed = owner.commit_receive_page(first, NOW).expect("first commit");
    let lease = owner
        .lease_acknowledgement(committed, NOW)
        .expect("lease first acknowledgement")
        .expect("first acknowledgement intent");
    owner
        .accept_acknowledgement(lease)
        .expect("accept first acknowledgement");

    let resumed = owner
        .load_checkpoint(&binding, NOW)
        .expect("load first cursor")
        .expect("first cursor");
    let received = batch(&resumed, &[0x41], None);
    let overlap = ReceivePageCommitV1::new(resumed, received).expect("overlap page");
    let committed = owner
        .commit_receive_page(overlap, NOW)
        .expect("deduplicated overlap commit");
    assert_eq!(
        committed.deduplication_outcomes(),
        [DeduplicationOutcomeV1::Duplicate]
    );
    let lease = owner
        .lease_acknowledgement(committed, NOW)
        .expect("lease overlap acknowledgement")
        .expect("overlap acknowledgement intent");
    owner
        .accept_acknowledgement(lease)
        .expect("accept overlap acknowledgement");

    let cursorless = owner
        .load_checkpoint(&binding, NOW)
        .expect("load cursorless successor")
        .expect("cursorless successor");
    assert!(cursorless.is_committed_page_without_cursor());
    let request = ResynchronizationRequestV1::new(
        cursorless,
        ResynchronizationReasonV1::ProviderStateReset,
        NOW,
    )
    .expect("resynchronization request");
    let recorded = owner
        .record_resynchronization(request, NOW)
        .expect("owner-recorded resynchronization");
    assert_eq!(
        recorded.resynchronization_reason(),
        Some(ResynchronizationReasonV1::ProviderStateReset)
    );
    let mut owner = owner.restart();
    let reloaded = owner
        .load_checkpoint(&binding, NOW)
        .expect("reload resynchronization")
        .expect("persisted resynchronization");
    assert_eq!(reloaded.revision().get(), 4);
    assert_eq!(
        reloaded.resynchronization_reason(),
        Some(ResynchronizationReasonV1::ProviderStateReset)
    );
}

#[test]
fn owner_rejects_stale_checkpoint_foreign_binding_and_expired_operations() {
    let binding = issued_binding(0x11);
    let initial = ReceiveCheckpointV1::new_generation(
        binding,
        ReceiveCheckpointRevision::new(1).expect("revision"),
        NOW,
    )
    .expect("fresh checkpoint");
    let received = batch(&initial, &[0x51], Some(vec![0x73; 16]));
    let transition = ReceivePageCommitV1::new(initial, received).expect("first page");
    let mut owner = DeterministicReceiveStateOwnerV1::new();
    let committed = owner
        .commit_receive_page(transition, NOW)
        .expect("first commit");
    let lease = owner
        .lease_acknowledgement(committed, NOW)
        .expect("lease acknowledgement")
        .expect("acknowledgement intent");
    owner
        .accept_acknowledgement(lease)
        .expect("accept acknowledgement");

    let stale = ReceiveCheckpointV1::new_generation(
        binding,
        ReceiveCheckpointRevision::new(1).expect("revision"),
        NOW,
    )
    .expect("stale checkpoint shape");
    let received = batch(&stale, &[0x52], None);
    let transition = ReceivePageCommitV1::new(stale, received).expect("stale transition shape");
    assert!(owner.commit_receive_page(transition, NOW).is_err());

    let foreign = issued_binding(0x12);
    assert!(
        owner
            .load_checkpoint(&foreign, NOW)
            .expect("foreign lookup")
            .is_none()
    );
    assert!(owner.load_checkpoint(&binding, NOW + 600).is_err());
}

#[test]
fn probe_foreign_owner_commit_handle_is_rejected() {
    let binding = issued_binding(0x11);
    let mut owners = [
        DeterministicReceiveStateOwnerV1::new(),
        DeterministicReceiveStateOwnerV1::new(),
    ];
    let mut commits = Vec::new();
    for owner in &mut owners {
        let checkpoint = ReceiveCheckpointV1::new_generation(
            binding,
            ReceiveCheckpointRevision::new(1).unwrap(),
            NOW,
        )
        .unwrap();
        let received = batch(&checkpoint, &[0x51], Some(vec![0x73; 16]));
        commits.push(
            owner
                .commit_receive_page(ReceivePageCommitV1::new(checkpoint, received).unwrap(), NOW)
                .unwrap(),
        );
    }
    let foreign_commit = commits.remove(0);
    assert!(
        owners[1]
            .lease_acknowledgement(foreign_commit, NOW)
            .is_err(),
        "owner B accepted a committed handle issued by owner A"
    );
}

#[test]
fn probe_pre_restart_lease_cannot_accept_recovered_lease() {
    let binding = issued_binding(0x11);
    let checkpoint = ReceiveCheckpointV1::new_generation(
        binding,
        ReceiveCheckpointRevision::new(1).unwrap(),
        NOW,
    )
    .unwrap();
    let received = batch(&checkpoint, &[0x51], Some(vec![0x73; 16]));
    let mut owner = DeterministicReceiveStateOwnerV1::new();
    let committed = owner
        .commit_receive_page(ReceivePageCommitV1::new(checkpoint, received).unwrap(), NOW)
        .unwrap();
    let old_lease = owner
        .lease_acknowledgement(committed, NOW)
        .unwrap()
        .unwrap();
    let mut owner = owner.restart();
    let _new_lease = owner
        .recover_acknowledgement(&binding, NOW)
        .unwrap()
        .unwrap();
    assert!(
        owner.accept_acknowledgement(old_lease).is_err(),
        "pre-restart lease accepted as the newly recovered lease"
    );
}

#[test]
fn probe_foreign_checkpoint_poll_is_rejected() {
    use session_transport::{DepositRequest, EnvelopeDelivery};
    let mut provider = DeterministicLifecycleProviderV1::new();
    let contract = provider.lifecycle_contract();
    let (control, budget) = operation();
    let request = MailboxIssueRequestV1::new(
        TransportProfileId::FastV1,
        BindingFingerprint::from_bytes([0x11; 32]).unwrap(),
        NOW + 600,
        budget,
    )
    .unwrap();
    let (_binding_a, deposit_a, receive_a, _, _) =
        ready(provider.issue(contract, request, &control))
            .unwrap()
            .into_authorities()
            .into_parts();
    let request = MailboxIssueRequestV1::new(
        TransportProfileId::FastV1,
        BindingFingerprint::from_bytes([0x12; 32]).unwrap(),
        NOW + 600,
        budget,
    )
    .unwrap();
    let (binding_b, _, _, _, _) = ready(provider.issue(contract, request, &control))
        .unwrap()
        .into_authorities()
        .into_parts();
    let envelope = CanonicalEnvelope::from_opaque(
        OpaqueEnvelope::new([0x31; 16], NOW + 300, vec![0x41; 32]).unwrap(),
    )
    .unwrap();
    ready(EnvelopeDelivery::deposit(
        &mut provider,
        &deposit_a,
        DepositRequest::new(envelope, budget).unwrap(),
        &control,
    ))
    .unwrap();
    let checkpoint_b = ReceiveCheckpointV1::new_generation(
        binding_b,
        ReceiveCheckpointRevision::new(1).unwrap(),
        NOW,
    )
    .unwrap();
    let poll_b = checkpoint_b
        .poll_request(8, 65_536, PollWait::immediate(), budget, NOW)
        .unwrap();
    let result = ready(EnvelopeDelivery::poll(
        &mut provider,
        &receive_a,
        poll_b,
        &control,
    ));
    assert!(
        result.is_err(),
        "receive authority A accepted checkpoint B and returned A's envelope tagged as B"
    );
}

#[test]
fn probe_consumed_recovered_ack_cannot_be_released_from_original_commit() {
    let binding = issued_binding(0x11);
    let checkpoint = ReceiveCheckpointV1::new_generation(
        binding,
        ReceiveCheckpointRevision::new(1).unwrap(),
        NOW,
    )
    .unwrap();
    let received = batch(&checkpoint, &[0x51], Some(vec![0x73; 16]));
    let mut owner = DeterministicReceiveStateOwnerV1::new();
    let committed = owner
        .commit_receive_page(ReceivePageCommitV1::new(checkpoint, received).unwrap(), NOW)
        .unwrap();
    let recovered = owner
        .recover_acknowledgement(&binding, NOW)
        .unwrap()
        .unwrap();
    owner.accept_acknowledgement(recovered).unwrap();
    assert!(
        owner.lease_acknowledgement(committed, NOW).is_err(),
        "terminally accepted acknowledgement was re-leased using original commit handle"
    );
}

#[test]
fn probe_foreign_delivery_id_acknowledgement_is_rejected() {
    use session_transport::{
        AcknowledgementRequest, BoundedDeliveryIds, DepositRequest, EnvelopeDelivery,
    };
    let mut provider = DeterministicLifecycleProviderV1::new();
    let contract = provider.lifecycle_contract();
    let (control, budget) = operation();
    let request = MailboxIssueRequestV1::new(
        TransportProfileId::FastV1,
        BindingFingerprint::from_bytes([0x11; 32]).unwrap(),
        NOW + 600,
        budget,
    )
    .unwrap();
    let (_, deposit_a, _, _, _) = ready(provider.issue(contract, request, &control))
        .unwrap()
        .into_authorities()
        .into_parts();
    let request = MailboxIssueRequestV1::new(
        TransportProfileId::FastV1,
        BindingFingerprint::from_bytes([0x12; 32]).unwrap(),
        NOW + 600,
        budget,
    )
    .unwrap();
    let (_, _, _, acknowledgement_b, _) = ready(provider.issue(contract, request, &control))
        .unwrap()
        .into_authorities()
        .into_parts();
    let envelope = CanonicalEnvelope::from_opaque(
        OpaqueEnvelope::new([0x31; 16], NOW + 300, vec![0x41; 32]).unwrap(),
    )
    .unwrap();
    let receipt_a = ready(EnvelopeDelivery::deposit(
        &mut provider,
        &deposit_a,
        DepositRequest::new(envelope, budget).unwrap(),
        &control,
    ))
    .unwrap();
    let request = AcknowledgementRequest::new(
        BoundedDeliveryIds::new(vec![*receipt_a.delivery_id()]).unwrap(),
        budget,
    );
    let result = ready(EnvelopeDelivery::acknowledge(
        &mut provider,
        &acknowledgement_b,
        request,
        &control,
    ));
    assert!(
        result.is_err(),
        "acknowledgement authority B accepted delivery ID from mailbox A"
    );
}

#[test]
fn owner_capacity_rejects_new_bytes_without_advancing_but_accepts_exact_duplicates() {
    let binding = issued_binding(0x31);
    let mut owner = DeterministicReceiveStateOwnerV1::new();
    for value in 1..=64 {
        let checkpoint = owner
            .load_checkpoint(&binding, NOW)
            .expect("load")
            .unwrap_or_else(|| {
                ReceiveCheckpointV1::new_generation(
                    binding,
                    ReceiveCheckpointRevision::new(1).expect("revision"),
                    NOW,
                )
                .expect("initial")
            });
        let page = batch(&checkpoint, &[value], None);
        let committed = owner
            .commit_receive_page(
                ReceivePageCommitV1::new(checkpoint, page).expect("transition"),
                NOW,
            )
            .expect("bounded commit");
        let lease = owner
            .lease_acknowledgement(committed, NOW)
            .expect("lease")
            .expect("intent");
        owner.accept_acknowledgement(lease).expect("accepted");
    }
    let checkpoint = owner
        .load_checkpoint(&binding, NOW)
        .expect("load")
        .expect("checkpoint");
    let revision = checkpoint.revision();
    let page = batch(&checkpoint, &[65], None);
    assert!(
        owner
            .commit_receive_page(
                ReceivePageCommitV1::new(checkpoint, page).expect("transition"),
                NOW
            )
            .is_err()
    );
    let mut owner = owner.restart();
    let checkpoint = owner
        .load_checkpoint(&binding, NOW)
        .expect("load")
        .expect("checkpoint");
    assert_eq!(checkpoint.revision(), revision);
    assert!(
        owner
            .recover_acknowledgement(&binding, NOW)
            .expect("no intent")
            .is_none()
    );
    let page = batch(&checkpoint, &[64], None);
    let committed = owner
        .commit_receive_page(
            ReceivePageCommitV1::new(checkpoint, page).expect("transition"),
            NOW,
        )
        .expect("exact duplicate at capacity");
    assert_eq!(
        committed.deduplication_outcomes(),
        &[DeduplicationOutcomeV1::Duplicate]
    );
}

#[test]
fn provider_cursor_fixture_rejects_legacy_bytes_and_rebinding_to_another_mailbox() {
    use session_transport::{BoundCursorV1, DepositRequest, EnvelopeDelivery};
    let mut provider = DeterministicLifecycleProviderV1::new();
    let contract = provider.lifecycle_contract();
    let (control, budget) = operation();
    let mut mailboxes = Vec::new();
    for value in [0x11, 0x12] {
        let request = MailboxIssueRequestV1::new(
            TransportProfileId::FastV1,
            BindingFingerprint::from_bytes([value; 32]).unwrap(),
            NOW + 600,
            budget,
        )
        .unwrap();
        let (binding, deposit, receive, _, _) = ready(provider.issue(contract, request, &control))
            .unwrap()
            .into_authorities()
            .into_parts();
        let envelope = CanonicalEnvelope::from_opaque(
            OpaqueEnvelope::new([value; 16], NOW + 300, vec![value; 32]).unwrap(),
        )
        .unwrap();
        ready(EnvelopeDelivery::deposit(
            &mut provider,
            &deposit,
            DepositRequest::new(envelope, budget).unwrap(),
            &control,
        ))
        .unwrap();
        mailboxes.push((binding, receive));
    }
    let (binding_a, receive_a) = &mailboxes[0];
    let initial = ReceiveCheckpointV1::new_generation(
        *binding_a,
        ReceiveCheckpointRevision::new(1).unwrap(),
        NOW,
    )
    .unwrap();
    let request = initial
        .poll_request(8, 65_536, PollWait::immediate(), budget, NOW)
        .unwrap();
    let page = ready(EnvelopeDelivery::poll(
        &mut provider,
        receive_a,
        request,
        &control,
    ))
    .unwrap();
    let cursor = page.next_cursor().unwrap().as_bytes().to_vec();
    let mut expected = binding_a.continuity_id().as_bytes().to_vec();
    expected.extend_from_slice(&1u64.to_be_bytes());
    expected.extend_from_slice(&1u64.to_be_bytes());
    expected.extend_from_slice(&1u64.to_be_bytes());
    assert_eq!(cursor, expected);
    for (binding, receive, bytes) in [
        (&mailboxes[1].0, &mailboxes[1].1, cursor),
        (binding_a, receive_a, 1u64.to_be_bytes().to_vec()),
    ] {
        let checkpoint = ReceiveCheckpointV1::resume(
            *binding,
            BoundCursorV1::new(Cursor::new(bytes).unwrap(), *binding),
            ReceiveCheckpointRevision::new(2).unwrap(),
            NOW,
        )
        .unwrap();
        let request = checkpoint
            .poll_request(8, 65_536, PollWait::immediate(), budget, NOW)
            .unwrap();
        assert!(
            ready(EnvelopeDelivery::poll(
                &mut provider,
                receive,
                request,
                &control
            ))
            .is_err()
        );
    }
}

#[test]
fn predictable_model_material_does_not_authorize_another_provider_instance() {
    use session_transport::{DepositRequest, EnvelopeDelivery};
    let (control, budget) = operation();
    let mut first = DeterministicLifecycleProviderV1::new();
    let mut second = DeterministicLifecycleProviderV1::new();
    let request = || {
        MailboxIssueRequestV1::new(
            TransportProfileId::FastV1,
            BindingFingerprint::from_bytes([0x11; 32]).unwrap(),
            NOW + 600,
            budget,
        )
        .unwrap()
    };
    let (_, deposit, _, _, _) = ready(first.issue(first.lifecycle_contract(), request(), &control))
        .unwrap()
        .into_authorities()
        .into_parts();
    ready(second.issue(second.lifecycle_contract(), request(), &control)).unwrap();
    let envelope = CanonicalEnvelope::from_opaque(
        OpaqueEnvelope::new([0x41; 16], NOW + 300, vec![0x41; 32]).unwrap(),
    )
    .unwrap();
    assert!(
        ready(EnvelopeDelivery::deposit(
            &mut second,
            &deposit,
            DepositRequest::new(envelope, budget).unwrap(),
            &control
        ))
        .is_err()
    );
}
