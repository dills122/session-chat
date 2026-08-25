use session_inviter_transaction::{
    CommitFault, CommitOutcome, InMemoryInviterJoinStore, InvitationState, InviterJoinCommit,
    OutboxState, ReservedInvitation, TransactionError, TransactionPolicy,
};
use session_protocol::{DepositCapability, LocalWelcomeDepositEndpoint, OpaqueEnvelope};

const NOW: u64 = 1_000;

fn policy(maximum_transactions: usize) -> TransactionPolicy {
    TransactionPolicy::new(
        maximum_transactions,
        255,
        4_096,
        2_097_152,
        65_536,
        4_096,
        3,
        60,
    )
    .expect("valid policy")
}

fn reservation(generation: u8, request: u8) -> ReservedInvitation {
    ReservedInvitation::new([1; 16], [generation; 64], [request; 16], NOW + 300)
        .expect("valid reservation")
}

fn commit(transaction: u8, generation: u8, request: u8) -> InviterJoinCommit {
    commit_with_delivery_material(
        transaction,
        generation,
        request,
        canonical_welcome(NOW + 180),
        canonical_endpoint(NOW + 240),
        NOW + 120,
    )
}

fn canonical_welcome(expires_at_unix_seconds: u64) -> Vec<u8> {
    OpaqueEnvelope::new([8; 16], expires_at_unix_seconds, vec![8; 32])
        .expect("valid envelope")
        .encode_canonical()
        .expect("canonical envelope")
}

fn canonical_endpoint(expires_at_unix_seconds: u64) -> Vec<u8> {
    LocalWelcomeDepositEndpoint::new(
        [9; 16],
        [10; 16],
        DepositCapability::new([11; 32]).expect("valid capability"),
        expires_at_unix_seconds,
    )
    .expect("valid endpoint")
    .encode_canonical()
    .expect("canonical endpoint")
}

fn commit_with_delivery_material(
    transaction: u8,
    generation: u8,
    request: u8,
    welcome_envelope: Vec<u8>,
    deposit_endpoint: Vec<u8>,
    outbox_expires_at_unix_seconds: u64,
) -> InviterJoinCommit {
    InviterJoinCommit::new(
        [transaction; 16],
        [1; 16],
        [generation; 64],
        [request; 16],
        [4; 32],
        vec![5; 16],
        7,
        8,
        vec![6; 32],
        vec![7; 512],
        welcome_envelope,
        deposit_endpoint,
        outbox_expires_at_unix_seconds,
    )
}

#[allow(clippy::too_many_arguments)]
fn sized_commit(
    transaction: u8,
    generation: u8,
    request: u8,
    group_bytes: usize,
    approval_bytes: usize,
    mls_state_bytes: usize,
    welcome_bytes: usize,
    endpoint_bytes: usize,
    epoch_before: u64,
    epoch_after: u64,
    outbox_expires_at: u64,
) -> InviterJoinCommit {
    InviterJoinCommit::new(
        [transaction; 16],
        [1; 16],
        [generation; 64],
        [request; 16],
        [4; 32],
        vec![5; group_bytes],
        epoch_before,
        epoch_after,
        vec![6; approval_bytes],
        vec![7; mls_state_bytes],
        vec![8; welcome_bytes],
        vec![9; endpoint_bytes],
        outbox_expires_at,
    )
}

fn seeded_store() -> InMemoryInviterJoinStore {
    let mut store = InMemoryInviterJoinStore::new(policy(4));
    store
        .seed_reservation(reservation(2, 3), NOW)
        .expect("reservation seeded");
    store
}

#[test]
fn every_precommit_fault_leaves_only_the_reservation() {
    let faults = [
        CommitFault::AfterReservationCheck,
        CommitFault::AfterReplayCheck,
        CommitFault::AfterApprovalStaging,
        CommitFault::AfterMlsStaging,
        CommitFault::AfterOutboxStaging,
    ];

    for fault in faults {
        let mut store = seeded_store();
        assert_eq!(
            store.commit_with_fault(&commit(10, 2, 3), NOW, fault),
            Err(TransactionError::InjectedFailure)
        );
        assert_eq!(
            store.invitation_state(&[1; 16]),
            Some(InvitationState::Reserved)
        );
        assert_eq!(store.recover(&[10; 16]), None);
        assert_eq!(store.committed_count(), 0);
    }
}

#[test]
fn lost_commit_response_recovers_one_complete_commit() {
    let mut store = seeded_store();
    let input = commit(10, 2, 3);

    assert_eq!(
        store.commit_with_fault(&input, NOW, CommitFault::AfterCommit),
        Err(TransactionError::OutcomeUnknown)
    );
    assert_eq!(
        store.invitation_state(&[1; 16]),
        Some(InvitationState::Consumed)
    );
    assert_eq!(store.committed_count(), 1);
    let recovered = store.recover(&[10; 16]).expect("commit is recoverable");
    assert_eq!(recovered.epoch_after, 8);
    assert_eq!(recovered.outbox_state, OutboxState::Pending);
    assert_eq!(recovered.delivery_attempts, 0);
    assert_eq!(
        store.commit_with_fault(&input, NOW, CommitFault::None),
        Ok(CommitOutcome::AlreadyCommitted)
    );
    assert_eq!(store.committed_count(), 1);
}

#[test]
fn conflicting_retry_and_stale_generation_fail_closed() {
    let mut store = seeded_store();
    let exact = commit(10, 2, 3);
    assert_eq!(
        store.commit_with_fault(&exact, NOW, CommitFault::None),
        Ok(CommitOutcome::Committed)
    );

    let conflict = InviterJoinCommit::new(
        [10; 16],
        [1; 16],
        [2; 64],
        [3; 16],
        [99; 32],
        vec![5; 16],
        7,
        8,
        vec![6; 32],
        vec![7; 512],
        canonical_welcome(NOW + 180),
        canonical_endpoint(NOW + 240),
        NOW + 120,
    );
    assert_eq!(
        store.commit_with_fault(&conflict, NOW, CommitFault::None),
        Err(TransactionError::Conflict)
    );

    let mut fresh_store = InMemoryInviterJoinStore::new(policy(4));
    let expiring =
        ReservedInvitation::new([1; 16], [2; 64], [3; 16], NOW + 1).expect("expiring reservation");
    fresh_store
        .seed_reservation(expiring, NOW)
        .expect("old generation seeded");
    assert_eq!(
        fresh_store.seed_reservation(
            ReservedInvitation::new([1; 16], [2; 64], [3; 16], NOW + 300)
                .expect("same-generation reissue input"),
            NOW + 1,
        ),
        Err(TransactionError::Conflict)
    );
    fresh_store
        .seed_reservation(reservation(44, 3), NOW + 1)
        .expect("same IDs reissued under a new generation");
    assert_eq!(
        fresh_store.commit_with_fault(&commit(11, 2, 3), NOW + 1, CommitFault::None),
        Err(TransactionError::ReservationMismatch)
    );
    assert_eq!(
        fresh_store.invitation_state(&[1; 16]),
        Some(InvitationState::Reserved)
    );

    let mut replay_store = InMemoryInviterJoinStore::new(policy(4));
    replay_store
        .seed_reservation(reservation(2, 3), NOW)
        .expect("first reservation");
    replay_store
        .seed_reservation(
            ReservedInvitation::new([50; 16], [51; 64], [3; 16], NOW + 300)
                .expect("second reservation"),
            NOW,
        )
        .expect("duplicate request is detected at commit");
    replay_store
        .commit_with_fault(&commit(10, 2, 3), NOW, CommitFault::None)
        .expect("first request commits");
    let duplicate_request = InviterJoinCommit::new(
        [52; 16],
        [50; 16],
        [51; 64],
        [3; 16],
        [53; 32],
        vec![54],
        1,
        2,
        vec![55],
        vec![56],
        canonical_welcome(NOW + 180),
        canonical_endpoint(NOW + 240),
        NOW + 120,
    );
    assert_eq!(
        replay_store.commit_with_fault(&duplicate_request, NOW, CommitFault::None),
        Err(TransactionError::Conflict)
    );
}

#[test]
fn delivery_failure_and_expired_lease_preserve_atomic_commit() {
    let mut store = seeded_store();
    store
        .commit_with_fault(&commit(10, 2, 3), NOW, CommitFault::None)
        .expect("commit succeeds");
    assert_eq!(store.pending_transaction_ids(NOW), vec![[10; 16]]);

    let lease = store
        .lease_delivery([10; 16], NOW, 10)
        .expect("lease succeeds");
    assert!(store.pending_transaction_ids(NOW + 1).is_empty());
    let payload = store
        .delivery_payload(&lease, NOW + 1)
        .expect("payload available");
    assert_eq!(payload.welcome_envelope, canonical_welcome(NOW + 180));
    assert_eq!(payload.deposit_endpoint, canonical_endpoint(NOW + 240));
    store.fail_delivery(&lease).expect("failure returns item");
    assert_eq!(
        store.recover(&[10; 16]).expect("record").outbox_state,
        OutboxState::Pending
    );

    let expired = store
        .lease_delivery([10; 16], NOW + 2, 10)
        .expect("second lease succeeds");
    assert_eq!(
        store.delivery_payload(&expired, NOW + 12).err(),
        Some(TransactionError::LeaseMismatch)
    );
    assert_eq!(
        store.complete_delivery(&expired, NOW + 12),
        Err(TransactionError::LeaseMismatch)
    );
    assert_eq!(store.pending_transaction_ids(NOW + 12), vec![[10; 16]]);
    let replacement = store
        .lease_delivery([10; 16], NOW + 12, 10)
        .expect("expired lease can be replaced");
    store
        .complete_delivery(&replacement, NOW + 13)
        .expect("delivery completes");
    store
        .complete_delivery(&replacement, NOW + 13)
        .expect("duplicate success is idempotent");

    let view = store.recover(&[10; 16]).expect("record remains");
    assert_eq!(view.outbox_state, OutboxState::Delivered);
    assert_eq!(view.delivery_attempts, 3);
    assert!(store.pending_transaction_ids(NOW + 13).is_empty());
    assert_eq!(
        store.invitation_state(&[1; 16]),
        Some(InvitationState::Consumed)
    );
    assert_eq!(store.committed_count(), 1);
}

#[test]
fn bounds_capacity_and_attempt_limits_fail_closed() {
    assert_eq!(
        TransactionPolicy::new(0, 1, 1, 1, 1, 1, 1, 1),
        Err(TransactionError::InvalidInput)
    );
    assert_eq!(
        TransactionPolicy::new(1, 256, 1, 1, 1, 1, 1, 1),
        Err(TransactionError::InvalidInput)
    );

    let mut store = seeded_store();
    let invalid_sizes = [
        (0, 1, 1, 1, 1),
        (256, 1, 1, 1, 1),
        (1, 0, 1, 1, 1),
        (1, 4_097, 1, 1, 1),
        (1, 1, 0, 1, 1),
        (1, 1, 2_097_153, 1, 1),
        (1, 1, 1, 0, 1),
        (1, 1, 1, 65_537, 1),
        (1, 1, 1, 1, 0),
        (1, 1, 1, 1, 4_097),
    ];
    for (group, approval, mls, welcome, endpoint) in invalid_sizes {
        let invalid = sized_commit(
            10,
            2,
            3,
            group,
            approval,
            mls,
            welcome,
            endpoint,
            7,
            8,
            NOW + 120,
        );
        assert_eq!(
            store.commit_with_fault(&invalid, NOW, CommitFault::None),
            Err(TransactionError::InvalidInput)
        );
    }
    let invalid_epoch = sized_commit(10, 2, 3, 1, 1, 1, 1, 1, u64::MAX, 0, NOW + 120);
    assert_eq!(
        store.commit_with_fault(&invalid_epoch, NOW, CommitFault::None),
        Err(TransactionError::InvalidInput)
    );
    let expired_outbox = commit_with_delivery_material(
        10,
        2,
        3,
        canonical_welcome(NOW + 180),
        canonical_endpoint(NOW + 240),
        NOW,
    );
    assert_eq!(
        store.commit_with_fault(&expired_outbox, NOW, CommitFault::None),
        Err(TransactionError::Expired)
    );
    assert_eq!(
        store.invitation_state(&[1; 16]),
        Some(InvitationState::Reserved)
    );

    store
        .commit_with_fault(&commit(10, 2, 3), NOW, CommitFault::None)
        .expect("valid commit");
    for attempt in 0..3_u8 {
        let lease = store
            .lease_delivery([10; 16], NOW + u64::from(attempt), 1)
            .expect("bounded attempt");
        store.fail_delivery(&lease).expect("return pending");
    }
    assert!(store.pending_transaction_ids(NOW + 4).is_empty());
    assert_eq!(
        store
            .recover(&[10; 16])
            .expect("record retained")
            .outbox_state,
        OutboxState::AttemptsExhausted
    );
    assert_eq!(
        store.lease_delivery([10; 16], NOW + 4, 1).err(),
        Some(TransactionError::AttemptsExhausted)
    );

    let mut capacity_store = InMemoryInviterJoinStore::new(policy(1));
    capacity_store
        .seed_reservation(reservation(2, 3), NOW)
        .expect("reservation seeded");
    capacity_store
        .commit_with_fault(&commit(10, 2, 3), NOW, CommitFault::None)
        .expect("first commit");
    let second_reservation = ReservedInvitation::new([11; 16], [12; 64], [13; 16], NOW + 300)
        .expect("second reservation");
    capacity_store
        .seed_reservation(second_reservation, NOW)
        .expect("reservation may be staged");
    let second = InviterJoinCommit::new(
        [14; 16],
        [11; 16],
        [12; 64],
        [13; 16],
        [15; 32],
        vec![16],
        1,
        2,
        vec![17],
        vec![18],
        canonical_welcome(NOW + 180),
        canonical_endpoint(NOW + 240),
        NOW + 120,
    );
    assert_eq!(
        capacity_store.commit_with_fault(&second, NOW, CommitFault::None),
        Err(TransactionError::CapacityExceeded)
    );
    assert_eq!(
        capacity_store.invitation_state(&[11; 16]),
        Some(InvitationState::Reserved)
    );
}

#[test]
fn stale_and_foreign_leases_cannot_complete_current_work() {
    let mut store = seeded_store();
    store
        .commit_with_fault(&commit(10, 2, 3), NOW, CommitFault::None)
        .expect("commit succeeds");

    let stale = store.lease_delivery([10; 16], NOW, 1).expect("first lease");
    store.fail_delivery(&stale).expect("release first lease");
    let current = store
        .lease_delivery([10; 16], NOW + 1, 10)
        .expect("replacement lease");
    assert_eq!(
        store.complete_delivery(&stale, NOW + 2),
        Err(TransactionError::LeaseMismatch)
    );

    let mut foreign_store = seeded_store();
    foreign_store
        .commit_with_fault(&commit(10, 2, 3), NOW, CommitFault::None)
        .expect("foreign commit succeeds");
    let foreign = foreign_store
        .lease_delivery([10; 16], NOW, 10)
        .expect("foreign lease");
    assert_eq!(
        store.complete_delivery(&foreign, NOW + 2),
        Err(TransactionError::LeaseMismatch)
    );
    store
        .complete_delivery(&current, NOW + 2)
        .expect("exact current lease completes");
}

#[test]
fn commit_rejects_invalid_delivery_material_and_expiry_scope() {
    let mut noncanonical_welcome = canonical_welcome(NOW + 180);
    noncanonical_welcome.push(0);
    let zero_id_welcome = OpaqueEnvelope::new([0; 16], NOW + 180, vec![8])
        .expect("protocol object")
        .encode_canonical()
        .expect("canonical protocol bytes");
    let cases = [
        commit_with_delivery_material(
            10,
            2,
            3,
            vec![0xff],
            canonical_endpoint(NOW + 240),
            NOW + 120,
        ),
        commit_with_delivery_material(
            10,
            2,
            3,
            noncanonical_welcome,
            canonical_endpoint(NOW + 240),
            NOW + 120,
        ),
        commit_with_delivery_material(
            10,
            2,
            3,
            zero_id_welcome,
            canonical_endpoint(NOW + 240),
            NOW + 120,
        ),
        commit_with_delivery_material(
            10,
            2,
            3,
            canonical_welcome(NOW + 180),
            vec![0xff],
            NOW + 120,
        ),
        commit_with_delivery_material(
            10,
            2,
            3,
            canonical_welcome(NOW + 110),
            canonical_endpoint(NOW + 240),
            NOW + 120,
        ),
        commit_with_delivery_material(
            10,
            2,
            3,
            canonical_welcome(NOW + 250),
            canonical_endpoint(NOW + 240),
            NOW + 120,
        ),
    ];

    for invalid in cases {
        let mut store = seeded_store();
        assert_eq!(
            store.commit_with_fault(&invalid, NOW, CommitFault::None),
            Err(TransactionError::InvalidInput)
        );
        assert_eq!(
            store.invitation_state(&[1; 16]),
            Some(InvitationState::Reserved)
        );
        assert_eq!(store.committed_count(), 0);
    }
}
