use std::collections::BTreeSet;

use session_inviter_transaction::{
    CommitFault, InMemoryInviterJoinStore, InvitationState, InviterJoinCommit, OutboxState,
    ReservedInvitation, TransactionError, TransactionPolicy,
};
use session_protocol::{LocalWelcomeDepositEndpoint, OpaqueEnvelope};
use session_transport::{
    DeliveryId, LocalMailboxPolicy, LocalMemoryWelcomeTransport,
    LocalWelcomeAcknowledgementCapability, LocalWelcomeReceiveCapability,
};

const NOW: u64 = 1_700_000_000;
const TRANSACTION_ID: [u8; 16] = [10; 16];
const INVITATION_ID: [u8; 16] = [1; 16];
const MAX_ATTEMPTS: u32 = 3;
const EXPECTED_SCHEDULES: usize = 27;

#[derive(Clone, Copy, Debug)]
enum AttemptOutcome {
    LostBeforeAcceptance,
    AcceptedAmbiguously,
    AcceptedAndRecorded,
}

const ATTEMPT_OUTCOMES: [AttemptOutcome; 3] = [
    AttemptOutcome::LostBeforeAcceptance,
    AttemptOutcome::AcceptedAmbiguously,
    AttemptOutcome::AcceptedAndRecorded,
];

fn policy(maximum_delivery_attempts: u32) -> TransactionPolicy {
    TransactionPolicy::new(
        4,
        255,
        4_096,
        2_097_152,
        65_536,
        4_096,
        maximum_delivery_attempts,
        60,
    )
    .expect("bounded transaction policy")
}

fn local_composition() -> (
    LocalMemoryWelcomeTransport,
    LocalWelcomeDepositEndpoint,
    LocalWelcomeReceiveCapability,
    LocalWelcomeAcknowledgementCapability,
) {
    let mut adapter =
        LocalMemoryWelcomeTransport::new(LocalMailboxPolicy::new(600, 1).expect("mailbox policy"))
            .expect("local adapter");
    let (deposit, receive, acknowledgement) = adapter
        .create_welcome_mailbox(NOW + 300, NOW)
        .expect("Welcome mailbox")
        .into_parts();
    (adapter, deposit, receive, acknowledgement)
}

fn seed_commit(
    store: &mut InMemoryInviterJoinStore,
    endpoint: &LocalWelcomeDepositEndpoint,
    outbox_expiry: u64,
    envelope_expiry: u64,
) {
    store
        .seed_reservation(
            ReservedInvitation::new(INVITATION_ID, [2; 64], [3; 16], NOW + 300)
                .expect("reservation"),
            NOW,
        )
        .expect("reservation seeded");
    let welcome = OpaqueEnvelope::new([8; 16], envelope_expiry, vec![9; 32])
        .expect("Welcome envelope")
        .encode_canonical()
        .expect("canonical Welcome");
    let commit = InviterJoinCommit::new(
        TRANSACTION_ID,
        INVITATION_ID,
        [2; 64],
        [3; 16],
        [4; 32],
        vec![5; 16],
        7,
        8,
        vec![6; 32],
        vec![7; 512],
        welcome,
        endpoint.encode_canonical().expect("canonical endpoint"),
        outbox_expiry,
    );
    store
        .commit_with_fault(&commit, NOW, CommitFault::None)
        .expect("atomic commit");
}

fn assert_membership_once(store: &InMemoryInviterJoinStore, case: &str) {
    assert_eq!(
        store.committed_count(),
        1,
        "{case}: no transport stage may repeat the membership commit"
    );
    assert_eq!(
        store.invitation_state(&INVITATION_ID),
        Some(InvitationState::Consumed),
        "{case}: delivery cannot reopen invitation authority"
    );
    assert_eq!(
        store
            .recover(&TRANSACTION_ID)
            .expect("committed transaction remains recoverable")
            .epoch_after,
        8,
        "{case}: delivery cannot repeat the MLS epoch transition"
    );
}

fn decode_delivery(
    store: &InMemoryInviterJoinStore,
    lease: &session_inviter_transaction::DeliveryLease,
    now: u64,
) -> (LocalWelcomeDepositEndpoint, OpaqueEnvelope) {
    let payload = store
        .delivery_payload(lease, now)
        .expect("live lease owns exact delivery material");
    (
        LocalWelcomeDepositEndpoint::decode_canonical(payload.deposit_endpoint)
            .expect("stored endpoint reconstructs"),
        OpaqueEnvelope::decode_canonical(payload.welcome_envelope)
            .expect("stored envelope reconstructs"),
    )
}

fn foreign_lease() -> (
    InMemoryInviterJoinStore,
    session_inviter_transaction::DeliveryLease,
) {
    let (_adapter, endpoint, _receive, _acknowledgement) = local_composition();
    let mut store = InMemoryInviterJoinStore::new(policy(MAX_ATTEMPTS));
    seed_commit(&mut store, &endpoint, NOW + 120, NOW + 180);
    let lease = store
        .lease_delivery(TRANSACTION_ID, NOW, 1)
        .expect("foreign lease");
    (store, lease)
}

#[test]
fn exhaustive_loss_ambiguity_delay_and_retry_schedules_never_repeat_membership() {
    let mut executed = 0;

    for first in ATTEMPT_OUTCOMES {
        for second in ATTEMPT_OUTCOMES {
            for third in ATTEMPT_OUTCOMES {
                let schedule = [first, second, third];
                let case = format!("case={executed} schedule={schedule:?}");
                let (mut adapter, endpoint, receive, acknowledgement) = local_composition();
                let mut store = InMemoryInviterJoinStore::new(policy(MAX_ATTEMPTS));
                seed_commit(&mut store, &endpoint, NOW + 120, NOW + 180);
                let mut now = NOW;
                let mut remote_receipt: Option<DeliveryId> = None;
                let mut stale_leases = Vec::new();
                let mut owner_recorded_acceptance = false;

                for outcome in schedule {
                    let lease = match store.lease_delivery(TRANSACTION_ID, now, 1) {
                        Ok(lease) => lease,
                        Err(TransactionError::AttemptsExhausted) => break,
                        Err(error) => panic!("{case}: unexpected lease failure: {error}"),
                    };
                    match outcome {
                        AttemptOutcome::LostBeforeAcceptance => {
                            store
                                .fail_delivery(&lease)
                                .expect("known loss returns exact lease to owner policy");
                        }
                        AttemptOutcome::AcceptedAmbiguously => {
                            let (deposit, welcome) = decode_delivery(&store, &lease, now);
                            let receipt = adapter
                                .deposit(&deposit, welcome, now)
                                .expect("adapter accepted before owner result was retained");
                            if let Some(prior) = remote_receipt {
                                assert!(
                                    receipt == prior,
                                    "{case}: ambiguous exact retries preserve receipt identity"
                                );
                            } else {
                                remote_receipt = Some(receipt);
                            }
                            stale_leases.push(lease);
                            now += 1;
                        }
                        AttemptOutcome::AcceptedAndRecorded => {
                            let (deposit, welcome) = decode_delivery(&store, &lease, now);
                            let receipt = adapter
                                .deposit(&deposit, welcome, now)
                                .expect("adapter accepted exact Welcome");
                            if let Some(prior) = remote_receipt {
                                assert!(
                                    receipt == prior,
                                    "{case}: recorded retry preserves receipt identity"
                                );
                            } else {
                                remote_receipt = Some(receipt);
                            }
                            store
                                .complete_delivery(&lease, now)
                                .expect("owner records only exact acceptance lease");
                            owner_recorded_acceptance = true;
                        }
                    }
                    assert_membership_once(&store, &case);
                    if owner_recorded_acceptance {
                        break;
                    }
                }

                if !owner_recorded_acceptance {
                    if matches!(
                        store
                            .recover(&TRANSACTION_ID)
                            .expect("transaction")
                            .outbox_state,
                        OutboxState::Leased
                    ) {
                        assert_eq!(
                            store.lease_delivery(TRANSACTION_ID, now, 1).err(),
                            Some(TransactionError::AttemptsExhausted),
                            "{case}: an expired final lease terminalizes at the attempt bound"
                        );
                    }
                    assert_eq!(
                        store
                            .recover(&TRANSACTION_ID)
                            .expect("transaction")
                            .outbox_state,
                        OutboxState::AttemptsExhausted,
                        "{case}: bounded loss/ambiguity cannot create unbounded retry"
                    );
                } else {
                    assert_eq!(
                        store
                            .recover(&TRANSACTION_ID)
                            .expect("transaction")
                            .outbox_state,
                        OutboxState::Delivered,
                        "{case}: only recorded adapter acceptance completes owner state"
                    );
                }
                assert!(
                    store.pending_transaction_ids(now).is_empty(),
                    "{case}: terminal owner work must be quiescent"
                );

                for stale in &stale_leases {
                    assert_eq!(
                        store.complete_delivery(stale, now),
                        Err(TransactionError::LeaseMismatch),
                        "{case}: delayed stale acceptance cannot overwrite current owner truth"
                    );
                }
                let (_foreign_store, foreign) = foreign_lease();
                assert_eq!(
                    store.complete_delivery(&foreign, now),
                    Err(TransactionError::LeaseMismatch),
                    "{case}: foreign owner authority cannot report delivery state"
                );
                assert_membership_once(&store, &case);

                let mut processed = BTreeSet::new();
                match remote_receipt {
                    Some(receipt) => {
                        let first = adapter
                            .receive(&receive, now)
                            .expect("receipt succeeds")
                            .expect("accepted Welcome is available");
                        let duplicate = adapter
                            .receive(&receive, now)
                            .expect("duplicate receipt succeeds")
                            .expect("unacknowledged Welcome remains available");
                        assert!(
                            first.delivery_id() == &receipt && duplicate.delivery_id() == &receipt,
                            "{case}: receipt identifies the one accepted delivery"
                        );
                        assert!(
                            processed.is_empty(),
                            "{case}: deposit acceptance and receipt are not application processing"
                        );
                        adapter
                            .acknowledge(&acknowledgement, receipt, now)
                            .expect("exact acknowledgement");
                        assert!(
                            processed.is_empty(),
                            "{case}: acknowledgement is not application processing"
                        );
                        processed.insert(*duplicate.envelope().envelope_id());
                        processed.insert(*first.envelope().envelope_id());
                        assert_eq!(
                            processed.len(),
                            1,
                            "{case}: duplicate/reordered application input applies once"
                        );
                    }
                    None => assert!(
                        adapter
                            .receive(&receive, now)
                            .expect("empty mailbox remains readable")
                            .is_none(),
                        "{case}: loss before acceptance creates no receipt"
                    ),
                }
                assert!(
                    adapter
                        .receive(&receive, now)
                        .expect("final mailbox observation")
                        .is_none(),
                    "{case}: acknowledgement or total loss reaches receiver quiescence"
                );
                assert_membership_once(&store, &case);
                executed += 1;
            }
        }
    }

    assert_eq!(executed, EXPECTED_SCHEDULES);
}

#[test]
fn expiry_after_ambiguous_acceptance_closes_owner_work_without_rollback() {
    let (mut adapter, endpoint, receive, acknowledgement) = local_composition();
    let mut store = InMemoryInviterJoinStore::new(policy(2));
    seed_commit(&mut store, &endpoint, NOW + 2, NOW + 3);

    let stale = store
        .lease_delivery(TRANSACTION_ID, NOW, 1)
        .expect("first bounded lease");
    let (deposit, welcome) = decode_delivery(&store, &stale, NOW);
    let receipt = adapter
        .deposit(&deposit, welcome, NOW)
        .expect("remote acceptance becomes ambiguous");

    let current = store
        .lease_delivery(TRANSACTION_ID, NOW + 1, 1)
        .expect("expired lease is replaced before outbox expiry");
    assert_eq!(
        store.complete_delivery(&stale, NOW + 1),
        Err(TransactionError::LeaseMismatch)
    );
    assert_eq!(
        store.complete_delivery(&current, NOW + 2),
        Err(TransactionError::LeaseMismatch),
        "outbox expiry rejects even an exact live lease result"
    );
    assert!(store.pending_transaction_ids(NOW + 2).is_empty());
    assert_membership_once(&store, "expiry-cut-point");

    let received = adapter
        .receive(&receive, NOW + 2)
        .expect("provider receipt remains independently observable")
        .expect("accepted envelope remains live until its own expiry");
    assert!(received.delivery_id() == &receipt);
    adapter
        .acknowledge(&acknowledgement, receipt, NOW + 2)
        .expect("receiver acknowledgement is independent of owner expiry");
    assert!(
        adapter
            .receive(&receive, NOW + 2)
            .expect("mailbox remains readable")
            .is_none()
    );
    assert_membership_once(&store, "expiry-cut-point");
}
