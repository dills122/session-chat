use std::collections::BTreeSet;

use session_protocol::OpaqueEnvelope;
use session_transport::{DeliveryId, EnvelopeTransport};
use transport_memory::{DeliveryAction, DeterministicMemoryTransport, MemoryMailboxPolicy};

const NOW: u64 = 1_700_000_000;
const ENVELOPES_PER_SCHEDULE: usize = 3;
const DELIVERY_ACTIONS: [DeliveryAction; 4] = [
    DeliveryAction::Deliver,
    DeliveryAction::Drop,
    DeliveryAction::Duplicate,
    DeliveryAction::Hold,
];
const EXPECTED_SCHEDULES: usize = 128;

#[derive(Clone, Copy, Debug)]
enum ReleaseOrder {
    OldestFirst,
    NewestFirst,
}

fn envelope(index: usize) -> OpaqueEnvelope {
    let id = u8::try_from(index + 1).expect("bounded fixture index");
    OpaqueEnvelope::new([id; 16], NOW + 120, vec![id + 0x40; 32]).expect("bounded opaque fixture")
}

fn drain_visible(
    transport: &mut DeterministicMemoryTransport,
    receive: &transport_memory::MemoryReceiveCapability,
    receipts: &[DeliveryId],
    processed: &mut BTreeSet<[u8; 16]>,
    case: &str,
) -> usize {
    let mut observations = 0;
    while let Some(received) = transport.receive(receive, NOW).expect("bounded receive") {
        assert!(
            receipts
                .iter()
                .any(|receipt| receipt == received.delivery_id()),
            "{case}: every observation must name an accepted receipt"
        );
        observations += 1;
        processed.insert(*received.envelope().envelope_id());
    }
    observations
}

#[test]
fn exhaustive_duplicate_reorder_loss_and_release_schedules_converge_once() {
    let mut executed = 0;

    for first in DELIVERY_ACTIONS {
        for second in DELIVERY_ACTIONS {
            for third in DELIVERY_ACTIONS {
                let schedule = [first, second, third];
                for release_order in [ReleaseOrder::OldestFirst, ReleaseOrder::NewestFirst] {
                    let case =
                        format!("case={executed} schedule={schedule:?} release={release_order:?}");
                    let mut transport = DeterministicMemoryTransport::new(
                        MemoryMailboxPolicy::new(300, 1, 3, 4).expect("bounded policy"),
                    )
                    .expect("memory transport");
                    let (deposit, receive, acknowledgement) = transport
                        .create_mailbox(NOW + 180, NOW)
                        .expect("bounded mailbox")
                        .into_parts();
                    let fixtures: Vec<_> = (0..ENVELOPES_PER_SCHEDULE).map(envelope).collect();
                    let mut receipts = Vec::with_capacity(ENVELOPES_PER_SCHEDULE);

                    for (action, fixture) in schedule.into_iter().zip(&fixtures) {
                        transport
                            .queue_action(action)
                            .expect("bounded delivery schedule");
                        receipts.push(
                            transport
                                .deposit(&deposit, fixture.clone(), NOW)
                                .expect("adapter accepts the scheduled deposit"),
                        );
                    }

                    let accepted = transport.conformance_snapshot();
                    assert_eq!(
                        accepted.live_envelopes(),
                        ENVELOPES_PER_SCHEDULE,
                        "{case}: acceptance retains one logical envelope per receipt"
                    );
                    assert_eq!(
                        receipts.len(),
                        ENVELOPES_PER_SCHEDULE,
                        "{case}: every accepted deposit returns a receipt"
                    );

                    let mut processed = BTreeSet::new();
                    let mut observations =
                        drain_visible(&mut transport, &receive, &receipts, &mut processed, &case);

                    let held = schedule
                        .iter()
                        .filter(|action| **action == DeliveryAction::Hold)
                        .count();
                    for remaining in (1..=held).rev() {
                        let index = match release_order {
                            ReleaseOrder::OldestFirst => 0,
                            ReleaseOrder::NewestFirst => remaining - 1,
                        };
                        transport
                            .release_held(index, NOW)
                            .expect("bounded held delivery remains releasable");
                    }
                    observations +=
                        drain_visible(&mut transport, &receive, &receipts, &mut processed, &case);

                    for (index, action) in schedule.iter().enumerate() {
                        if *action != DeliveryAction::Drop {
                            continue;
                        }
                        let retry_receipt = transport
                            .deposit(&deposit, fixtures[index].clone(), NOW)
                            .expect("exact retry releases a lost accepted attempt");
                        assert!(
                            retry_receipt == receipts[index],
                            "{case}: exact retry must preserve receipt identity"
                        );
                    }
                    observations +=
                        drain_visible(&mut transport, &receive, &receipts, &mut processed, &case);

                    assert!(
                        observations >= ENVELOPES_PER_SCHEDULE,
                        "{case}: every logical envelope must eventually be observed during drain"
                    );
                    assert_eq!(
                        processed.len(),
                        ENVELOPES_PER_SCHEDULE,
                        "{case}: duplicate observations must apply only once"
                    );
                    assert_eq!(
                        transport.conformance_snapshot().live_envelopes(),
                        ENVELOPES_PER_SCHEDULE,
                        "{case}: application processing is not acknowledgement"
                    );

                    for receipt in &receipts {
                        transport
                            .acknowledge(&acknowledgement, *receipt, NOW)
                            .expect("exact acknowledgement");
                    }
                    let quiescent = transport.conformance_snapshot();
                    assert_eq!(
                        quiescent.live_envelopes(),
                        0,
                        "{case}: acknowledgement clears provider-owned live state"
                    );
                    assert_eq!(
                        quiescent.visible_copies(),
                        0,
                        "{case}: no visible duplicate may remain"
                    );
                    assert_eq!(
                        quiescent.held_copies(),
                        0,
                        "{case}: no delayed copy may remain"
                    );
                    assert_eq!(
                        quiescent.queued_delivery_actions(),
                        0,
                        "{case}: the bounded schedule must be exhausted"
                    );
                    assert!(
                        transport
                            .receive(&receive, NOW)
                            .expect("quiescent mailbox remains readable")
                            .is_none(),
                        "{case}: acknowledged work must not reappear"
                    );
                    assert_eq!(
                        processed.len(),
                        ENVELOPES_PER_SCHEDULE,
                        "{case}: acknowledgement cannot repeat application processing"
                    );
                    executed += 1;
                }
            }
        }
    }

    assert_eq!(executed, EXPECTED_SCHEDULES);
}

#[test]
fn acknowledgement_and_application_processing_are_independent_transitions() {
    let mut transport = DeterministicMemoryTransport::new(
        MemoryMailboxPolicy::new(300, 1, 1, 2).expect("bounded policy"),
    )
    .expect("memory transport");
    let (deposit, receive, acknowledgement) = transport
        .create_mailbox(NOW + 180, NOW)
        .expect("bounded mailbox")
        .into_parts();
    transport
        .queue_action(DeliveryAction::Duplicate)
        .expect("one duplicate schedule");
    let receipt = transport
        .deposit(&deposit, envelope(0), NOW)
        .expect("adapter acceptance returns a receipt");

    let first = transport
        .receive(&receive, NOW)
        .expect("first receive")
        .expect("first duplicate copy");
    let second = transport
        .receive(&receive, NOW)
        .expect("second receive")
        .expect("second duplicate copy");
    let mut processed = BTreeSet::new();
    assert!(
        processed.is_empty(),
        "receipt and receive do not process content"
    );

    transport
        .acknowledge(&acknowledgement, receipt, NOW)
        .expect("acknowledgement succeeds independently");
    assert!(
        processed.is_empty(),
        "acknowledgement must not imply application processing"
    );

    processed.insert(*second.envelope().envelope_id());
    processed.insert(*first.envelope().envelope_id());
    assert_eq!(
        processed.len(),
        1,
        "reordered duplicate processing applies one logical transition"
    );
    assert_eq!(transport.conformance_snapshot().live_envelopes(), 0);
    assert!(
        transport
            .receive(&receive, NOW)
            .expect("mailbox remains readable")
            .is_none()
    );
}
