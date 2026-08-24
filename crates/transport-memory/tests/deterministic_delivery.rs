use session_protocol::OpaqueEnvelope;
use session_transport::EnvelopeTransport;
use transport_memory::{
    DeliveryAction, DeterministicMemoryTransport, MemoryMailboxPolicy, MemoryTransportError,
};

const NOW: u64 = 1_700_000_000;

fn envelope(id: u8, ciphertext: u8) -> OpaqueEnvelope {
    OpaqueEnvelope::new([id; 16], NOW + 120, vec![ciphertext; 32]).expect("bounded opaque envelope")
}

fn transport(
    mailbox_capacity: usize,
    envelope_capacity: usize,
    attempt_capacity: usize,
) -> DeterministicMemoryTransport {
    DeterministicMemoryTransport::new(
        MemoryMailboxPolicy::new(300, mailbox_capacity, envelope_capacity, attempt_capacity)
            .expect("valid deterministic policy"),
    )
    .expect("create deterministic memory transport")
}

#[test]
fn right_specific_contract_delivers_only_the_opaque_envelope() {
    let mut transport = transport(1, 2, 3);
    let (deposit, receive, acknowledgement) = transport
        .create_mailbox(NOW + 180, NOW)
        .expect("create mailbox")
        .into_parts();
    let expected = envelope(0x11, 0x21);

    let delivery_id = EnvelopeTransport::deposit(&mut transport, &deposit, expected.clone(), NOW)
        .expect("deposit through provider-neutral contract");
    let received = EnvelopeTransport::receive(&mut transport, &receive, NOW)
        .expect("receive with read-only authority")
        .expect("default action makes delivery visible");
    assert_eq!(received.delivery_id(), &delivery_id);
    assert_eq!(received.envelope(), &expected);

    EnvelopeTransport::acknowledge(&mut transport, &acknowledgement, delivery_id, NOW)
        .expect("acknowledge with separate authority");
    assert!(
        EnvelopeTransport::receive(&mut transport, &receive, NOW)
            .expect("mailbox remains readable")
            .is_none()
    );
}

#[test]
fn explicit_fault_plan_models_loss_retry_duplication_and_reordering() {
    let mut transport = transport(1, 4, 4);
    let (deposit, receive, acknowledgement) = transport
        .create_mailbox(NOW + 180, NOW)
        .expect("create mailbox")
        .into_parts();
    let first = envelope(0x31, 0x41);
    let second = envelope(0x32, 0x42);
    let lost = envelope(0x33, 0x43);

    transport
        .queue_action(DeliveryAction::Hold)
        .expect("hold first delivery");
    transport
        .queue_action(DeliveryAction::Duplicate)
        .expect("deliver two copies of second first");
    let first_id = transport
        .deposit(&deposit, first.clone(), NOW)
        .expect("hold first envelope");
    let second_id = transport
        .deposit(&deposit, second.clone(), NOW)
        .expect("make second envelope visible");

    let observed_second = transport
        .receive(&receive, NOW)
        .expect("read second")
        .expect("second is visible first");
    assert_eq!(observed_second.delivery_id(), &second_id);
    assert_eq!(observed_second.envelope(), &second);
    assert_eq!(
        transport
            .receive(&receive, NOW)
            .expect("read explicitly duplicated delivery")
            .expect("second scheduled copy remains visible")
            .delivery_id(),
        &second_id
    );
    transport
        .acknowledge(&acknowledgement, second_id, NOW)
        .expect("acknowledge second");

    transport
        .release_held(0, NOW)
        .expect("release first after second");
    assert_eq!(
        transport
            .receive(&receive, NOW)
            .expect("read reordered first")
            .expect("first is now visible")
            .delivery_id(),
        &first_id
    );
    transport
        .acknowledge(&acknowledgement, first_id, NOW)
        .expect("acknowledge first");

    transport
        .queue_action(DeliveryAction::Drop)
        .expect("drop next attempt");
    let lost_id = transport
        .deposit(&deposit, lost.clone(), NOW)
        .expect("transport accepts but drops attempt");
    assert!(
        transport
            .receive(&receive, NOW)
            .expect("mailbox remains readable")
            .is_none()
    );
    assert_eq!(
        transport
            .deposit(&deposit, lost, NOW)
            .expect("exact retry uses the same logical delivery"),
        lost_id
    );
    assert_eq!(
        transport
            .receive(&receive, NOW)
            .expect("read retried delivery")
            .expect("default action delivers retry")
            .delivery_id(),
        &lost_id
    );
}

#[test]
fn foreign_and_expired_authorities_leave_the_target_mailbox_unchanged() {
    let mut target = transport(1, 2, 2);
    let (target_deposit, target_receive, target_acknowledgement) = target
        .create_mailbox(NOW + 180, NOW)
        .expect("create target mailbox")
        .into_parts();
    let mut foreign = transport(1, 2, 2);
    let (foreign_deposit, foreign_receive, foreign_acknowledgement) = foreign
        .create_mailbox(NOW + 180, NOW)
        .expect("create foreign mailbox")
        .into_parts();
    let expected = envelope(0x41, 0x51);

    assert_eq!(
        target.deposit(&foreign_deposit, expected.clone(), NOW),
        Err(MemoryTransportError::Rejected)
    );
    let delivery_id = target
        .deposit(&target_deposit, expected.clone(), NOW)
        .expect("target deposit succeeds");
    assert_eq!(
        target.receive(&foreign_receive, NOW),
        Err(MemoryTransportError::Rejected)
    );
    assert_eq!(
        target.acknowledge(&foreign_acknowledgement, delivery_id, NOW),
        Err(MemoryTransportError::Rejected)
    );
    assert_eq!(
        target
            .receive(&target_receive, NOW)
            .expect("target remains readable")
            .expect("target delivery remains")
            .envelope(),
        &expected
    );
    assert_eq!(
        target.acknowledge(&target_acknowledgement, delivery_id, NOW + 180),
        Err(MemoryTransportError::Rejected)
    );
}

#[test]
fn invalid_held_release_does_not_consume_a_full_held_queue() {
    let mut transport = transport(1, 1, 2);
    let (deposit, receive, _) = transport
        .create_mailbox(NOW + 180, NOW)
        .expect("create mailbox")
        .into_parts();
    let held = envelope(0x49, 0x59);
    transport
        .queue_action(DeliveryAction::Hold)
        .expect("hold first attempt");
    transport
        .queue_action(DeliveryAction::Hold)
        .expect("hold exact retry");
    let delivery_id = transport
        .deposit(&deposit, held.clone(), NOW)
        .expect("hold first attempt");
    assert_eq!(
        transport
            .deposit(&deposit, held, NOW)
            .expect("hold second attempt"),
        delivery_id
    );

    assert_eq!(
        transport.release_held(2, NOW),
        Err(MemoryTransportError::Rejected)
    );
    assert_eq!(
        transport
            .release_held(0, NOW)
            .expect("valid held item remains releasable"),
        delivery_id
    );
    assert_eq!(
        transport
            .receive(&receive, NOW)
            .expect("read released item")
            .expect("released item is visible")
            .delivery_id(),
        &delivery_id
    );
}

#[test]
fn capacity_attempt_and_idempotency_bounds_fail_closed() {
    assert_eq!(
        MemoryMailboxPolicy::new(0, 1, 1, 1),
        Err(MemoryTransportError::InvalidPolicy)
    );
    assert_eq!(
        MemoryMailboxPolicy::new(60, 0, 1, 1),
        Err(MemoryTransportError::InvalidPolicy)
    );
    assert_eq!(
        MemoryMailboxPolicy::new(60, 1, 0, 1),
        Err(MemoryTransportError::InvalidPolicy)
    );
    assert_eq!(
        MemoryMailboxPolicy::new(60, 1, 1, 0),
        Err(MemoryTransportError::InvalidPolicy)
    );

    let mut transport = transport(1, 1, 2);
    let (deposit, receive, _) = transport
        .create_mailbox(NOW + 180, NOW)
        .expect("create bounded mailbox")
        .into_parts();
    let first = envelope(0x51, 0x61);
    let changed = envelope(0x51, 0x62);
    let other = envelope(0x52, 0x63);
    transport
        .queue_action(DeliveryAction::Drop)
        .expect("drop first attempt");
    let first_id = transport
        .deposit(&deposit, first.clone(), NOW)
        .expect("accept first attempt");

    assert_eq!(
        transport.deposit(&deposit, changed, NOW),
        Err(MemoryTransportError::Rejected)
    );
    assert_eq!(
        transport.deposit(&deposit, other, NOW),
        Err(MemoryTransportError::CapacityExceeded)
    );
    assert_eq!(
        transport
            .deposit(&deposit, first.clone(), NOW)
            .expect("second exact attempt is allowed"),
        first_id
    );
    assert_eq!(
        transport.deposit(&deposit, first, NOW),
        Err(MemoryTransportError::CapacityExceeded)
    );
    assert_eq!(
        transport
            .receive(&receive, NOW)
            .expect("read second attempt")
            .expect("second attempt delivered")
            .delivery_id(),
        &first_id
    );
}
