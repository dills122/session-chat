use session_protocol::OpaqueEnvelope;
use session_transport::{LocalMailboxPolicy, LocalMemoryWelcomeTransport, LocalTransportError};

const NOW: u64 = 1_700_000_000;

fn test_transport(capacity: usize) -> LocalMemoryWelcomeTransport {
    LocalMemoryWelcomeTransport::new(
        LocalMailboxPolicy::new(300, capacity).expect("valid mailbox policy"),
    )
    .expect("create local transport")
}

fn envelope(id: u8, ciphertext: u8, expires_at: u64) -> OpaqueEnvelope {
    OpaqueEnvelope::new([id; 16], expires_at, vec![ciphertext; 32])
        .expect("bounded opaque envelope")
}

#[test]
fn one_mailbox_uses_distinct_deposit_receive_and_acknowledgement_authorities() {
    let mut transport = test_transport(2);
    let mailbox = transport
        .create_welcome_mailbox(NOW + 120, NOW)
        .expect("create bounded mailbox");
    let (deposit, receive, acknowledgement) = mailbox.into_parts();
    let expected = envelope(0x11, 0x21, NOW + 60);

    let delivery_id = transport
        .deposit(&deposit, expected.clone(), NOW)
        .expect("deposit with sender authority");
    let received = transport
        .receive(&receive, NOW)
        .expect("receive with joiner authority")
        .expect("one envelope is retained");
    assert_eq!(received.delivery_id(), &delivery_id);
    assert_eq!(received.envelope(), &expected);

    transport
        .acknowledge(&acknowledgement, delivery_id, NOW)
        .expect("separate acknowledgement authority deletes delivery");
    assert!(
        transport
            .receive(&receive, NOW)
            .expect("mailbox remains readable")
            .is_none()
    );
}

#[test]
fn exact_retry_is_idempotent_and_never_resurrects_an_acknowledged_welcome() {
    let mut transport = test_transport(1);
    let (deposit, receive, acknowledgement) = transport
        .create_welcome_mailbox(NOW + 120, NOW)
        .expect("create mailbox")
        .into_parts();
    let welcome = envelope(0x31, 0x41, NOW + 60);
    let first = transport
        .deposit(&deposit, welcome.clone(), NOW)
        .expect("first deposit succeeds");
    let retry = transport
        .deposit(&deposit, welcome.clone(), NOW)
        .expect("exact retry succeeds");
    assert_eq!(retry, first);

    transport
        .acknowledge(&acknowledgement, first, NOW)
        .expect("acknowledge once");
    transport
        .acknowledge(&acknowledgement, first, NOW)
        .expect("acknowledgement retry is idempotent");
    assert_eq!(
        transport
            .deposit(&deposit, welcome, NOW)
            .expect("deposit retry remains idempotent after acknowledgement"),
        first
    );
    assert!(
        transport
            .receive(&receive, NOW)
            .expect("mailbox remains readable")
            .is_none()
    );
}

#[test]
fn a_different_second_envelope_is_rejected_without_replacement() {
    let mut transport = test_transport(1);
    let (deposit, receive, _) = transport
        .create_welcome_mailbox(NOW + 120, NOW)
        .expect("create mailbox")
        .into_parts();
    let first = envelope(0x51, 0x61, NOW + 60);
    let changed_same_id = envelope(0x51, 0x62, NOW + 60);
    let different_id = envelope(0x52, 0x63, NOW + 60);
    transport
        .deposit(&deposit, first.clone(), NOW)
        .expect("first deposit succeeds");

    assert_eq!(
        transport.deposit(&deposit, changed_same_id, NOW),
        Err(LocalTransportError::Rejected)
    );
    assert_eq!(
        transport.deposit(&deposit, different_id, NOW),
        Err(LocalTransportError::Rejected)
    );
    assert_eq!(
        transport
            .receive(&receive, NOW)
            .expect("receive original")
            .expect("original remains")
            .envelope(),
        &first
    );
}

#[test]
fn foreign_or_expired_authority_cannot_mutate_another_mailbox() {
    let mut transport = test_transport(2);
    let (deposit_a, receive_a, acknowledgement_a) = transport
        .create_welcome_mailbox(NOW + 120, NOW)
        .expect("create mailbox A")
        .into_parts();
    let (_, receive_b, acknowledgement_b) = transport
        .create_welcome_mailbox(NOW + 120, NOW)
        .expect("create mailbox B")
        .into_parts();
    let welcome = envelope(0x71, 0x72, NOW + 60);
    let mut foreign_transport = test_transport(1);
    let (foreign_deposit, _, _) = foreign_transport
        .create_welcome_mailbox(NOW + 120, NOW)
        .expect("create foreign mailbox")
        .into_parts();

    assert_eq!(
        transport.deposit(&foreign_deposit, welcome.clone(), NOW),
        Err(LocalTransportError::Rejected)
    );
    let delivery = transport
        .deposit(&deposit_a, welcome.clone(), NOW)
        .expect("deposit into A");

    assert!(
        transport
            .receive(&receive_b, NOW)
            .expect("B remains readable")
            .is_none()
    );
    assert_eq!(
        transport.acknowledge(&acknowledgement_b, delivery, NOW),
        Err(LocalTransportError::Rejected)
    );
    assert_eq!(
        transport
            .receive(&receive_a, NOW)
            .expect("A remains readable")
            .expect("A delivery remains")
            .envelope(),
        &welcome
    );
    assert_eq!(
        transport.acknowledge(&acknowledgement_a, delivery, NOW + 120),
        Err(LocalTransportError::Rejected)
    );
}

#[test]
fn mailbox_and_envelope_bounds_fail_before_storage_mutation() {
    assert_eq!(
        LocalMailboxPolicy::new(0, 1),
        Err(LocalTransportError::InvalidPolicy)
    );
    assert_eq!(
        LocalMailboxPolicy::new(300, 0),
        Err(LocalTransportError::InvalidPolicy)
    );
    let mut transport = test_transport(1);
    assert!(matches!(
        transport.create_welcome_mailbox(NOW + 301, NOW),
        Err(LocalTransportError::Rejected)
    ));
    assert_eq!(transport.mailbox_count(), 0);
    let (deposit, receive, _) = transport
        .create_welcome_mailbox(NOW + 120, NOW)
        .expect("create bounded mailbox")
        .into_parts();

    assert_eq!(
        transport.deposit(&deposit, envelope(0x81, 0x82, NOW), NOW),
        Err(LocalTransportError::Rejected)
    );
    assert_eq!(
        transport.deposit(&deposit, envelope(0x83, 0x84, NOW + 121), NOW),
        Err(LocalTransportError::Rejected)
    );
    assert!(
        transport
            .receive(&receive, NOW)
            .expect("mailbox remains readable")
            .is_none()
    );
    assert!(matches!(
        transport.create_welcome_mailbox(NOW + 120, NOW),
        Err(LocalTransportError::CapacityExceeded)
    ));
}
