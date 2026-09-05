use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use minicbor::Encoder;
use session_protocol::OpaqueEnvelope;
use session_transport::{
    AcknowledgementRequest, BoundedDeliveryIds, CanonicalEnvelope, Cursor, DeliveryId,
    DepositRequest, DepositRight, DispatchControl, EnforcementModeV1, EnvelopeDelivery,
    OperationBudget, PollRequest, PollWait, RetryAdvice, TransportFailureCode, TransportProfileId,
    bind_fast_transport_v1,
};
use transport_conformance::{
    CONNECTED_DELIVERY_CONFORMANCE_REQUESTS_V1, run_connected_delivery_conformance_v1,
};
use transport_iroh::{
    FastMailboxPolicy, IrohFastDelivery, IrohFastEndpoint, IrohFastMailboxService,
    MAX_FAST_ENVELOPES_PER_MAILBOX, MAX_FAST_LIVE_MAILBOXES, MAX_FAST_MAILBOX_LIFETIME_SECONDS,
    MAX_FAST_RETAINED_BYTES_PER_MAILBOX,
};

const OPERATION_DURATION: Duration = Duration::from_secs(5);

struct LiveControl {
    wall_now_unix_seconds: u64,
}

impl DispatchControl for LiveControl {
    fn monotonic_now(&self) -> Instant {
        Instant::now()
    }

    fn wall_now_unix_seconds(&self) -> Option<u64> {
        Some(self.wall_now_unix_seconds)
    }

    fn is_cancelled(&self) -> bool {
        false
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs()
}

fn budget() -> OperationBudget {
    OperationBudget::new(Instant::now() + OPERATION_DURATION, 512 * 1024, 1)
        .expect("valid operation budget")
}

fn policy() -> FastMailboxPolicy {
    FastMailboxPolicy::new(
        MAX_FAST_MAILBOX_LIFETIME_SECONDS,
        MAX_FAST_LIVE_MAILBOXES,
        MAX_FAST_ENVELOPES_PER_MAILBOX,
        MAX_FAST_RETAINED_BYTES_PER_MAILBOX,
    )
    .expect("valid policy")
}

fn canonical(id: u8, ciphertext: u8, now: u64) -> Vec<u8> {
    canonical_with_expiry(id, ciphertext, now + 120)
}

fn canonical_with_expiry(id: u8, ciphertext: u8, expires_at_unix_seconds: u64) -> Vec<u8> {
    OpaqueEnvelope::new([id; 16], expires_at_unix_seconds, vec![ciphertext; 32])
        .and_then(|envelope| envelope.encode_canonical())
        .expect("canonical envelope")
}

fn wire_response(operation: u8, status: u16, payload: &[u8]) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(4)
        .and_then(|encoder| encoder.u16(1))
        .and_then(|encoder| encoder.u8(operation))
        .and_then(|encoder| encoder.u16(status))
        .and_then(|encoder| encoder.bytes(payload))
        .expect("encode response");
    encoder.into_writer()
}

fn deposit_request(bytes: &[u8]) -> DepositRequest {
    DepositRequest::new(
        CanonicalEnvelope::from_canonical_bytes(bytes.to_vec()).expect("validated envelope"),
        budget(),
    )
    .expect("deposit request")
}

fn poll_request(cursor: Option<Cursor>, maximum_envelopes: u16, maximum_bytes: u32) -> PollRequest {
    PollRequest::new(
        cursor,
        maximum_envelopes,
        maximum_bytes,
        PollWait::immediate(),
        budget(),
    )
    .expect("poll request")
}

fn acknowledgement_request(delivery_id: DeliveryId) -> AcknowledgementRequest {
    AcknowledgementRequest::new(
        BoundedDeliveryIds::new(vec![delivery_id]).expect("bounded acknowledgement set"),
        budget(),
    )
}

async fn assert_deposit_response_rejected(response: Vec<u8>, now: u64) {
    let host = IrohFastEndpoint::bind_loopback().await.expect("bind host");
    let host_id = host.id();
    let host_address = host.address();
    let mut service = IrohFastMailboxService::new(policy());
    let (deposit, _, _) = service
        .issue_mailbox(host_id, now + 300, now)
        .expect("issue online mailbox")
        .into_dispatch_parts();
    let (release_server, wait_for_client) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        let mut link = host
            .accept(
                None,
                OPERATION_DURATION,
                transport_iroh::MAX_FAST_FRAME_BYTES,
            )
            .await
            .expect("accept client");
        let _request = link
            .receive_frame(OPERATION_DURATION)
            .await
            .expect("receive deposit request");
        link.send_frame(&response, OPERATION_DURATION)
            .await
            .expect("send hostile response");
        let _ = wait_for_client.await;
    });
    let client_endpoint = IrohFastEndpoint::bind_loopback()
        .await
        .expect("bind client");
    let client_link = client_endpoint
        .connect_address(
            host_address,
            OPERATION_DURATION,
            transport_iroh::MAX_FAST_FRAME_BYTES,
        )
        .await
        .expect("connect client");
    let mut delivery = IrohFastDelivery::new(client_link).expect("bind exact Fast link limits");
    let result = delivery
        .deposit(
            &deposit,
            deposit_request(&canonical(0x41, 0x51, now)),
            &LiveControl {
                wall_now_unix_seconds: now,
            },
        )
        .await;
    let Err(failure) = result else {
        panic!("hostile deposit response must fail");
    };
    assert_eq!(failure.code(), TransportFailureCode::CorruptRemoteResponse);
    release_server.send(()).expect("release server task");
    server_task.await.expect("server task completes");
}

async fn assert_poll_payload_rejected(payload: Vec<u8>, now: u64) {
    let response = wire_response(2, 0, &payload);
    let host = IrohFastEndpoint::bind_loopback().await.expect("bind host");
    let host_id = host.id();
    let host_address = host.address();
    let mut service = IrohFastMailboxService::new(policy());
    let (_, receive, _) = service
        .issue_mailbox(host_id, now + 300, now)
        .expect("issue online mailbox")
        .into_dispatch_parts();
    let (release_server, wait_for_client) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        let mut link = host
            .accept(
                None,
                OPERATION_DURATION,
                transport_iroh::MAX_FAST_FRAME_BYTES,
            )
            .await
            .expect("accept client");
        let _request = link
            .receive_frame(OPERATION_DURATION)
            .await
            .expect("receive poll request");
        link.send_frame(&response, OPERATION_DURATION)
            .await
            .expect("send hostile response");
        let _ = wait_for_client.await;
    });
    let client_endpoint = IrohFastEndpoint::bind_loopback()
        .await
        .expect("bind client");
    let client_link = client_endpoint
        .connect_address(
            host_address,
            OPERATION_DURATION,
            transport_iroh::MAX_FAST_FRAME_BYTES,
        )
        .await
        .expect("connect client");
    let mut delivery = IrohFastDelivery::new(client_link).expect("bind exact Fast link limits");
    let result = delivery
        .poll(
            &receive,
            poll_request(None, 2, 64 * 1024),
            &LiveControl {
                wall_now_unix_seconds: now,
            },
        )
        .await;
    let Err(failure) = result else {
        panic!("hostile poll payload must fail");
    };
    assert_eq!(failure.code(), TransportFailureCode::CorruptRemoteResponse);
    release_server.send(()).expect("release server task");
    server_task.await.expect("server task completes");
}

async fn assert_wire_request_rejected(request: Vec<u8>) {
    let host = IrohFastEndpoint::bind_loopback().await.expect("bind host");
    let host_address = host.address();
    let service = IrohFastMailboxService::new(policy());
    let server_task = tokio::spawn(async move {
        let link = host
            .accept(
                None,
                OPERATION_DURATION,
                transport_iroh::MAX_FAST_FRAME_BYTES,
            )
            .await
            .expect("accept client");
        service.serve_requests(link, 1, OPERATION_DURATION).await
    });
    let client_endpoint = IrohFastEndpoint::bind_loopback()
        .await
        .expect("bind client");
    let mut client_link = client_endpoint
        .connect_address(
            host_address,
            OPERATION_DURATION,
            transport_iroh::MAX_FAST_FRAME_BYTES,
        )
        .await
        .expect("connect client");
    client_link
        .send_frame(&request, OPERATION_DURATION)
        .await
        .expect("send hostile request");
    assert!(matches!(
        server_task.await.expect("server task completes"),
        Err(transport_iroh::IrohFastError::FrameRejected)
    ));
}

fn encoded_wire_request(
    version: u16,
    operation: u8,
    mailbox_id: &[u8],
    secret: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(5)
        .and_then(|encoder| encoder.u16(version))
        .and_then(|encoder| encoder.u8(operation))
        .and_then(|encoder| encoder.bytes(mailbox_id))
        .and_then(|encoder| encoder.bytes(secret))
        .and_then(|encoder| encoder.bytes(payload))
        .expect("encode hostile request fixture");
    encoder.into_writer()
}

#[test]
fn adapter_manifest_binds_only_the_disclosed_fast_profile() {
    assert!(matches!(
        FastMailboxPolicy::new(0, 1, 1, 1),
        Err(transport_iroh::IrohFastError::InvalidBound)
    ));
    assert!(matches!(
        FastMailboxPolicy::new(MAX_FAST_MAILBOX_LIFETIME_SECONDS + 1, 1, 1, 1),
        Err(transport_iroh::IrohFastError::InvalidBound)
    ));
    assert!(matches!(
        FastMailboxPolicy::new(1, 0, 1, 1),
        Err(transport_iroh::IrohFastError::InvalidBound)
    ));
    assert!(matches!(
        FastMailboxPolicy::new(1, MAX_FAST_LIVE_MAILBOXES + 1, 1, 1),
        Err(transport_iroh::IrohFastError::InvalidBound)
    ));
    assert!(matches!(
        FastMailboxPolicy::new(1, 1, 0, 1),
        Err(transport_iroh::IrohFastError::InvalidBound)
    ));
    assert!(matches!(
        FastMailboxPolicy::new(1, 1, MAX_FAST_ENVELOPES_PER_MAILBOX + 1, 1),
        Err(transport_iroh::IrohFastError::InvalidBound)
    ));
    assert!(matches!(
        FastMailboxPolicy::new(1, 1, 1, 0),
        Err(transport_iroh::IrohFastError::InvalidBound)
    ));
    assert!(matches!(
        FastMailboxPolicy::new(1, 1, 1, MAX_FAST_RETAINED_BYTES_PER_MAILBOX + 1),
        Err(transport_iroh::IrohFastError::InvalidBound)
    ));

    let manifest = IrohFastDelivery::manifest().expect("valid adapter manifest");
    let binding =
        bind_fast_transport_v1(manifest, [0x51; 32], 1_700_000_000).expect("bind Fast adapter");
    assert_eq!(binding.profile(), TransportProfileId::FastV1);
    assert_eq!(
        binding.enforcement(),
        EnforcementModeV1::InProcessAmbientNetwork
    );
    assert_eq!(
        binding.adapter_id().as_str(),
        "session-chat.adapter.iroh-fast.v1"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_loopback_uses_the_common_delivery_contract() {
    let now = unix_now();
    let host = IrohFastEndpoint::bind_loopback().await.expect("bind host");
    let host_id = host.id();
    let host_address = host.address();
    let mut service = IrohFastMailboxService::new(policy());
    let (deposit, receive, acknowledgement) = service
        .issue_mailbox(host_id, now + 300, now)
        .expect("issue online mailbox")
        .into_dispatch_parts();

    let service_task = tokio::spawn(async move {
        let server_link = host
            .accept(
                None,
                OPERATION_DURATION,
                transport_iroh::MAX_FAST_FRAME_BYTES,
            )
            .await
            .expect("accept client");
        service
            .serve_requests(
                server_link,
                CONNECTED_DELIVERY_CONFORMANCE_REQUESTS_V1,
                OPERATION_DURATION,
            )
            .await
    });
    let client_endpoint = IrohFastEndpoint::bind_loopback()
        .await
        .expect("bind client");
    let client_link = client_endpoint
        .connect_address(
            host_address,
            OPERATION_DURATION,
            transport_iroh::MAX_FAST_FRAME_BYTES,
        )
        .await
        .expect("connect client");
    let mut delivery = IrohFastDelivery::new(client_link).expect("bind exact Fast link limits");
    let control = LiveControl {
        wall_now_unix_seconds: now,
    };

    run_connected_delivery_conformance_v1(
        &mut delivery,
        &deposit,
        &receive,
        &acknowledgement,
        now,
        &control,
        budget,
    )
    .await
    .expect("Iroh adapter passes shared delivery case");

    let (client_close, server_result) =
        tokio::join!(delivery.close(OPERATION_DURATION), service_task,);
    client_close.expect("client closes cleanly");
    server_result
        .expect("service task completes")
        .expect("service closes cleanly");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connected_mailbox_enforces_queue_cursor_and_acknowledgement_boundaries() {
    const REQUESTS: usize = 16;

    let now = unix_now();
    let host = IrohFastEndpoint::bind_loopback().await.expect("bind host");
    let host_id = host.id();
    let host_address = host.address();
    let mut service = IrohFastMailboxService::new(
        FastMailboxPolicy::new(300, 1, 2, 4_096).expect("small bounded policy"),
    );
    assert!(matches!(
        service.issue_mailbox(host_id, now, now),
        Err(transport_iroh::IrohFastError::InvalidBound)
    ));
    let (deposit, receive, acknowledgement) = service
        .issue_mailbox(host_id, now + 300, now)
        .expect("issue online mailbox")
        .into_dispatch_parts();
    assert!(matches!(
        service.issue_mailbox(host_id, now + 300, now),
        Err(transport_iroh::IrohFastError::EndpointUnavailable)
    ));
    let mut orphan_service = IrohFastMailboxService::new(policy());
    let (orphan_deposit, _, _) = orphan_service
        .issue_mailbox(host_id, now + 300, now)
        .expect("issue authority unknown to serving state")
        .into_dispatch_parts();
    let cloned_deposit = DepositRight::from_provider(deposit.provider().clone());

    let service_task = tokio::spawn(async move {
        let server_link = host
            .accept(
                None,
                OPERATION_DURATION,
                transport_iroh::MAX_FAST_FRAME_BYTES,
            )
            .await
            .expect("accept client");
        service
            .serve_requests(server_link, REQUESTS, OPERATION_DURATION)
            .await
    });
    let client_endpoint = IrohFastEndpoint::bind_loopback()
        .await
        .expect("bind client");
    let client_link = client_endpoint
        .connect_address(
            host_address,
            OPERATION_DURATION,
            transport_iroh::MAX_FAST_FRAME_BYTES,
        )
        .await
        .expect("connect client");
    let mut delivery = IrohFastDelivery::new(client_link).expect("bind exact Fast link limits");
    let control = LiveControl {
        wall_now_unix_seconds: now,
    };
    let first_bytes = canonical(0x71, 0x81, now);
    let second_bytes = canonical(0x72, 0x82, now);

    let unknown_authority = delivery
        .deposit(&orphan_deposit, deposit_request(&first_bytes), &control)
        .await;
    let Err(unknown_authority) = unknown_authority else {
        panic!("mailbox absent from serving state must fail");
    };
    assert_eq!(
        unknown_authority.code(),
        TransportFailureCode::InvalidAuthority
    );

    let earlier_control = LiveControl {
        wall_now_unix_seconds: now - 2,
    };
    let expired_remotely = delivery
        .deposit(
            &deposit,
            deposit_request(&canonical_with_expiry(0x70, 0x80, now - 1)),
            &earlier_control,
        )
        .await;
    let Err(expired_remotely) = expired_remotely else {
        panic!("service wall clock must reject an expired envelope");
    };
    assert_eq!(
        expired_remotely.code(),
        TransportFailureCode::ExpiredEnvelope
    );

    let first = delivery
        .deposit(&deposit, deposit_request(&first_bytes), &control)
        .await
        .expect("first deposit");
    let first_id = *first.delivery_id();
    let second = delivery
        .deposit(&cloned_deposit, deposit_request(&second_bytes), &control)
        .await
        .expect("deposit through transferred cloneable right");
    let second_id = *second.delivery_id();

    let retry = delivery
        .deposit(&deposit, deposit_request(&first_bytes), &control)
        .await
        .expect("exact deposit retry");
    assert_eq!(retry.delivery_id(), &first_id);

    let conflict = delivery
        .deposit(
            &deposit,
            deposit_request(&canonical(0x71, 0x91, now)),
            &control,
        )
        .await;
    let Err(conflict) = conflict else {
        panic!("same envelope ID with different bytes must fail");
    };
    assert_eq!(conflict.code(), TransportFailureCode::IdempotencyConflict);

    let full = delivery
        .deposit(
            &deposit,
            deposit_request(&canonical(0x73, 0x83, now)),
            &control,
        )
        .await;
    let Err(full) = full else {
        panic!("bounded mailbox must reject a third retained envelope");
    };
    assert_eq!(full.code(), TransportFailureCode::QueueFull);

    let too_small = delivery
        .poll(&receive, poll_request(None, 1, 1), &control)
        .await;
    let Err(too_small) = too_small else {
        panic!("poll byte limit must be enforced before returning an envelope");
    };
    assert_eq!(too_small.code(), TransportFailureCode::EnvelopeTooLarge);

    let first_page = delivery
        .poll(&receive, poll_request(None, 1, 64 * 1024), &control)
        .await
        .expect("first bounded page");
    assert_eq!(first_page.len(), 1);
    assert_eq!(first_page.items()[0].delivery_id(), &first_id);
    assert_eq!(first_page.items()[0].envelope().as_bytes(), first_bytes);
    let (_, cursor) = first_page.into_parts();
    let cursor = cursor.expect("another retained envelope produces a cursor");

    let second_page = delivery
        .poll(&receive, poll_request(Some(cursor), 1, 64 * 1024), &control)
        .await
        .expect("cursor resumes at the second envelope");
    assert_eq!(second_page.len(), 1);
    assert_eq!(second_page.items()[0].delivery_id(), &second_id);
    assert_eq!(second_page.items()[0].envelope().as_bytes(), second_bytes);

    let invalid_cursor = delivery
        .poll(
            &receive,
            poll_request(
                Some(Cursor::new(vec![0x55; 40]).expect("bounded opaque cursor")),
                1,
                64 * 1024,
            ),
            &control,
        )
        .await;
    let Err(invalid_cursor) = invalid_cursor else {
        panic!("unauthenticated cursor must fail");
    };
    assert_eq!(invalid_cursor.code(), TransportFailureCode::InvalidCursor);

    let foreign = DeliveryId::from_provider_bytes([0x99; 16]).expect("delivery ID");
    let foreign_acknowledgement = delivery
        .acknowledge(&acknowledgement, acknowledgement_request(foreign), &control)
        .await;
    let Err(foreign_acknowledgement) = foreign_acknowledgement else {
        panic!("foreign delivery ID must fail exact-mailbox acknowledgement");
    };
    assert_eq!(
        foreign_acknowledgement.code(),
        TransportFailureCode::AuthorityScopeMismatch
    );

    delivery
        .acknowledge(
            &acknowledgement,
            acknowledgement_request(first_id),
            &control,
        )
        .await
        .expect("acknowledge first envelope");
    delivery
        .acknowledge(
            &acknowledgement,
            acknowledgement_request(first_id),
            &control,
        )
        .await
        .expect("exact acknowledgement retry is idempotent");
    delivery
        .acknowledge(
            &acknowledgement,
            acknowledgement_request(second_id),
            &control,
        )
        .await
        .expect("acknowledge second envelope");
    assert!(
        delivery
            .poll(&receive, poll_request(None, 2, 64 * 1024), &control)
            .await
            .expect("final poll")
            .is_empty()
    );

    let (client_close, server_result) =
        tokio::join!(delivery.close(OPERATION_DURATION), service_task,);
    client_close.expect("client closes cleanly");
    server_result
        .expect("service task completes")
        .expect("service closes cleanly");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_failure_statuses_map_to_bounded_transport_failures() {
    const DEPOSIT_OPERATION: u8 = 1;
    const STATUSES: &[(u16, TransportFailureCode)] = &[
        (1, TransportFailureCode::InvalidAuthority),
        (2, TransportFailureCode::AuthorityScopeMismatch),
        (3, TransportFailureCode::ExpiredEnvelope),
        (4, TransportFailureCode::EnvelopeTooLarge),
        (5, TransportFailureCode::IdempotencyConflict),
        (6, TransportFailureCode::InvalidCursor),
        (7, TransportFailureCode::QueueFull),
        (8, TransportFailureCode::RateLimited),
        (9, TransportFailureCode::Unavailable),
        (10, TransportFailureCode::DeadlineExceeded),
        (11, TransportFailureCode::Cancelled),
        (12, TransportFailureCode::CorruptRemoteResponse),
        (13, TransportFailureCode::PolicyViolation),
        (14, TransportFailureCode::Misconfigured),
        (15, TransportFailureCode::Internal),
        (99, TransportFailureCode::CorruptRemoteResponse),
    ];

    let now = unix_now();
    let host = IrohFastEndpoint::bind_loopback().await.expect("bind host");
    let host_id = host.id();
    let host_address = host.address();
    let mut service = IrohFastMailboxService::new(policy());
    let (deposit, _, _) = service
        .issue_mailbox(host_id, now + 300, now)
        .expect("issue online mailbox")
        .into_dispatch_parts();

    let (release_server, wait_for_client) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        let mut link = host
            .accept(
                None,
                OPERATION_DURATION,
                transport_iroh::MAX_FAST_FRAME_BYTES,
            )
            .await
            .expect("accept client");
        for (status, _) in STATUSES {
            let _request = link
                .receive_frame(OPERATION_DURATION)
                .await
                .expect("receive deposit request");
            link.send_frame(
                &wire_response(DEPOSIT_OPERATION, *status, &[]),
                OPERATION_DURATION,
            )
            .await
            .expect("send bounded remote failure");
        }
        let _ = wait_for_client.await;
    });

    let client_endpoint = IrohFastEndpoint::bind_loopback()
        .await
        .expect("bind client");
    let client_link = client_endpoint
        .connect_address(
            host_address,
            OPERATION_DURATION,
            transport_iroh::MAX_FAST_FRAME_BYTES,
        )
        .await
        .expect("connect client");
    let mut delivery = IrohFastDelivery::new(client_link).expect("bind exact Fast link limits");
    assert!(delivery.remote_id() == host_id);
    let control = LiveControl {
        wall_now_unix_seconds: now,
    };
    let canonical = canonical(0x61, 0x71, now);

    for (status, expected_code) in STATUSES {
        let result = delivery
            .deposit(&deposit, deposit_request(&canonical), &control)
            .await;
        let Err(failure) = result else {
            panic!("remote failure status must not be accepted");
        };
        assert_eq!(failure.code(), *expected_code, "remote status {status}");
        let expected_retry = match expected_code {
            TransportFailureCode::QueueFull
            | TransportFailureCode::RateLimited
            | TransportFailureCode::Unavailable
            | TransportFailureCode::Internal => RetryAdvice::Backoff,
            _ => RetryAdvice::Never,
        };
        assert_eq!(failure.retry_advice(), expected_retry);
    }
    release_server.send(()).expect("release server task");
    server_task.await.expect("server task completes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_success_responses_poison_before_state_is_accepted() {
    let now = unix_now();

    assert_deposit_response_rejected(vec![0x80], now).await;
    assert_deposit_response_rejected(wire_response(1, 0, &[0x44; 15]), now).await;

    let mut wrong_version = Encoder::new(Vec::new());
    wrong_version
        .array(4)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.u16(0))
        .and_then(|encoder| encoder.bytes(&[0x44; 16]))
        .expect("encode wrong version");
    assert_deposit_response_rejected(wrong_version.into_writer(), now).await;

    for incomplete in [
        vec![0x84, 0x01],
        vec![0x84, 0x01, 0x01],
        vec![0x84, 0x01, 0x01, 0x00],
    ] {
        assert_deposit_response_rejected(incomplete, now).await;
    }
    let mut trailing = wire_response(1, 0, &[0x44; 16]);
    trailing.push(0);
    assert_deposit_response_rejected(trailing, now).await;
    assert_deposit_response_rejected(
        vec![0x84, 0x19, 0x00, 0x01, 0x01, 0x00, 0x50]
            .into_iter()
            .chain([0x44; 16])
            .collect(),
        now,
    )
    .await;

    assert_poll_payload_rejected(vec![0x80], now).await;
    assert_poll_payload_rejected(vec![0x82, 0x9f, 0xff, 0x40], now).await;

    let mut excessive_count = Encoder::new(Vec::new());
    excessive_count
        .array(2)
        .and_then(|encoder| encoder.array(u64::from(session_transport::MAX_POLL_ENVELOPES) + 1))
        .and_then(|encoder| encoder.bytes(&[]))
        .expect("encode excessive item count");
    assert_poll_payload_rejected(excessive_count.into_writer(), now).await;

    let canonical = canonical(0x42, 0x52, now);
    let mut short_id = Encoder::new(Vec::new());
    short_id
        .array(2)
        .and_then(|encoder| encoder.array(1))
        .and_then(|encoder| encoder.array(2))
        .and_then(|encoder| encoder.bytes(&[0x44; 15]))
        .and_then(|encoder| encoder.bytes(&canonical))
        .and_then(|encoder| encoder.bytes(&[]))
        .expect("encode short delivery ID");
    assert_poll_payload_rejected(short_id.into_writer(), now).await;

    let mut invalid_envelope = Encoder::new(Vec::new());
    invalid_envelope
        .array(2)
        .and_then(|encoder| encoder.array(1))
        .and_then(|encoder| encoder.array(2))
        .and_then(|encoder| encoder.bytes(&[0x44; 16]))
        .and_then(|encoder| encoder.bytes(&[0]))
        .and_then(|encoder| encoder.bytes(&[]))
        .expect("encode invalid canonical envelope");
    assert_poll_payload_rejected(invalid_envelope.into_writer(), now).await;

    let mut excessive_cursor = Encoder::new(Vec::new());
    excessive_cursor
        .array(2)
        .and_then(|encoder| encoder.array(0))
        .and_then(|encoder| encoder.bytes(&vec![0x55; session_transport::MAX_CURSOR_BYTES + 1]))
        .expect("encode excessive cursor");
    assert_poll_payload_rejected(excessive_cursor.into_writer(), now).await;

    let mut trailing_payload = Encoder::new(Vec::new());
    trailing_payload
        .array(2)
        .and_then(|encoder| encoder.array(0))
        .and_then(|encoder| encoder.bytes(&[]))
        .and_then(|encoder| encoder.u8(0))
        .expect("encode trailing poll payload");
    assert_poll_payload_rejected(trailing_payload.into_writer(), now).await;
    assert_poll_payload_rejected(vec![0x82, 0x98, 0x00, 0x40], now).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_requests_are_rejected_before_authority_lookup() {
    assert_wire_request_rejected(vec![0x80]).await;
    assert_wire_request_rejected(encoded_wire_request(2, 1, &[0x44; 16], &[0x55; 32], &[])).await;
    assert_wire_request_rejected(vec![0x85, 0x01]).await;
    assert_wire_request_rejected(encoded_wire_request(1, 1, &[0x44; 15], &[0x55; 32], &[])).await;
    assert_wire_request_rejected(encoded_wire_request(1, 1, &[0x44; 16], &[0x55; 31], &[])).await;

    let mut missing_payload = Encoder::new(Vec::new());
    missing_payload
        .array(5)
        .and_then(|encoder| encoder.u16(1))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.bytes(&[0x44; 16]))
        .and_then(|encoder| encoder.bytes(&[0x55; 32]))
        .expect("encode truncated request");
    assert_wire_request_rejected(missing_payload.into_writer()).await;

    let mut trailing = encoded_wire_request(1, 1, &[0x44; 16], &[0x55; 32], &[]);
    trailing.push(0);
    assert_wire_request_rejected(trailing).await;

    let noncanonical = vec![0x85, 0x19, 0x00, 0x01, 0x01, 0x50]
        .into_iter()
        .chain([0x44; 16])
        .chain([0x58, 0x20])
        .chain([0x55; 32])
        .chain([0x40])
        .collect();
    assert_wire_request_rejected(noncanonical).await;
    assert_wire_request_rejected(encoded_wire_request(1, 0xff, &[0x44; 16], &[0x55; 32], &[]))
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_preflight_rejects_scope_lifetime_and_byte_budget_violations() {
    let now = unix_now();
    let host = IrohFastEndpoint::bind_loopback().await.expect("bind host");
    let host_id = host.id();
    let host_address = host.address();
    let other = IrohFastEndpoint::bind_loopback()
        .await
        .expect("bind unrelated endpoint");
    let mut service = IrohFastMailboxService::new(policy());
    let (deposit, receive, _) = service
        .issue_mailbox(host_id, now + 300, now)
        .expect("issue serving mailbox")
        .into_dispatch_parts();
    let mut foreign_service = IrohFastMailboxService::new(policy());
    let (foreign_deposit, _, _) = foreign_service
        .issue_mailbox(other.id(), now + 300, now)
        .expect("issue wrong-peer authority")
        .into_dispatch_parts();
    let mut short_service = IrohFastMailboxService::new(policy());
    let (short_deposit, _, _) = short_service
        .issue_mailbox(host_id, now + 1, now)
        .expect("issue short authority")
        .into_dispatch_parts();

    let service_task = tokio::spawn(async move {
        let link = host
            .accept(
                None,
                OPERATION_DURATION,
                transport_iroh::MAX_FAST_FRAME_BYTES,
            )
            .await
            .expect("accept client");
        service.serve_requests(link, 1, OPERATION_DURATION).await
    });
    let client_endpoint = IrohFastEndpoint::bind_loopback()
        .await
        .expect("bind client");
    let client_link = client_endpoint
        .connect_address(
            host_address,
            OPERATION_DURATION,
            transport_iroh::MAX_FAST_FRAME_BYTES,
        )
        .await
        .expect("connect client");
    let mut delivery = IrohFastDelivery::new(client_link).expect("bind exact Fast link limits");
    let control = LiveControl {
        wall_now_unix_seconds: now,
    };
    let canonical = canonical(0x31, 0x41, now);

    let wrong_peer = delivery
        .deposit(&foreign_deposit, deposit_request(&canonical), &control)
        .await;
    let Err(wrong_peer) = wrong_peer else {
        panic!("authority scoped to another peer must fail locally");
    };
    assert_eq!(
        wrong_peer.code(),
        TransportFailureCode::AuthorityScopeMismatch
    );

    let expired_authority = delivery
        .deposit(
            &short_deposit,
            deposit_request(&canonical),
            &LiveControl {
                wall_now_unix_seconds: now + 2,
            },
        )
        .await;
    let Err(expired_authority) = expired_authority else {
        panic!("expired authority must fail locally");
    };
    assert_eq!(
        expired_authority.code(),
        TransportFailureCode::InvalidAuthority
    );

    let outlives_authority = delivery
        .deposit(&short_deposit, deposit_request(&canonical), &control)
        .await;
    let Err(outlives_authority) = outlives_authority else {
        panic!("envelope may not outlive deposit authority");
    };
    assert_eq!(
        outlives_authority.code(),
        TransportFailureCode::ExpiredEnvelope
    );

    let expired_envelope = delivery
        .deposit(
            &deposit,
            deposit_request(&canonical_with_expiry(0x32, 0x42, now)),
            &control,
        )
        .await;
    let Err(expired_envelope) = expired_envelope else {
        panic!("envelope expired at the observed wall time must fail locally");
    };
    assert_eq!(
        expired_envelope.code(),
        TransportFailureCode::ExpiredEnvelope
    );

    let tight_envelope =
        CanonicalEnvelope::from_canonical_bytes(canonical.clone()).expect("validated envelope");
    let tight_budget = OperationBudget::new(
        Instant::now() + OPERATION_DURATION,
        u64::try_from(tight_envelope.as_bytes().len()).expect("bounded envelope length"),
        1,
    )
    .expect("tight operation budget");
    let tight_request =
        DepositRequest::new(tight_envelope, tight_budget).expect("deposit fits payload budget");
    let request_overhead = delivery.deposit(&deposit, tight_request, &control).await;
    let Err(request_overhead) = request_overhead else {
        panic!("wire framing must remain inside the caller byte budget");
    };
    assert_eq!(
        request_overhead.code(),
        TransportFailureCode::EnvelopeTooLarge
    );

    let tiny_budget = OperationBudget::new(Instant::now() + OPERATION_DURATION, 1, 1)
        .expect("nonzero operation budget");
    let tiny_poll = PollRequest::new(None, 1, 1, PollWait::immediate(), tiny_budget)
        .expect("provider-neutral request fits its declared payload budget");
    let poll_overhead = delivery.poll(&receive, tiny_poll, &control).await;
    let Err(poll_overhead) = poll_overhead else {
        panic!("poll protocol overhead must remain inside the caller byte budget");
    };
    assert_eq!(poll_overhead.code(), TransportFailureCode::EnvelopeTooLarge);

    delivery
        .deposit(&deposit, deposit_request(&canonical), &control)
        .await
        .expect("valid request remains usable after local rejections");
    other
        .close(OPERATION_DURATION)
        .await
        .expect("close unrelated endpoint");
    let (client_close, server_result) =
        tokio::join!(delivery.close(OPERATION_DURATION), service_task,);
    client_close.expect("client closes cleanly");
    server_result
        .expect("service task completes")
        .expect("service closes cleanly");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn semantic_response_corruption_poisons_the_ordered_link() {
    let now = unix_now();
    let host = IrohFastEndpoint::bind_loopback().await.expect("bind host");
    let host_id = host.id();
    let host_address = host.address();
    let mut service = IrohFastMailboxService::new(policy());
    let (deposit, _, _) = service
        .issue_mailbox(host_id, now + 300, now)
        .expect("issue online mailbox")
        .into_dispatch_parts();

    let (release_server, wait_for_client) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        let mut link = host
            .accept(
                None,
                OPERATION_DURATION,
                transport_iroh::MAX_FAST_FRAME_BYTES,
            )
            .await
            .expect("accept client");
        let _request = link
            .receive_frame(OPERATION_DURATION)
            .await
            .expect("receive deposit");
        let mut encoder = Encoder::new(Vec::new());
        encoder
            .array(4)
            .and_then(|encoder| encoder.u16(1))
            .and_then(|encoder| encoder.u8(2))
            .and_then(|encoder| encoder.u16(0))
            .and_then(|encoder| encoder.bytes(&[0x44; 16]))
            .expect("encode wrong-operation response");
        link.send_frame(&encoder.into_writer(), OPERATION_DURATION)
            .await
            .expect("send corrupt response");
        let _ = wait_for_client.await;
    });

    let client_endpoint = IrohFastEndpoint::bind_loopback()
        .await
        .expect("bind client");
    let client_link = client_endpoint
        .connect_address(
            host_address,
            OPERATION_DURATION,
            transport_iroh::MAX_FAST_FRAME_BYTES,
        )
        .await
        .expect("connect client");
    let mut delivery = IrohFastDelivery::new(client_link).expect("bind exact Fast link limits");
    let control = LiveControl {
        wall_now_unix_seconds: now,
    };
    let canonical = OpaqueEnvelope::new([0x61; 16], now + 120, vec![0x71; 16])
        .and_then(|envelope| envelope.encode_canonical())
        .expect("canonical envelope");

    let first = EnvelopeDelivery::deposit(
        &mut delivery,
        &deposit,
        DepositRequest::new(
            CanonicalEnvelope::from_canonical_bytes(canonical.clone()).expect("validated envelope"),
            budget(),
        )
        .expect("deposit request"),
        &control,
    )
    .await;
    let Err(first) = first else {
        panic!("wrong operation must fail");
    };
    assert_eq!(first.code(), TransportFailureCode::CorruptRemoteResponse);

    let second = EnvelopeDelivery::deposit(
        &mut delivery,
        &deposit,
        DepositRequest::new(
            CanonicalEnvelope::from_canonical_bytes(canonical).expect("validated retry"),
            budget(),
        )
        .expect("retry request"),
        &control,
    )
    .await;
    let Err(second) = second else {
        panic!("poisoned link must reject reuse");
    };
    assert_eq!(second.code(), TransportFailureCode::Unavailable);
    release_server.send(()).expect("release server task");
    server_task.await.expect("server task completes");
}
