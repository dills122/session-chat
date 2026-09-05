use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use minicbor::Encoder;
use session_protocol::OpaqueEnvelope;
use session_transport::{
    CanonicalEnvelope, DepositRequest, DispatchControl, EnforcementModeV1, EnvelopeDelivery,
    OperationBudget, TransportFailureCode, TransportProfileId, bind_fast_transport_v1,
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

#[test]
fn adapter_manifest_binds_only_the_disclosed_fast_profile() {
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
