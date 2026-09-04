use std::time::Duration;

use transport_iroh::{FastEndpointId, IrohFastEndpoint, IrohFastError};

const DEADLINE: Duration = Duration::from_secs(5);
const MAXIMUM_FRAME_BYTES: usize = 4_096;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_endpoints_exchange_bounded_frames_with_authenticated_ids() {
    let host = IrohFastEndpoint::bind_loopback().await.expect("bind host");
    let host_id = host.id();
    let host_address = host.address();
    let join = IrohFastEndpoint::bind_loopback().await.expect("bind join");
    let join_id = join.id();

    let host_task = tokio::spawn(async move {
        let mut link = host
            .accept(Some(join_id), DEADLINE, MAXIMUM_FRAME_BYTES)
            .await
            .expect("accept authenticated joiner");
        assert!(link.remote_id() == join_id);
        assert_eq!(
            link.receive_frame(DEADLINE).await.expect("request"),
            b"join"
        );
        link.send_frame(b"welcome", DEADLINE)
            .await
            .expect("response");
        link.close(DEADLINE).await.expect("close host");
    });

    let mut link = join
        .connect_address(host_address, DEADLINE, MAXIMUM_FRAME_BYTES)
        .await
        .expect("connect to exact host address");
    assert!(link.remote_id() == host_id);
    link.send_frame(b"join", DEADLINE).await.expect("request");
    assert_eq!(
        link.receive_frame(DEADLINE).await.expect("response"),
        b"welcome"
    );
    link.close(DEADLINE).await.expect("close join");
    host_task.await.expect("host task");
}

#[tokio::test]
async fn local_frame_bounds_fail_before_network_write() {
    let host = IrohFastEndpoint::bind_loopback().await.expect("bind host");
    let host_address = host.address();
    let join = IrohFastEndpoint::bind_loopback().await.expect("bind join");

    let host_task =
        tokio::spawn(async move { host.accept(None, DEADLINE, 4).await.expect("accept joiner") });
    let mut join_link = join
        .connect_address(host_address, DEADLINE, 4)
        .await
        .expect("connect joiner");
    assert_eq!(
        join_link.send_frame(&[], DEADLINE).await,
        Err(IrohFastError::FrameRejected)
    );
    assert_eq!(
        join_link.send_frame(&[0_u8; 5], DEADLINE).await,
        Err(IrohFastError::FrameRejected)
    );
    join_link
        .send_frame(&[0x01], DEADLINE)
        .await
        .expect("trigger lazy stream acceptance");
    let mut host_link = host_task.await.expect("host task");
    assert_eq!(
        host_link
            .receive_frame(DEADLINE)
            .await
            .expect("valid frame"),
        [0x01]
    );
    let (join_close, host_close) =
        tokio::join!(join_link.close(DEADLINE), host_link.close(DEADLINE),);
    join_close.expect("close join");
    host_close.expect("close host");
}

#[tokio::test]
#[ignore = "requires public N0 address-lookup and relay connectivity"]
async fn public_endpoint_reaches_an_online_n0_path() {
    let endpoint = IrohFastEndpoint::bind_public()
        .await
        .expect("bind public endpoint");
    endpoint
        .wait_online(Duration::from_secs(30))
        .await
        .expect("public endpoint online");
    endpoint.close().await;
}

#[test]
fn endpoint_id_parser_rejects_unbounded_or_noncanonical_input() {
    assert!(matches!(
        FastEndpointId::parse(""),
        Err(IrohFastError::PeerRejected)
    ));
    assert!(matches!(
        FastEndpointId::parse(&"a".repeat(129)),
        Err(IrohFastError::PeerRejected)
    ));
    assert!(matches!(
        FastEndpointId::parse("not-an-endpoint-id"),
        Err(IrohFastError::PeerRejected)
    ));
}
