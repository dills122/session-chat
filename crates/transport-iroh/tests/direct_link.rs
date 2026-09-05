use std::{str::FromStr, time::Duration};

use iroh::PublicKey;
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
async fn local_frame_bounds_and_idle_receive_deadline_fail_closed() {
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
        join_link.receive_frame_bounded(DEADLINE, 0).await,
        Err(IrohFastError::InvalidBound)
    );
    assert_eq!(
        join_link.receive_frame_bounded(DEADLINE, 5).await,
        Err(IrohFastError::InvalidBound)
    );
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
    assert_eq!(
        host_link.receive_frame(Duration::from_millis(20)).await,
        Err(IrohFastError::DeadlineExceeded)
    );
    assert_eq!(
        host_link.receive_frame(DEADLINE).await,
        Err(IrohFastError::ConnectionUnavailable)
    );
    assert_eq!(
        host_link.close(DEADLINE).await,
        Err(IrohFastError::ConnectionUnavailable)
    );
    assert!(join_link.close(DEADLINE).await.is_err());
}

#[tokio::test]
async fn accept_times_out_and_excessive_deadlines_fail_before_network_work() {
    let invalid_accept = IrohFastEndpoint::bind_loopback()
        .await
        .expect("bind invalid accept endpoint");
    assert!(matches!(
        invalid_accept.accept(None, DEADLINE, 0).await,
        Err(IrohFastError::InvalidBound)
    ));

    let timeout_endpoint = IrohFastEndpoint::bind_loopback()
        .await
        .expect("bind timeout endpoint");
    assert!(matches!(
        timeout_endpoint
            .accept(None, Duration::from_millis(20), MAXIMUM_FRAME_BYTES)
            .await,
        Err(IrohFastError::DeadlineExceeded)
    ));

    let host = IrohFastEndpoint::bind_loopback().await.expect("bind host");
    let host_address = host.address();
    let join = IrohFastEndpoint::bind_loopback().await.expect("bind join");
    assert!(matches!(
        join.connect_address(host_address, Duration::MAX, MAXIMUM_FRAME_BYTES)
            .await,
        Err(IrohFastError::InvalidBound)
    ));
    host.close(DEADLINE).await.expect("close host");

    let public_host = IrohFastEndpoint::bind_loopback()
        .await
        .expect("bind public-id host");
    let public_host_id = public_host.id();
    let public_join = IrohFastEndpoint::bind_loopback()
        .await
        .expect("bind public-id joiner");
    assert!(matches!(
        public_join
            .connect_public(public_host_id, Duration::MAX, MAXIMUM_FRAME_BYTES)
            .await,
        Err(IrohFastError::InvalidBound)
    ));
    public_host
        .close(DEADLINE)
        .await
        .expect("close public-id host");

    let endpoint = IrohFastEndpoint::bind_loopback()
        .await
        .expect("bind online endpoint");
    assert_eq!(
        endpoint.wait_online(Duration::MAX).await,
        Err(IrohFastError::InvalidBound)
    );
    assert!(matches!(
        endpoint.wait_online(Duration::from_millis(20)).await,
        Ok(()) | Err(IrohFastError::DeadlineExceeded)
    ));
    endpoint.close(DEADLINE).await.expect("close endpoint");

    let endpoint = IrohFastEndpoint::bind_loopback()
        .await
        .expect("bind close endpoint");
    assert_eq!(
        endpoint.close(Duration::MAX).await,
        Err(IrohFastError::InvalidBound)
    );
}

#[tokio::test]
async fn receiver_rejects_a_frame_above_its_own_bound() {
    let host = IrohFastEndpoint::bind_loopback().await.expect("bind host");
    let host_address = host.address();
    let join = IrohFastEndpoint::bind_loopback().await.expect("bind join");

    let host_task = tokio::spawn(async move {
        host.accept(None, DEADLINE, 4)
            .await
            .expect("accept bounded joiner")
    });
    let mut join_link = join
        .connect_address(host_address, DEADLINE, 5)
        .await
        .expect("connect joiner");
    join_link
        .send_frame(&[0xA5; 5], DEADLINE)
        .await
        .expect("send locally valid frame");
    let mut host_link = host_task.await.expect("host task");

    assert_eq!(
        host_link.receive_frame(DEADLINE).await,
        Err(IrohFastError::FrameRejected)
    );
    assert_eq!(
        host_link.close(DEADLINE).await,
        Err(IrohFastError::ConnectionUnavailable)
    );
    assert!(join_link.close(DEADLINE).await.is_err());
}

#[tokio::test]
async fn frame_and_close_operations_reject_excessive_deadlines() {
    let host = IrohFastEndpoint::bind_loopback().await.expect("bind host");
    let host_address = host.address();
    let join = IrohFastEndpoint::bind_loopback().await.expect("bind join");

    let host_task = tokio::spawn(async move {
        host.accept(None, DEADLINE, MAXIMUM_FRAME_BYTES)
            .await
            .expect("accept joiner")
    });
    let mut join_link = join
        .connect_address(host_address, DEADLINE, MAXIMUM_FRAME_BYTES)
        .await
        .expect("connect joiner");
    join_link
        .send_frame(b"ready", DEADLINE)
        .await
        .expect("trigger lazy stream acceptance");
    let mut host_link = host_task.await.expect("host task");
    assert_eq!(
        host_link
            .receive_frame(DEADLINE)
            .await
            .expect("ready frame"),
        b"ready"
    );

    assert_eq!(
        join_link.send_frame(b"frame", Duration::MAX).await,
        Err(IrohFastError::InvalidBound)
    );
    assert_eq!(
        join_link.receive_frame(Duration::MAX).await,
        Err(IrohFastError::InvalidBound)
    );
    assert_eq!(
        join_link.close(Duration::MAX).await,
        Err(IrohFastError::InvalidBound)
    );
    assert_eq!(
        host_link.close(Duration::MAX).await,
        Err(IrohFastError::InvalidBound)
    );
}

#[tokio::test]
async fn accept_rejects_an_authenticated_but_unexpected_peer() {
    let host = IrohFastEndpoint::bind_loopback().await.expect("bind host");
    let host_address = host.address();
    let join = IrohFastEndpoint::bind_loopback().await.expect("bind join");
    let other = IrohFastEndpoint::bind_loopback().await.expect("bind other");
    let other_id = other.id();

    let (host_result, _join_result) = tokio::join!(
        host.accept(Some(other_id), DEADLINE, MAXIMUM_FRAME_BYTES),
        join.connect_address(host_address, DEADLINE, MAXIMUM_FRAME_BYTES),
    );
    assert!(matches!(host_result, Err(IrohFastError::PeerRejected)));
    other.close(DEADLINE).await.expect("close other");
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
    endpoint.close(DEADLINE).await.expect("close endpoint");
}

#[tokio::test]
async fn endpoint_id_parser_rejects_unbounded_or_noncanonical_input() {
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
    assert!(matches!(
        FastEndpointId::parse("é"),
        Err(IrohFastError::PeerRejected)
    ));

    let endpoint = IrohFastEndpoint::bind_loopback()
        .await
        .expect("bind endpoint");
    let canonical = endpoint.id().as_text();
    let alternate = PublicKey::from_str(&canonical)
        .expect("parse canonical public key")
        .to_z32();
    assert_ne!(alternate, canonical);
    assert!(FastEndpointId::parse(&canonical).is_ok());
    assert!(matches!(
        FastEndpointId::parse(&alternate),
        Err(IrohFastError::PeerRejected)
    ));
    endpoint.close(DEADLINE).await.expect("close endpoint");
}
