#![forbid(unsafe_code)]

//! Bounded Iroh link for explicit FastV1 online experiments.
//!
//! This crate carries already-canonical Session Chat frames between two
//! authenticated Iroh endpoints. It is not an offline mailbox and does not
//! implement the reusable `EnvelopeDelivery` lifecycle contract.
//!
//! The endpoint/stream patterns follow Iroh 1.1.0's official examples:
//! <https://docs.rs/iroh/1.1.0/iroh/#examples>.

use std::{str::FromStr, time::Duration};

use iroh::{
    Endpoint, EndpointAddr, PublicKey,
    endpoint::{Connection, RecvStream, SendStream, presets},
};
use thiserror::Error;
use tokio::time::{Instant, timeout, timeout_at};

/// ALPN dedicated to the first version of Session Chat's Fast online link.
pub const SESSION_CHAT_FAST_ALPN_V1: &[u8] = b"session-chat/fast-link/1";

const FRAME_LENGTH_BYTES: usize = 4;

/// Coarse, payload-free failure from the experimental Fast link.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum IrohFastError {
    /// A caller supplied a zero, excessive, or otherwise invalid bound.
    #[error("invalid Fast link bound")]
    InvalidBound,
    /// The local Iroh endpoint could not be created.
    #[error("Fast link endpoint unavailable")]
    EndpointUnavailable,
    /// Connection setup or acceptance failed or exceeded its deadline.
    #[error("Fast link connection unavailable")]
    ConnectionUnavailable,
    /// The authenticated remote endpoint did not match the required peer.
    #[error("Fast link peer rejected")]
    PeerRejected,
    /// A frame was empty, malformed, truncated, or exceeded its bound.
    #[error("Fast link frame rejected")]
    FrameRejected,
    /// A bounded frame operation exceeded its caller-owned deadline.
    #[error("Fast link operation deadline exceeded")]
    DeadlineExceeded,
}

/// Public Iroh endpoint identifier used for authenticated Fast connections.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FastEndpointId(PublicKey);

impl FastEndpointId {
    /// Parses the public endpoint identifier printed by a Fast host.
    pub fn parse(value: &str) -> Result<Self, IrohFastError> {
        if value.is_empty() || value.len() > 128 || !value.is_ascii() {
            return Err(IrohFastError::PeerRejected);
        }
        PublicKey::from_str(value)
            .map(Self)
            .map_err(|_| IrohFastError::PeerRejected)
    }

    /// Returns the public text form suitable for an explicit host/join command.
    #[must_use]
    pub fn as_text(self) -> String {
        self.0.to_string()
    }
}

/// Exact in-memory addressing information for direct-only tests.
#[derive(Clone)]
pub struct FastEndpointAddress(EndpointAddr);

/// Bound Iroh endpoint before one connection is accepted or initiated.
pub struct IrohFastEndpoint {
    endpoint: Endpoint,
}

impl IrohFastEndpoint {
    /// Binds an explicit public Fast endpoint using Iroh's documented N0 preset.
    ///
    /// This may use address lookup, DNS, relays, NAT discovery, direct paths,
    /// and port mapping. Callers must disclose that observer set.
    pub async fn bind_public() -> Result<Self, IrohFastError> {
        let endpoint = Endpoint::builder(presets::N0)
            .alpns(vec![SESSION_CHAT_FAST_ALPN_V1.to_vec()])
            .bind()
            .await
            .map_err(|_| IrohFastError::EndpointUnavailable)?;
        Ok(Self { endpoint })
    }

    /// Binds a relay-free, lookup-free loopback endpoint for retained tests.
    pub async fn bind_loopback() -> Result<Self, IrohFastError> {
        let endpoint = iroh::endpoint::Builder::new(presets::Minimal)
            .bind_addr("127.0.0.1:0")
            .map_err(|_| IrohFastError::EndpointUnavailable)?
            .alpns(vec![SESSION_CHAT_FAST_ALPN_V1.to_vec()])
            .bind()
            .await
            .map_err(|_| IrohFastError::EndpointUnavailable)?;
        Ok(Self { endpoint })
    }

    /// Returns this endpoint's authenticated public identifier.
    #[must_use]
    pub fn id(&self) -> FastEndpointId {
        FastEndpointId(self.endpoint.id())
    }

    /// Captures exact current direct/relay addressing for an in-memory handoff.
    #[must_use]
    pub fn address(&self) -> FastEndpointAddress {
        FastEndpointAddress(self.endpoint.addr())
    }

    /// Waits for the public preset to establish an online path within a bound.
    pub async fn wait_online(&self, deadline: Duration) -> Result<(), IrohFastError> {
        require_duration(deadline)?;
        timeout(deadline, self.endpoint.online())
            .await
            .map_err(|_| IrohFastError::DeadlineExceeded)?;
        Ok(())
    }

    /// Closes an unconnected endpoint and waits for its background work to stop.
    pub async fn close(self) {
        self.endpoint.close().await;
    }

    /// Accepts one connection and optionally requires one authenticated peer ID.
    pub async fn accept(
        self,
        expected_peer: Option<FastEndpointId>,
        deadline: Duration,
        maximum_frame_bytes: usize,
    ) -> Result<IrohFastLink, IrohFastError> {
        validate_link_bounds(deadline, maximum_frame_bytes)?;
        let deadline = Instant::now() + deadline;
        let incoming = timeout_at(deadline, self.endpoint.accept())
            .await
            .map_err(|_| IrohFastError::DeadlineExceeded)?
            .ok_or(IrohFastError::ConnectionUnavailable)?;
        let connection = timeout_at(deadline, incoming)
            .await
            .map_err(|_| IrohFastError::DeadlineExceeded)?
            .map_err(|_| IrohFastError::ConnectionUnavailable)?;
        if expected_peer.is_some_and(|expected| connection.remote_id() != expected.0) {
            connection.close(1_u8.into(), b"peer rejected");
            self.endpoint.close().await;
            return Err(IrohFastError::PeerRejected);
        }
        let (send, receive) = timeout_at(deadline, connection.accept_bi())
            .await
            .map_err(|_| IrohFastError::DeadlineExceeded)?
            .map_err(|_| IrohFastError::ConnectionUnavailable)?;
        Ok(IrohFastLink::new(
            self.endpoint,
            connection,
            send,
            receive,
            maximum_frame_bytes,
        ))
    }

    /// Connects to a public endpoint ID using the configured address lookup.
    pub async fn connect_public(
        self,
        remote: FastEndpointId,
        deadline: Duration,
        maximum_frame_bytes: usize,
    ) -> Result<IrohFastLink, IrohFastError> {
        self.connect_address(
            FastEndpointAddress(EndpointAddr::new(remote.0)),
            deadline,
            maximum_frame_bytes,
        )
        .await
    }

    /// Connects to exact addressing information supplied in memory.
    pub async fn connect_address(
        self,
        remote: FastEndpointAddress,
        deadline: Duration,
        maximum_frame_bytes: usize,
    ) -> Result<IrohFastLink, IrohFastError> {
        validate_link_bounds(deadline, maximum_frame_bytes)?;
        let deadline = Instant::now() + deadline;
        let connection = timeout_at(
            deadline,
            self.endpoint
                .connect(remote.0.clone(), SESSION_CHAT_FAST_ALPN_V1),
        )
        .await
        .map_err(|_| IrohFastError::DeadlineExceeded)?
        .map_err(|_| IrohFastError::ConnectionUnavailable)?;
        if connection.remote_id() != remote.0.id {
            connection.close(1_u8.into(), b"peer rejected");
            self.endpoint.close().await;
            return Err(IrohFastError::PeerRejected);
        }
        let (send, receive) = timeout_at(deadline, connection.open_bi())
            .await
            .map_err(|_| IrohFastError::DeadlineExceeded)?
            .map_err(|_| IrohFastError::ConnectionUnavailable)?;
        Ok(IrohFastLink::new(
            self.endpoint,
            connection,
            send,
            receive,
            maximum_frame_bytes,
        ))
    }
}

/// One authenticated ordered online link with bounded application framing.
pub struct IrohFastLink {
    endpoint: Endpoint,
    connection: Connection,
    send: SendStream,
    receive: RecvStream,
    maximum_frame_bytes: usize,
}

impl IrohFastLink {
    fn new(
        endpoint: Endpoint,
        connection: Connection,
        send: SendStream,
        receive: RecvStream,
        maximum_frame_bytes: usize,
    ) -> Self {
        Self {
            endpoint,
            connection,
            send,
            receive,
            maximum_frame_bytes,
        }
    }

    /// Returns the authenticated remote endpoint ID.
    #[must_use]
    pub fn remote_id(&self) -> FastEndpointId {
        FastEndpointId(self.connection.remote_id())
    }

    /// Writes one nonempty bounded frame within the supplied deadline.
    pub async fn send_frame(
        &mut self,
        bytes: &[u8],
        deadline: Duration,
    ) -> Result<(), IrohFastError> {
        require_duration(deadline)?;
        if bytes.is_empty() || bytes.len() > self.maximum_frame_bytes {
            return Err(IrohFastError::FrameRejected);
        }
        let length = u32::try_from(bytes.len()).map_err(|_| IrohFastError::FrameRejected)?;
        timeout(deadline, async {
            self.send
                .write_all(&length.to_be_bytes())
                .await
                .map_err(|_| IrohFastError::ConnectionUnavailable)?;
            self.send
                .write_all(bytes)
                .await
                .map_err(|_| IrohFastError::ConnectionUnavailable)
        })
        .await
        .map_err(|_| IrohFastError::DeadlineExceeded)?
    }

    /// Reads one length-prefixed frame and rejects its length before allocation.
    pub async fn receive_frame(&mut self, deadline: Duration) -> Result<Vec<u8>, IrohFastError> {
        require_duration(deadline)?;
        timeout(deadline, async {
            let mut length = [0_u8; FRAME_LENGTH_BYTES];
            self.receive
                .read_exact(&mut length)
                .await
                .map_err(|_| IrohFastError::FrameRejected)?;
            let length = usize::try_from(u32::from_be_bytes(length))
                .map_err(|_| IrohFastError::FrameRejected)?;
            if length == 0 || length > self.maximum_frame_bytes {
                return Err(IrohFastError::FrameRejected);
            }
            let mut bytes = vec![0_u8; length];
            self.receive
                .read_exact(&mut bytes)
                .await
                .map_err(|_| IrohFastError::FrameRejected)?;
            Ok(bytes)
        })
        .await
        .map_err(|_| IrohFastError::DeadlineExceeded)?
    }

    /// Gracefully finishes the stream, waits for peer receipt, and closes the endpoint.
    pub async fn close(mut self, deadline: Duration) -> Result<(), IrohFastError> {
        require_duration(deadline)?;
        self.send
            .finish()
            .map_err(|_| IrohFastError::ConnectionUnavailable)?;
        let _peer_receipt = timeout(deadline, self.send.stopped())
            .await
            .map_err(|_| IrohFastError::DeadlineExceeded)?;
        self.connection.close(0_u8.into(), b"complete");
        self.endpoint.close().await;
        Ok(())
    }
}

fn validate_link_bounds(
    deadline: Duration,
    maximum_frame_bytes: usize,
) -> Result<(), IrohFastError> {
    require_duration(deadline)?;
    if maximum_frame_bytes == 0 || maximum_frame_bytes > u32::MAX as usize {
        return Err(IrohFastError::InvalidBound);
    }
    Ok(())
}

fn require_duration(deadline: Duration) -> Result<(), IrohFastError> {
    if deadline.is_zero() {
        return Err(IrohFastError::InvalidBound);
    }
    Ok(())
}
