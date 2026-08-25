//! Compile-time evidence for the local right-specific capability boundary.
//!
//! The sender-facing deposit endpoint has one deliberate canonical wire
//! encoding, but it is still secret-bearing and must not enter ordinary
//! diagnostics or implicit copies.
//!
//! ```compile_fail
//! use session_protocol::LocalWelcomeDepositEndpoint;
//!
//! fn require_debug<T: std::fmt::Debug>() {}
//! require_debug::<LocalWelcomeDepositEndpoint>();
//! ```
//!
//! ```compile_fail
//! use session_protocol::LocalWelcomeDepositEndpoint;
//!
//! fn require_display<T: std::fmt::Display>() {}
//! require_display::<LocalWelcomeDepositEndpoint>();
//! ```
//!
//! ```compile_fail
//! use session_protocol::LocalWelcomeDepositEndpoint;
//!
//! fn require_clone<T: Clone>() {}
//! require_clone::<LocalWelcomeDepositEndpoint>();
//! ```

use session_protocol::LocalWelcomeDepositEndpoint;
use zeroize::Zeroize;

use crate::{CAPABILITY_BYTES, IDENTIFIER_BYTES};

/// Joiner-only authority for reading one local Welcome mailbox.
///
/// This secret-bearing type intentionally does not implement `Clone`, `Debug`,
/// `Display`, or serialization.
///
/// ```compile_fail
/// use session_transport::LocalWelcomeReceiveCapability;
///
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<LocalWelcomeReceiveCapability>();
/// ```
///
/// ```compile_fail
/// use session_transport::LocalWelcomeReceiveCapability;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<LocalWelcomeReceiveCapability>();
/// ```
///
/// ```compile_fail
/// use session_transport::LocalWelcomeReceiveCapability;
///
/// fn require_display<T: std::fmt::Display>() {}
/// require_display::<LocalWelcomeReceiveCapability>();
/// ```
///
/// ```compile_fail
/// use session_protocol::OpaqueEnvelope;
/// use session_transport::{LocalMemoryWelcomeTransport, LocalWelcomeReceiveCapability};
///
/// fn cannot_deposit(
///     transport: &mut LocalMemoryWelcomeTransport,
///     authority: &LocalWelcomeReceiveCapability,
///     envelope: OpaqueEnvelope,
/// ) {
///     transport.deposit(authority, envelope, 0);
/// }
/// ```
///
/// ```compile_fail
/// use session_transport::{
///     DeliveryId, LocalMemoryWelcomeTransport, LocalWelcomeReceiveCapability,
/// };
///
/// fn cannot_acknowledge(
///     transport: &mut LocalMemoryWelcomeTransport,
///     authority: &LocalWelcomeReceiveCapability,
///     delivery_id: DeliveryId,
/// ) {
///     transport.acknowledge(authority, delivery_id, 0);
/// }
/// ```
pub struct LocalWelcomeReceiveCapability {
    transport_instance_id: [u8; IDENTIFIER_BYTES],
    mailbox_id: [u8; IDENTIFIER_BYTES],
    secret: [u8; CAPABILITY_BYTES],
    expires_at_unix_seconds: u64,
}

impl LocalWelcomeReceiveCapability {
    pub(crate) const fn new(
        transport_instance_id: [u8; IDENTIFIER_BYTES],
        mailbox_id: [u8; IDENTIFIER_BYTES],
        secret: [u8; CAPABILITY_BYTES],
        expires_at_unix_seconds: u64,
    ) -> Self {
        Self {
            transport_instance_id,
            mailbox_id,
            secret,
            expires_at_unix_seconds,
        }
    }

    pub(crate) const fn transport_instance_id(&self) -> &[u8; IDENTIFIER_BYTES] {
        &self.transport_instance_id
    }

    pub(crate) const fn mailbox_id(&self) -> &[u8; IDENTIFIER_BYTES] {
        &self.mailbox_id
    }

    pub(crate) const fn expose_secret(&self) -> &[u8; CAPABILITY_BYTES] {
        &self.secret
    }

    pub(crate) const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }
}

impl Drop for LocalWelcomeReceiveCapability {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Joiner-only authority for deleting one local Welcome delivery.
///
/// This secret-bearing type intentionally does not implement `Clone`, `Debug`,
/// `Display`, or serialization.
///
/// ```compile_fail
/// use session_transport::LocalWelcomeAcknowledgementCapability;
///
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<LocalWelcomeAcknowledgementCapability>();
/// ```
///
/// ```compile_fail
/// use session_transport::LocalWelcomeAcknowledgementCapability;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<LocalWelcomeAcknowledgementCapability>();
/// ```
///
/// ```compile_fail
/// use session_transport::LocalWelcomeAcknowledgementCapability;
///
/// fn require_display<T: std::fmt::Display>() {}
/// require_display::<LocalWelcomeAcknowledgementCapability>();
/// ```
///
/// ```compile_fail
/// use session_transport::{
///     LocalMemoryWelcomeTransport, LocalWelcomeAcknowledgementCapability,
/// };
///
/// fn cannot_receive(
///     transport: &mut LocalMemoryWelcomeTransport,
///     authority: &LocalWelcomeAcknowledgementCapability,
/// ) {
///     transport.receive(authority, 0);
/// }
/// ```
///
/// ```compile_fail
/// use session_protocol::OpaqueEnvelope;
/// use session_transport::{
///     LocalMemoryWelcomeTransport, LocalWelcomeAcknowledgementCapability,
/// };
///
/// fn cannot_deposit(
///     transport: &mut LocalMemoryWelcomeTransport,
///     authority: &LocalWelcomeAcknowledgementCapability,
///     envelope: OpaqueEnvelope,
/// ) {
///     transport.deposit(authority, envelope, 0);
/// }
/// ```
///
/// ```compile_fail
/// use session_protocol::LocalWelcomeDepositEndpoint;
/// use session_transport::{DeliveryId, LocalMemoryWelcomeTransport};
///
/// fn cannot_acknowledge(
///     transport: &mut LocalMemoryWelcomeTransport,
///     endpoint: &LocalWelcomeDepositEndpoint,
///     delivery_id: DeliveryId,
/// ) {
///     transport.acknowledge(endpoint, delivery_id, 0);
/// }
/// ```
///
/// ```compile_fail
/// use session_protocol::LocalWelcomeDepositEndpoint;
/// use session_transport::LocalMemoryWelcomeTransport;
///
/// fn cannot_receive(
///     transport: &mut LocalMemoryWelcomeTransport,
///     endpoint: &LocalWelcomeDepositEndpoint,
/// ) {
///     transport.receive(endpoint, 0);
/// }
/// ```
///
/// ```compile_fail
/// use session_transport::{DeliveryId, LocalMemoryWelcomeTransport};
///
/// fn identifier_is_not_authority(
///     transport: &mut LocalMemoryWelcomeTransport,
///     delivery_id: DeliveryId,
/// ) {
///     transport.acknowledge(&delivery_id, delivery_id, 0);
/// }
/// ```
pub struct LocalWelcomeAcknowledgementCapability {
    transport_instance_id: [u8; IDENTIFIER_BYTES],
    mailbox_id: [u8; IDENTIFIER_BYTES],
    secret: [u8; CAPABILITY_BYTES],
    expires_at_unix_seconds: u64,
}

impl LocalWelcomeAcknowledgementCapability {
    pub(crate) const fn new(
        transport_instance_id: [u8; IDENTIFIER_BYTES],
        mailbox_id: [u8; IDENTIFIER_BYTES],
        secret: [u8; CAPABILITY_BYTES],
        expires_at_unix_seconds: u64,
    ) -> Self {
        Self {
            transport_instance_id,
            mailbox_id,
            secret,
            expires_at_unix_seconds,
        }
    }

    pub(crate) const fn transport_instance_id(&self) -> &[u8; IDENTIFIER_BYTES] {
        &self.transport_instance_id
    }

    pub(crate) const fn mailbox_id(&self) -> &[u8; IDENTIFIER_BYTES] {
        &self.mailbox_id
    }

    pub(crate) const fn expose_secret(&self) -> &[u8; CAPABILITY_BYTES] {
        &self.secret
    }

    pub(crate) const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }
}

impl Drop for LocalWelcomeAcknowledgementCapability {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Fresh local mailbox authorities split by operation.
///
/// Only the deposit endpoint is intended to enter a protected join request.
pub struct LocalWelcomeMailbox {
    deposit: LocalWelcomeDepositEndpoint,
    receive: LocalWelcomeReceiveCapability,
    acknowledgement: LocalWelcomeAcknowledgementCapability,
}

impl LocalWelcomeMailbox {
    pub(crate) const fn new(
        deposit: LocalWelcomeDepositEndpoint,
        receive: LocalWelcomeReceiveCapability,
        acknowledgement: LocalWelcomeAcknowledgementCapability,
    ) -> Self {
        Self {
            deposit,
            receive,
            acknowledgement,
        }
    }

    /// Separates the sender-facing endpoint from joiner-retained rights.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        LocalWelcomeDepositEndpoint,
        LocalWelcomeReceiveCapability,
        LocalWelcomeAcknowledgementCapability,
    ) {
        (self.deposit, self.receive, self.acknowledgement)
    }
}
