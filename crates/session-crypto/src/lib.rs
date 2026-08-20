#![forbid(unsafe_code)]

//! Provider-neutral Session Chat message protection contract.

use std::{error::Error, fmt};

/// Maximum plaintext accepted for one application message.
pub const MAX_APPLICATION_MESSAGE_BYTES: usize = 16 * 1024;
/// Maximum protected protocol message accepted before backend parsing.
pub const MAX_PROTECTED_MESSAGE_BYTES: usize = 64 * 1024;

/// Coarse failure shared by every Session Chat message backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageSessionError {
    /// Attacker-controlled or application input exceeded its outer bound.
    InputTooLarge,
    /// The selected backend or current session state rejected the operation.
    Rejected,
}

impl fmt::Display for MessageSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge => formatter.write_str("message exceeds the configured bound"),
            Self::Rejected => formatter.write_str("message operation rejected"),
        }
    }
}

impl Error for MessageSessionError {}

/// Verifies the application plaintext bound shared by all backends.
pub fn validate_application_message(plaintext: &[u8]) -> Result<(), MessageSessionError> {
    if plaintext.len() > MAX_APPLICATION_MESSAGE_BYTES {
        return Err(MessageSessionError::InputTooLarge);
    }
    Ok(())
}

/// Bounded, opaque protocol bytes emitted or consumed by a message backend.
#[derive(Eq, PartialEq)]
pub struct ProtectedMessage(Vec<u8>);

impl ProtectedMessage {
    /// Copies untrusted bytes only after enforcing the shared outer bound.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MessageSessionError> {
        validate_length(bytes.len(), MAX_PROTECTED_MESSAGE_BYTES)?;
        Ok(Self(bytes.to_vec()))
    }

    /// Takes ownership of untrusted bytes only after enforcing the shared outer bound.
    pub fn from_vec(bytes: Vec<u8>) -> Result<Self, MessageSessionError> {
        validate_length(bytes.len(), MAX_PROTECTED_MESSAGE_BYTES)?;
        Ok(Self(bytes))
    }

    /// Borrows the opaque protected bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the owned opaque protected bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Bounded application plaintext returned by a message backend.
#[derive(Eq, PartialEq)]
pub struct ApplicationMessage(Vec<u8>);

impl ApplicationMessage {
    /// Copies plaintext only after enforcing the shared application bound.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MessageSessionError> {
        validate_length(bytes.len(), MAX_APPLICATION_MESSAGE_BYTES)?;
        Ok(Self(bytes.to_vec()))
    }

    /// Takes ownership of plaintext only after enforcing the shared application bound.
    pub fn from_vec(bytes: Vec<u8>) -> Result<Self, MessageSessionError> {
        validate_length(bytes.len(), MAX_APPLICATION_MESSAGE_BYTES)?;
        Ok(Self(bytes))
    }

    /// Borrows the application plaintext.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the owned application plaintext.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for ApplicationMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplicationMessage")
            .field("byte_length", &self.0.len())
            .finish()
    }
}

impl fmt::Debug for ProtectedMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedMessage")
            .field("byte_length", &self.0.len())
            .finish()
    }
}

/// Provider-neutral result of processing one protected session message.
#[derive(Eq, PartialEq)]
pub enum MessageEvent {
    /// Decrypted application bytes owned by the caller.
    Application(ApplicationMessage),
    /// An authenticated membership operation advanced the local epoch.
    EpochAdvanced,
    /// An authenticated membership operation removed this client.
    Removed,
}

impl fmt::Debug for MessageEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Application(plaintext) => fmt::Debug::fmt(plaintext, formatter),
            Self::EpochAdvanced => formatter.write_str("EpochAdvanced"),
            Self::Removed => formatter.write_str("Removed"),
        }
    }
}

fn validate_length(length: usize, maximum: usize) -> Result<(), MessageSessionError> {
    if length > maximum {
        return Err(MessageSessionError::InputTooLarge);
    }
    Ok(())
}

/// Application-facing operations for one already-established encrypted session.
///
/// Implementations must enforce the shared bounds before provider parsing and
/// must map provider-specific failures to [`MessageSessionError`]. The trait is
/// object-safe so an application composition root can select an allowlisted
/// backend for a newly created session without exposing its concrete types.
/// Active sessions must not silently change backend implementations.
pub trait MessageSession {
    /// Returns the current authenticated membership epoch.
    fn epoch(&self) -> u64;

    /// Returns the current member count.
    fn member_count(&self) -> usize;

    /// Protects one bounded application message without transporting it.
    fn protect_application_message(
        &mut self,
        plaintext: &[u8],
    ) -> Result<ProtectedMessage, MessageSessionError>;

    /// Processes one bounded protected message and returns its coarse effect.
    fn process_protected_message(
        &mut self,
        message: ProtectedMessage,
    ) -> Result<MessageEvent, MessageSessionError>;
}
