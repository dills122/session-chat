#![forbid(unsafe_code)]

//! Versioned, bounded wire objects for Session Chat 2.0.

use minicbor::{Decoder, Encoder};
use thiserror::Error;

/// The only protocol version accepted by this implementation increment.
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum encoded size accepted before any CBOR processing occurs.
pub const MAX_WIRE_OBJECT_BYTES: usize = 64 * 1024;

/// Maximum ciphertext carried by an opaque transport envelope.
pub const MAX_ENVELOPE_CIPHERTEXT_BYTES: usize = 60 * 1024;

const ENVELOPE_ID_BYTES: usize = 16;
const OPAQUE_ENVELOPE_FIELDS: u64 = 5;

/// Version 1 top-level wire object identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum WireObjectType {
    /// A transport-visible container whose contents remain uninterpreted bytes.
    OpaqueEnvelope = 1,
}

impl TryFrom<u16> for WireObjectType {
    type Error = WireError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            value if value == Self::OpaqueEnvelope as u16 => Ok(Self::OpaqueEnvelope),
            unsupported => Err(WireError::UnsupportedObjectType(unsupported)),
        }
    }
}

/// A bounded transport object containing no identity or message-type metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpaqueEnvelope {
    envelope_id: [u8; ENVELOPE_ID_BYTES],
    expires_at_unix_seconds: u64,
    ciphertext: Vec<u8>,
}

impl OpaqueEnvelope {
    /// Constructs an envelope after applying variable-field limits.
    pub fn new(
        envelope_id: [u8; ENVELOPE_ID_BYTES],
        expires_at_unix_seconds: u64,
        ciphertext: Vec<u8>,
    ) -> Result<Self, WireError> {
        if ciphertext.len() > MAX_ENVELOPE_CIPHERTEXT_BYTES {
            return Err(WireError::CiphertextTooLarge {
                actual: ciphertext.len(),
                maximum: MAX_ENVELOPE_CIPHERTEXT_BYTES,
            });
        }

        Ok(Self {
            envelope_id,
            expires_at_unix_seconds,
            ciphertext,
        })
    }

    /// Returns the fixed wire object discriminator.
    #[must_use]
    pub const fn object_type(&self) -> WireObjectType {
        WireObjectType::OpaqueEnvelope
    }

    /// Returns the random id used for replay and deduplication tracking.
    #[must_use]
    pub const fn envelope_id(&self) -> &[u8; ENVELOPE_ID_BYTES] {
        &self.envelope_id
    }

    /// Returns the absolute Unix expiration time in seconds.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    /// Returns the uninterpreted encrypted content.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Encodes the restricted deterministic-CBOR representation from ADR 0005.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, WireError> {
        let mut encoder = Encoder::new(Vec::with_capacity(self.ciphertext.len() + 32));

        encoder
            .array(OPAQUE_ENVELOPE_FIELDS)
            .and_then(|encoder| encoder.u16(PROTOCOL_VERSION))
            .and_then(|encoder| encoder.u16(self.object_type() as u16))
            .and_then(|encoder| encoder.bytes(&self.envelope_id))
            .and_then(|encoder| encoder.u64(self.expires_at_unix_seconds))
            .and_then(|encoder| encoder.bytes(&self.ciphertext))
            .map_err(|_| WireError::Encoding)?;

        let encoded = encoder.into_writer();
        if encoded.len() > MAX_WIRE_OBJECT_BYTES {
            return Err(WireError::WireObjectTooLarge {
                actual: encoded.len(),
                maximum: MAX_WIRE_OBJECT_BYTES,
            });
        }

        Ok(encoded)
    }

    /// Decodes only the exact deterministic representation accepted by version 1.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_WIRE_OBJECT_BYTES {
            return Err(WireError::WireObjectTooLarge {
                actual: bytes.len(),
                maximum: MAX_WIRE_OBJECT_BYTES,
            });
        }

        let mut decoder = Decoder::new(bytes);
        if decoder.array().map_err(|_| WireError::Malformed)? != Some(OPAQUE_ENVELOPE_FIELDS) {
            return Err(WireError::Malformed);
        }

        let version = decoder.u16().map_err(|_| WireError::Malformed)?;
        if version != PROTOCOL_VERSION {
            return Err(WireError::UnsupportedVersion(version));
        }

        let object_type = decoder.u16().map_err(|_| WireError::Malformed)?;
        WireObjectType::try_from(object_type)?;

        let encoded_id = decoder.bytes().map_err(|_| WireError::Malformed)?;
        if encoded_id.len() != ENVELOPE_ID_BYTES {
            return Err(WireError::InvalidEnvelopeIdLength(encoded_id.len()));
        }
        let mut envelope_id = [0; ENVELOPE_ID_BYTES];
        envelope_id.copy_from_slice(encoded_id);

        let expires_at_unix_seconds = decoder.u64().map_err(|_| WireError::Malformed)?;
        let ciphertext = decoder.bytes().map_err(|_| WireError::Malformed)?;
        if ciphertext.len() > MAX_ENVELOPE_CIPHERTEXT_BYTES {
            return Err(WireError::CiphertextTooLarge {
                actual: ciphertext.len(),
                maximum: MAX_ENVELOPE_CIPHERTEXT_BYTES,
            });
        }

        if decoder.position() != bytes.len() {
            return Err(WireError::TrailingData);
        }

        let envelope = Self::new(envelope_id, expires_at_unix_seconds, ciphertext.to_vec())?;
        if envelope.encode_canonical()?.as_slice() != bytes {
            return Err(WireError::NonDeterministicEncoding);
        }

        Ok(envelope)
    }
}

/// Fail-closed errors exposed by the version 1 wire boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WireError {
    /// The object exceeded the total pre-parse byte limit.
    #[error("wire object size {actual} exceeds maximum {maximum}")]
    WireObjectTooLarge { actual: usize, maximum: usize },

    /// The opaque ciphertext exceeded its field limit.
    #[error("ciphertext size {actual} exceeds maximum {maximum}")]
    CiphertextTooLarge { actual: usize, maximum: usize },

    /// The explicit protocol version is not supported.
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u16),

    /// The explicit wire object type is not supported.
    #[error("unsupported wire object type {0}")]
    UnsupportedObjectType(u16),

    /// The replay identifier did not have the required fixed size.
    #[error("envelope id has invalid length {0}")]
    InvalidEnvelopeIdLength(usize),

    /// The CBOR object was malformed or outside the restricted profile.
    #[error("malformed wire object")]
    Malformed,

    /// Bytes followed the single expected top-level object.
    #[error("wire object contains trailing data")]
    TrailingData,

    /// The object decoded but did not use its unique deterministic representation.
    #[error("wire object is not deterministically encoded")]
    NonDeterministicEncoding,

    /// The bounded in-memory encoder failed.
    #[error("wire object encoding failed")]
    Encoding,
}
