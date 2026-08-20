#![forbid(unsafe_code)]

//! Versioned, bounded wire objects for Session Chat 2.0.

mod invitation;
mod protected_join;

use minicbor::{Decoder, Encoder};
use thiserror::Error;

pub use invitation::{
    AdmissionMode, ApplicationProtocolVersion, CapabilityInvitationClaims,
    CapabilityInvitationV2Claims, InvitationEncryptionSuite, InvitationUsePolicy,
    JoinRequestSchemaVersion, MAX_SIGNED_INVITATION_BYTES, SecretCapability, SignatureSuite,
    SignedCapabilityInvitation, SignedCapabilityInvitationV2, TransportProfile,
};
pub use protected_join::{
    AdmissionProofVersion, CapabilityJoinRequest, CredentialType, DepositCapability,
    InvitationJoinBinding, JoinRequestBinding, LocalWelcomeDepositEndpoint,
    MAX_CAPABILITY_JOIN_REQUEST_BYTES, MAX_JOIN_KEY_PACKAGE_BYTES,
    MAX_LOCAL_WELCOME_ENDPOINT_BYTES, MAX_PROTECTED_JOIN_CIPHERTEXT_BYTES,
    MAX_PROTECTED_JOIN_REQUEST_BYTES, MlsCiphersuite, MlsKeyPackageBinding, MlsProtocolVersion,
    NestedObjectType, ProtectedJoinRequest,
};

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
    /// A signed, single-use Phase 1 secret-capability invitation.
    SignedCapabilityInvitation = 2,
    /// An HPKE-protected capability join request.
    ProtectedJoinRequest = 3,
}

impl TryFrom<u16> for WireObjectType {
    type Error = WireError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            value if value == Self::OpaqueEnvelope as u16 => Ok(Self::OpaqueEnvelope),
            value if value == Self::SignedCapabilityInvitation as u16 => {
                Ok(Self::SignedCapabilityInvitation)
            }
            value if value == Self::ProtectedJoinRequest as u16 => Ok(Self::ProtectedJoinRequest),
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
        if object_type != WireObjectType::OpaqueEnvelope as u16 {
            return Err(WireError::UnsupportedObjectType(object_type));
        }

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

    /// A signed invitation replay identifier did not have its fixed size.
    #[error("invitation id has invalid length {0}")]
    InvalidInvitationIdLength(usize),

    /// An invitation join challenge did not have its fixed size.
    #[error("join challenge has invalid length {0}")]
    InvalidJoinChallengeLength(usize),

    /// A secret capability did not have its fixed size.
    #[error("secret capability has invalid length {0}")]
    InvalidSecretCapabilityLength(usize),

    /// An invitation verifying key did not have its fixed size.
    #[error("inviter verifying key has invalid length {0}")]
    InvalidVerifyingKeyLength(usize),

    /// An invitation signature did not have its fixed size.
    #[error("invitation signature has invalid length {0}")]
    InvalidSignatureLength(usize),

    /// The signed invitation declares a signature suite this version cannot use.
    #[error("unsupported signature suite {0}")]
    UnsupportedSignatureSuite(u16),

    /// The signed invitation declares an admission mode this version cannot use.
    #[error("unsupported admission mode {0}")]
    UnsupportedAdmissionMode(u16),

    /// The signed invitation declares a use policy this version cannot use.
    #[error("unsupported invitation use policy {0}")]
    UnsupportedInvitationUsePolicy(u16),

    /// The signed invitation declares an unsupported HPKE profile.
    #[error("unsupported invitation encryption suite {0}")]
    UnsupportedInvitationEncryptionSuite(u16),

    /// The signed invitation declares an unsupported protected-request schema.
    #[error("unsupported join request schema {0}")]
    UnsupportedJoinRequestSchema(u16),

    /// The signed invitation declares an unsupported application selection.
    #[error("unsupported application protocol version {0}")]
    UnsupportedApplicationProtocolVersion(u16),

    /// The signed invitation declares an unsupported transport profile.
    #[error("unsupported transport profile {0}")]
    UnsupportedTransportProfile(u16),

    /// An invitation identifier used the reserved all-zero value.
    #[error("invitation id must not be all zero")]
    ZeroInvitationId,

    /// A join challenge used the reserved all-zero value.
    #[error("join challenge must not be all zero")]
    ZeroJoinChallenge,

    /// A secret capability used the reserved all-zero value.
    #[error("secret capability must not be all zero")]
    ZeroSecretCapability,

    /// An invitation HPKE key identifier used the reserved all-zero value.
    #[error("invitation encryption key id must not be all zero")]
    ZeroInvitationKeyId,

    /// An invitation HPKE public key used the reserved all-zero value.
    #[error("invitation HPKE public key must not be all zero")]
    ZeroHpkePublicKey,

    /// An invitation HPKE key identifier did not have its fixed size.
    #[error("invitation encryption key id has invalid length {0}")]
    InvalidInvitationKeyIdLength(usize),

    /// An invitation HPKE public key did not have its fixed size.
    #[error("invitation HPKE public key has invalid length {0}")]
    InvalidHpkePublicKeyLength(usize),

    #[error("HPKE encapsulated key has invalid length {0}")]
    InvalidHpkeEncapsulatedKeyLength(usize),

    #[error("protected join ciphertext must not be empty")]
    EmptyProtectedJoinCiphertext,

    #[error("protected join ciphertext size {actual} exceeds maximum {maximum}")]
    ProtectedJoinCiphertextTooLarge { actual: usize, maximum: usize },

    #[error("unsupported admission proof version {0}")]
    UnsupportedAdmissionProofVersion(u16),

    #[error("unsupported MLS protocol version {0}")]
    UnsupportedMlsProtocolVersion(u16),

    #[error("unsupported MLS ciphersuite {0}")]
    UnsupportedMlsCiphersuite(u16),

    #[error("unsupported credential type {0}")]
    UnsupportedCredentialType(u16),

    #[error("transport instance id has invalid length {0}")]
    InvalidTransportInstanceIdLength(usize),

    #[error("mailbox id has invalid length {0}")]
    InvalidMailboxIdLength(usize),

    #[error("deposit capability has invalid length {0}")]
    InvalidDepositCapabilityLength(usize),

    #[error("transport instance id must not be all zero")]
    ZeroTransportInstanceId,

    #[error("mailbox id must not be all zero")]
    ZeroMailboxId,

    #[error("deposit capability must not be all zero")]
    ZeroDepositCapability,

    #[error("join request id has invalid length {0}")]
    InvalidJoinRequestIdLength(usize),

    #[error("join request nonce has invalid length {0}")]
    InvalidRequestNonceLength(usize),

    #[error("KeyPackage reference has invalid length {0}")]
    InvalidKeyPackageReferenceLength(usize),

    #[error("credential identity has invalid length {0}")]
    InvalidCredentialIdentityLength(usize),

    #[error("leaf signature key has invalid length {0}")]
    InvalidLeafSignatureKeyLength(usize),

    #[error("join request id must not be all zero")]
    ZeroJoinRequestId,

    #[error("join request nonce must not be all zero")]
    ZeroRequestNonce,

    #[error("credential identity must not be all zero")]
    ZeroCredentialIdentity,

    #[error("leaf signature key must not be all zero")]
    ZeroLeafSignatureKey,

    #[error("invalid MLS leaf signature key")]
    InvalidLeafSignatureKey,

    #[error("KeyPackage must not be empty")]
    EmptyKeyPackage,

    #[error("KeyPackage size {actual} exceeds maximum {maximum}")]
    KeyPackageTooLarge { actual: usize, maximum: usize },

    #[error("join request expiration {expires_at} must be later than issue time {issued_at}")]
    InvalidJoinRequestTimeRange { issued_at: u64, expires_at: u64 },

    #[error("response endpoint must not outlive the join request")]
    ResponseEndpointOutlivesRequest,

    /// The invitation expiration was not strictly later than its issue time.
    #[error("invitation expiration {expires_at} must be later than issue time {issued_at}")]
    InvalidInvitationTimeRange { issued_at: u64, expires_at: u64 },

    /// The encoded Ed25519 public key could not be parsed.
    #[error("invalid invitation verifying key")]
    InvalidVerifyingKey,

    /// Strict Ed25519 verification failed.
    #[error("invalid invitation signature")]
    InvalidSignature,

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
