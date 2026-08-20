use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use minicbor::{Decoder, Encoder};
use zeroize::{Zeroize, Zeroizing};

use crate::{PROTOCOL_VERSION, WireError, WireObjectType};

/// Maximum encoded size accepted before parsing a signed invitation.
pub const MAX_SIGNED_INVITATION_BYTES: usize = 512;

/// Application-domain prefix for every version 1 invitation signature.
const SIGNED_INVITATION_SIGNATURE_DOMAIN: &[u8] = b"session-chat/signed-invitation/v1\0";
const SIGNED_INVITATION_V2_SIGNATURE_DOMAIN: &[u8] = b"session-chat/signed-invitation/v2\0";

const INVITATION_V2_VERSION: u16 = 2;

const INVITATION_ID_BYTES: usize = 16;
const JOIN_CHALLENGE_BYTES: usize = 32;
const SECRET_CAPABILITY_BYTES: usize = 32;
const VERIFYING_KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const UNSIGNED_INVITATION_FIELDS: u64 = 11;
const SIGNED_INVITATION_FIELDS: u64 = 12;
const UNSIGNED_INVITATION_V2_FIELDS: u64 = 17;
const SIGNED_INVITATION_V2_FIELDS: u64 = 18;
const INVITATION_KEY_ID_BYTES: usize = 16;
const HPKE_PUBLIC_KEY_BYTES: usize = 32;

/// Signature suites supported by the version 1 invitation contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum SignatureSuite {
    /// RFC 8032 Ed25519 with strict verification.
    Ed25519 = 1,
}

impl TryFrom<u16> for SignatureSuite {
    type Error = WireError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            value if value == Self::Ed25519 as u16 => Ok(Self::Ed25519),
            unsupported => Err(WireError::UnsupportedSignatureSuite(unsupported)),
        }
    }
}

/// Admission modes supported by the Phase 1 invitation contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum AdmissionMode {
    /// Possession of the invitation's secret capability permits a join request.
    SecretCapability = 1,
}

impl TryFrom<u16> for AdmissionMode {
    type Error = WireError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            value if value == Self::SecretCapability as u16 => Ok(Self::SecretCapability),
            unsupported => Err(WireError::UnsupportedAdmissionMode(unsupported)),
        }
    }
}

/// Consumption policies supported by the Phase 1 invitation contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum InvitationUsePolicy {
    /// The invitation identifier may be accepted exactly once.
    SingleUse = 1,
}

impl TryFrom<u16> for InvitationUsePolicy {
    type Error = WireError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            value if value == Self::SingleUse as u16 => Ok(Self::SingleUse),
            unsupported => Err(WireError::UnsupportedInvitationUsePolicy(unsupported)),
        }
    }
}

/// Invitation-encryption suites supported by the protected capability join.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum InvitationEncryptionSuite {
    /// RFC 9180 PSK mode with X25519, HKDF-SHA256, and AES-128-GCM.
    X25519HkdfSha256Aes128GcmPsk = 1,
}

impl TryFrom<u16> for InvitationEncryptionSuite {
    type Error = WireError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            value if value == Self::X25519HkdfSha256Aes128GcmPsk as u16 => {
                Ok(Self::X25519HkdfSha256Aes128GcmPsk)
            }
            unsupported => Err(WireError::UnsupportedInvitationEncryptionSuite(unsupported)),
        }
    }
}

/// Protected join-request schema versions supported by invitation v2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum JoinRequestSchemaVersion {
    /// The fixed protected capability join-request schema from ADR 0014.
    V1 = 1,
}

impl TryFrom<u16> for JoinRequestSchemaVersion {
    type Error = WireError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            value if value == Self::V1 as u16 => Ok(Self::V1),
            unsupported => Err(WireError::UnsupportedJoinRequestSchema(unsupported)),
        }
    }
}

/// Application protocol selections supported by the Phase 1 join contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ApplicationProtocolVersion {
    /// Phase 1 Session Chat application selection.
    V1 = 1,
}

impl TryFrom<u16> for ApplicationProtocolVersion {
    type Error = WireError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            value if value == Self::V1 as u16 => Ok(Self::V1),
            unsupported => Err(WireError::UnsupportedApplicationProtocolVersion(
                unsupported,
            )),
        }
    }
}

/// Delivery profiles supported by the local Phase 1 join contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum TransportProfile {
    /// Deterministic in-process delivery only.
    LocalMemory = 1,
}

impl TryFrom<u16> for TransportProfile {
    type Error = WireError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            value if value == Self::LocalMemory as u16 => Ok(Self::LocalMemory),
            unsupported => Err(WireError::UnsupportedTransportProfile(unsupported)),
        }
    }
}

/// A bearer capability whose owned bytes are cleared when dropped.
#[derive(Eq, PartialEq)]
pub struct SecretCapability([u8; SECRET_CAPABILITY_BYTES]);

impl SecretCapability {
    /// Constructs a capability while rejecting the reserved all-zero value.
    pub fn new(bytes: [u8; SECRET_CAPABILITY_BYTES]) -> Result<Self, WireError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(WireError::ZeroSecretCapability);
        }

        Ok(Self(bytes))
    }

    /// Exposes the bearer secret to the admission layer explicitly.
    #[must_use]
    pub const fn expose_secret(&self) -> &[u8; SECRET_CAPABILITY_BYTES] {
        &self.0
    }
}

impl Drop for SecretCapability {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Unsigned fields bound by a version 1 capability invitation signature.
#[derive(Eq, PartialEq)]
pub struct CapabilityInvitationClaims {
    invitation_id: [u8; INVITATION_ID_BYTES],
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    join_challenge: [u8; JOIN_CHALLENGE_BYTES],
    capability: SecretCapability,
}

impl CapabilityInvitationClaims {
    /// Constructs structurally valid claims without reading ambient time.
    pub fn new(
        invitation_id: [u8; INVITATION_ID_BYTES],
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
        join_challenge: [u8; JOIN_CHALLENGE_BYTES],
        capability: SecretCapability,
    ) -> Result<Self, WireError> {
        if invitation_id.iter().all(|byte| *byte == 0) {
            return Err(WireError::ZeroInvitationId);
        }
        if join_challenge.iter().all(|byte| *byte == 0) {
            return Err(WireError::ZeroJoinChallenge);
        }
        if expires_at_unix_seconds <= issued_at_unix_seconds {
            return Err(WireError::InvalidInvitationTimeRange {
                issued_at: issued_at_unix_seconds,
                expires_at: expires_at_unix_seconds,
            });
        }

        Ok(Self {
            invitation_id,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            join_challenge,
            capability,
        })
    }
}

/// Additional signed fields required by the version 2 protected join contract.
#[derive(Eq, PartialEq)]
pub struct CapabilityInvitationV2Claims {
    base: CapabilityInvitationClaims,
    invitation_key_id: [u8; INVITATION_KEY_ID_BYTES],
    hpke_recipient_public_key: [u8; HPKE_PUBLIC_KEY_BYTES],
}

impl CapabilityInvitationV2Claims {
    /// Extends structurally valid capability claims with invitation HPKE context.
    pub fn new(
        base: CapabilityInvitationClaims,
        invitation_key_id: [u8; INVITATION_KEY_ID_BYTES],
        hpke_recipient_public_key: [u8; HPKE_PUBLIC_KEY_BYTES],
    ) -> Result<Self, WireError> {
        if invitation_key_id.iter().all(|byte| *byte == 0) {
            return Err(WireError::ZeroInvitationKeyId);
        }
        if hpke_recipient_public_key.iter().all(|byte| *byte == 0) {
            return Err(WireError::ZeroHpkePublicKey);
        }

        Ok(Self {
            base,
            invitation_key_id,
            hpke_recipient_public_key,
        })
    }
}

/// A canonical Phase 1 capability invitation authenticated by Ed25519.
#[derive(Eq, PartialEq)]
pub struct SignedCapabilityInvitation {
    claims: CapabilityInvitationClaims,
    inviter_verifying_key: [u8; VERIFYING_KEY_BYTES],
    signature: [u8; SIGNATURE_BYTES],
}

impl SignedCapabilityInvitation {
    /// Signs the canonical claims with a caller-owned invitation-scoped key.
    pub fn sign(
        claims: CapabilityInvitationClaims,
        signing_key: &SigningKey,
    ) -> Result<Self, WireError> {
        let inviter_verifying_key = signing_key.verifying_key().to_bytes();
        let signing_input = signing_input(&claims, &inviter_verifying_key)?;
        let signature = signing_key.sign(signing_input.as_slice()).to_bytes();

        Ok(Self {
            claims,
            inviter_verifying_key,
            signature,
        })
    }

    /// Returns the fixed wire object discriminator.
    #[must_use]
    pub const fn object_type(&self) -> WireObjectType {
        WireObjectType::SignedCapabilityInvitation
    }

    /// Returns the fixed signature suite.
    #[must_use]
    pub const fn signature_suite(&self) -> SignatureSuite {
        SignatureSuite::Ed25519
    }

    /// Returns the fixed Phase 1 admission mode.
    #[must_use]
    pub const fn admission_mode(&self) -> AdmissionMode {
        AdmissionMode::SecretCapability
    }

    /// Returns the fixed Phase 1 consumption policy.
    #[must_use]
    pub const fn use_policy(&self) -> InvitationUsePolicy {
        InvitationUsePolicy::SingleUse
    }

    /// Returns the random identifier used for one-time consumption.
    #[must_use]
    pub const fn invitation_id(&self) -> &[u8; INVITATION_ID_BYTES] {
        &self.claims.invitation_id
    }

    /// Returns the absolute Unix issue time in seconds.
    #[must_use]
    pub const fn issued_at_unix_seconds(&self) -> u64 {
        self.claims.issued_at_unix_seconds
    }

    /// Returns the absolute Unix expiration time in seconds.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.claims.expires_at_unix_seconds
    }

    /// Returns the random challenge future admission proofs must bind.
    #[must_use]
    pub const fn join_challenge(&self) -> &[u8; JOIN_CHALLENGE_BYTES] {
        &self.claims.join_challenge
    }

    /// Returns the bearer capability through its explicit secret wrapper.
    #[must_use]
    pub const fn capability(&self) -> &SecretCapability {
        &self.claims.capability
    }

    /// Returns the invitation-scoped Ed25519 verifying key.
    #[must_use]
    pub const fn inviter_verifying_key(&self) -> &[u8; VERIFYING_KEY_BYTES] {
        &self.inviter_verifying_key
    }

    /// Returns the public signature that binds this exact descriptor.
    #[must_use]
    pub const fn signature(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.signature
    }

    /// Encodes the restricted deterministic-CBOR representation from the spec.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, WireError> {
        let mut encoder = Encoder::new(Vec::with_capacity(256));
        encode_fields(
            &mut encoder,
            SIGNED_INVITATION_FIELDS,
            &self.claims,
            &self.inviter_verifying_key,
        )?;
        encoder
            .bytes(&self.signature)
            .map_err(|_| WireError::Encoding)?;

        let encoded = encoder.into_writer();
        if encoded.len() > MAX_SIGNED_INVITATION_BYTES {
            return Err(WireError::WireObjectTooLarge {
                actual: encoded.len(),
                maximum: MAX_SIGNED_INVITATION_BYTES,
            });
        }

        Ok(encoded)
    }

    /// Decodes canonical bytes and strictly verifies their Ed25519 signature.
    pub fn decode_and_verify(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_SIGNED_INVITATION_BYTES {
            return Err(WireError::WireObjectTooLarge {
                actual: bytes.len(),
                maximum: MAX_SIGNED_INVITATION_BYTES,
            });
        }

        let mut decoder = Decoder::new(bytes);
        if decoder.array().map_err(|_| WireError::Malformed)? != Some(SIGNED_INVITATION_FIELDS) {
            return Err(WireError::Malformed);
        }

        let version = decoder.u16().map_err(|_| WireError::Malformed)?;
        if version != PROTOCOL_VERSION {
            return Err(WireError::UnsupportedVersion(version));
        }

        let object_type = decoder.u16().map_err(|_| WireError::Malformed)?;
        if object_type != WireObjectType::SignedCapabilityInvitation as u16 {
            return Err(WireError::UnsupportedObjectType(object_type));
        }

        let signature_suite = decoder.u16().map_err(|_| WireError::Malformed)?;
        SignatureSuite::try_from(signature_suite)?;

        let invitation_id = decode_fixed::<INVITATION_ID_BYTES>(
            &mut decoder,
            WireError::InvalidInvitationIdLength,
        )?;
        let issued_at_unix_seconds = decoder.u64().map_err(|_| WireError::Malformed)?;
        let expires_at_unix_seconds = decoder.u64().map_err(|_| WireError::Malformed)?;

        let admission_mode = decoder.u16().map_err(|_| WireError::Malformed)?;
        AdmissionMode::try_from(admission_mode)?;
        let use_policy = decoder.u16().map_err(|_| WireError::Malformed)?;
        InvitationUsePolicy::try_from(use_policy)?;

        let join_challenge = decode_fixed::<JOIN_CHALLENGE_BYTES>(
            &mut decoder,
            WireError::InvalidJoinChallengeLength,
        )?;
        let capability_bytes = Zeroizing::new(decode_fixed::<SECRET_CAPABILITY_BYTES>(
            &mut decoder,
            WireError::InvalidSecretCapabilityLength,
        )?);
        let inviter_verifying_key = decode_fixed::<VERIFYING_KEY_BYTES>(
            &mut decoder,
            WireError::InvalidVerifyingKeyLength,
        )?;
        let signature =
            decode_fixed::<SIGNATURE_BYTES>(&mut decoder, WireError::InvalidSignatureLength)?;

        if decoder.position() != bytes.len() {
            return Err(WireError::TrailingData);
        }

        let claims = CapabilityInvitationClaims::new(
            invitation_id,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            join_challenge,
            SecretCapability::new(*capability_bytes)?,
        )?;
        let invitation = Self {
            claims,
            inviter_verifying_key,
            signature,
        };

        let canonical = Zeroizing::new(invitation.encode_canonical()?);
        if canonical.as_slice() != bytes {
            return Err(WireError::NonDeterministicEncoding);
        }

        let verifying_key = VerifyingKey::from_bytes(&invitation.inviter_verifying_key)
            .map_err(|_| WireError::InvalidVerifyingKey)?;
        let signing_input = signing_input(&invitation.claims, &invitation.inviter_verifying_key)?;
        verifying_key
            .verify_strict(
                signing_input.as_slice(),
                &Signature::from_bytes(&invitation.signature),
            )
            .map_err(|_| WireError::InvalidSignature)?;

        Ok(invitation)
    }
}

/// A canonical version 2 capability invitation carrying protected-join context.
#[derive(Eq, PartialEq)]
pub struct SignedCapabilityInvitationV2 {
    claims: CapabilityInvitationV2Claims,
    inviter_verifying_key: [u8; VERIFYING_KEY_BYTES],
    signature: [u8; SIGNATURE_BYTES],
}

impl SignedCapabilityInvitationV2 {
    /// Signs the canonical version 2 claims with an invitation-scoped key.
    pub fn sign(
        claims: CapabilityInvitationV2Claims,
        signing_key: &SigningKey,
    ) -> Result<Self, WireError> {
        let inviter_verifying_key = signing_key.verifying_key().to_bytes();
        let signing_input = signing_input_v2(&claims, &inviter_verifying_key)?;
        let signature = signing_key.sign(signing_input.as_slice()).to_bytes();

        Ok(Self {
            claims,
            inviter_verifying_key,
            signature,
        })
    }

    /// Returns the fixed version 2 invitation schema identifier.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        INVITATION_V2_VERSION
    }

    /// Returns the shared signed-invitation wire object discriminator.
    #[must_use]
    pub const fn object_type(&self) -> WireObjectType {
        WireObjectType::SignedCapabilityInvitation
    }

    /// Returns the fixed signature suite.
    #[must_use]
    pub const fn signature_suite(&self) -> SignatureSuite {
        SignatureSuite::Ed25519
    }

    /// Returns the fixed invitation-encryption profile.
    #[must_use]
    pub const fn invitation_encryption_suite(&self) -> InvitationEncryptionSuite {
        InvitationEncryptionSuite::X25519HkdfSha256Aes128GcmPsk
    }

    /// Returns the fixed protected-request schema.
    #[must_use]
    pub const fn join_request_schema(&self) -> JoinRequestSchemaVersion {
        JoinRequestSchemaVersion::V1
    }

    /// Returns the fixed application selection.
    #[must_use]
    pub const fn application_protocol_version(&self) -> ApplicationProtocolVersion {
        ApplicationProtocolVersion::V1
    }

    /// Returns the fixed local transport profile.
    #[must_use]
    pub const fn transport_profile(&self) -> TransportProfile {
        TransportProfile::LocalMemory
    }

    /// Returns the fixed capability admission mode.
    #[must_use]
    pub const fn admission_mode(&self) -> AdmissionMode {
        AdmissionMode::SecretCapability
    }

    /// Returns the fixed single-use policy.
    #[must_use]
    pub const fn use_policy(&self) -> InvitationUsePolicy {
        InvitationUsePolicy::SingleUse
    }

    /// Returns the invitation identifier.
    #[must_use]
    pub const fn invitation_id(&self) -> &[u8; INVITATION_ID_BYTES] {
        &self.claims.base.invitation_id
    }

    /// Returns the absolute issue time.
    #[must_use]
    pub const fn issued_at_unix_seconds(&self) -> u64 {
        self.claims.base.issued_at_unix_seconds
    }

    /// Returns the absolute expiration time.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.claims.base.expires_at_unix_seconds
    }

    /// Returns the invitation join challenge.
    #[must_use]
    pub const fn join_challenge(&self) -> &[u8; JOIN_CHALLENGE_BYTES] {
        &self.claims.base.join_challenge
    }

    /// Returns the HPKE PSK bearer capability through its secret wrapper.
    #[must_use]
    pub const fn capability(&self) -> &SecretCapability {
        &self.claims.base.capability
    }

    /// Returns the invitation-scoped Ed25519 verifying key.
    #[must_use]
    pub const fn inviter_verifying_key(&self) -> &[u8; VERIFYING_KEY_BYTES] {
        &self.inviter_verifying_key
    }

    /// Returns the invitation HPKE key-generation identifier.
    #[must_use]
    pub const fn invitation_key_id(&self) -> &[u8; INVITATION_KEY_ID_BYTES] {
        &self.claims.invitation_key_id
    }

    /// Returns the invitation-scoped X25519 recipient public key bytes.
    #[must_use]
    pub const fn hpke_recipient_public_key(&self) -> &[u8; HPKE_PUBLIC_KEY_BYTES] {
        &self.claims.hpke_recipient_public_key
    }

    /// Returns the Ed25519 signature over the version 2 domain and fields.
    #[must_use]
    pub const fn signature(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.signature
    }

    /// Encodes the exact restricted deterministic-CBOR representation.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, WireError> {
        let mut encoder = Encoder::new(Vec::with_capacity(320));
        encode_fields_v2(
            &mut encoder,
            SIGNED_INVITATION_V2_FIELDS,
            &self.claims,
            &self.inviter_verifying_key,
        )?;
        encoder
            .bytes(&self.signature)
            .map_err(|_| WireError::Encoding)?;

        let encoded = encoder.into_writer();
        if encoded.len() > MAX_SIGNED_INVITATION_BYTES {
            return Err(WireError::WireObjectTooLarge {
                actual: encoded.len(),
                maximum: MAX_SIGNED_INVITATION_BYTES,
            });
        }
        Ok(encoded)
    }

    /// Decodes canonical version 2 bytes and strictly verifies their signature.
    pub fn decode_and_verify(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_SIGNED_INVITATION_BYTES {
            return Err(WireError::WireObjectTooLarge {
                actual: bytes.len(),
                maximum: MAX_SIGNED_INVITATION_BYTES,
            });
        }

        let mut decoder = Decoder::new(bytes);
        if decoder.array().map_err(|_| WireError::Malformed)? != Some(SIGNED_INVITATION_V2_FIELDS) {
            return Err(WireError::Malformed);
        }

        let version = decoder.u16().map_err(|_| WireError::Malformed)?;
        if version != INVITATION_V2_VERSION {
            return Err(WireError::UnsupportedVersion(version));
        }
        let object_type = decoder.u16().map_err(|_| WireError::Malformed)?;
        if object_type != WireObjectType::SignedCapabilityInvitation as u16 {
            return Err(WireError::UnsupportedObjectType(object_type));
        }

        SignatureSuite::try_from(decoder.u16().map_err(|_| WireError::Malformed)?)?;
        InvitationEncryptionSuite::try_from(decoder.u16().map_err(|_| WireError::Malformed)?)?;
        JoinRequestSchemaVersion::try_from(decoder.u16().map_err(|_| WireError::Malformed)?)?;
        ApplicationProtocolVersion::try_from(decoder.u16().map_err(|_| WireError::Malformed)?)?;
        TransportProfile::try_from(decoder.u16().map_err(|_| WireError::Malformed)?)?;

        let invitation_id = decode_fixed::<INVITATION_ID_BYTES>(
            &mut decoder,
            WireError::InvalidInvitationIdLength,
        )?;
        let issued_at_unix_seconds = decoder.u64().map_err(|_| WireError::Malformed)?;
        let expires_at_unix_seconds = decoder.u64().map_err(|_| WireError::Malformed)?;
        AdmissionMode::try_from(decoder.u16().map_err(|_| WireError::Malformed)?)?;
        InvitationUsePolicy::try_from(decoder.u16().map_err(|_| WireError::Malformed)?)?;

        let join_challenge = decode_fixed::<JOIN_CHALLENGE_BYTES>(
            &mut decoder,
            WireError::InvalidJoinChallengeLength,
        )?;
        let capability_bytes = Zeroizing::new(decode_fixed::<SECRET_CAPABILITY_BYTES>(
            &mut decoder,
            WireError::InvalidSecretCapabilityLength,
        )?);
        let inviter_verifying_key = decode_fixed::<VERIFYING_KEY_BYTES>(
            &mut decoder,
            WireError::InvalidVerifyingKeyLength,
        )?;
        let invitation_key_id = decode_fixed::<INVITATION_KEY_ID_BYTES>(
            &mut decoder,
            WireError::InvalidInvitationKeyIdLength,
        )?;
        let hpke_recipient_public_key = decode_fixed::<HPKE_PUBLIC_KEY_BYTES>(
            &mut decoder,
            WireError::InvalidHpkePublicKeyLength,
        )?;
        let signature =
            decode_fixed::<SIGNATURE_BYTES>(&mut decoder, WireError::InvalidSignatureLength)?;

        if decoder.position() != bytes.len() {
            return Err(WireError::TrailingData);
        }

        let base = CapabilityInvitationClaims::new(
            invitation_id,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            join_challenge,
            SecretCapability::new(*capability_bytes)?,
        )?;
        let claims =
            CapabilityInvitationV2Claims::new(base, invitation_key_id, hpke_recipient_public_key)?;
        let invitation = Self {
            claims,
            inviter_verifying_key,
            signature,
        };

        let canonical = Zeroizing::new(invitation.encode_canonical()?);
        if canonical.as_slice() != bytes {
            return Err(WireError::NonDeterministicEncoding);
        }

        let verifying_key = VerifyingKey::from_bytes(&invitation.inviter_verifying_key)
            .map_err(|_| WireError::InvalidVerifyingKey)?;
        let signing_input =
            signing_input_v2(&invitation.claims, &invitation.inviter_verifying_key)?;
        verifying_key
            .verify_strict(
                signing_input.as_slice(),
                &Signature::from_bytes(&invitation.signature),
            )
            .map_err(|_| WireError::InvalidSignature)?;

        Ok(invitation)
    }
}

fn signing_input(
    claims: &CapabilityInvitationClaims,
    inviter_verifying_key: &[u8; VERIFYING_KEY_BYTES],
) -> Result<Zeroizing<Vec<u8>>, WireError> {
    let mut encoder = Encoder::new(Vec::with_capacity(192));
    encode_fields(
        &mut encoder,
        UNSIGNED_INVITATION_FIELDS,
        claims,
        inviter_verifying_key,
    )?;

    let unsigned = Zeroizing::new(encoder.into_writer());
    let mut input = Zeroizing::new(Vec::with_capacity(
        SIGNED_INVITATION_SIGNATURE_DOMAIN.len() + unsigned.len(),
    ));
    input.extend_from_slice(SIGNED_INVITATION_SIGNATURE_DOMAIN);
    input.extend_from_slice(unsigned.as_slice());
    Ok(input)
}

fn encode_fields(
    encoder: &mut Encoder<Vec<u8>>,
    field_count: u64,
    claims: &CapabilityInvitationClaims,
    inviter_verifying_key: &[u8; VERIFYING_KEY_BYTES],
) -> Result<(), WireError> {
    encoder
        .array(field_count)
        .and_then(|encoder| encoder.u16(PROTOCOL_VERSION))
        .and_then(|encoder| encoder.u16(WireObjectType::SignedCapabilityInvitation as u16))
        .and_then(|encoder| encoder.u16(SignatureSuite::Ed25519 as u16))
        .and_then(|encoder| encoder.bytes(&claims.invitation_id))
        .and_then(|encoder| encoder.u64(claims.issued_at_unix_seconds))
        .and_then(|encoder| encoder.u64(claims.expires_at_unix_seconds))
        .and_then(|encoder| encoder.u16(AdmissionMode::SecretCapability as u16))
        .and_then(|encoder| encoder.u16(InvitationUsePolicy::SingleUse as u16))
        .and_then(|encoder| encoder.bytes(&claims.join_challenge))
        .and_then(|encoder| encoder.bytes(claims.capability.expose_secret()))
        .and_then(|encoder| encoder.bytes(inviter_verifying_key))
        .map_err(|_| WireError::Encoding)?;
    Ok(())
}

fn signing_input_v2(
    claims: &CapabilityInvitationV2Claims,
    inviter_verifying_key: &[u8; VERIFYING_KEY_BYTES],
) -> Result<Zeroizing<Vec<u8>>, WireError> {
    let mut encoder = Encoder::new(Vec::with_capacity(256));
    encode_fields_v2(
        &mut encoder,
        UNSIGNED_INVITATION_V2_FIELDS,
        claims,
        inviter_verifying_key,
    )?;

    let unsigned = Zeroizing::new(encoder.into_writer());
    let mut input = Zeroizing::new(Vec::with_capacity(
        SIGNED_INVITATION_V2_SIGNATURE_DOMAIN.len() + unsigned.len(),
    ));
    input.extend_from_slice(SIGNED_INVITATION_V2_SIGNATURE_DOMAIN);
    input.extend_from_slice(unsigned.as_slice());
    Ok(input)
}

fn encode_fields_v2(
    encoder: &mut Encoder<Vec<u8>>,
    field_count: u64,
    claims: &CapabilityInvitationV2Claims,
    inviter_verifying_key: &[u8; VERIFYING_KEY_BYTES],
) -> Result<(), WireError> {
    encoder
        .array(field_count)
        .and_then(|encoder| encoder.u16(INVITATION_V2_VERSION))
        .and_then(|encoder| encoder.u16(WireObjectType::SignedCapabilityInvitation as u16))
        .and_then(|encoder| encoder.u16(SignatureSuite::Ed25519 as u16))
        .and_then(|encoder| {
            encoder.u16(InvitationEncryptionSuite::X25519HkdfSha256Aes128GcmPsk as u16)
        })
        .and_then(|encoder| encoder.u16(JoinRequestSchemaVersion::V1 as u16))
        .and_then(|encoder| encoder.u16(ApplicationProtocolVersion::V1 as u16))
        .and_then(|encoder| encoder.u16(TransportProfile::LocalMemory as u16))
        .and_then(|encoder| encoder.bytes(&claims.base.invitation_id))
        .and_then(|encoder| encoder.u64(claims.base.issued_at_unix_seconds))
        .and_then(|encoder| encoder.u64(claims.base.expires_at_unix_seconds))
        .and_then(|encoder| encoder.u16(AdmissionMode::SecretCapability as u16))
        .and_then(|encoder| encoder.u16(InvitationUsePolicy::SingleUse as u16))
        .and_then(|encoder| encoder.bytes(&claims.base.join_challenge))
        .and_then(|encoder| encoder.bytes(claims.base.capability.expose_secret()))
        .and_then(|encoder| encoder.bytes(inviter_verifying_key))
        .and_then(|encoder| encoder.bytes(&claims.invitation_key_id))
        .and_then(|encoder| encoder.bytes(&claims.hpke_recipient_public_key))
        .map_err(|_| WireError::Encoding)?;
    Ok(())
}

fn decode_fixed<const N: usize>(
    decoder: &mut Decoder<'_>,
    length_error: fn(usize) -> WireError,
) -> Result<[u8; N], WireError> {
    let encoded = decoder.bytes().map_err(|_| WireError::Malformed)?;
    if encoded.len() != N {
        return Err(length_error(encoded.len()));
    }

    let mut bytes = [0; N];
    bytes.copy_from_slice(encoded);
    Ok(bytes)
}
