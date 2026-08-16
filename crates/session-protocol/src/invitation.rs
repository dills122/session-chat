use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use minicbor::{Decoder, Encoder};
use zeroize::{Zeroize, Zeroizing};

use crate::{PROTOCOL_VERSION, WireError, WireObjectType};

/// Maximum encoded size accepted before parsing a signed invitation.
pub const MAX_SIGNED_INVITATION_BYTES: usize = 512;

/// Application-domain prefix for every version 1 invitation signature.
const SIGNED_INVITATION_SIGNATURE_DOMAIN: &[u8] = b"session-chat/signed-invitation/v1\0";

const INVITATION_ID_BYTES: usize = 16;
const JOIN_CHALLENGE_BYTES: usize = 32;
const SECRET_CAPABILITY_BYTES: usize = 32;
const VERIFYING_KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const UNSIGNED_INVITATION_FIELDS: u64 = 11;
const SIGNED_INVITATION_FIELDS: u64 = 12;

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

/// A bearer capability whose owned bytes are cleared when dropped.
#[derive(Clone, Eq, PartialEq)]
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
#[derive(Clone, Eq, PartialEq)]
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

/// A canonical Phase 1 capability invitation authenticated by Ed25519.
#[derive(Clone, Eq, PartialEq)]
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
        let capability_bytes = decode_fixed::<SECRET_CAPABILITY_BYTES>(
            &mut decoder,
            WireError::InvalidSecretCapabilityLength,
        )?;
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
            SecretCapability::new(capability_bytes)?,
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
