use ed25519_dalek::VerifyingKey;
use minicbor::{Decoder, Encoder};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    ApplicationProtocolVersion, InvitationEncryptionSuite, TransportProfile, WireError,
    WireObjectType,
};

pub const MAX_LOCAL_WELCOME_ENDPOINT_BYTES: usize = 128;
pub const MAX_CAPABILITY_JOIN_REQUEST_BYTES: usize = 24 * 1024;
pub const MAX_JOIN_KEY_PACKAGE_BYTES: usize = 16 * 1024;
pub const MAX_PROTECTED_JOIN_REQUEST_BYTES: usize = 32 * 1024;
pub const MAX_PROTECTED_JOIN_CIPHERTEXT_BYTES: usize = MAX_PROTECTED_JOIN_REQUEST_BYTES - 75;

const LOCAL_WELCOME_ENDPOINT_VERSION: u16 = 1;
const CAPABILITY_JOIN_REQUEST_VERSION: u16 = 1;
const PROTECTED_JOIN_REQUEST_VERSION: u16 = 1;
const LOCAL_WELCOME_ENDPOINT_FIELDS: u64 = 7;
const CAPABILITY_JOIN_REQUEST_FIELDS: u64 = 21;
const PROTECTED_JOIN_REQUEST_FIELDS: u64 = 7;
const PROTECTED_JOIN_AAD_FIELDS: u64 = 6;
const IDENTIFIER_BYTES: usize = 16;
const FIXED_KEY_BYTES: usize = 32;
const DEPOSIT_CAPABILITY_BYTES: usize = 32;

/// Object identifiers used only inside another protected protocol object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum NestedObjectType {
    /// The canonical decrypted capability join request.
    CapabilityJoinRequest = 4,
    /// A deposit-only local response endpoint for one Welcome.
    LocalWelcomeDepositEndpoint = 5,
}

/// Capability-proof versions supported by the first protected join schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum AdmissionProofVersion {
    /// RFC 9180 PSK opening proves possession for the exact bound context.
    HpkePskCapability = 1,
}

impl TryFrom<u16> for AdmissionProofVersion {
    type Error = WireError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            value if value == Self::HpkePskCapability as u16 => Ok(Self::HpkePskCapability),
            unsupported => Err(WireError::UnsupportedAdmissionProofVersion(unsupported)),
        }
    }
}

/// MLS protocol versions supported by the first protected join schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum MlsProtocolVersion {
    /// RFC 9420 MLS 1.0.
    Mls10 = 1,
}

impl TryFrom<u16> for MlsProtocolVersion {
    type Error = WireError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            value if value == Self::Mls10 as u16 => Ok(Self::Mls10),
            unsupported => Err(WireError::UnsupportedMlsProtocolVersion(unsupported)),
        }
    }
}

/// MLS ciphersuites supported by the first protected join schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum MlsCiphersuite {
    /// MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.
    Suite1 = 1,
}

impl TryFrom<u16> for MlsCiphersuite {
    type Error = WireError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            value if value == Self::Suite1 as u16 => Ok(Self::Suite1),
            unsupported => Err(WireError::UnsupportedMlsCiphersuite(unsupported)),
        }
    }
}

/// Credential encodings supported by the first protected join schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum CredentialType {
    /// RFC 9420 BasicCredential with a session-scoped identity.
    Basic = 1,
}

impl TryFrom<u16> for CredentialType {
    type Error = WireError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            value if value == Self::Basic as u16 => Ok(Self::Basic),
            unsupported => Err(WireError::UnsupportedCredentialType(unsupported)),
        }
    }
}

/// A bounded HPKE-protected capability join request.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedJoinRequest {
    invitation_id: [u8; IDENTIFIER_BYTES],
    invitation_key_id: [u8; IDENTIFIER_BYTES],
    encapsulated_key: [u8; FIXED_KEY_BYTES],
    ciphertext: Vec<u8>,
}

impl ProtectedJoinRequest {
    pub fn new(
        invitation_id: [u8; IDENTIFIER_BYTES],
        invitation_key_id: [u8; IDENTIFIER_BYTES],
        encapsulated_key: [u8; FIXED_KEY_BYTES],
        ciphertext: Vec<u8>,
    ) -> Result<Self, WireError> {
        reject_zero(&invitation_id, WireError::ZeroInvitationId)?;
        reject_zero(&invitation_key_id, WireError::ZeroInvitationKeyId)?;
        if ciphertext.is_empty() {
            return Err(WireError::EmptyProtectedJoinCiphertext);
        }
        if ciphertext.len() > MAX_PROTECTED_JOIN_CIPHERTEXT_BYTES {
            return Err(WireError::ProtectedJoinCiphertextTooLarge {
                actual: ciphertext.len(),
                maximum: MAX_PROTECTED_JOIN_CIPHERTEXT_BYTES,
            });
        }
        Ok(Self {
            invitation_id,
            invitation_key_id,
            encapsulated_key,
            ciphertext,
        })
    }

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        PROTECTED_JOIN_REQUEST_VERSION
    }

    #[must_use]
    pub const fn object_type(&self) -> WireObjectType {
        WireObjectType::ProtectedJoinRequest
    }

    #[must_use]
    pub const fn invitation_encryption_suite(&self) -> InvitationEncryptionSuite {
        InvitationEncryptionSuite::X25519HkdfSha256Aes128GcmPsk
    }

    #[must_use]
    pub const fn invitation_id(&self) -> &[u8; IDENTIFIER_BYTES] {
        &self.invitation_id
    }

    #[must_use]
    pub const fn invitation_key_id(&self) -> &[u8; IDENTIFIER_BYTES] {
        &self.invitation_key_id
    }

    #[must_use]
    pub const fn encapsulated_key(&self) -> &[u8; FIXED_KEY_BYTES] {
        &self.encapsulated_key
    }

    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Returns the canonical six-field HPKE associated data.
    pub fn aad_canonical(&self) -> Result<Vec<u8>, WireError> {
        self.encode_prefix(PROTECTED_JOIN_AAD_FIELDS)
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>, WireError> {
        let mut encoder = Encoder::new(self.encode_prefix(PROTECTED_JOIN_REQUEST_FIELDS)?);
        encoder
            .bytes(&self.ciphertext)
            .map_err(|_| WireError::Encoding)?;
        let encoded = encoder.into_writer();
        if encoded.len() > MAX_PROTECTED_JOIN_REQUEST_BYTES {
            return Err(WireError::WireObjectTooLarge {
                actual: encoded.len(),
                maximum: MAX_PROTECTED_JOIN_REQUEST_BYTES,
            });
        }
        Ok(encoded)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, WireError> {
        prebound(bytes, MAX_PROTECTED_JOIN_REQUEST_BYTES)?;
        let mut decoder = Decoder::new(bytes);
        require_array(&mut decoder, PROTECTED_JOIN_REQUEST_FIELDS)?;
        require_value(
            &mut decoder,
            PROTECTED_JOIN_REQUEST_VERSION,
            WireError::UnsupportedVersion,
        )?;
        require_value(
            &mut decoder,
            WireObjectType::ProtectedJoinRequest as u16,
            WireError::UnsupportedObjectType,
        )?;
        InvitationEncryptionSuite::try_from(decoder.u16().map_err(|_| WireError::Malformed)?)?;
        let invitation_id =
            decode_fixed::<IDENTIFIER_BYTES>(&mut decoder, WireError::InvalidInvitationIdLength)?;
        let invitation_key_id = decode_fixed::<IDENTIFIER_BYTES>(
            &mut decoder,
            WireError::InvalidInvitationKeyIdLength,
        )?;
        let encapsulated_key = decode_fixed::<FIXED_KEY_BYTES>(
            &mut decoder,
            WireError::InvalidHpkeEncapsulatedKeyLength,
        )?;
        let ciphertext = decoder.bytes().map_err(|_| WireError::Malformed)?;
        if ciphertext.is_empty() {
            return Err(WireError::EmptyProtectedJoinCiphertext);
        }
        if ciphertext.len() > MAX_PROTECTED_JOIN_CIPHERTEXT_BYTES {
            return Err(WireError::ProtectedJoinCiphertextTooLarge {
                actual: ciphertext.len(),
                maximum: MAX_PROTECTED_JOIN_CIPHERTEXT_BYTES,
            });
        }
        reject_trailing(&decoder, bytes)?;

        let decoded = Self::new(
            invitation_id,
            invitation_key_id,
            encapsulated_key,
            ciphertext.to_vec(),
        )?;
        if decoded.encode_canonical()?.as_slice() != bytes {
            return Err(WireError::NonDeterministicEncoding);
        }
        Ok(decoded)
    }

    fn encode_prefix(&self, fields: u64) -> Result<Vec<u8>, WireError> {
        let mut encoder = Encoder::new(Vec::with_capacity(96));
        encoder
            .array(fields)
            .and_then(|encoder| encoder.u16(PROTECTED_JOIN_REQUEST_VERSION))
            .and_then(|encoder| encoder.u16(WireObjectType::ProtectedJoinRequest as u16))
            .and_then(|encoder| {
                encoder.u16(InvitationEncryptionSuite::X25519HkdfSha256Aes128GcmPsk as u16)
            })
            .and_then(|encoder| encoder.bytes(&self.invitation_id))
            .and_then(|encoder| encoder.bytes(&self.invitation_key_id))
            .and_then(|encoder| encoder.bytes(&self.encapsulated_key))
            .map_err(|_| WireError::Encoding)?;
        Ok(encoder.into_writer())
    }
}

/// A bearer authority that can deposit only into one local Welcome mailbox.
#[derive(Eq, PartialEq)]
pub struct DepositCapability([u8; DEPOSIT_CAPABILITY_BYTES]);

impl DepositCapability {
    pub fn new(bytes: [u8; DEPOSIT_CAPABILITY_BYTES]) -> Result<Self, WireError> {
        reject_zero(&bytes, WireError::ZeroDepositCapability)?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn expose_secret(&self) -> &[u8; DEPOSIT_CAPABILITY_BYTES] {
        &self.0
    }
}

impl Drop for DepositCapability {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A closed local response descriptor carrying deposit authority only.
#[derive(Eq, PartialEq)]
pub struct LocalWelcomeDepositEndpoint {
    transport_instance_id: [u8; IDENTIFIER_BYTES],
    mailbox_id: [u8; IDENTIFIER_BYTES],
    deposit_capability: DepositCapability,
    expires_at_unix_seconds: u64,
}

impl LocalWelcomeDepositEndpoint {
    pub fn new(
        transport_instance_id: [u8; IDENTIFIER_BYTES],
        mailbox_id: [u8; IDENTIFIER_BYTES],
        deposit_capability: DepositCapability,
        expires_at_unix_seconds: u64,
    ) -> Result<Self, WireError> {
        reject_zero(&transport_instance_id, WireError::ZeroTransportInstanceId)?;
        reject_zero(&mailbox_id, WireError::ZeroMailboxId)?;
        Ok(Self {
            transport_instance_id,
            mailbox_id,
            deposit_capability,
            expires_at_unix_seconds,
        })
    }

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        LOCAL_WELCOME_ENDPOINT_VERSION
    }

    #[must_use]
    pub const fn object_type(&self) -> NestedObjectType {
        NestedObjectType::LocalWelcomeDepositEndpoint
    }

    #[must_use]
    pub const fn transport_profile(&self) -> TransportProfile {
        TransportProfile::LocalMemory
    }

    #[must_use]
    pub const fn transport_instance_id(&self) -> &[u8; IDENTIFIER_BYTES] {
        &self.transport_instance_id
    }

    #[must_use]
    pub const fn mailbox_id(&self) -> &[u8; IDENTIFIER_BYTES] {
        &self.mailbox_id
    }

    #[must_use]
    pub const fn deposit_capability(&self) -> &DepositCapability {
        &self.deposit_capability
    }

    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>, WireError> {
        let mut encoder = Encoder::new(Vec::with_capacity(96));
        self.encode_into(&mut encoder)?;
        let encoded = encoder.into_writer();
        if encoded.len() > MAX_LOCAL_WELCOME_ENDPOINT_BYTES {
            return Err(WireError::WireObjectTooLarge {
                actual: encoded.len(),
                maximum: MAX_LOCAL_WELCOME_ENDPOINT_BYTES,
            });
        }
        Ok(encoded)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, WireError> {
        prebound(bytes, MAX_LOCAL_WELCOME_ENDPOINT_BYTES)?;
        let mut decoder = Decoder::new(bytes);
        let endpoint = Self::decode_from(&mut decoder)?;
        reject_trailing(&decoder, bytes)?;
        if endpoint.encode_canonical()?.as_slice() != bytes {
            return Err(WireError::NonDeterministicEncoding);
        }
        Ok(endpoint)
    }

    fn encode_into(&self, encoder: &mut Encoder<Vec<u8>>) -> Result<(), WireError> {
        encoder
            .array(LOCAL_WELCOME_ENDPOINT_FIELDS)
            .and_then(|encoder| encoder.u16(LOCAL_WELCOME_ENDPOINT_VERSION))
            .and_then(|encoder| encoder.u16(NestedObjectType::LocalWelcomeDepositEndpoint as u16))
            .and_then(|encoder| encoder.u16(TransportProfile::LocalMemory as u16))
            .and_then(|encoder| encoder.bytes(&self.transport_instance_id))
            .and_then(|encoder| encoder.bytes(&self.mailbox_id))
            .and_then(|encoder| encoder.bytes(self.deposit_capability.expose_secret()))
            .and_then(|encoder| encoder.u64(self.expires_at_unix_seconds))
            .map_err(|_| WireError::Encoding)?;
        Ok(())
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, WireError> {
        require_array(decoder, LOCAL_WELCOME_ENDPOINT_FIELDS)?;
        require_value(
            decoder,
            LOCAL_WELCOME_ENDPOINT_VERSION,
            WireError::UnsupportedVersion,
        )?;
        require_value(
            decoder,
            NestedObjectType::LocalWelcomeDepositEndpoint as u16,
            WireError::UnsupportedObjectType,
        )?;
        TransportProfile::try_from(decoder.u16().map_err(|_| WireError::Malformed)?)?;
        let transport_instance_id =
            decode_fixed::<IDENTIFIER_BYTES>(decoder, WireError::InvalidTransportInstanceIdLength)?;
        let mailbox_id =
            decode_fixed::<IDENTIFIER_BYTES>(decoder, WireError::InvalidMailboxIdLength)?;
        let capability = Zeroizing::new(decode_fixed::<DEPOSIT_CAPABILITY_BYTES>(
            decoder,
            WireError::InvalidDepositCapabilityLength,
        )?);
        let expires_at_unix_seconds = decoder.u64().map_err(|_| WireError::Malformed)?;
        Self::new(
            transport_instance_id,
            mailbox_id,
            DepositCapability::new(*capability)?,
            expires_at_unix_seconds,
        )
    }
}

/// Invitation-generation values repeated inside the protected request.
#[derive(Eq, PartialEq)]
pub struct InvitationJoinBinding {
    invitation_id: [u8; IDENTIFIER_BYTES],
    join_challenge: [u8; FIXED_KEY_BYTES],
    invitation_key_id: [u8; IDENTIFIER_BYTES],
    intended_verifier: [u8; FIXED_KEY_BYTES],
}

impl InvitationJoinBinding {
    pub fn new(
        invitation_id: [u8; IDENTIFIER_BYTES],
        join_challenge: [u8; FIXED_KEY_BYTES],
        invitation_key_id: [u8; IDENTIFIER_BYTES],
        intended_verifier: [u8; FIXED_KEY_BYTES],
    ) -> Result<Self, WireError> {
        reject_zero(&invitation_id, WireError::ZeroInvitationId)?;
        reject_zero(&join_challenge, WireError::ZeroJoinChallenge)?;
        reject_zero(&invitation_key_id, WireError::ZeroInvitationKeyId)?;
        let intended_verifier = VerifyingKey::from_bytes(&intended_verifier)
            .map_err(|_| WireError::InvalidVerifyingKey)?;
        if intended_verifier.is_weak() {
            return Err(WireError::InvalidVerifyingKey);
        }
        Ok(Self {
            invitation_id,
            join_challenge,
            invitation_key_id,
            intended_verifier: intended_verifier.to_bytes(),
        })
    }
}

/// Fresh replay and validity values for one protected join request.
#[derive(Eq, PartialEq)]
pub struct JoinRequestBinding {
    join_request_id: [u8; IDENTIFIER_BYTES],
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    request_nonce: [u8; FIXED_KEY_BYTES],
}

impl JoinRequestBinding {
    pub fn new(
        join_request_id: [u8; IDENTIFIER_BYTES],
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
        request_nonce: [u8; FIXED_KEY_BYTES],
    ) -> Result<Self, WireError> {
        reject_zero(&join_request_id, WireError::ZeroJoinRequestId)?;
        reject_zero(&request_nonce, WireError::ZeroRequestNonce)?;
        if expires_at_unix_seconds <= issued_at_unix_seconds {
            return Err(WireError::InvalidJoinRequestTimeRange {
                issued_at: issued_at_unix_seconds,
                expires_at: expires_at_unix_seconds,
            });
        }
        Ok(Self {
            join_request_id,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            request_nonce,
        })
    }
}

/// Exact MLS KeyPackage values that admission must compare after validation.
#[derive(Eq, PartialEq)]
pub struct MlsKeyPackageBinding {
    key_package_reference: [u8; FIXED_KEY_BYTES],
    key_package: Vec<u8>,
    credential_identity: [u8; FIXED_KEY_BYTES],
    leaf_signature_key: [u8; FIXED_KEY_BYTES],
}

impl MlsKeyPackageBinding {
    pub fn new(
        key_package_reference: [u8; FIXED_KEY_BYTES],
        key_package: Vec<u8>,
        credential_identity: [u8; FIXED_KEY_BYTES],
        leaf_signature_key: [u8; FIXED_KEY_BYTES],
    ) -> Result<Self, WireError> {
        if key_package.is_empty() {
            return Err(WireError::EmptyKeyPackage);
        }
        if key_package.len() > MAX_JOIN_KEY_PACKAGE_BYTES {
            return Err(WireError::KeyPackageTooLarge {
                actual: key_package.len(),
                maximum: MAX_JOIN_KEY_PACKAGE_BYTES,
            });
        }
        reject_zero(&credential_identity, WireError::ZeroCredentialIdentity)?;
        reject_zero(&leaf_signature_key, WireError::ZeroLeafSignatureKey)?;
        let leaf_signature_key = VerifyingKey::from_bytes(&leaf_signature_key)
            .map_err(|_| WireError::InvalidLeafSignatureKey)?;
        if leaf_signature_key.is_weak() {
            return Err(WireError::InvalidLeafSignatureKey);
        }
        Ok(Self {
            key_package_reference,
            key_package,
            credential_identity,
            leaf_signature_key: leaf_signature_key.to_bytes(),
        })
    }
}

/// Canonical decrypted capability request from ADR 0014.
#[derive(Eq, PartialEq)]
pub struct CapabilityJoinRequest {
    invitation: InvitationJoinBinding,
    request: JoinRequestBinding,
    mls: MlsKeyPackageBinding,
    response_endpoint: LocalWelcomeDepositEndpoint,
}

impl CapabilityJoinRequest {
    pub fn new(
        invitation: InvitationJoinBinding,
        request: JoinRequestBinding,
        mls: MlsKeyPackageBinding,
        response_endpoint: LocalWelcomeDepositEndpoint,
    ) -> Result<Self, WireError> {
        if response_endpoint.expires_at_unix_seconds > request.expires_at_unix_seconds {
            return Err(WireError::ResponseEndpointOutlivesRequest);
        }
        Ok(Self {
            invitation,
            request,
            mls,
            response_endpoint,
        })
    }

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        CAPABILITY_JOIN_REQUEST_VERSION
    }

    #[must_use]
    pub const fn object_type(&self) -> NestedObjectType {
        NestedObjectType::CapabilityJoinRequest
    }

    #[must_use]
    pub const fn admission_proof_version(&self) -> AdmissionProofVersion {
        AdmissionProofVersion::HpkePskCapability
    }

    #[must_use]
    pub const fn invitation_id(&self) -> &[u8; IDENTIFIER_BYTES] {
        &self.invitation.invitation_id
    }

    #[must_use]
    pub const fn join_challenge(&self) -> &[u8; FIXED_KEY_BYTES] {
        &self.invitation.join_challenge
    }

    #[must_use]
    pub const fn invitation_key_id(&self) -> &[u8; IDENTIFIER_BYTES] {
        &self.invitation.invitation_key_id
    }

    #[must_use]
    pub const fn intended_verifier(&self) -> &[u8; FIXED_KEY_BYTES] {
        &self.invitation.intended_verifier
    }

    #[must_use]
    pub const fn join_request_id(&self) -> &[u8; IDENTIFIER_BYTES] {
        &self.request.join_request_id
    }

    #[must_use]
    pub const fn issued_at_unix_seconds(&self) -> u64 {
        self.request.issued_at_unix_seconds
    }

    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.request.expires_at_unix_seconds
    }

    #[must_use]
    pub const fn request_nonce(&self) -> &[u8; FIXED_KEY_BYTES] {
        &self.request.request_nonce
    }

    #[must_use]
    pub const fn mls_protocol_version(&self) -> MlsProtocolVersion {
        MlsProtocolVersion::Mls10
    }

    #[must_use]
    pub const fn mls_ciphersuite(&self) -> MlsCiphersuite {
        MlsCiphersuite::Suite1
    }

    #[must_use]
    pub const fn key_package_reference(&self) -> &[u8; FIXED_KEY_BYTES] {
        &self.mls.key_package_reference
    }

    #[must_use]
    pub fn key_package(&self) -> &[u8] {
        &self.mls.key_package
    }

    #[must_use]
    pub const fn credential_type(&self) -> CredentialType {
        CredentialType::Basic
    }

    #[must_use]
    pub const fn credential_identity(&self) -> &[u8; FIXED_KEY_BYTES] {
        &self.mls.credential_identity
    }

    #[must_use]
    pub const fn leaf_signature_key(&self) -> &[u8; FIXED_KEY_BYTES] {
        &self.mls.leaf_signature_key
    }

    #[must_use]
    pub const fn application_protocol_version(&self) -> ApplicationProtocolVersion {
        ApplicationProtocolVersion::V1
    }

    #[must_use]
    pub const fn transport_profile(&self) -> TransportProfile {
        TransportProfile::LocalMemory
    }

    #[must_use]
    pub const fn response_endpoint(&self) -> &LocalWelcomeDepositEndpoint {
        &self.response_endpoint
    }

    /// Moves the deposit-only response endpoint out of the authenticated request.
    #[must_use]
    pub fn into_response_endpoint(self) -> LocalWelcomeDepositEndpoint {
        self.response_endpoint
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>, WireError> {
        let mut encoder = Encoder::new(Vec::with_capacity(self.mls.key_package.len() + 320));
        encoder
            .array(CAPABILITY_JOIN_REQUEST_FIELDS)
            .and_then(|encoder| encoder.u16(CAPABILITY_JOIN_REQUEST_VERSION))
            .and_then(|encoder| encoder.u16(NestedObjectType::CapabilityJoinRequest as u16))
            .and_then(|encoder| encoder.u16(AdmissionProofVersion::HpkePskCapability as u16))
            .and_then(|encoder| encoder.bytes(&self.invitation.invitation_id))
            .and_then(|encoder| encoder.bytes(&self.invitation.join_challenge))
            .and_then(|encoder| encoder.bytes(&self.invitation.invitation_key_id))
            .and_then(|encoder| encoder.bytes(&self.invitation.intended_verifier))
            .and_then(|encoder| encoder.bytes(&self.request.join_request_id))
            .and_then(|encoder| encoder.u64(self.request.issued_at_unix_seconds))
            .and_then(|encoder| encoder.u64(self.request.expires_at_unix_seconds))
            .and_then(|encoder| encoder.bytes(&self.request.request_nonce))
            .and_then(|encoder| encoder.u16(MlsProtocolVersion::Mls10 as u16))
            .and_then(|encoder| encoder.u16(MlsCiphersuite::Suite1 as u16))
            .and_then(|encoder| encoder.bytes(&self.mls.key_package_reference))
            .and_then(|encoder| encoder.bytes(&self.mls.key_package))
            .and_then(|encoder| encoder.u16(CredentialType::Basic as u16))
            .and_then(|encoder| encoder.bytes(&self.mls.credential_identity))
            .and_then(|encoder| encoder.bytes(&self.mls.leaf_signature_key))
            .and_then(|encoder| encoder.u16(ApplicationProtocolVersion::V1 as u16))
            .and_then(|encoder| encoder.u16(TransportProfile::LocalMemory as u16))
            .map_err(|_| WireError::Encoding)?;
        self.response_endpoint.encode_into(&mut encoder)?;

        let encoded = encoder.into_writer();
        if encoded.len() > MAX_CAPABILITY_JOIN_REQUEST_BYTES {
            return Err(WireError::WireObjectTooLarge {
                actual: encoded.len(),
                maximum: MAX_CAPABILITY_JOIN_REQUEST_BYTES,
            });
        }
        Ok(encoded)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, WireError> {
        prebound(bytes, MAX_CAPABILITY_JOIN_REQUEST_BYTES)?;
        let mut decoder = Decoder::new(bytes);
        require_array(&mut decoder, CAPABILITY_JOIN_REQUEST_FIELDS)?;
        require_value(
            &mut decoder,
            CAPABILITY_JOIN_REQUEST_VERSION,
            WireError::UnsupportedVersion,
        )?;
        require_value(
            &mut decoder,
            NestedObjectType::CapabilityJoinRequest as u16,
            WireError::UnsupportedObjectType,
        )?;
        AdmissionProofVersion::try_from(decoder.u16().map_err(|_| WireError::Malformed)?)?;

        let invitation_id =
            decode_fixed::<IDENTIFIER_BYTES>(&mut decoder, WireError::InvalidInvitationIdLength)?;
        let join_challenge =
            decode_fixed::<FIXED_KEY_BYTES>(&mut decoder, WireError::InvalidJoinChallengeLength)?;
        let invitation_key_id = decode_fixed::<IDENTIFIER_BYTES>(
            &mut decoder,
            WireError::InvalidInvitationKeyIdLength,
        )?;
        let intended_verifier =
            decode_fixed::<FIXED_KEY_BYTES>(&mut decoder, WireError::InvalidVerifyingKeyLength)?;
        let join_request_id =
            decode_fixed::<IDENTIFIER_BYTES>(&mut decoder, WireError::InvalidJoinRequestIdLength)?;
        let issued_at_unix_seconds = decoder.u64().map_err(|_| WireError::Malformed)?;
        let expires_at_unix_seconds = decoder.u64().map_err(|_| WireError::Malformed)?;
        let request_nonce =
            decode_fixed::<FIXED_KEY_BYTES>(&mut decoder, WireError::InvalidRequestNonceLength)?;

        MlsProtocolVersion::try_from(decoder.u16().map_err(|_| WireError::Malformed)?)?;
        MlsCiphersuite::try_from(decoder.u16().map_err(|_| WireError::Malformed)?)?;
        let key_package_reference = decode_fixed::<FIXED_KEY_BYTES>(
            &mut decoder,
            WireError::InvalidKeyPackageReferenceLength,
        )?;
        let key_package = decoder.bytes().map_err(|_| WireError::Malformed)?;
        if key_package.is_empty() {
            return Err(WireError::EmptyKeyPackage);
        }
        if key_package.len() > MAX_JOIN_KEY_PACKAGE_BYTES {
            return Err(WireError::KeyPackageTooLarge {
                actual: key_package.len(),
                maximum: MAX_JOIN_KEY_PACKAGE_BYTES,
            });
        }
        CredentialType::try_from(decoder.u16().map_err(|_| WireError::Malformed)?)?;
        let credential_identity = decode_fixed::<FIXED_KEY_BYTES>(
            &mut decoder,
            WireError::InvalidCredentialIdentityLength,
        )?;
        let leaf_signature_key = decode_fixed::<FIXED_KEY_BYTES>(
            &mut decoder,
            WireError::InvalidLeafSignatureKeyLength,
        )?;
        ApplicationProtocolVersion::try_from(decoder.u16().map_err(|_| WireError::Malformed)?)?;
        TransportProfile::try_from(decoder.u16().map_err(|_| WireError::Malformed)?)?;
        let response_endpoint = LocalWelcomeDepositEndpoint::decode_from(&mut decoder)?;
        reject_trailing(&decoder, bytes)?;

        let invitation = InvitationJoinBinding::new(
            invitation_id,
            join_challenge,
            invitation_key_id,
            intended_verifier,
        )?;
        let request = JoinRequestBinding::new(
            join_request_id,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            request_nonce,
        )?;
        let mls = MlsKeyPackageBinding::new(
            key_package_reference,
            key_package.to_vec(),
            credential_identity,
            leaf_signature_key,
        )?;
        let decoded = Self::new(invitation, request, mls, response_endpoint)?;
        if decoded.encode_canonical()?.as_slice() != bytes {
            return Err(WireError::NonDeterministicEncoding);
        }
        Ok(decoded)
    }
}

fn prebound(bytes: &[u8], maximum: usize) -> Result<(), WireError> {
    if bytes.len() > maximum {
        return Err(WireError::WireObjectTooLarge {
            actual: bytes.len(),
            maximum,
        });
    }
    Ok(())
}

fn require_array(decoder: &mut Decoder<'_>, fields: u64) -> Result<(), WireError> {
    if decoder.array().map_err(|_| WireError::Malformed)? != Some(fields) {
        return Err(WireError::Malformed);
    }
    Ok(())
}

fn require_value(
    decoder: &mut Decoder<'_>,
    expected: u16,
    error: fn(u16) -> WireError,
) -> Result<(), WireError> {
    let actual = decoder.u16().map_err(|_| WireError::Malformed)?;
    if actual != expected {
        return Err(error(actual));
    }
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

fn reject_zero<const N: usize>(bytes: &[u8; N], error: WireError) -> Result<(), WireError> {
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(error);
    }
    Ok(())
}

fn reject_trailing(decoder: &Decoder<'_>, bytes: &[u8]) -> Result<(), WireError> {
    if decoder.position() != bytes.len() {
        return Err(WireError::TrailingData);
    }
    Ok(())
}
