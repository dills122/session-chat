#![forbid(unsafe_code)]

//! Provider-neutral one-shot HPKE protection for capability join requests.

use std::{error::Error, fmt};

use ed25519_dalek::SigningKey;
use mls_rs_core::crypto::{
    CipherSuite, CipherSuiteProvider, CryptoProvider, HpkeContextR, HpkeContextS, HpkePsk,
    HpkePublicKey, HpkeSecretKey,
};
use mls_rs_crypto_awslc::{AwsLcAead, AwsLcCryptoProvider, AwsLcHkdf, EcdhKem, dhkem};
use mls_rs_crypto_hpke::hpke::Hpke;
use session_protocol::{
    CapabilityInvitationClaims, CapabilityInvitationV2Claims, CapabilityJoinRequest,
    ProtectedJoinRequest, SecretCapability, SignedCapabilityInvitationV2,
};
use zeroize::{Zeroize, Zeroizing};

const HPKE_KEY_BYTES: usize = 32;
const PSK_ID_DOMAIN: &[u8] = b"session-chat/invitation-capability-psk/v1\0";
const INFO_DOMAIN: &[u8] = b"session-chat/join-request-hpke/v1\0";

type AwsLcHpke = Hpke<EcdhKem, AwsLcHkdf, AwsLcAead>;

/// Coarse failures exposed by the join-protection boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JoinProtectionError {
    /// A bounded protocol value could not fit the selected profile.
    InputTooLarge,
    /// The provider, key, authentication context, or canonical input was rejected.
    Rejected,
}

impl fmt::Display for JoinProtectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge => formatter.write_str("join-protection input exceeds its bound"),
            Self::Rejected => formatter.write_str("join-protection operation rejected"),
        }
    }
}

impl Error for JoinProtectionError {}

/// Provider-neutral owned bytes for one invitation-scoped X25519 private key.
pub struct InvitationHpkePrivateKey([u8; HPKE_KEY_BYTES]);

impl InvitationHpkePrivateKey {
    /// Restores an exact private key from a protected local vault.
    pub fn from_bytes(bytes: [u8; HPKE_KEY_BYTES]) -> Result<Self, JoinProtectionError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(JoinProtectionError::Rejected);
        }
        Ok(Self(bytes))
    }

    fn provider_key(&self) -> HpkeSecretKey {
        HpkeSecretKey::from(self.0.to_vec())
    }
}

impl Drop for InvitationHpkePrivateKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A fresh invitation key pair whose private half is neither cloneable nor formattable.
pub struct GeneratedInvitationHpkeKey {
    private_key: InvitationHpkePrivateKey,
    public_key: [u8; HPKE_KEY_BYTES],
}

/// A complete fresh invitation-v2 context created by one reviewed provider API.
pub struct GeneratedCapabilityInvitationV2 {
    invitation: SignedCapabilityInvitationV2,
    private_key: InvitationHpkePrivateKey,
}

impl GeneratedCapabilityInvitationV2 {
    /// Borrows the signed bearer invitation for encoding and request protection.
    #[must_use]
    pub const fn invitation(&self) -> &SignedCapabilityInvitationV2 {
        &self.invitation
    }

    /// Borrows the invitation-owned HPKE private key for opening one request.
    #[must_use]
    pub const fn private_key(&self) -> &InvitationHpkePrivateKey {
        &self.private_key
    }
}

/// A canonically decoded request authenticated by one successful HPKE PSK open.
///
/// Construction is restricted to [`InvitationJoinProtector`]
/// implementations. The value is intentionally non-`Clone` and non-`Debug` so
/// downstream admission can require cryptographic provenance without accepting
/// a separately constructed [`CapabilityJoinRequest`].
pub struct OpenedCapabilityJoinRequest {
    request: CapabilityJoinRequest,
    invitation_signature: [u8; 64],
}

impl OpenedCapabilityJoinRequest {
    /// Borrows the exact canonical request recovered from HPKE plaintext.
    #[must_use]
    pub const fn request(&self) -> &CapabilityJoinRequest {
        &self.request
    }

    /// Returns the exact signed invitation instance used for this HPKE open.
    #[must_use]
    pub const fn invitation_signature(&self) -> &[u8; 64] {
        &self.invitation_signature
    }

    /// Moves the exact authenticated request into the next one-shot boundary.
    #[must_use]
    pub fn into_request(self) -> CapabilityJoinRequest {
        self.request
    }
}

impl GeneratedInvitationHpkeKey {
    /// Returns the exact X25519 public key for signed invitation v2.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; HPKE_KEY_BYTES] {
        &self.public_key
    }

    /// Moves the private key into invitation-owned protected state.
    #[must_use]
    pub fn into_private_key(self) -> InvitationHpkePrivateKey {
        self.private_key
    }
}

/// Provider-neutral one-shot protection for the exact ADR 0014 join profile.
pub trait InvitationJoinProtector {
    /// Generates and signs every random field in one invitation-v2 context.
    fn generate_capability_invitation(
        &self,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<GeneratedCapabilityInvitationV2, JoinProtectionError>;

    /// Generates a fresh invitation-scoped X25519 key pair.
    fn generate_invitation_key(&self) -> Result<GeneratedInvitationHpkeKey, JoinProtectionError>;

    /// Seals one canonical inner request using the invitation capability as HPKE PSK.
    fn seal_capability_request(
        &self,
        invitation: &SignedCapabilityInvitationV2,
        request: &CapabilityJoinRequest,
    ) -> Result<ProtectedJoinRequest, JoinProtectionError>;

    /// Opens and canonically decodes one request under the exact signed context.
    fn open_capability_request(
        &self,
        private_key: &InvitationHpkePrivateKey,
        invitation: &SignedCapabilityInvitationV2,
        protected: &ProtectedJoinRequest,
    ) -> Result<OpenedCapabilityJoinRequest, JoinProtectionError>;
}

/// AWS-LC implementation of the fixed RFC 9180 PSK profile from ADR 0014.
#[derive(Clone, Copy, Default)]
pub struct AwsLcInvitationJoinProtector;

impl AwsLcInvitationJoinProtector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl InvitationJoinProtector for AwsLcInvitationJoinProtector {
    fn generate_capability_invitation(
        &self,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<GeneratedCapabilityInvitationV2, JoinProtectionError> {
        let crypto = AwsLcCryptoProvider::new();
        let cipher_suite = crypto
            .cipher_suite_provider(CipherSuite::CURVE25519_AES128)
            .ok_or(JoinProtectionError::Rejected)?;
        let mut invitation_id = [0; 16];
        let mut join_challenge = [0; 32];
        let mut invitation_key_id = [0; 16];
        let mut capability = Zeroizing::new([0; 32]);
        let mut signing_seed = Zeroizing::new([0; 32]);
        for output in [
            invitation_id.as_mut_slice(),
            join_challenge.as_mut_slice(),
            invitation_key_id.as_mut_slice(),
            capability.as_mut_slice(),
            signing_seed.as_mut_slice(),
        ] {
            cipher_suite
                .random_bytes(output)
                .map_err(coarse_provider_error)?;
        }

        let generated_hpke = self.generate_invitation_key()?;
        let base = CapabilityInvitationClaims::new(
            invitation_id,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            join_challenge,
            SecretCapability::new(*capability).map_err(protocol_error)?,
        )
        .map_err(protocol_error)?;
        let claims = CapabilityInvitationV2Claims::new(
            base,
            invitation_key_id,
            *generated_hpke.public_key(),
        )
        .map_err(protocol_error)?;
        let signing_key = SigningKey::from_bytes(&signing_seed);
        let invitation =
            SignedCapabilityInvitationV2::sign(claims, &signing_key).map_err(protocol_error)?;

        Ok(GeneratedCapabilityInvitationV2 {
            invitation,
            private_key: generated_hpke.into_private_key(),
        })
    }

    fn generate_invitation_key(&self) -> Result<GeneratedInvitationHpkeKey, JoinProtectionError> {
        let hpke = hpke()?;
        let (private_key, public_key) = hpke.generate().map_err(coarse_provider_error)?;
        let private_key = fixed_key(private_key.as_ref())?;
        let public_key = fixed_key(public_key.as_ref())?;
        if public_key.iter().all(|byte| *byte == 0) {
            return Err(JoinProtectionError::Rejected);
        }
        Ok(GeneratedInvitationHpkeKey {
            private_key: InvitationHpkePrivateKey::from_bytes(private_key)?,
            public_key,
        })
    }

    fn seal_capability_request(
        &self,
        invitation: &SignedCapabilityInvitationV2,
        request: &CapabilityJoinRequest,
    ) -> Result<ProtectedJoinRequest, JoinProtectionError> {
        validate_inner_context(invitation, request)?;

        let hpke = hpke()?;
        let recipient_public_key =
            HpkePublicKey::from(invitation.hpke_recipient_public_key().to_vec());
        hpke.public_key_validate(&recipient_public_key)
            .map_err(coarse_provider_error)?;
        let psk_id = psk_id(invitation);
        let info = hpke_info(invitation);
        let psk = HpkePsk::new(&psk_id, invitation.capability().expose_secret());
        let (encapsulated_key, mut sender) = hpke
            .setup_sender(&recipient_public_key, &info, Some(psk))
            .map_err(coarse_provider_error)?;
        let encapsulated_key = fixed_key(&encapsulated_key)?;
        let aad_source = ProtectedJoinRequest::new(
            *invitation.invitation_id(),
            *invitation.invitation_key_id(),
            encapsulated_key,
            vec![0],
        )
        .map_err(protocol_error)?;
        let aad = aad_source.aad_canonical().map_err(protocol_error)?;
        let plaintext = Zeroizing::new(request.encode_canonical().map_err(protocol_error)?);
        let ciphertext = sender
            .seal(Some(&aad), &plaintext)
            .map_err(coarse_provider_error)?;

        ProtectedJoinRequest::new(
            *invitation.invitation_id(),
            *invitation.invitation_key_id(),
            encapsulated_key,
            ciphertext,
        )
        .map_err(protocol_error)
    }

    fn open_capability_request(
        &self,
        private_key: &InvitationHpkePrivateKey,
        invitation: &SignedCapabilityInvitationV2,
        protected: &ProtectedJoinRequest,
    ) -> Result<OpenedCapabilityJoinRequest, JoinProtectionError> {
        if protected.invitation_id() != invitation.invitation_id()
            || protected.invitation_key_id() != invitation.invitation_key_id()
        {
            return Err(JoinProtectionError::Rejected);
        }

        let hpke = hpke()?;
        let local_secret = private_key.provider_key();
        let local_public = HpkePublicKey::from(invitation.hpke_recipient_public_key().to_vec());
        hpke.public_key_validate(&local_public)
            .map_err(coarse_provider_error)?;
        let psk_id = psk_id(invitation);
        let info = hpke_info(invitation);
        let psk = HpkePsk::new(&psk_id, invitation.capability().expose_secret());
        let mut receiver = hpke
            .setup_receiver(
                protected.encapsulated_key(),
                &local_secret,
                &local_public,
                &info,
                Some(psk),
            )
            .map_err(coarse_provider_error)?;
        let aad = protected.aad_canonical().map_err(protocol_error)?;
        let plaintext = receiver
            .open(Some(&aad), protected.ciphertext())
            .map_err(coarse_provider_error)?;
        let request = CapabilityJoinRequest::decode_canonical(&plaintext)
            .map_err(|_| JoinProtectionError::Rejected)?;
        validate_inner_context(invitation, &request)?;
        Ok(OpenedCapabilityJoinRequest {
            request,
            invitation_signature: *invitation.signature(),
        })
    }
}

fn hpke() -> Result<AwsLcHpke, JoinProtectionError> {
    let suite = CipherSuite::CURVE25519_AES128;
    let kem = dhkem(suite).ok_or(JoinProtectionError::Rejected)?;
    let kdf = AwsLcHkdf::new(suite).ok_or(JoinProtectionError::Rejected)?;
    let aead = AwsLcAead::new(suite).ok_or(JoinProtectionError::Rejected)?;
    Ok(Hpke::new(kem, kdf, Some(aead)))
}

fn validate_inner_context(
    invitation: &SignedCapabilityInvitationV2,
    request: &CapabilityJoinRequest,
) -> Result<(), JoinProtectionError> {
    if request.invitation_id() != invitation.invitation_id()
        || request.join_challenge() != invitation.join_challenge()
        || request.invitation_key_id() != invitation.invitation_key_id()
        || request.intended_verifier() != invitation.inviter_verifying_key()
        || request.issued_at_unix_seconds() < invitation.issued_at_unix_seconds()
        || request.expires_at_unix_seconds() > invitation.expires_at_unix_seconds()
    {
        return Err(JoinProtectionError::Rejected);
    }
    Ok(())
}

fn psk_id(invitation: &SignedCapabilityInvitationV2) -> Vec<u8> {
    let mut psk_id = Vec::with_capacity(PSK_ID_DOMAIN.len() + 64);
    psk_id.extend_from_slice(PSK_ID_DOMAIN);
    psk_id.extend_from_slice(invitation.invitation_id());
    psk_id.extend_from_slice(invitation.join_challenge());
    psk_id.extend_from_slice(invitation.invitation_key_id());
    psk_id
}

fn hpke_info(invitation: &SignedCapabilityInvitationV2) -> Vec<u8> {
    let mut info = Vec::with_capacity(INFO_DOMAIN.len() + 138);
    info.extend_from_slice(INFO_DOMAIN);
    for value in [
        invitation.schema_version(),
        invitation.invitation_encryption_suite() as u16,
        invitation.join_request_schema() as u16,
        invitation.application_protocol_version() as u16,
        invitation.transport_profile() as u16,
    ] {
        info.extend_from_slice(&value.to_be_bytes());
    }
    info.extend_from_slice(invitation.invitation_id());
    info.extend_from_slice(invitation.join_challenge());
    info.extend_from_slice(invitation.invitation_key_id());
    info.extend_from_slice(invitation.hpke_recipient_public_key());
    info.extend_from_slice(invitation.inviter_verifying_key());
    info
}

fn fixed_key(bytes: &[u8]) -> Result<[u8; HPKE_KEY_BYTES], JoinProtectionError> {
    bytes.try_into().map_err(|_| JoinProtectionError::Rejected)
}

fn protocol_error(error: session_protocol::WireError) -> JoinProtectionError {
    match error {
        session_protocol::WireError::WireObjectTooLarge { .. }
        | session_protocol::WireError::KeyPackageTooLarge { .. }
        | session_protocol::WireError::ProtectedJoinCiphertextTooLarge { .. } => {
            JoinProtectionError::InputTooLarge
        }
        _ => JoinProtectionError::Rejected,
    }
}

fn coarse_provider_error<T>(_: T) -> JoinProtectionError {
    JoinProtectionError::Rejected
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use hpke::{
        Deserializable, Kem as KemTrait, OpModeR, PskBundle, aead::AesGcm128, kdf::HkdfSha256,
        kem::X25519HkdfSha256, setup_receiver,
    };
    use mls_rs_core::crypto::{HpkeCiphertext, HpkePsk};
    use session_protocol::{
        CapabilityInvitationClaims, CapabilityInvitationV2Claims, CapabilityJoinRequest,
        DepositCapability, InvitationJoinBinding, JoinRequestBinding, LocalWelcomeDepositEndpoint,
        MlsKeyPackageBinding, SecretCapability, SignedCapabilityInvitationV2,
    };

    use super::*;

    const INVITATION_ID: [u8; 16] = [0x11; 16];
    const JOIN_CHALLENGE: [u8; 32] = [0x22; 32];
    const CAPABILITY: [u8; 32] = [0x33; 32];
    const INVITATION_KEY_ID: [u8; 16] = [0x44; 16];
    const ISSUED_AT: u64 = 1_700_000_000;
    const EXPIRES_AT: u64 = ISSUED_AT + 3_600;

    fn invitation(recipient_public_key: [u8; 32]) -> SignedCapabilityInvitationV2 {
        let base = CapabilityInvitationClaims::new(
            INVITATION_ID,
            ISSUED_AT,
            EXPIRES_AT,
            JOIN_CHALLENGE,
            SecretCapability::new(CAPABILITY).expect("fixture capability is nonzero"),
        )
        .expect("fixture invitation claims are valid");
        let claims =
            CapabilityInvitationV2Claims::new(base, INVITATION_KEY_ID, recipient_public_key)
                .expect("fixture v2 claims are valid");
        SignedCapabilityInvitationV2::sign(claims, &SigningKey::from_bytes(&[0xa5; 32]))
            .expect("fixture signing succeeds")
    }

    fn request() -> CapabilityJoinRequest {
        let signing_key = SigningKey::from_bytes(&[0xa5; 32]);
        let invitation = InvitationJoinBinding::new(
            INVITATION_ID,
            JOIN_CHALLENGE,
            INVITATION_KEY_ID,
            signing_key.verifying_key().to_bytes(),
        )
        .expect("fixture invitation binding is valid");
        let request = JoinRequestBinding::new([0x55; 16], ISSUED_AT + 1, EXPIRES_AT, [0x66; 32])
            .expect("fixture request binding is valid");
        let mls = MlsKeyPackageBinding::new(
            [0x77; 32],
            b"key-package".to_vec(),
            [0x88; 32],
            SigningKey::from_bytes(&[0xb6; 32])
                .verifying_key()
                .to_bytes(),
        )
        .expect("fixture MLS binding is valid");
        let endpoint = LocalWelcomeDepositEndpoint::new(
            [0x99; 16],
            [0xaa; 16],
            DepositCapability::new([0xbb; 32]).expect("fixture deposit capability is nonzero"),
            EXPIRES_AT,
        )
        .expect("fixture endpoint is valid");

        CapabilityJoinRequest::new(invitation, request, mls, endpoint)
            .expect("fixture inner request is valid")
    }

    #[test]
    fn aws_lc_output_opens_with_independent_hpke_implementation() {
        type IndependentKem = X25519HkdfSha256;

        let protector = AwsLcInvitationJoinProtector::new();
        let generated = protector
            .generate_invitation_key()
            .expect("provider key generation succeeds");
        let signed = invitation(*generated.public_key());
        let private_key = generated.into_private_key();
        let request = request();
        let protected = protector
            .seal_capability_request(&signed, &request)
            .expect("bounded request seals");

        let receiver_private = <IndependentKem as KemTrait>::PrivateKey::from_bytes(&private_key.0)
            .expect("AWS-LC private key uses the standard X25519 encoding");
        let encapsulated =
            <IndependentKem as KemTrait>::EncappedKey::from_bytes(protected.encapsulated_key())
                .expect("AWS-LC encapsulated key uses the standard X25519 encoding");
        let psk_id = psk_id(&signed);
        let bundle = PskBundle::new(signed.capability().expose_secret(), &psk_id)
            .expect("the profile has a nonempty PSK and identifier");
        let mut receiver = setup_receiver::<AesGcm128, HkdfSha256, IndependentKem>(
            &OpModeR::Psk(bundle),
            &receiver_private,
            &encapsulated,
            &hpke_info(&signed),
        )
        .expect("independent provider accepts the standard context");
        let plaintext = receiver
            .open(
                protected.ciphertext(),
                &protected.aad_canonical().expect("AAD encodes"),
            )
            .expect("independent provider authenticates the AWS-LC output");

        assert_eq!(
            plaintext,
            request.encode_canonical().expect("request encodes")
        );
    }

    #[test]
    fn aws_lc_opens_rfc_9180_psk_vector() {
        let receiver_public =
            decode_hex("9fed7e8c17387560e92cc6462a68049657246a09bfa8ade7aefe589672016366");
        let receiver_private =
            decode_hex("c5eb01eb457fe6c6f57577c5413b931550a162c71a03ac8d196babbd4e5ce0fd");
        let encapsulated =
            decode_hex("0ad0950d9fb9588e59690b74f1237ecdf1d775cd60be2eca57af5a4b0471c91b");
        let ciphertext = decode_hex(
            "e52c6fed7f758d0cf7145689f21bc1be6ec9ea097fef4e959440012f4feb73fb611b946199e681f4cfc34db8ea",
        );
        let psk = decode_hex("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82");
        let psk_id = decode_hex("456e6e796e20447572696e206172616e204d6f726961");
        let info = decode_hex("4f6465206f6e2061204772656369616e2055726e");
        let aad = decode_hex("436f756e742d30");
        let expected = decode_hex("4265617574792069732074727574682c20747275746820626561757479");
        let hpke = hpke().expect("fixed provider suite exists");

        let plaintext = hpke
            .open(
                &HpkeCiphertext {
                    kem_output: encapsulated,
                    ciphertext,
                },
                &HpkeSecretKey::from(receiver_private),
                &HpkePublicKey::from(receiver_public),
                &info,
                Some(HpkePsk::new(&psk_id, &psk)),
                Some(&aad),
            )
            .expect("AWS-LC opens the RFC 9180 PSK vector");

        assert_eq!(plaintext.as_slice(), expected);
    }

    #[test]
    fn typed_psk_identifier_and_info_match_the_adopted_byte_contract() {
        let recipient_public_key = [0xd1; 32];
        let signed = invitation(recipient_public_key);
        let mut expected_psk_id = b"session-chat/invitation-capability-psk/v1\0".to_vec();
        expected_psk_id.extend_from_slice(&INVITATION_ID);
        expected_psk_id.extend_from_slice(&JOIN_CHALLENGE);
        expected_psk_id.extend_from_slice(&INVITATION_KEY_ID);

        let mut expected_info = b"session-chat/join-request-hpke/v1\0".to_vec();
        for selection in [2_u16, 1, 1, 1, 1] {
            expected_info.extend_from_slice(&selection.to_be_bytes());
        }
        expected_info.extend_from_slice(&INVITATION_ID);
        expected_info.extend_from_slice(&JOIN_CHALLENGE);
        expected_info.extend_from_slice(&INVITATION_KEY_ID);
        expected_info.extend_from_slice(&recipient_public_key);
        expected_info.extend_from_slice(signed.inviter_verifying_key());

        assert_eq!(psk_id(&signed), expected_psk_id);
        assert_eq!(hpke_info(&signed), expected_info);
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0, "hex fixture must have full bytes");
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let pair = std::str::from_utf8(pair).expect("hex fixture is ASCII");
                u8::from_str_radix(pair, 16).expect("hex fixture is valid")
            })
            .collect()
    }
}
