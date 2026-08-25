#![forbid(unsafe_code)]

//! Bounded non-production portable passphrase key-wrapper laboratory.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use aws_lc_rs::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    rand,
};
use session_storage::{
    BackupExposure, DeviceBinding, KeyStorageProtection, ProtectorCapabilities, SessionId,
    SessionKeyProtector, UnsealedSessionKey, UserPresence,
};
use thiserror::Error;
use zeroize::Zeroizing;

/// Exact byte length of one canonical version 1 wrapped-key record.
pub const WRAPPED_SESSION_KEY_V1_BYTES: usize = 102;
/// Maximum passphrase input accepted before KDF work.
pub const MAX_PASSPHRASE_BYTES: usize = 1024;

const FORMAT_MAGIC: &[u8; 8] = b"SCVKWRP\0";
const FORMAT_VERSION: u16 = 1;
const ARGON2_PROFILE: u16 = 1;
const AEAD_SUITE: u16 = 1;
const ARGON2_MEMORY_KIB: u32 = 65_536;
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_LANES: u32 = 4;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;
const PREFIX_BYTES: usize = 54;
const WRAPPED_KEY_AND_TAG_BYTES: usize = 48;
const SESSION_SCOPE_BYTES: usize = 32;
const KEK_BYTES: usize = 32;
const AAD_DOMAIN: &[u8] = b"session-chat/portable-wrapped-session-key/v1\0";

/// Coarse failure from the portable key-wrapper boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PortableKeyError {
    /// Input, context, randomness, KDF, or authenticated decryption was rejected.
    #[error("portable key operation rejected")]
    Rejected,
}

/// Owned passphrase bytes cleared when this value is dropped.
///
/// This type intentionally implements neither `Clone`, `Debug`, nor `Display`.
///
/// ```compile_fail
/// use key_protector_passphrase::PortablePassphrase;
/// fn require_debug<T: core::fmt::Debug>() {}
/// require_debug::<PortablePassphrase>();
/// ```
///
/// ```compile_fail
/// use key_protector_passphrase::PortablePassphrase;
/// fn require_clone<T: Clone>() {}
/// require_clone::<PortablePassphrase>();
/// ```
pub struct PortablePassphrase(Zeroizing<Vec<u8>>);

impl PortablePassphrase {
    /// Accepts nonempty, pre-bounded passphrase bytes without interpreting text.
    pub fn new(bytes: Vec<u8>) -> Result<Self, PortableKeyError> {
        let bytes = Zeroizing::new(bytes);
        if bytes.is_empty() || bytes.len() > MAX_PASSPHRASE_BYTES {
            return Err(PortableKeyError::Rejected);
        }
        Ok(Self(bytes))
    }
}

/// One exact canonical version 1 wrapped-key record.
///
/// This ciphertext value intentionally does not implement `Debug` or `Display`.
pub struct WrappedSessionKeyV1([u8; WRAPPED_SESSION_KEY_V1_BYTES]);

impl WrappedSessionKeyV1 {
    /// Strictly decodes one exact fixed-size record.
    pub fn decode(encoded: &[u8]) -> Result<Self, PortableKeyError> {
        let encoded: [u8; WRAPPED_SESSION_KEY_V1_BYTES] =
            encoded.try_into().map_err(|_| PortableKeyError::Rejected)?;
        validate_prefix(&encoded)?;
        Ok(Self(encoded))
    }

    /// Borrows the exact canonical persisted bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; WRAPPED_SESSION_KEY_V1_BYTES] {
        &self.0
    }
}

/// Fresh random session key and its passphrase-wrapped persisted record.
pub struct ProvisionedSessionKey {
    wrapped: WrappedSessionKeyV1,
    unsealed: UnsealedSessionKey,
}

impl ProvisionedSessionKey {
    /// Separates the persisted wrapper from the newly provisioned key.
    #[must_use]
    pub fn into_parts(self) -> (WrappedSessionKeyV1, UnsealedSessionKey) {
        (self.wrapped, self.unsealed)
    }
}

/// Exact-session protector backed by one portable wrapped-key record.
///
/// The protector owns ciphertext only. A passphrase must arrive as a one-shot
/// credential for each attempt and is never retained between calls. This type
/// intentionally implements neither `Clone`, `Debug`, nor `Display`.
///
/// ```compile_fail
/// use key_protector_passphrase::PortablePassphraseKeyProtector;
/// fn require_debug<T: core::fmt::Debug>() {}
/// require_debug::<PortablePassphraseKeyProtector>();
/// ```
pub struct PortablePassphraseKeyProtector {
    session_id: SessionId,
    wrapped: WrappedSessionKeyV1,
}

impl PortablePassphraseKeyProtector {
    /// Binds one canonical wrapped-key record to its out-of-band session scope.
    #[must_use]
    pub const fn new(session_id: SessionId, wrapped: WrappedSessionKeyV1) -> Self {
        Self {
            session_id,
            wrapped,
        }
    }
}

impl SessionKeyProtector for PortablePassphraseKeyProtector {
    type Credential = PortablePassphrase;
    type Error = PortableKeyError;

    fn capabilities(&self) -> ProtectorCapabilities {
        PortablePassphraseKeyWrapper::new().capabilities()
    }

    fn unseal_session_key(
        &mut self,
        session_id: SessionId,
        passphrase: Self::Credential,
    ) -> Result<UnsealedSessionKey, Self::Error> {
        if session_id != self.session_id {
            return Err(PortableKeyError::Rejected);
        }
        PortablePassphraseKeyWrapper::new().unseal(session_id, passphrase, &self.wrapped)
    }
}

/// AWS-LC and Argon2id implementation of the fixed laboratory profile.
#[derive(Clone, Copy, Default)]
pub struct PortablePassphraseKeyWrapper;

impl PortablePassphraseKeyWrapper {
    /// Creates the fixed portable wrapper implementation.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Reports the deliberately weaker, backup-capable portable properties.
    #[must_use]
    pub const fn capabilities(self) -> ProtectorCapabilities {
        ProtectorCapabilities::new(
            KeyStorageProtection::ApplicationWrapped,
            DeviceBinding::Unknown,
            UserPresence::None,
            BackupExposure::MayBackup,
        )
    }

    /// Generates and wraps one fresh random session key.
    pub fn provision(
        self,
        session_id: SessionId,
        passphrase: PortablePassphrase,
    ) -> Result<ProvisionedSessionKey, PortableKeyError> {
        let mut session_key = Zeroizing::new([0u8; SESSION_SCOPE_BYTES]);
        let mut salt = [0u8; SALT_BYTES];
        let mut nonce = [0u8; NONCE_BYTES];
        rand::fill(session_key.as_mut_slice()).map_err(|_| PortableKeyError::Rejected)?;
        rand::fill(&mut salt).map_err(|_| PortableKeyError::Rejected)?;
        rand::fill(&mut nonce).map_err(|_| PortableKeyError::Rejected)?;

        let wrapped = wrap_with_material(session_id, &passphrase, &session_key, salt, nonce)?;
        let unsealed = UnsealedSessionKey::from_provider_bytes(*session_key)
            .map_err(|_| PortableKeyError::Rejected)?;
        Ok(ProvisionedSessionKey { wrapped, unsealed })
    }

    /// Authenticates and unwraps one key for the caller-supplied session scope.
    pub fn unseal(
        self,
        session_id: SessionId,
        passphrase: PortablePassphrase,
        wrapped: &WrappedSessionKeyV1,
    ) -> Result<UnsealedSessionKey, PortableKeyError> {
        validate_prefix(&wrapped.0)?;
        let salt: &[u8; SALT_BYTES] = wrapped.0[26..42]
            .try_into()
            .map_err(|_| PortableKeyError::Rejected)?;
        let nonce: [u8; NONCE_BYTES] = wrapped.0[42..54]
            .try_into()
            .map_err(|_| PortableKeyError::Rejected)?;
        let kek = derive_kek(&passphrase, salt)?;
        let key = LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM, kek.as_ref()).map_err(|_| PortableKeyError::Rejected)?,
        );
        let aad = authenticated_context(&wrapped.0[..PREFIX_BYTES], session_id);
        let mut ciphertext = Zeroizing::new(wrapped.0[PREFIX_BYTES..].to_vec());
        let plaintext = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad.as_slice()),
                ciphertext.as_mut_slice(),
            )
            .map_err(|_| PortableKeyError::Rejected)?;
        if plaintext.len() != SESSION_SCOPE_BYTES {
            return Err(PortableKeyError::Rejected);
        }
        let mut plaintext_key = Zeroizing::new([0u8; SESSION_SCOPE_BYTES]);
        plaintext_key.copy_from_slice(plaintext);
        UnsealedSessionKey::from_provider_bytes(*plaintext_key)
            .map_err(|_| PortableKeyError::Rejected)
    }
}

fn wrap_with_material(
    session_id: SessionId,
    passphrase: &PortablePassphrase,
    session_key: &[u8; SESSION_SCOPE_BYTES],
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
) -> Result<WrappedSessionKeyV1, PortableKeyError> {
    if session_key.iter().all(|byte| *byte == 0) {
        return Err(PortableKeyError::Rejected);
    }
    let mut encoded = [0u8; WRAPPED_SESSION_KEY_V1_BYTES];
    encoded[..8].copy_from_slice(FORMAT_MAGIC);
    encoded[8..10].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
    encoded[10..12].copy_from_slice(&ARGON2_PROFILE.to_be_bytes());
    encoded[12..14].copy_from_slice(&AEAD_SUITE.to_be_bytes());
    encoded[14..18].copy_from_slice(&ARGON2_MEMORY_KIB.to_be_bytes());
    encoded[18..22].copy_from_slice(&ARGON2_TIME_COST.to_be_bytes());
    encoded[22..26].copy_from_slice(&ARGON2_LANES.to_be_bytes());
    encoded[26..42].copy_from_slice(&salt);
    encoded[42..54].copy_from_slice(&nonce);

    let kek = derive_kek(passphrase, &salt)?;
    let key = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, kek.as_ref()).map_err(|_| PortableKeyError::Rejected)?,
    );
    let aad = authenticated_context(&encoded[..PREFIX_BYTES], session_id);
    let mut ciphertext_bytes = Vec::new();
    ciphertext_bytes
        .try_reserve_exact(WRAPPED_KEY_AND_TAG_BYTES)
        .map_err(|_| PortableKeyError::Rejected)?;
    ciphertext_bytes.extend_from_slice(session_key);
    let mut ciphertext = Zeroizing::new(ciphertext_bytes);
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad.as_slice()),
        &mut *ciphertext,
    )
    .map_err(|_| PortableKeyError::Rejected)?;
    if ciphertext.len() != WRAPPED_KEY_AND_TAG_BYTES {
        return Err(PortableKeyError::Rejected);
    }
    encoded[PREFIX_BYTES..].copy_from_slice(&ciphertext);
    Ok(WrappedSessionKeyV1(encoded))
}

fn derive_kek(
    passphrase: &PortablePassphrase,
    salt: &[u8; SALT_BYTES],
) -> Result<Zeroizing<[u8; KEK_BYTES]>, PortableKeyError> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_TIME_COST,
        ARGON2_LANES,
        Some(KEK_BYTES),
    )
    .map_err(|_| PortableKeyError::Rejected)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone());
    let mut memory_blocks = Vec::new();
    memory_blocks
        .try_reserve_exact(params.block_count())
        .map_err(|_| PortableKeyError::Rejected)?;
    memory_blocks.resize_with(params.block_count(), Block::default);
    let mut memory = Zeroizing::new(memory_blocks);
    let mut kek = Zeroizing::new([0u8; KEK_BYTES]);
    argon2
        .hash_password_into_with_memory(
            passphrase.0.as_slice(),
            salt,
            kek.as_mut_slice(),
            memory.as_mut_slice(),
        )
        .map_err(|_| PortableKeyError::Rejected)?;
    Ok(kek)
}

fn authenticated_context(prefix: &[u8], session_id: SessionId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + PREFIX_BYTES + SESSION_SCOPE_BYTES);
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(prefix);
    aad.extend_from_slice(session_id.as_bytes());
    aad
}

fn validate_prefix(encoded: &[u8; WRAPPED_SESSION_KEY_V1_BYTES]) -> Result<(), PortableKeyError> {
    if &encoded[..8] != FORMAT_MAGIC
        || encoded[8..10] != FORMAT_VERSION.to_be_bytes()
        || encoded[10..12] != ARGON2_PROFILE.to_be_bytes()
        || encoded[12..14] != AEAD_SUITE.to_be_bytes()
        || encoded[14..18] != ARGON2_MEMORY_KIB.to_be_bytes()
        || encoded[18..22] != ARGON2_TIME_COST.to_be_bytes()
        || encoded[22..26] != ARGON2_LANES.to_be_bytes()
    {
        return Err(PortableKeyError::Rejected);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{AssociatedData, ParamsBuilder};

    #[test]
    fn rfc_9106_argon2id_known_answer() {
        let mut builder = ParamsBuilder::new();
        builder
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .output_len(32)
            .data(AssociatedData::new(&[4u8; 12]).expect("bounded associated data"));
        let params = builder.build().expect("RFC parameters");
        let argon2 = Argon2::new_with_secret(
            &[3u8; 8],
            Algorithm::Argon2id,
            Version::V0x13,
            params.clone(),
        )
        .expect("RFC secret");
        let mut memory = Zeroizing::new(vec![Block::default(); params.block_count()]);
        let mut output = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into_with_memory(
                &[1u8; 32],
                &[2u8; 16],
                output.as_mut_slice(),
                memory.as_mut_slice(),
            )
            .expect("RFC Argon2id operation");
        assert_eq!(
            *output,
            [
                0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b,
                0x53, 0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9,
                0x6b, 0x01, 0xe6, 0x59,
            ]
        );
    }

    #[test]
    fn portable_v1_known_answer_fixture_is_byte_exact() {
        let session_id = SessionId::new([0x11; 32]).expect("session ID");
        let passphrase =
            PortablePassphrase::new(vec![0x00, 0x80, 0xff, 0x41]).expect("binary passphrase");
        let wrapped =
            wrap_with_material(session_id, &passphrase, &[0x22; 32], [0x33; 16], [0x44; 12])
                .expect("deterministic fixture");
        assert_eq!(
            *wrapped.as_bytes(),
            [
                83, 67, 86, 75, 87, 82, 80, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0,
                4, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 68, 68, 68, 68,
                68, 68, 68, 68, 68, 68, 68, 68, 152, 11, 47, 30, 203, 78, 121, 139, 112, 113, 11,
                90, 128, 250, 156, 241, 122, 1, 97, 229, 111, 149, 53, 52, 208, 112, 152, 239, 227,
                194, 155, 239, 133, 16, 68, 32, 44, 77, 35, 140, 236, 146, 143, 203, 79, 241, 247,
                246,
            ]
        );

        PortablePassphraseKeyWrapper::new()
            .unseal(session_id, passphrase, &wrapped)
            .expect("known-answer fixture authenticates and unwraps");
    }
}
