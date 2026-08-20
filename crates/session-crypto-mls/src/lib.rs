#![forbid(unsafe_code)]

//! Isolated MLS protocol adapter for Session Chat Phase 1.

use std::time::Duration;

use mls_rs::{
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, Group, MlsMessage, ProtocolVersion,
    WireFormat,
    client_builder::MlsConfig,
    extension::ExtensionType,
    external_client::{ExternalClient, builder::MlsConfig as ExternalMlsConfig},
    group::{CommitEffect, ReceivedMessage},
    identity::{
        SigningIdentity,
        basic::{BasicCredential, BasicIdentityProvider},
    },
    mls_rs_codec::MlsDecode,
};
use mls_rs_crypto_awslc::AwsLcCryptoProvider;
use thiserror::Error;

/// Exact byte length of a Phase 1 session-scoped credential identity.
pub const SESSION_CREDENTIAL_ID_BYTES: usize = 32;
/// Exact byte length of a Phase 1 group identifier.
pub const SESSION_GROUP_ID_BYTES: usize = 32;
/// Maximum TLS-serialized KeyPackage accepted before parsing.
pub const MAX_KEY_PACKAGE_BYTES: usize = 16 * 1024;
/// Maximum TLS-serialized MLS protocol message accepted before parsing.
pub const MAX_MLS_MESSAGE_BYTES: usize = 64 * 1024;
/// Maximum application plaintext accepted for one Phase 1 message.
pub const MAX_APPLICATION_BYTES: usize = 16 * 1024;

const KEY_PACKAGE_REFERENCE_BYTES: usize = 32;
const KEY_PACKAGE_LIFETIME: Duration = Duration::from_secs(3_600);
const CIPHERSUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

/// Coarse, non-provider-specific MLS adapter failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MlsAdapterError {
    /// A fixed-length identifier was all zero.
    #[error("invalid identifier")]
    InvalidIdentifier,
    /// Attacker-controlled input exceeded its pre-parse bound.
    #[error("input exceeds the configured bound")]
    InputTooLarge,
    /// A KeyPackage was not one exact canonical TLS object.
    #[error("malformed key package")]
    MalformedKeyPackage,
    /// Cryptographic or Phase 1 policy validation rejected a KeyPackage.
    #[error("key package rejected")]
    RejectedKeyPackage,
    /// MLS rejected a group or message operation.
    #[error("MLS protocol operation rejected")]
    ProtocolRejected,
    /// The provider returned output outside the Phase 1 contract.
    #[error("unexpected MLS provider output")]
    UnexpectedProviderOutput,
    /// Phase 1 permits exactly two members.
    #[error("the two-member Phase 1 group is full")]
    GroupFull,
}

/// Fresh random BasicCredential identity for one Session Chat session.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SessionCredentialId([u8; SESSION_CREDENTIAL_ID_BYTES]);

impl SessionCredentialId {
    /// Accepts a fixed-length, nonzero session-scoped identifier.
    pub fn new(bytes: [u8; SESSION_CREDENTIAL_ID_BYTES]) -> Result<Self, MlsAdapterError> {
        nonzero(bytes).map(Self)
    }

    /// Returns the public session-scoped credential identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SESSION_CREDENTIAL_ID_BYTES] {
        &self.0
    }
}

/// Opaque, fixed-length identifier for one MLS group.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SessionGroupId([u8; SESSION_GROUP_ID_BYTES]);

impl SessionGroupId {
    /// Accepts a fixed-length, nonzero group identifier.
    pub fn new(bytes: [u8; SESSION_GROUP_ID_BYTES]) -> Result<Self, MlsAdapterError> {
        nonzero(bytes).map(Self)
    }

    /// Returns the group identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SESSION_GROUP_ID_BYTES] {
        &self.0
    }
}

fn nonzero<const N: usize>(bytes: [u8; N]) -> Result<[u8; N], MlsAdapterError> {
    (!bytes.iter().all(|byte| *byte == 0))
        .then_some(bytes)
        .ok_or(MlsAdapterError::InvalidIdentifier)
}

/// A client whose MLS state is isolated to in-memory provider repositories.
pub struct SessionMlsClient<C: MlsConfig> {
    inner: Client<C>,
}

/// Creates a Phase 1 client with the selected suite and a one-hour KeyPackage lifetime.
pub fn create_client(
    credential_identity: SessionCredentialId,
) -> Result<SessionMlsClient<impl MlsConfig>, MlsAdapterError> {
    let crypto = AwsLcCryptoProvider::default();
    let cipher_suite = crypto
        .cipher_suite_provider(CIPHERSUITE)
        .ok_or(MlsAdapterError::UnexpectedProviderOutput)?;
    let (secret, public) = cipher_suite
        .signature_key_generate()
        .map_err(|_| MlsAdapterError::ProtocolRejected)?;
    let credential = BasicCredential::new(credential_identity.0.to_vec());
    let identity = SigningIdentity::new(credential.into_credential(), public);
    let inner = Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto)
        .protocol_version(ProtocolVersion::MLS_10)
        .key_package_lifetime(KEY_PACKAGE_LIFETIME)
        .signing_identity(identity, secret, CIPHERSUITE)
        .build();

    Ok(SessionMlsClient { inner })
}

/// Bounded serialized KeyPackage produced by a Session Chat client.
pub struct KeyPackageMessage(Vec<u8>);

impl KeyPackageMessage {
    /// Borrows the TLS-serialized KeyPackage message.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<C: MlsConfig> SessionMlsClient<C> {
    /// Generates one one-shot KeyPackage using a caller-supplied clock value.
    pub fn generate_key_package(
        &self,
        now_unix_seconds: u64,
    ) -> Result<KeyPackageMessage, MlsAdapterError> {
        let message = self
            .inner
            .generate_key_package_message(
                Default::default(),
                Default::default(),
                Some(now_unix_seconds.into()),
            )
            .map_err(|_| MlsAdapterError::ProtocolRejected)?;
        let bytes = message
            .to_bytes()
            .map_err(|_| MlsAdapterError::UnexpectedProviderOutput)?;
        if bytes.len() > MAX_KEY_PACKAGE_BYTES {
            return Err(MlsAdapterError::UnexpectedProviderOutput);
        }

        Ok(KeyPackageMessage(bytes))
    }

    /// Creates an isolated one-member group with no extensions.
    pub fn create_group(
        &self,
        group_id: SessionGroupId,
        now_unix_seconds: u64,
    ) -> Result<SessionMlsGroup<C>, MlsAdapterError> {
        let inner = self
            .inner
            .create_group_with_id(
                group_id.0.to_vec(),
                Default::default(),
                Default::default(),
                Some(now_unix_seconds.into()),
            )
            .map_err(|_| MlsAdapterError::ProtocolRejected)?;
        SessionMlsGroup::from_provider(inner)
    }

    /// Consumes one bounded Welcome to join its corresponding two-member group.
    pub fn join_group(
        &self,
        welcome: WelcomeMessage,
        now_unix_seconds: u64,
    ) -> Result<SessionMlsGroup<C>, MlsAdapterError> {
        let message = decode_exact(&welcome.0).map_err(|_| MlsAdapterError::ProtocolRejected)?;
        if message.wire_format() != WireFormat::Welcome
            || message.cipher_suite() != Some(CIPHERSUITE)
        {
            return Err(MlsAdapterError::ProtocolRejected);
        }
        let (inner, new_member) = self
            .inner
            .join_group(None, &message, Some(now_unix_seconds.into()))
            .map_err(|_| MlsAdapterError::ProtocolRejected)?;
        if new_member
            .group_info_extensions()
            .iter()
            .any(|extension| extension.extension_type != ExtensionType::RATCHET_TREE)
        {
            return Err(MlsAdapterError::ProtocolRejected);
        }
        let group = SessionMlsGroup::from_provider(inner)?;
        if group.member_count() != 2 {
            return Err(MlsAdapterError::UnexpectedProviderOutput);
        }
        Ok(group)
    }
}

/// Canonical ciphersuite hash reference over one exact validated KeyPackage.
pub type KeyPackageReference = [u8; KEY_PACKAGE_REFERENCE_BYTES];

/// Linear value owning the exact KeyPackage message accepted by policy.
pub struct ValidatedKeyPackage {
    message: MlsMessage,
    reference: KeyPackageReference,
    credential_identity: [u8; SESSION_CREDENTIAL_ID_BYTES],
    leaf_signature_key: [u8; 32],
}

impl ValidatedKeyPackage {
    /// Returns the canonical RFC 9420 KeyPackage reference.
    #[must_use]
    pub const fn key_package_reference(&self) -> &KeyPackageReference {
        &self.reference
    }

    /// Returns the BasicCredential's exact session-scoped identity.
    #[must_use]
    pub const fn credential_identity(&self) -> &[u8; SESSION_CREDENTIAL_ID_BYTES] {
        &self.credential_identity
    }

    /// Returns the leaf signature public key authenticated by the KeyPackage.
    #[must_use]
    pub const fn leaf_signature_key(&self) -> &[u8; 32] {
        &self.leaf_signature_key
    }
}

/// Stateless external KeyPackage validator using the selected provider.
pub struct KeyPackageValidator<C: ExternalMlsConfig> {
    inner: ExternalClient<C>,
    crypto: AwsLcCryptoProvider,
}

/// Creates the external validation boundary used before admission.
#[must_use]
pub fn create_key_package_validator() -> KeyPackageValidator<impl ExternalMlsConfig> {
    let crypto = AwsLcCryptoProvider::default();
    let inner = ExternalClient::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto.clone())
        .build();
    KeyPackageValidator { inner, crypto }
}

impl<C: ExternalMlsConfig> KeyPackageValidator<C> {
    /// Parses, cryptographically validates, and binds one exact KeyPackage.
    pub fn validate_key_package(
        &self,
        encoded: &[u8],
        now_unix_seconds: u64,
    ) -> Result<ValidatedKeyPackage, MlsAdapterError> {
        if encoded.is_empty() || encoded.len() > MAX_KEY_PACKAGE_BYTES {
            return Err(if encoded.len() > MAX_KEY_PACKAGE_BYTES {
                MlsAdapterError::InputTooLarge
            } else {
                MlsAdapterError::MalformedKeyPackage
            });
        }

        let message = decode_exact(encoded).map_err(|_| MlsAdapterError::MalformedKeyPackage)?;
        if message.wire_format() != WireFormat::KeyPackage
            || message.cipher_suite() != Some(CIPHERSUITE)
        {
            return Err(MlsAdapterError::RejectedKeyPackage);
        }

        let key_package = self
            .inner
            .validate_key_package(message.clone(), Some(now_unix_seconds.into()))
            .map_err(|_| MlsAdapterError::RejectedKeyPackage)?;
        if message.as_key_package() != Some(&key_package)
            || key_package.version() != ProtocolVersion::MLS_10
            || key_package.cipher_suite() != CIPHERSUITE
            || !key_package.ungreased_extensions().is_empty()
        {
            return Err(MlsAdapterError::RejectedKeyPackage);
        }

        let signing_identity = key_package.signing_identity();
        let credential_identity: [u8; SESSION_CREDENTIAL_ID_BYTES] = signing_identity
            .credential
            .as_basic()
            .ok_or(MlsAdapterError::RejectedKeyPackage)?
            .identifier()
            .try_into()
            .map_err(|_| MlsAdapterError::RejectedKeyPackage)?;
        nonzero(credential_identity).map_err(|_| MlsAdapterError::RejectedKeyPackage)?;
        let leaf_signature_key: [u8; 32] = signing_identity
            .signature_key
            .as_ref()
            .try_into()
            .map_err(|_| MlsAdapterError::RejectedKeyPackage)?;
        let cipher_suite = self
            .crypto
            .cipher_suite_provider(CIPHERSUITE)
            .ok_or(MlsAdapterError::UnexpectedProviderOutput)?;
        let reference: KeyPackageReference = key_package
            .to_reference(&cipher_suite)
            .map_err(|_| MlsAdapterError::RejectedKeyPackage)?
            .as_ref()
            .try_into()
            .map_err(|_| MlsAdapterError::UnexpectedProviderOutput)?;

        Ok(ValidatedKeyPackage {
            message,
            reference,
            credential_identity,
            leaf_signature_key,
        })
    }
}

fn decode_exact(encoded: &[u8]) -> Result<MlsMessage, ()> {
    let mut remaining = encoded;
    let message = MlsMessage::mls_decode(&mut remaining).map_err(|_| ())?;
    remaining.is_empty().then_some(message).ok_or(())
}

/// A bounded opaque MLS Commit or application message.
pub struct MlsWireMessage(Vec<u8>);

impl MlsWireMessage {
    /// Copies untrusted bytes only after enforcing the outer message bound.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MlsAdapterError> {
        if bytes.len() > MAX_MLS_MESSAGE_BYTES {
            return Err(MlsAdapterError::InputTooLarge);
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Borrows the opaque TLS-serialized message.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Coarse result of processing a bounded MLS message.
#[derive(Debug, Eq, PartialEq)]
pub enum IncomingMessage {
    /// Decrypted application bytes.
    Application(Vec<u8>),
    /// A valid Commit advanced the local epoch.
    EpochAdvanced,
    /// A valid Commit removed this client.
    Removed,
}

/// In-memory two-member Phase 1 group behind the Session Chat adapter.
pub struct SessionMlsGroup<C: MlsConfig> {
    inner: Group<C>,
    group_id: SessionGroupId,
}

impl<C: MlsConfig> SessionMlsGroup<C> {
    fn from_provider(inner: Group<C>) -> Result<Self, MlsAdapterError> {
        let group_id: [u8; SESSION_GROUP_ID_BYTES] = inner
            .group_id()
            .try_into()
            .map_err(|_| MlsAdapterError::UnexpectedProviderOutput)?;
        let group_id =
            SessionGroupId::new(group_id).map_err(|_| MlsAdapterError::UnexpectedProviderOutput)?;
        if inner.protocol_version() != ProtocolVersion::MLS_10
            || inner.cipher_suite() != CIPHERSUITE
            || inner.roster().members_iter().any(|member| {
                !member.extensions().is_empty()
                    || member
                        .signing_identity()
                        .credential
                        .as_basic()
                        .is_none_or(|credential| credential.identifier().len() != 32)
            })
        {
            return Err(MlsAdapterError::UnexpectedProviderOutput);
        }
        Ok(Self { inner, group_id })
    }

    /// Returns the MLS epoch held by this in-memory instance.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.inner.current_epoch()
    }

    /// Returns the number of nonblank leaves in the current roster.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.inner.roster().members_iter().count()
    }

    /// Returns the fixed Session Chat group identifier.
    #[must_use]
    pub const fn group_id(&self) -> &[u8; SESSION_GROUP_ID_BYTES] {
        self.group_id.as_bytes()
    }

    /// Prepares an Add without applying its pending group state.
    pub fn prepare_add(
        &mut self,
        validated: ValidatedKeyPackage,
        now_unix_seconds: u64,
    ) -> Result<PreparedAddition<'_, C>, MlsAdapterError> {
        if self.member_count() != 1 {
            return Err(MlsAdapterError::GroupFull);
        }
        if self
            .inner
            .roster()
            .member_identities_iter()
            .any(|identity| {
                identity.credential.as_basic().is_some_and(|credential| {
                    credential.identifier() == validated.credential_identity
                })
            })
        {
            return Err(MlsAdapterError::RejectedKeyPackage);
        }

        let epoch_before = self.epoch();
        let reference = validated.reference;
        let output = self
            .inner
            .commit_builder()
            .add_member(validated.message)
            .map(|builder| builder.commit_time(now_unix_seconds.into()))
            .and_then(|builder| builder.build())
            .map_err(|_| MlsAdapterError::ProtocolRejected)?;
        let [welcome] = output.welcome_messages.as_slice() else {
            self.inner.clear_pending_commit();
            return Err(MlsAdapterError::UnexpectedProviderOutput);
        };
        if !welcome
            .welcome_key_package_references()
            .iter()
            .any(|candidate| candidate.as_ref() == reference)
        {
            self.inner.clear_pending_commit();
            return Err(MlsAdapterError::UnexpectedProviderOutput);
        }

        let welcome = WelcomeMessage::from_provider(welcome)?;
        let commit = MlsWireMessage::from_provider(&output.commit_message)?;
        Ok(PreparedAddition {
            group: self,
            epoch_before,
            reference,
            welcome: Some(welcome),
            commit: Some(commit),
            applied: false,
        })
    }

    /// Encrypts one bounded application message for the current epoch.
    pub fn encrypt_application_message(
        &mut self,
        plaintext: &[u8],
    ) -> Result<MlsWireMessage, MlsAdapterError> {
        if plaintext.len() > MAX_APPLICATION_BYTES {
            return Err(MlsAdapterError::InputTooLarge);
        }
        let message = self
            .inner
            .encrypt_application_message(plaintext, Vec::new())
            .map_err(|_| MlsAdapterError::ProtocolRejected)?;
        MlsWireMessage::from_provider(&message)
    }

    /// Processes one exact bounded MLS Commit or application message.
    pub fn process_message(
        &mut self,
        message: MlsWireMessage,
    ) -> Result<IncomingMessage, MlsAdapterError> {
        let message = decode_exact(&message.0).map_err(|_| MlsAdapterError::ProtocolRejected)?;
        match self
            .inner
            .process_incoming_message(message)
            .map_err(|_| MlsAdapterError::ProtocolRejected)?
        {
            ReceivedMessage::ApplicationMessage(application) => {
                if application.data().len() > MAX_APPLICATION_BYTES
                    || !application.authenticated_data.is_empty()
                {
                    return Err(MlsAdapterError::ProtocolRejected);
                }
                Ok(IncomingMessage::Application(application.data().to_vec()))
            }
            ReceivedMessage::Commit(commit) => match commit.effect {
                CommitEffect::NewEpoch(_) => Ok(IncomingMessage::EpochAdvanced),
                CommitEffect::Removed { .. } => Ok(IncomingMessage::Removed),
                CommitEffect::ReInit(_) => Err(MlsAdapterError::ProtocolRejected),
            },
            _ => Err(MlsAdapterError::ProtocolRejected),
        }
    }
}

impl MlsWireMessage {
    fn from_provider(message: &MlsMessage) -> Result<Self, MlsAdapterError> {
        let bytes = message
            .to_bytes()
            .map_err(|_| MlsAdapterError::UnexpectedProviderOutput)?;
        if bytes.len() > MAX_MLS_MESSAGE_BYTES {
            return Err(MlsAdapterError::UnexpectedProviderOutput);
        }
        Ok(Self(bytes))
    }
}

/// One bounded encrypted Welcome. This value is deliberately non-Clone.
pub struct WelcomeMessage(Vec<u8>);

impl WelcomeMessage {
    fn from_provider(message: &MlsMessage) -> Result<Self, MlsAdapterError> {
        let bytes = message
            .to_bytes()
            .map_err(|_| MlsAdapterError::UnexpectedProviderOutput)?;
        if bytes.len() > MAX_MLS_MESSAGE_BYTES {
            return Err(MlsAdapterError::UnexpectedProviderOutput);
        }
        Ok(Self(bytes))
    }
}

/// Pending Add whose group state has not yet advanced.
pub struct PreparedAddition<'a, C: MlsConfig> {
    group: &'a mut SessionMlsGroup<C>,
    epoch_before: u64,
    reference: KeyPackageReference,
    welcome: Option<WelcomeMessage>,
    commit: Option<MlsWireMessage>,
    applied: bool,
}

impl<C: MlsConfig> PreparedAddition<'_, C> {
    /// Returns the exact KeyPackage reference targeted by the Welcome.
    #[must_use]
    pub const fn key_package_reference(&self) -> &KeyPackageReference {
        &self.reference
    }

    /// Returns the epoch before applying the pending Add.
    #[must_use]
    pub const fn epoch_before(&self) -> u64 {
        self.epoch_before
    }

    /// Observes that prepare did not advance the current group epoch.
    #[must_use]
    pub fn current_group_epoch(&self) -> u64 {
        self.group.epoch()
    }

    /// Applies the pending Add in memory and returns its transport outputs.
    pub fn apply(mut self) -> Result<CommittedAddition, MlsAdapterError> {
        self.group
            .inner
            .apply_pending_commit()
            .map_err(|_| MlsAdapterError::ProtocolRejected)?;
        if self.group.epoch() != self.epoch_before + 1 || self.group.member_count() != 2 {
            return Err(MlsAdapterError::UnexpectedProviderOutput);
        }
        self.applied = true;
        Ok(CommittedAddition {
            reference: self.reference,
            welcome: self
                .welcome
                .take()
                .ok_or(MlsAdapterError::UnexpectedProviderOutput)?,
            commit: self
                .commit
                .take()
                .ok_or(MlsAdapterError::UnexpectedProviderOutput)?,
        })
    }
}

impl<C: MlsConfig> Drop for PreparedAddition<'_, C> {
    fn drop(&mut self) {
        if !self.applied {
            self.group.inner.clear_pending_commit();
        }
    }
}

/// Applied in-memory Add plus the exact opaque transport outputs it produced.
pub struct CommittedAddition {
    reference: KeyPackageReference,
    welcome: WelcomeMessage,
    commit: MlsWireMessage,
}

impl CommittedAddition {
    /// Returns the reference checked against the encrypted Welcome recipients.
    #[must_use]
    pub const fn key_package_reference(&self) -> &KeyPackageReference {
        &self.reference
    }

    /// Borrows the Commit output for future durable outbox staging.
    #[must_use]
    pub const fn commit(&self) -> &MlsWireMessage {
        &self.commit
    }

    /// Consumes the result into the one-shot Welcome value.
    #[must_use]
    pub fn into_welcome(self) -> WelcomeMessage {
        self.welcome
    }
}
