#![forbid(unsafe_code)]

//! Isolated MLS protocol adapter for Session Chat Phase 1.

use std::time::Duration;

use mls_rs::mls_rs_codec::{self, MlsDecode, MlsEncode};
use mls_rs::{
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, Group, MlsMessage,
    ProtocolVersion, WireFormat,
    client_builder::MlsConfig,
    crypto::HpkePublicKey,
    extension::ExtensionType,
    external_client::{ExternalClient, builder::MlsConfig as ExternalMlsConfig},
    group::{CommitEffect, LeafNode, ReceivedMessage},
    identity::{
        SigningIdentity,
        basic::{BasicCredential, BasicIdentityProvider},
    },
};
use mls_rs_core::{group::GroupStateStorage, key_package::KeyPackageStorage};
use mls_rs_crypto_awslc::AwsLcCryptoProvider;
use session_crypto::{
    ApplicationMessage, MessageEvent, MessageSession, MessageSessionError, ProtectedMessage,
    validate_application_message,
};
use thiserror::Error;

/// Opaque configuration bound used by ownership-preserving integration wrappers.
pub use mls_rs::client_builder::MlsConfig as SessionMlsConfig;
pub use session_crypto::{
    MAX_APPLICATION_MESSAGE_BYTES as MAX_APPLICATION_BYTES,
    MAX_PROTECTED_MESSAGE_BYTES as MAX_MLS_MESSAGE_BYTES,
};

/// Exact byte length of a Phase 1 session-scoped credential identity.
pub const SESSION_CREDENTIAL_ID_BYTES: usize = 32;
/// Exact byte length of a Phase 1 group identifier.
pub const SESSION_GROUP_ID_BYTES: usize = 32;
/// Maximum TLS-serialized KeyPackage accepted before parsing.
pub const MAX_KEY_PACKAGE_BYTES: usize = 16 * 1024;
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

/// A client whose MLS state is isolated behind configured provider repositories.
pub struct SessionMlsClient<C: MlsConfig> {
    inner: Client<C>,
    credential_identity: SessionCredentialId,
}

fn create_client_with_credential_identity(
    credential_identity: SessionCredentialId,
    crypto: AwsLcCryptoProvider,
) -> Result<SessionMlsClient<impl MlsConfig>, MlsAdapterError> {
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

    Ok(SessionMlsClient {
        inner,
        credential_identity,
    })
}

/// Creates a Phase 1 client with a fresh random session identity, the selected
/// suite, and a one-hour KeyPackage lifetime.
pub fn create_client() -> Result<SessionMlsClient<impl MlsConfig>, MlsAdapterError> {
    let crypto = AwsLcCryptoProvider::default();
    let cipher_suite = crypto
        .cipher_suite_provider(CIPHERSUITE)
        .ok_or(MlsAdapterError::UnexpectedProviderOutput)?;
    let mut bytes = [0; SESSION_CREDENTIAL_ID_BYTES];
    cipher_suite
        .random_bytes(&mut bytes)
        .map_err(|_| MlsAdapterError::ProtocolRejected)?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(MlsAdapterError::UnexpectedProviderOutput);
    }

    create_client_with_credential_identity(SessionCredentialId(bytes), crypto)
}

/// Creates a Phase 1 client with caller-owned MLS group and KeyPackage stores.
///
/// The stores remain separate provider types because `mls-rs` invokes them
/// separately. A durable implementation that needs one joiner-local transaction
/// must coordinate those two trait calls behind shared provider state.
pub fn create_client_with_storage<G, K>(
    group_state_storage: G,
    key_package_storage: K,
) -> Result<SessionMlsClient<impl MlsConfig>, MlsAdapterError>
where
    G: GroupStateStorage + Clone,
    K: KeyPackageStorage + Clone,
{
    let crypto = AwsLcCryptoProvider::default();
    let cipher_suite = crypto
        .cipher_suite_provider(CIPHERSUITE)
        .ok_or(MlsAdapterError::UnexpectedProviderOutput)?;
    let mut credential_identity = [0; SESSION_CREDENTIAL_ID_BYTES];
    cipher_suite
        .random_bytes(&mut credential_identity)
        .map_err(|_| MlsAdapterError::ProtocolRejected)?;
    if credential_identity.iter().all(|byte| *byte == 0) {
        return Err(MlsAdapterError::UnexpectedProviderOutput);
    }
    let (secret, public) = cipher_suite
        .signature_key_generate()
        .map_err(|_| MlsAdapterError::ProtocolRejected)?;
    let identity = SigningIdentity::new(
        BasicCredential::new(credential_identity.to_vec()).into_credential(),
        public,
    );
    let inner = Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto)
        .key_package_repo(key_package_storage)
        .group_state_storage(group_state_storage)
        .protocol_version(ProtocolVersion::MLS_10)
        .key_package_lifetime(KEY_PACKAGE_LIFETIME)
        .signing_identity(identity, secret, CIPHERSUITE)
        .build();

    Ok(SessionMlsClient {
        inner,
        credential_identity: SessionCredentialId(credential_identity),
    })
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
    /// Returns this client's adapter-generated session-scoped credential identity.
    #[must_use]
    pub const fn credential_identity(&self) -> &SessionCredentialId {
        &self.credential_identity
    }

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

#[derive(MlsDecode)]
struct KeyPackagePolicyView {
    version: ProtocolVersion,
    cipher_suite: CipherSuite,
    hpke_init_key: HpkePublicKey,
    leaf_node: LeafNode,
    extensions: ExtensionList,
    #[mls_codec(with = "mls_rs::mls_rs_codec::byte_vec")]
    signature: Vec<u8>,
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

        // mls-rs 0.56.0 does not expose the KeyPackage leaf through its public
        // accessor API. Re-decode the provider-validated KeyPackage with the
        // exact pinned TLS layout solely to enforce the closed Phase 1 leaf
        // extension/capability policy. Cryptographic validation remains above.
        let encoded_key_package = key_package
            .mls_encode_to_vec()
            .map_err(|_| MlsAdapterError::RejectedKeyPackage)?;
        let mut remaining = encoded_key_package.as_slice();
        let policy_view = KeyPackagePolicyView::mls_decode(&mut remaining)
            .map_err(|_| MlsAdapterError::RejectedKeyPackage)?;
        if !remaining.is_empty()
            || policy_view.version != key_package.version()
            || policy_view.cipher_suite != key_package.cipher_suite()
            || policy_view.leaf_node.signing_identity != *key_package.signing_identity()
            || !policy_view.extensions.is_empty()
            || !policy_view.leaf_node.extensions.is_empty()
            || !policy_view.leaf_node.capabilities.extensions().is_empty()
            || !policy_view.leaf_node.capabilities.proposals().is_empty()
            || policy_view.leaf_node.capabilities.protocol_versions() != [ProtocolVersion::MLS_10]
            || policy_view.leaf_node.capabilities.credentials()
                != [BasicCredential::credential_type()]
        {
            return Err(MlsAdapterError::RejectedKeyPackage);
        }
        let _ = (policy_view.hpke_init_key, policy_view.signature);

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
    inactive: bool,
}

impl<C: MlsConfig> SessionMlsGroup<C> {
    fn from_provider(inner: Group<C>) -> Result<Self, MlsAdapterError> {
        let group_id: [u8; SESSION_GROUP_ID_BYTES] = inner
            .group_id()
            .try_into()
            .map_err(|_| MlsAdapterError::UnexpectedProviderOutput)?;
        let group_id =
            SessionGroupId::new(group_id).map_err(|_| MlsAdapterError::UnexpectedProviderOutput)?;
        let group = Self {
            inner,
            group_id,
            inactive: false,
        };
        if !group.phase_one_invariants_hold() {
            return Err(MlsAdapterError::UnexpectedProviderOutput);
        }
        Ok(group)
    }

    fn phase_one_invariants_hold(&self) -> bool {
        if self.inner.protocol_version() != ProtocolVersion::MLS_10
            || self.inner.cipher_suite() != CIPHERSUITE
            || self.inner.group_id() != self.group_id.as_bytes()
        {
            return false;
        }

        let members = self.inner.roster().members();
        if !(1..=2).contains(&members.len()) {
            return false;
        }
        let mut identities = Vec::with_capacity(members.len());
        for member in members {
            let capabilities = member.capabilities();
            let Some(credential) = member.signing_identity().credential.as_basic() else {
                return false;
            };
            let Ok(identity) =
                <[u8; SESSION_CREDENTIAL_ID_BYTES]>::try_from(credential.identifier())
            else {
                return false;
            };
            if identity.iter().all(|byte| *byte == 0)
                || identities.contains(&identity)
                || member.signing_identity().signature_key.as_ref().len() != 32
                || !member.extensions().is_empty()
                || capabilities.protocol_versions() != [ProtocolVersion::MLS_10]
                || !capabilities.cipher_suites().contains(&CIPHERSUITE)
                || !capabilities.extensions().is_empty()
                || !capabilities.proposals().is_empty()
                || capabilities.credentials() != [BasicCredential::credential_type()]
            {
                return false;
            }
            identities.push(identity);
        }
        true
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

    /// Persists the provider's complete current snapshot and pending epochs.
    ///
    /// For a joining client, `mls-rs` subsequently asks its configured
    /// KeyPackage store to delete the exact one-time KeyPackage. A durable
    /// provider must make those owner-local effects atomic.
    pub fn write_to_storage(&mut self) -> Result<(), MlsAdapterError> {
        self.inner
            .write_to_storage()
            .map_err(|_| MlsAdapterError::ProtocolRejected)
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

        let welcome = match WelcomeMessage::from_provider(welcome) {
            Ok(welcome) => welcome,
            Err(error) => {
                self.inner.clear_pending_commit();
                return Err(error);
            }
        };
        let commit = match MlsWireMessage::from_provider(&output.commit_message) {
            Ok(commit) => commit,
            Err(error) => {
                self.inner.clear_pending_commit();
                return Err(error);
            }
        };
        Ok(PreparedAddition {
            group: self,
            epoch_before,
            reference,
            welcome: Some(welcome),
            commit: Some(commit),
            applied: false,
        })
    }

    /// Prepares removal of the only peer without applying the pending epoch.
    pub fn prepare_remove_peer(
        &mut self,
        now_unix_seconds: u64,
    ) -> Result<PreparedRemoval<'_, C>, MlsAdapterError> {
        if self.member_count() != 2 {
            return Err(MlsAdapterError::ProtocolRejected);
        }
        let local_index = self.inner.current_member_index();
        let peer_index = self
            .inner
            .roster()
            .members_iter()
            .find(|member| member.index() != local_index)
            .map(|member| member.index())
            .ok_or(MlsAdapterError::UnexpectedProviderOutput)?;
        let epoch_before = self.epoch();
        let output = self
            .inner
            .commit_builder()
            .remove_member(peer_index)
            .map(|builder| builder.commit_time(now_unix_seconds.into()))
            .and_then(|builder| builder.build())
            .map_err(|_| MlsAdapterError::ProtocolRejected)?;
        if !output.welcome_messages.is_empty() {
            self.inner.clear_pending_commit();
            return Err(MlsAdapterError::UnexpectedProviderOutput);
        }
        let commit = match MlsWireMessage::from_provider(&output.commit_message) {
            Ok(commit) => commit,
            Err(error) => {
                self.inner.clear_pending_commit();
                return Err(error);
            }
        };
        Ok(PreparedRemoval {
            group: self,
            epoch_before,
            commit: Some(commit),
            applied: false,
        })
    }

    /// Prepares an empty Commit with a path update without advancing the epoch.
    pub fn prepare_epoch_update(
        &mut self,
        now_unix_seconds: u64,
    ) -> Result<PreparedEpochUpdate<'_, C>, MlsAdapterError> {
        if self.inactive || !(1..=2).contains(&self.member_count()) {
            return Err(MlsAdapterError::ProtocolRejected);
        }
        let epoch_before = self.epoch();
        let member_count_before = self.member_count();
        let output = self
            .inner
            .commit_builder()
            .commit_time(now_unix_seconds.into())
            .build()
            .map_err(|_| MlsAdapterError::ProtocolRejected)?;
        if !output.contains_update_path || !output.welcome_messages.is_empty() {
            self.inner.clear_pending_commit();
            return Err(MlsAdapterError::UnexpectedProviderOutput);
        }
        let commit = match MlsWireMessage::from_provider(&output.commit_message) {
            Ok(commit) => commit,
            Err(error) => {
                self.inner.clear_pending_commit();
                return Err(error);
            }
        };
        Ok(PreparedEpochUpdate {
            group: self,
            epoch_before,
            member_count_before,
            commit: Some(commit),
            applied: false,
        })
    }

    /// Encrypts one bounded application message for the current epoch.
    pub fn encrypt_application_message(
        &mut self,
        plaintext: &[u8],
    ) -> Result<MlsWireMessage, MlsAdapterError> {
        if self.inactive {
            return Err(MlsAdapterError::ProtocolRejected);
        }
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
        if self.inactive {
            return Err(MlsAdapterError::ProtocolRejected);
        }
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
                CommitEffect::NewEpoch(_) => {
                    if !self.phase_one_invariants_hold() {
                        self.inactive = true;
                        return Err(MlsAdapterError::ProtocolRejected);
                    }
                    Ok(IncomingMessage::EpochAdvanced)
                }
                CommitEffect::Removed { .. } => {
                    self.inactive = true;
                    Ok(IncomingMessage::Removed)
                }
                CommitEffect::ReInit(_) => Err(MlsAdapterError::ProtocolRejected),
            },
            _ => Err(MlsAdapterError::ProtocolRejected),
        }
    }
}

impl<C: MlsConfig> MessageSession for SessionMlsGroup<C> {
    fn epoch(&self) -> u64 {
        SessionMlsGroup::epoch(self)
    }

    fn member_count(&self) -> usize {
        SessionMlsGroup::member_count(self)
    }

    fn protect_application_message(
        &mut self,
        plaintext: &[u8],
    ) -> Result<ProtectedMessage, MessageSessionError> {
        validate_application_message(plaintext)?;
        let message = SessionMlsGroup::encrypt_application_message(self, plaintext)
            .map_err(message_session_error)?;
        ProtectedMessage::from_vec(message.0)
    }

    fn process_protected_message(
        &mut self,
        message: ProtectedMessage,
    ) -> Result<MessageEvent, MessageSessionError> {
        let message = MlsWireMessage(message.into_bytes());
        match SessionMlsGroup::process_message(self, message).map_err(message_session_error)? {
            IncomingMessage::Application(plaintext) => Ok(MessageEvent::Application(
                ApplicationMessage::from_vec(plaintext)?,
            )),
            IncomingMessage::EpochAdvanced => Ok(MessageEvent::EpochAdvanced),
            IncomingMessage::Removed => Ok(MessageEvent::Removed),
        }
    }
}

fn message_session_error(error: MlsAdapterError) -> MessageSessionError {
    match error {
        MlsAdapterError::InputTooLarge => MessageSessionError::InputTooLarge,
        MlsAdapterError::InvalidIdentifier
        | MlsAdapterError::MalformedKeyPackage
        | MlsAdapterError::RejectedKeyPackage
        | MlsAdapterError::ProtocolRejected
        | MlsAdapterError::UnexpectedProviderOutput
        | MlsAdapterError::GroupFull => MessageSessionError::Rejected,
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
    /// Copies untrusted bytes only after enforcing the outer Welcome bound.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MlsAdapterError> {
        if bytes.len() > MAX_MLS_MESSAGE_BYTES {
            return Err(MlsAdapterError::InputTooLarge);
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Borrows the opaque TLS-serialized Welcome.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

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
        if self.group.epoch() != self.epoch_before + 1
            || self.group.member_count() != 2
            || !self.group.phase_one_invariants_hold()
        {
            self.group.inactive = true;
            return Err(MlsAdapterError::UnexpectedProviderOutput);
        }
        let Some(welcome) = self.welcome.take() else {
            self.group.inactive = true;
            return Err(MlsAdapterError::UnexpectedProviderOutput);
        };
        let Some(commit) = self.commit.take() else {
            self.group.inactive = true;
            return Err(MlsAdapterError::UnexpectedProviderOutput);
        };
        self.applied = true;
        Ok(CommittedAddition {
            reference: self.reference,
            welcome,
            commit,
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

    /// Borrows the one-shot Welcome output for transport serialization.
    #[must_use]
    pub const fn welcome(&self) -> &WelcomeMessage {
        &self.welcome
    }

    /// Consumes the result into the one-shot Welcome value.
    #[must_use]
    pub fn into_welcome(self) -> WelcomeMessage {
        self.welcome
    }
}

/// Pending peer removal whose group state has not yet advanced.
pub struct PreparedRemoval<'a, C: MlsConfig> {
    group: &'a mut SessionMlsGroup<C>,
    epoch_before: u64,
    commit: Option<MlsWireMessage>,
    applied: bool,
}

impl<C: MlsConfig> PreparedRemoval<'_, C> {
    /// Returns the epoch before applying the pending removal.
    #[must_use]
    pub const fn epoch_before(&self) -> u64 {
        self.epoch_before
    }

    /// Observes that prepare did not advance the current group epoch.
    #[must_use]
    pub fn current_group_epoch(&self) -> u64 {
        self.group.epoch()
    }

    /// Applies the pending removal in memory and returns its Commit.
    pub fn apply(mut self) -> Result<CommittedRemoval, MlsAdapterError> {
        self.group
            .inner
            .apply_pending_commit()
            .map_err(|_| MlsAdapterError::ProtocolRejected)?;
        if self.group.epoch() != self.epoch_before + 1
            || self.group.member_count() != 1
            || !self.group.phase_one_invariants_hold()
        {
            self.group.inactive = true;
            return Err(MlsAdapterError::UnexpectedProviderOutput);
        }
        let Some(commit) = self.commit.take() else {
            self.group.inactive = true;
            return Err(MlsAdapterError::UnexpectedProviderOutput);
        };
        self.applied = true;
        Ok(CommittedRemoval { commit })
    }
}

impl<C: MlsConfig> Drop for PreparedRemoval<'_, C> {
    fn drop(&mut self) {
        if !self.applied {
            self.group.inner.clear_pending_commit();
        }
    }
}

/// Applied in-memory peer removal and its opaque Commit output.
pub struct CommittedRemoval {
    commit: MlsWireMessage,
}

/// Pending path update whose group state has not yet advanced.
pub struct PreparedEpochUpdate<'a, C: MlsConfig> {
    group: &'a mut SessionMlsGroup<C>,
    epoch_before: u64,
    member_count_before: usize,
    commit: Option<MlsWireMessage>,
    applied: bool,
}

impl<C: MlsConfig> PreparedEpochUpdate<'_, C> {
    /// Returns the epoch before applying the pending path update.
    #[must_use]
    pub const fn epoch_before(&self) -> u64 {
        self.epoch_before
    }

    /// Applies the pending path update in memory and returns its Commit.
    pub fn apply(mut self) -> Result<CommittedEpochUpdate, MlsAdapterError> {
        self.group
            .inner
            .apply_pending_commit()
            .map_err(|_| MlsAdapterError::ProtocolRejected)?;
        if self.group.epoch() != self.epoch_before + 1
            || self.group.member_count() != self.member_count_before
            || !self.group.phase_one_invariants_hold()
        {
            self.group.inactive = true;
            return Err(MlsAdapterError::UnexpectedProviderOutput);
        }
        let Some(commit) = self.commit.take() else {
            self.group.inactive = true;
            return Err(MlsAdapterError::UnexpectedProviderOutput);
        };
        self.applied = true;
        Ok(CommittedEpochUpdate { commit })
    }
}

impl<C: MlsConfig> Drop for PreparedEpochUpdate<'_, C> {
    fn drop(&mut self) {
        if !self.applied {
            self.group.inner.clear_pending_commit();
        }
    }
}

/// Applied in-memory path update and its opaque Commit output.
pub struct CommittedEpochUpdate {
    commit: MlsWireMessage,
}

impl CommittedEpochUpdate {
    /// Borrows the Commit for durable outbox staging or test delivery.
    #[must_use]
    pub const fn commit(&self) -> &MlsWireMessage {
        &self.commit
    }

    /// Consumes the result into the opaque Commit.
    #[must_use]
    pub fn into_commit(self) -> MlsWireMessage {
        self.commit
    }
}

impl CommittedRemoval {
    /// Borrows the Commit for durable outbox staging or test delivery.
    #[must_use]
    pub const fn commit(&self) -> &MlsWireMessage {
        &self.commit
    }

    /// Consumes the result into the opaque Commit.
    #[must_use]
    pub fn into_commit(self) -> MlsWireMessage {
        self.commit
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
    use zeroize::Zeroizing;

    use super::*;

    #[derive(Clone, Default)]
    struct RecordingStorage {
        writes: Arc<AtomicUsize>,
    }

    impl RecordingStorage {
        fn write_count(&self) -> usize {
            self.writes.load(Ordering::SeqCst)
        }
    }

    impl GroupStateStorage for RecordingStorage {
        type Error = Infallible;

        fn state(&self, _group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
            Ok(None)
        }

        fn epoch(
            &self,
            _group_id: &[u8],
            _epoch_id: u64,
        ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
            Ok(None)
        }

        fn write(
            &mut self,
            _state: GroupState,
            _epoch_inserts: Vec<EpochRecord>,
            _epoch_updates: Vec<EpochRecord>,
        ) -> Result<(), Self::Error> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn max_epoch_id(&self, _group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
            Ok(None)
        }
    }

    fn create_client_with_storage(
        credential_identity: SessionCredentialId,
        storage: RecordingStorage,
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
            .group_state_storage(storage)
            .signing_identity(identity, secret, CIPHERSUITE)
            .build();

        Ok(SessionMlsClient {
            inner,
            credential_identity,
        })
    }

    #[test]
    fn duplicate_identity_still_fails_closed() -> Result<(), MlsAdapterError> {
        const NOW: u64 = 1_800_000_000;
        let credential_identity = SessionCredentialId([0x11; SESSION_CREDENTIAL_ID_BYTES]);
        let alice = create_client_with_credential_identity(
            credential_identity,
            AwsLcCryptoProvider::default(),
        )?;
        let duplicate_alice = create_client_with_credential_identity(
            credential_identity,
            AwsLcCryptoProvider::default(),
        )?;
        let validator = create_key_package_validator();
        let key_package = duplicate_alice.generate_key_package(NOW)?;
        let validated = validator.validate_key_package(key_package.as_bytes(), NOW)?;
        let mut group =
            alice.create_group(SessionGroupId::new([0x77; SESSION_GROUP_ID_BYTES])?, NOW)?;

        assert!(matches!(
            group.prepare_add(validated, NOW),
            Err(MlsAdapterError::RejectedKeyPackage)
        ));

        Ok(())
    }

    #[test]
    fn provider_persists_only_after_an_explicit_group_write() -> Result<(), MlsAdapterError> {
        const NOW: u64 = 1_800_000_000;
        let storage = RecordingStorage::default();
        let alice = create_client_with_storage(
            SessionCredentialId([0x11; SESSION_CREDENTIAL_ID_BYTES]),
            storage.clone(),
        )?;
        let bob = create_client()?;
        let validator = create_key_package_validator();
        let bob_key_package = bob.generate_key_package(NOW)?;
        let validated = validator.validate_key_package(bob_key_package.as_bytes(), NOW)?;

        let mut alice_group =
            alice.create_group(SessionGroupId::new([0x77; SESSION_GROUP_ID_BYTES])?, NOW)?;
        assert_eq!(storage.write_count(), 0);
        let prepared = alice_group.prepare_add(validated, NOW)?;
        assert_eq!(storage.write_count(), 0);
        prepared.apply()?;
        assert_eq!(storage.write_count(), 0);

        alice_group
            .inner
            .write_to_storage()
            .map_err(|_| MlsAdapterError::ProtocolRejected)?;
        assert_eq!(storage.write_count(), 1);

        Ok(())
    }

    #[test]
    fn authenticated_commit_cannot_expand_a_phase_one_group() -> Result<(), MlsAdapterError> {
        const NOW: u64 = 1_800_000_000;
        let alice = create_client()?;
        let bob = create_client()?;
        let carol = create_client()?;
        let validator = create_key_package_validator();
        let bob_key_package = bob.generate_key_package(NOW)?;
        let bob_validated = validator.validate_key_package(bob_key_package.as_bytes(), NOW)?;
        let mut alice_group =
            alice.create_group(SessionGroupId::new([0x77; SESSION_GROUP_ID_BYTES])?, NOW)?;
        let addition = alice_group.prepare_add(bob_validated, NOW)?.apply()?;
        let mut bob_group = bob.join_group(addition.into_welcome(), NOW)?;

        let carol_key_package = carol.generate_key_package(NOW)?;
        let carol_validated = validator.validate_key_package(carol_key_package.as_bytes(), NOW)?;
        let output = bob_group
            .inner
            .commit_builder()
            .add_member(carol_validated.message)
            .map(|builder| builder.commit_time(NOW.into()))
            .and_then(|builder| builder.build())
            .map_err(|_| MlsAdapterError::ProtocolRejected)?;
        let commit = MlsWireMessage::from_provider(&output.commit_message)?;

        assert_eq!(
            alice_group.process_message(commit),
            Err(MlsAdapterError::ProtocolRejected)
        );
        assert!(matches!(
            alice_group.encrypt_application_message(b"must stay poisoned"),
            Err(MlsAdapterError::ProtocolRejected)
        ));

        Ok(())
    }
}
