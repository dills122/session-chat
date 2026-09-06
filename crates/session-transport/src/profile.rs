use thiserror::Error;

use crate::{AdapterId, MAX_POLL_ENCODED_BYTES, MAX_POLL_ENVELOPES, TransportProfileId};

const MANIFEST_VERSION_V1: u16 = 1;
const LOCAL_CONFIGURATION_SCHEMA_V1: u16 = 1;
const LOCAL_MAX_ENVELOPE_ENCODED_BYTES: u32 = 65_536;
const FAST_CONFIGURATION_SCHEMA_V1: u16 = 1;
const FAST_MAX_ENVELOPE_ENCODED_BYTES: u32 = 65_536;
const FAST_MAX_BATCH_ENCODED_BYTES: u32 = 192 * 1024;
const FAST_MAX_BATCH_ENVELOPES: u16 = 64;
const FAST_MAX_CURSOR_BYTES: u16 = 40;
const CONFIGURATION_FINGERPRINT_BYTES: usize = 32;
const MAX_ADAPTER_VERSION_BYTES: usize = 64;

/// Stable non-secret FastV1 copy fixture for transport-selection UI tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FastProfileDisclosureV1 {
    title: &'static str,
    content_security: &'static str,
    route_behavior: &'static str,
    direct_exposure: &'static str,
    relay_exposure: &'static str,
    discovery_exposure: &'static str,
    availability: &'static str,
    anonymous: bool,
    offline_delivery: bool,
}

impl FastProfileDisclosureV1 {
    #[must_use]
    pub const fn title(self) -> &'static str {
        self.title
    }

    #[must_use]
    pub const fn content_security(self) -> &'static str {
        self.content_security
    }

    #[must_use]
    pub const fn route_behavior(self) -> &'static str {
        self.route_behavior
    }

    #[must_use]
    pub const fn direct_exposure(self) -> &'static str {
        self.direct_exposure
    }

    #[must_use]
    pub const fn relay_exposure(self) -> &'static str {
        self.relay_exposure
    }

    #[must_use]
    pub const fn discovery_exposure(self) -> &'static str {
        self.discovery_exposure
    }

    #[must_use]
    pub const fn availability(self) -> &'static str {
        self.availability
    }

    #[must_use]
    pub const fn anonymous(self) -> bool {
        self.anonymous
    }

    #[must_use]
    pub const fn offline_delivery(self) -> bool {
        self.offline_delivery
    }
}

/// Returns the exact FastV1 transport disclosure fixture.
#[must_use]
pub const fn fast_profile_disclosure_v1() -> FastProfileDisclosureV1 {
    FastProfileDisclosureV1 {
        title: "Fast",
        content_security: "End-to-end encrypted content",
        route_behavior: "Uses a direct connection when available and an Iroh relay otherwise.",
        direct_exposure: "A direct peer can learn your network address.",
        relay_exposure: "An Iroh relay can observe endpoint identifiers, network addresses, timing, and traffic volume.",
        discovery_exposure: "Iroh address lookup, DNS, and NAT traversal services can observe connection metadata.",
        availability: "Both participants must be online for this experimental adapter.",
        anonymous: false,
        offline_delivery: false,
    }
}

/// Validated non-secret implementation version retained in local evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterVersionV1(Box<str>);

impl AdapterVersionV1 {
    pub fn new(value: &str) -> Result<Self, BindingErrorV1> {
        let valid_edge = value
            .as_bytes()
            .first()
            .zip(value.as_bytes().last())
            .is_some_and(|(first, last)| {
                first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric()
            });
        let valid_bytes = value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        });
        if value.len() > MAX_ADAPTER_VERSION_BYTES || !valid_edge || !valid_bytes {
            return Err(BindingErrorV1::InvalidManifest);
        }
        Ok(Self(value.into()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Non-secret declared hard limits for one adapter configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterLimitsV1 {
    maximum_envelope_encoded_bytes: u32,
    maximum_batch_encoded_bytes: u32,
    maximum_batch_envelopes: u16,
    maximum_cursor_bytes: u16,
}

impl AdapterLimitsV1 {
    pub fn new(
        maximum_envelope_encoded_bytes: u32,
        maximum_batch_encoded_bytes: u32,
        maximum_batch_envelopes: u16,
        maximum_cursor_bytes: u16,
    ) -> Result<Self, BindingErrorV1> {
        if maximum_envelope_encoded_bytes == 0
            || maximum_batch_encoded_bytes == 0
            || maximum_batch_envelopes == 0
            || maximum_envelope_encoded_bytes > maximum_batch_encoded_bytes
        {
            return Err(BindingErrorV1::InvalidManifest);
        }
        Ok(Self {
            maximum_envelope_encoded_bytes,
            maximum_batch_encoded_bytes,
            maximum_batch_envelopes,
            maximum_cursor_bytes,
        })
    }
}

/// Closed mailbox-operation sets admitted by the version 1 binder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterOperationsV1 {
    DepositOnly,
    DepositPollAcknowledge,
}

/// Declared retry ownership inside an adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InternalRetryV1 {
    CoordinatorOnly,
    AdapterManaged { maximum_attempts: u16 },
}

/// Closed egress declaration; ambient network access is always broader than LocalV1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EgressDeclarationV1 {
    None,
    AmbientNetwork,
}

/// Whether the adapter declares work outside caller-owned operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackgroundWorkV1 {
    None,
    Declared,
}

/// Local implementation execution boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterExecutionV1 {
    InProcess,
    IsolatedProcess,
}

/// Enforcement recorded for one selected local binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnforcementModeV1 {
    InProcessNoNetwork,
    /// In-process adapter with explicitly disclosed ordinary network access.
    InProcessAmbientNetwork,
    ScopedNetworkBroker,
    IsolatedProcess,
}

/// One non-secret adapter capability declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterManifestV1 {
    adapter_id: AdapterId,
    adapter_version: AdapterVersionV1,
    profile: TransportProfileId,
    limits: AdapterLimitsV1,
    operations: AdapterOperationsV1,
    internal_retry: InternalRetryV1,
    egress: EgressDeclarationV1,
    background_work: BackgroundWorkV1,
    execution: AdapterExecutionV1,
    configuration_schema_version: u16,
}

impl AdapterManifestV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        manifest_version: u16,
        adapter_id: AdapterId,
        adapter_version: AdapterVersionV1,
        profile: TransportProfileId,
        limits: AdapterLimitsV1,
        operations: AdapterOperationsV1,
        internal_retry: InternalRetryV1,
        egress: EgressDeclarationV1,
        background_work: BackgroundWorkV1,
        execution: AdapterExecutionV1,
        configuration_schema_version: u16,
    ) -> Result<Self, BindingErrorV1> {
        if manifest_version != MANIFEST_VERSION_V1 {
            return Err(BindingErrorV1::UnsupportedManifestVersion);
        }
        if configuration_schema_version == 0
            || matches!(
                internal_retry,
                InternalRetryV1::AdapterManaged {
                    maximum_attempts: 0
                }
            )
        {
            return Err(BindingErrorV1::InvalidManifest);
        }
        Ok(Self {
            adapter_id,
            adapter_version,
            profile,
            limits,
            operations,
            internal_retry,
            egress,
            background_work,
            execution,
            configuration_schema_version,
        })
    }
}

/// Non-secret evidence that one local profile was bound to one implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportBindingRecordV1 {
    profile: TransportProfileId,
    adapter_id: AdapterId,
    adapter_version: AdapterVersionV1,
    configuration_fingerprint: [u8; CONFIGURATION_FINGERPRINT_BYTES],
    enforcement: EnforcementModeV1,
    selected_at_unix_seconds: u64,
}

impl TransportBindingRecordV1 {
    #[must_use]
    pub const fn profile(&self) -> TransportProfileId {
        self.profile
    }

    #[must_use]
    pub const fn adapter_id(&self) -> &AdapterId {
        &self.adapter_id
    }

    #[must_use]
    pub const fn adapter_version(&self) -> &AdapterVersionV1 {
        &self.adapter_version
    }

    #[must_use]
    pub const fn configuration_fingerprint(&self) -> &[u8; CONFIGURATION_FINGERPRINT_BYTES] {
        &self.configuration_fingerprint
    }

    #[must_use]
    pub const fn selected_at_unix_seconds(&self) -> u64 {
        self.selected_at_unix_seconds
    }

    #[must_use]
    pub const fn enforcement(&self) -> EnforcementModeV1 {
        self.enforcement
    }
}

/// Binds exactly one selected profile; this API accepts no fallback list.
pub fn bind_transport_v1(
    selected_profile: TransportProfileId,
    manifest: AdapterManifestV1,
    configuration_fingerprint: [u8; CONFIGURATION_FINGERPRINT_BYTES],
    enforcement: EnforcementModeV1,
    selected_at_unix_seconds: u64,
) -> Result<TransportBindingRecordV1, BindingErrorV1> {
    if selected_profile != TransportProfileId::LocalV1 {
        return Err(BindingErrorV1::UnsupportedProfile);
    }
    if manifest.configuration_schema_version != LOCAL_CONFIGURATION_SCHEMA_V1 {
        return Err(BindingErrorV1::UnsupportedConfigurationSchema);
    }
    if manifest.profile != selected_profile
        || manifest.limits.maximum_envelope_encoded_bytes != LOCAL_MAX_ENVELOPE_ENCODED_BYTES
        || manifest.limits.maximum_batch_encoded_bytes != MAX_POLL_ENCODED_BYTES
        || manifest.limits.maximum_batch_envelopes != MAX_POLL_ENVELOPES
        || manifest.limits.maximum_cursor_bytes != 0
        || manifest.operations != AdapterOperationsV1::DepositPollAcknowledge
        || manifest.internal_retry != InternalRetryV1::CoordinatorOnly
        || manifest.egress != EgressDeclarationV1::None
        || manifest.background_work != BackgroundWorkV1::None
        || manifest.execution != AdapterExecutionV1::InProcess
        || enforcement != EnforcementModeV1::InProcessNoNetwork
    {
        return Err(BindingErrorV1::ManifestMismatch);
    }
    if configuration_fingerprint.iter().all(|byte| *byte == 0) || selected_at_unix_seconds == 0 {
        return Err(BindingErrorV1::InvalidBindingRecord);
    }
    Ok(TransportBindingRecordV1 {
        profile: selected_profile,
        adapter_id: manifest.adapter_id,
        adapter_version: manifest.adapter_version,
        configuration_fingerprint,
        enforcement,
        selected_at_unix_seconds,
    })
}

/// Binds the reviewed version 1 Fast profile to one ambient-network adapter.
///
/// This records the profile's direct/relay metadata exposure and admits no
/// fallback profile. It does not claim network isolation, offline delivery, or
/// durable mailbox state.
pub fn bind_fast_transport_v1(
    manifest: AdapterManifestV1,
    configuration_fingerprint: [u8; CONFIGURATION_FINGERPRINT_BYTES],
    selected_at_unix_seconds: u64,
) -> Result<TransportBindingRecordV1, BindingErrorV1> {
    if manifest.configuration_schema_version != FAST_CONFIGURATION_SCHEMA_V1 {
        return Err(BindingErrorV1::UnsupportedConfigurationSchema);
    }
    if manifest.profile != TransportProfileId::FastV1
        || manifest.limits.maximum_envelope_encoded_bytes != FAST_MAX_ENVELOPE_ENCODED_BYTES
        || manifest.limits.maximum_batch_encoded_bytes != FAST_MAX_BATCH_ENCODED_BYTES
        || manifest.limits.maximum_batch_envelopes != FAST_MAX_BATCH_ENVELOPES
        || manifest.limits.maximum_cursor_bytes != FAST_MAX_CURSOR_BYTES
        || manifest.operations != AdapterOperationsV1::DepositPollAcknowledge
        || manifest.internal_retry != InternalRetryV1::CoordinatorOnly
        || manifest.egress != EgressDeclarationV1::AmbientNetwork
        || manifest.background_work != BackgroundWorkV1::Declared
        || manifest.execution != AdapterExecutionV1::InProcess
    {
        return Err(BindingErrorV1::ManifestMismatch);
    }
    if configuration_fingerprint.iter().all(|byte| *byte == 0) || selected_at_unix_seconds == 0 {
        return Err(BindingErrorV1::InvalidBindingRecord);
    }
    Ok(TransportBindingRecordV1 {
        profile: TransportProfileId::FastV1,
        adapter_id: manifest.adapter_id,
        adapter_version: manifest.adapter_version,
        configuration_fingerprint,
        enforcement: EnforcementModeV1::InProcessAmbientNetwork,
        selected_at_unix_seconds,
    })
}

/// Stable fail-closed profile-binding error categories.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BindingErrorV1 {
    #[error("unsupported adapter manifest version")]
    UnsupportedManifestVersion,
    #[error("unsupported transport profile binding")]
    UnsupportedProfile,
    #[error("unsupported adapter configuration schema")]
    UnsupportedConfigurationSchema,
    #[error("invalid adapter manifest")]
    InvalidManifest,
    #[error("adapter manifest does not satisfy the selected profile")]
    ManifestMismatch,
    #[error("invalid transport binding record")]
    InvalidBindingRecord,
}
