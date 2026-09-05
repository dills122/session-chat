use session_transport::{
    AdapterExecutionV1, AdapterId, AdapterLimitsV1, AdapterManifestV1, AdapterOperationsV1,
    AdapterVersionV1, BackgroundWorkV1, BindingErrorV1, EgressDeclarationV1, EnforcementModeV1,
    InternalRetryV1, TransportProfileId, bind_fast_transport_v1, bind_transport_v1,
};

const SELECTED_AT: u64 = 1_700_000_000;

fn manifest(
    profile: TransportProfileId,
    limits: AdapterLimitsV1,
    operations: AdapterOperationsV1,
    retry: InternalRetryV1,
    egress: EgressDeclarationV1,
    background: BackgroundWorkV1,
) -> AdapterManifestV1 {
    AdapterManifestV1::new(
        1,
        AdapterId::new("session-chat.adapter.memory.v1").expect("adapter ID"),
        AdapterVersionV1::new("0.1.0").expect("adapter version"),
        profile,
        limits,
        operations,
        retry,
        egress,
        background,
        AdapterExecutionV1::InProcess,
        1,
    )
    .expect("structurally valid manifest")
}

fn local_manifest() -> AdapterManifestV1 {
    manifest(
        TransportProfileId::LocalV1,
        AdapterLimitsV1::new(65_536, 4 * 1024 * 1024, 64, 0).expect("bounded limits"),
        AdapterOperationsV1::DepositPollAcknowledge,
        InternalRetryV1::CoordinatorOnly,
        EgressDeclarationV1::None,
        BackgroundWorkV1::None,
    )
}

fn fast_manifest() -> AdapterManifestV1 {
    manifest(
        TransportProfileId::FastV1,
        AdapterLimitsV1::new(65_536, 192 * 1024, 64, 40).expect("bounded Fast limits"),
        AdapterOperationsV1::DepositPollAcknowledge,
        InternalRetryV1::CoordinatorOnly,
        EgressDeclarationV1::AmbientNetwork,
        BackgroundWorkV1::Declared,
    )
}

#[test]
fn local_manifest_binds_one_profile_without_minting_authority() {
    let record = bind_transport_v1(
        TransportProfileId::LocalV1,
        local_manifest(),
        [0xa5; 32],
        EnforcementModeV1::InProcessNoNetwork,
        SELECTED_AT,
    )
    .expect("reviewed LocalV1 manifest");

    assert_eq!(record.profile(), TransportProfileId::LocalV1);
    assert_eq!(
        record.adapter_id().as_str(),
        "session-chat.adapter.memory.v1"
    );
    assert_eq!(record.adapter_version().as_str(), "0.1.0");
    assert_eq!(record.configuration_fingerprint(), &[0xa5; 32]);
    assert_eq!(record.enforcement(), EnforcementModeV1::InProcessNoNetwork);
    assert_eq!(record.selected_at_unix_seconds(), SELECTED_AT);
    let diagnostics = format!("{record:?}");
    assert!(!diagnostics.contains("route"));
    assert!(!diagnostics.contains("capability"));
}

#[test]
fn fast_manifest_records_ambient_network_enforcement_without_fallback() {
    let record = bind_fast_transport_v1(fast_manifest(), [0xb6; 32], SELECTED_AT)
        .expect("reviewed FastV1 manifest");

    assert_eq!(record.profile(), TransportProfileId::FastV1);
    assert_eq!(
        record.enforcement(),
        EnforcementModeV1::InProcessAmbientNetwork
    );
    assert_eq!(record.configuration_fingerprint(), &[0xb6; 32]);
}

#[test]
fn fast_binding_rejects_local_or_underdeclared_manifests() {
    assert_eq!(
        bind_fast_transport_v1(local_manifest(), [0xb6; 32], SELECTED_AT),
        Err(BindingErrorV1::ManifestMismatch)
    );
    let no_background = manifest(
        TransportProfileId::FastV1,
        AdapterLimitsV1::new(65_536, 192 * 1024, 64, 40).expect("bounded Fast limits"),
        AdapterOperationsV1::DepositPollAcknowledge,
        InternalRetryV1::CoordinatorOnly,
        EgressDeclarationV1::AmbientNetwork,
        BackgroundWorkV1::None,
    );
    assert_eq!(
        bind_fast_transport_v1(no_background, [0xb6; 32], SELECTED_AT),
        Err(BindingErrorV1::ManifestMismatch)
    );
}

#[test]
fn binding_rejects_unknown_versions_and_nonlocal_profile_selection() {
    assert_eq!(
        AdapterManifestV1::new(
            2,
            AdapterId::new("session-chat.adapter.memory.v1").expect("adapter ID"),
            AdapterVersionV1::new("0.1.0").expect("adapter version"),
            TransportProfileId::LocalV1,
            AdapterLimitsV1::new(65_536, 4 * 1024 * 1024, 64, 0).expect("limits"),
            AdapterOperationsV1::DepositPollAcknowledge,
            InternalRetryV1::CoordinatorOnly,
            EgressDeclarationV1::None,
            BackgroundWorkV1::None,
            AdapterExecutionV1::InProcess,
            1,
        ),
        Err(BindingErrorV1::UnsupportedManifestVersion)
    );

    assert_eq!(
        bind_transport_v1(
            TransportProfileId::FastV1,
            local_manifest(),
            [0xa5; 32],
            EnforcementModeV1::InProcessNoNetwork,
            SELECTED_AT,
        ),
        Err(BindingErrorV1::UnsupportedProfile)
    );

    let unknown_configuration = AdapterManifestV1::new(
        1,
        AdapterId::new("session-chat.adapter.memory.v1").expect("adapter ID"),
        AdapterVersionV1::new("0.1.0").expect("adapter version"),
        TransportProfileId::LocalV1,
        AdapterLimitsV1::new(65_536, 4 * 1024 * 1024, 64, 0).expect("limits"),
        AdapterOperationsV1::DepositPollAcknowledge,
        InternalRetryV1::CoordinatorOnly,
        EgressDeclarationV1::None,
        BackgroundWorkV1::None,
        AdapterExecutionV1::InProcess,
        2,
    )
    .expect("structurally valid unknown configuration schema");
    assert_eq!(
        bind_transport_v1(
            TransportProfileId::LocalV1,
            unknown_configuration,
            [0xa5; 32],
            EnforcementModeV1::InProcessNoNetwork,
            SELECTED_AT,
        ),
        Err(BindingErrorV1::UnsupportedConfigurationSchema)
    );
}

#[test]
fn local_binding_rejects_broader_egress_retry_operations_and_sizes() {
    let cases = [
        manifest(
            TransportProfileId::LocalV1,
            AdapterLimitsV1::new(65_536, 4 * 1024 * 1024, 64, 0).expect("limits"),
            AdapterOperationsV1::DepositPollAcknowledge,
            InternalRetryV1::CoordinatorOnly,
            EgressDeclarationV1::AmbientNetwork,
            BackgroundWorkV1::None,
        ),
        manifest(
            TransportProfileId::LocalV1,
            AdapterLimitsV1::new(65_536, 4 * 1024 * 1024, 64, 0).expect("limits"),
            AdapterOperationsV1::DepositPollAcknowledge,
            InternalRetryV1::AdapterManaged {
                maximum_attempts: 2,
            },
            EgressDeclarationV1::None,
            BackgroundWorkV1::None,
        ),
        manifest(
            TransportProfileId::LocalV1,
            AdapterLimitsV1::new(65_536, 4 * 1024 * 1024, 64, 0).expect("limits"),
            AdapterOperationsV1::DepositOnly,
            InternalRetryV1::CoordinatorOnly,
            EgressDeclarationV1::None,
            BackgroundWorkV1::None,
        ),
        manifest(
            TransportProfileId::LocalV1,
            AdapterLimitsV1::new(65_536, 4 * 1024 * 1024 + 1, 64, 0).expect("limits"),
            AdapterOperationsV1::DepositPollAcknowledge,
            InternalRetryV1::CoordinatorOnly,
            EgressDeclarationV1::None,
            BackgroundWorkV1::None,
        ),
        manifest(
            TransportProfileId::LocalV1,
            AdapterLimitsV1::new(65_536, 4 * 1024 * 1024, 64, 1).expect("limits"),
            AdapterOperationsV1::DepositPollAcknowledge,
            InternalRetryV1::CoordinatorOnly,
            EgressDeclarationV1::None,
            BackgroundWorkV1::None,
        ),
    ];

    for rejected in cases {
        assert_eq!(
            bind_transport_v1(
                TransportProfileId::LocalV1,
                rejected,
                [0xa5; 32],
                EnforcementModeV1::InProcessNoNetwork,
                SELECTED_AT,
            ),
            Err(BindingErrorV1::ManifestMismatch)
        );
    }
}

#[test]
fn local_binding_rejects_background_work_and_invalid_record_inputs() {
    let background = manifest(
        TransportProfileId::LocalV1,
        AdapterLimitsV1::new(65_536, 4 * 1024 * 1024, 64, 0).expect("limits"),
        AdapterOperationsV1::DepositPollAcknowledge,
        InternalRetryV1::CoordinatorOnly,
        EgressDeclarationV1::None,
        BackgroundWorkV1::Declared,
    );
    assert_eq!(
        bind_transport_v1(
            TransportProfileId::LocalV1,
            background,
            [0xa5; 32],
            EnforcementModeV1::InProcessNoNetwork,
            SELECTED_AT,
        ),
        Err(BindingErrorV1::ManifestMismatch)
    );
    assert_eq!(
        bind_transport_v1(
            TransportProfileId::LocalV1,
            local_manifest(),
            [0; 32],
            EnforcementModeV1::InProcessNoNetwork,
            SELECTED_AT,
        ),
        Err(BindingErrorV1::InvalidBindingRecord)
    );
}
