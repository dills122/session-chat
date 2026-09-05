use std::time::{Duration, Instant};

use session_transport::{
    AcknowledgementRight, AcknowledgementScopeV1, BindingFingerprint, BoundCursorV1, Cursor,
    CursorBindingV1, CursorPersistenceV1, CursorSchemaVersion, DepositRight,
    LifecycleProviderContractV1, MailboxAuthoritySetV1, MailboxContinuityId, MailboxGeneration,
    MailboxGenerationPolicyV1, MailboxIssueRequestV1, MailboxIssueResultV1,
    MailboxLifecycleContractError, MailboxRotationPolicyV1, MailboxRotationResultV1,
    OperationBudget, ProviderStateEpoch, ReceiveRight, ReceiveScopeFingerprint,
    ReceiveStateOwnershipV1, RotationId, RotationModeV1, RotationRequestV1, RotationRight,
    TransportProfileId,
};

const NOW: u64 = 1_700_000_200;

fn budget() -> OperationBudget {
    OperationBudget::new(Instant::now() + Duration::from_secs(30), 65_536, 1)
        .expect("bounded operation")
}

fn binding(generation: u64) -> CursorBindingV1 {
    binding_with(generation, 0x11, 0x22, 0x33, 7, 1_700_000_600)
}

fn binding_with(
    generation: u64,
    configuration: u8,
    continuity: u8,
    receive_scope: u8,
    provider_epoch: u64,
    expires_at: u64,
) -> CursorBindingV1 {
    binding_for_profile(
        TransportProfileId::FastV1,
        generation,
        configuration,
        continuity,
        receive_scope,
        1,
        provider_epoch,
        expires_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn binding_for_profile(
    profile: TransportProfileId,
    generation: u64,
    configuration: u8,
    continuity: u8,
    receive_scope: u8,
    cursor_schema: u16,
    provider_epoch: u64,
    expires_at: u64,
) -> CursorBindingV1 {
    CursorBindingV1::new(
        profile,
        BindingFingerprint::from_bytes([configuration; 32]).expect("nonzero binding fingerprint"),
        MailboxContinuityId::from_provider_bytes([continuity; 16]).expect("nonzero continuity ID"),
        MailboxGeneration::new(generation).expect("nonzero generation"),
        ReceiveScopeFingerprint::from_bytes([receive_scope; 32]).expect("nonzero receive scope"),
        CursorSchemaVersion::new(cursor_schema).expect("nonzero cursor schema"),
        ProviderStateEpoch::new(provider_epoch).expect("nonzero provider epoch"),
        expires_at,
    )
    .expect("valid cursor binding")
}

fn authorities(
    binding: CursorBindingV1,
) -> MailboxAuthoritySetV1<[u8; 1], [u8; 1], [u8; 1], [u8; 1]> {
    MailboxAuthoritySetV1::from_provider(
        binding,
        DepositRight::from_provider([0x91]),
        ReceiveRight::from_provider([0x92]),
        AcknowledgementRight::from_provider([0x93]),
        RotationRight::from_provider([0x94]),
    )
}

#[test]
fn cursor_binding_requires_every_non_authorizing_scope_component() {
    let binding = binding(4);

    assert_eq!(binding.profile(), TransportProfileId::FastV1);
    assert_eq!(binding.binding_fingerprint().as_bytes(), &[0x11; 32]);
    assert_eq!(binding.continuity_id().as_bytes(), &[0x22; 16]);
    assert_eq!(binding.generation().get(), 4);
    assert_eq!(binding.receive_scope().as_bytes(), &[0x33; 32]);
    assert_eq!(binding.cursor_schema().get(), 1);
    assert_eq!(binding.provider_state_epoch().get(), 7);
    assert_eq!(binding.expires_at_unix_seconds(), 1_700_000_600);

    assert_eq!(
        BindingFingerprint::from_bytes([0; 32]).err(),
        Some(MailboxLifecycleContractError::InvalidBindingFingerprint)
    );
    assert_eq!(
        MailboxContinuityId::from_provider_bytes([0; 16]).err(),
        Some(MailboxLifecycleContractError::InvalidContinuityId)
    );
    assert_eq!(
        MailboxGeneration::new(0),
        Err(MailboxLifecycleContractError::InvalidGeneration)
    );
    assert_eq!(
        ReceiveScopeFingerprint::from_bytes([0; 32]).err(),
        Some(MailboxLifecycleContractError::InvalidReceiveScope)
    );
    assert_eq!(
        CursorSchemaVersion::new(0),
        Err(MailboxLifecycleContractError::InvalidCursorSchema)
    );
    assert_eq!(
        ProviderStateEpoch::new(0),
        Err(MailboxLifecycleContractError::InvalidProviderStateEpoch)
    );
    assert_eq!(
        CursorBindingV1::new(
            TransportProfileId::LocalV1,
            BindingFingerprint::from_bytes([0x11; 32]).expect("binding fingerprint"),
            MailboxContinuityId::from_provider_bytes([0x22; 16]).expect("continuity ID"),
            MailboxGeneration::new(1).expect("generation"),
            ReceiveScopeFingerprint::from_bytes([0x33; 32]).expect("receive scope"),
            CursorSchemaVersion::new(1).expect("cursor schema"),
            ProviderStateEpoch::new(1).expect("provider epoch"),
            1_700_000_600,
        )
        .err(),
        Some(MailboxLifecycleContractError::UnsupportedLifecycleProfile)
    );
}

#[test]
fn bound_cursor_is_continuation_state_not_mailbox_authority() {
    let cursor = BoundCursorV1::new(
        Cursor::new(vec![0x44; 24]).expect("bounded cursor"),
        binding(4),
    );

    assert_eq!(cursor.cursor().as_bytes(), &[0x44; 24]);
    assert_eq!(cursor.binding().generation().get(), 4);
}

#[test]
fn provider_issues_four_right_specific_values_for_one_exact_generation() {
    struct Deposit;
    struct Receive;
    struct Acknowledge;
    struct Rotate;

    let authorities = MailboxAuthoritySetV1::from_provider(
        binding(4),
        DepositRight::from_provider(Deposit),
        ReceiveRight::from_provider(Receive),
        AcknowledgementRight::from_provider(Acknowledge),
        RotationRight::from_provider(Rotate),
    );

    assert_eq!(authorities.binding().generation().get(), 4);
    let (returned_binding, _, _, _, _) = authorities.into_parts();
    assert_eq!(returned_binding.generation().get(), 4);
}

#[test]
fn lifecycle_provider_declaration_fixes_cursor_rotation_and_owner_semantics() {
    let declaration = LifecycleProviderContractV1::new(
        TransportProfileId::FastV1,
        CursorSchemaVersion::new(1).expect("cursor schema"),
        300,
    )
    .expect("bounded lifecycle declaration");

    assert_eq!(declaration.profile(), TransportProfileId::FastV1);
    assert_eq!(declaration.cursor_schema().get(), 1);
    assert_eq!(
        declaration.cursor_persistence(),
        CursorPersistenceV1::OwnerBoundRestartableProviderEpoch
    );
    assert_eq!(
        declaration.generation_policy(),
        MailboxGenerationPolicyV1::MonotonicNonReused
    );
    assert_eq!(
        declaration.rotation_policy(),
        MailboxRotationPolicyV1::CompareAndSwapBoundedRoutineDrain
    );
    assert_eq!(declaration.maximum_routine_drain_seconds(), 300);
    assert_eq!(
        declaration.acknowledgement_scope(),
        AcknowledgementScopeV1::ExactSetPerGeneration
    );
    assert_eq!(
        declaration.receive_state_ownership(),
        ReceiveStateOwnershipV1::ExternalAtomicOwner
    );

    let predecessor = binding(4);
    let rotation = RotationRequestV1::new(
        RotationId::from_provider_bytes([0x45; 16]).expect("rotation ID"),
        predecessor,
        RotationModeV1::Routine {
            drain_predecessor_until_unix_seconds: 1_700_000_500,
        },
        1_700_001_000,
        budget(),
    )
    .expect("routine rotation");
    assert_eq!(
        declaration.validate_rotation_request(&rotation, 1_700_000_200),
        Ok(())
    );
    assert_eq!(
        declaration.validate_rotation_request(&rotation, 1_700_000_199),
        Err(MailboxLifecycleContractError::InvalidRotation)
    );
    assert_eq!(
        LifecycleProviderContractV1::new(
            TransportProfileId::FastV1,
            CursorSchemaVersion::new(3).expect("cursor schema"),
            0,
        ),
        Err(MailboxLifecycleContractError::InvalidLifecycleDeclaration)
    );
    assert_eq!(
        LifecycleProviderContractV1::new(
            TransportProfileId::LocalV1,
            CursorSchemaVersion::new(3).expect("cursor schema"),
            300,
        ),
        Err(MailboxLifecycleContractError::UnsupportedLifecycleProfile)
    );
}

#[test]
fn issue_and_rotation_requests_are_bounded_and_generation_specific() {
    let issue = MailboxIssueRequestV1::new(
        TransportProfileId::FastV1,
        BindingFingerprint::from_bytes([0x51; 32]).expect("binding fingerprint"),
        1_700_000_600,
        budget(),
    )
    .expect("valid issue request");
    assert_eq!(issue.profile(), TransportProfileId::FastV1);
    assert_eq!(issue.expires_at_unix_seconds(), 1_700_000_600);
    assert_eq!(
        MailboxIssueRequestV1::new(
            TransportProfileId::LocalV1,
            BindingFingerprint::from_bytes([0x51; 32]).expect("binding fingerprint"),
            1_700_000_600,
            budget(),
        )
        .err(),
        Some(MailboxLifecycleContractError::UnsupportedLifecycleProfile)
    );

    let predecessor = binding(4);
    let rotation_id = RotationId::from_provider_bytes([0x52; 16]).expect("rotation ID");
    let routine = RotationRequestV1::new(
        rotation_id,
        predecessor,
        RotationModeV1::Routine {
            drain_predecessor_until_unix_seconds: 1_700_000_500,
        },
        1_700_001_000,
        budget(),
    )
    .expect("bounded routine rotation");
    assert_eq!(routine.predecessor().generation().get(), 4);
    assert_eq!(routine.successor_generation().get(), 5);
    assert_eq!(routine.rotation_id().as_bytes(), &[0x52; 16]);

    assert_eq!(
        RotationRequestV1::new(
            RotationId::from_provider_bytes([0x53; 16]).expect("rotation ID"),
            predecessor,
            RotationModeV1::Routine {
                drain_predecessor_until_unix_seconds: predecessor.expires_at_unix_seconds() + 1,
            },
            1_700_001_000,
            budget(),
        )
        .err(),
        Some(MailboxLifecycleContractError::InvalidRotation)
    );

    let compromise = RotationRequestV1::new(
        RotationId::from_provider_bytes([0x54; 16]).expect("rotation ID"),
        predecessor,
        RotationModeV1::Compromise,
        1_700_001_000,
        budget(),
    )
    .expect("compromise rotation has no overlap");
    assert_eq!(compromise.mode(), RotationModeV1::Compromise);
}

#[test]
fn generation_increment_fails_closed_at_exhaustion() {
    assert_eq!(
        MailboxGeneration::new(u64::MAX)
            .expect("valid terminal generation")
            .successor(),
        Err(MailboxLifecycleContractError::GenerationExhausted)
    );
}

#[test]
fn issue_result_rejects_provider_scope_substitution() {
    let declaration = LifecycleProviderContractV1::new(
        TransportProfileId::FastV1,
        CursorSchemaVersion::new(1).expect("cursor schema"),
        300,
    )
    .expect("lifecycle declaration");
    let request = MailboxIssueRequestV1::new(
        TransportProfileId::FastV1,
        BindingFingerprint::from_bytes([0x61; 32]).expect("binding fingerprint"),
        1_700_000_600,
        budget(),
    )
    .expect("issue request");
    let valid = binding_for_profile(
        TransportProfileId::FastV1,
        1,
        0x61,
        0x62,
        0x63,
        1,
        1,
        1_700_000_600,
    );
    let issued = MailboxIssueResultV1::new(declaration, request, authorities(valid), NOW)
        .expect("provider output matches request");
    assert_eq!(issued.lifecycle_contract(), declaration);
    assert!(issued.authorities().binding() == &valid);

    let request = MailboxIssueRequestV1::new(
        TransportProfileId::FastV1,
        BindingFingerprint::from_bytes([0x61; 32]).expect("binding fingerprint"),
        1_700_000_600,
        budget(),
    )
    .expect("issue request");
    let substituted = binding_for_profile(
        TransportProfileId::FastV1,
        1,
        0x64,
        0x62,
        0x63,
        1,
        1,
        1_700_000_600,
    );
    assert_eq!(
        MailboxIssueResultV1::new(declaration, request, authorities(substituted), NOW).err(),
        Some(MailboxLifecycleContractError::ProviderResultMismatch)
    );

    let request = MailboxIssueRequestV1::new(
        TransportProfileId::FastV1,
        BindingFingerprint::from_bytes([0x61; 32]).expect("binding fingerprint"),
        1_700_000_600,
        budget(),
    )
    .expect("issue request");
    let wrong_schema = binding_for_profile(
        TransportProfileId::FastV1,
        1,
        0x61,
        0x62,
        0x63,
        2,
        1,
        1_700_000_600,
    );
    assert_eq!(
        MailboxIssueResultV1::new(declaration, request, authorities(wrong_schema), NOW).err(),
        Some(MailboxLifecycleContractError::ProviderResultMismatch)
    );

    let mismatched_declaration = LifecycleProviderContractV1::new(
        TransportProfileId::PrivateInteractiveV1,
        CursorSchemaVersion::new(1).expect("cursor schema"),
        300,
    )
    .expect("different lifecycle declaration");
    let request = MailboxIssueRequestV1::new(
        TransportProfileId::FastV1,
        BindingFingerprint::from_bytes([0x61; 32]).expect("binding fingerprint"),
        1_700_000_600,
        budget(),
    )
    .expect("issue request");
    assert_eq!(
        MailboxIssueResultV1::new(mismatched_declaration, request, authorities(valid), NOW).err(),
        Some(MailboxLifecycleContractError::ProviderResultMismatch)
    );

    let expired_request = MailboxIssueRequestV1::new(
        TransportProfileId::FastV1,
        BindingFingerprint::from_bytes([0x61; 32]).expect("binding fingerprint"),
        NOW,
        budget(),
    )
    .expect("expired request shape");
    let expired_binding =
        binding_for_profile(TransportProfileId::FastV1, 1, 0x61, 0x62, 0x63, 1, 1, NOW);
    assert_eq!(
        MailboxIssueResultV1::new(
            declaration,
            expired_request,
            authorities(expired_binding),
            NOW,
        )
        .err(),
        Some(MailboxLifecycleContractError::ProviderResultMismatch)
    );
}

#[test]
fn rotation_result_requires_the_exact_successor_and_fresh_scope() {
    let declaration = LifecycleProviderContractV1::new(
        TransportProfileId::FastV1,
        CursorSchemaVersion::new(1).expect("cursor schema"),
        300,
    )
    .expect("lifecycle declaration");
    let predecessor = binding_with(4, 0x71, 0x72, 0x73, 8, 1_700_000_600);
    let request = RotationRequestV1::new(
        RotationId::from_provider_bytes([0x74; 16]).expect("rotation ID"),
        predecessor,
        RotationModeV1::Compromise,
        1_700_001_000,
        budget(),
    )
    .expect("rotation request");
    let successor = binding_with(5, 0x71, 0x72, 0x75, 8, 1_700_001_000);
    let result =
        MailboxRotationResultV1::new(declaration, request, authorities(successor), 1_700_000_200)
            .expect("exact fresh successor");
    assert_eq!(result.lifecycle_contract(), declaration);
    assert_eq!(result.predecessor_generation().get(), 4);
    assert_eq!(result.authorities().binding().generation().get(), 5);

    let request = RotationRequestV1::new(
        RotationId::from_provider_bytes([0x76; 16]).expect("rotation ID"),
        predecessor,
        RotationModeV1::Compromise,
        1_700_001_000,
        budget(),
    )
    .expect("rotation request");
    let reused_scope = binding_with(5, 0x71, 0x72, 0x73, 8, 1_700_001_000);
    assert_eq!(
        MailboxRotationResultV1::new(
            declaration,
            request,
            authorities(reused_scope),
            1_700_000_200,
        )
        .err(),
        Some(MailboxLifecycleContractError::ProviderResultMismatch)
    );
}

#[test]
fn rotation_is_bound_to_expected_profile_schema_and_drain_declaration() {
    let predecessor = binding_with(4, 0x81, 0x82, 0x83, 8, 1_700_000_600);
    let successor = binding_with(5, 0x81, 0x82, 0x84, 8, 1_700_001_000);
    let request = RotationRequestV1::new(
        RotationId::from_provider_bytes([0x85; 16]).expect("rotation ID"),
        predecessor,
        RotationModeV1::Compromise,
        1_700_001_000,
        budget(),
    )
    .expect("rotation request");
    let wrong_profile = LifecycleProviderContractV1::new(
        TransportProfileId::PrivateInteractiveV1,
        CursorSchemaVersion::new(1).expect("cursor schema"),
        300,
    )
    .expect("different declaration");
    assert_eq!(
        MailboxRotationResultV1::new(
            wrong_profile,
            request,
            authorities(successor),
            1_700_000_200,
        )
        .err(),
        Some(MailboxLifecycleContractError::ProviderResultMismatch)
    );

    let request = RotationRequestV1::new(
        RotationId::from_provider_bytes([0x86; 16]).expect("rotation ID"),
        predecessor,
        RotationModeV1::Compromise,
        1_700_001_000,
        budget(),
    )
    .expect("rotation request");
    let wrong_schema = LifecycleProviderContractV1::new(
        TransportProfileId::FastV1,
        CursorSchemaVersion::new(2).expect("cursor schema"),
        300,
    )
    .expect("different declaration");
    assert_eq!(
        MailboxRotationResultV1::new(wrong_schema, request, authorities(successor), 1_700_000_200,)
            .err(),
        Some(MailboxLifecycleContractError::ProviderResultMismatch)
    );

    let request = RotationRequestV1::new(
        RotationId::from_provider_bytes([0x87; 16]).expect("rotation ID"),
        predecessor,
        RotationModeV1::Routine {
            drain_predecessor_until_unix_seconds: 1_700_000_301,
        },
        1_700_001_000,
        budget(),
    )
    .expect("rotation request shape");
    let short_drain = LifecycleProviderContractV1::new(
        TransportProfileId::FastV1,
        CursorSchemaVersion::new(1).expect("cursor schema"),
        100,
    )
    .expect("short drain declaration");
    assert_eq!(
        MailboxRotationResultV1::new(short_drain, request, authorities(successor), 1_700_000_200,)
            .err(),
        Some(MailboxLifecycleContractError::InvalidRotation)
    );
}
