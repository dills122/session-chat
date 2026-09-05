use std::path::PathBuf;

use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
use rusqlite::{Connection, params};
use session_crypto_hpke::AwsLcInvitationJoinProtector;
use session_crypto_mls::{
    SessionGroupId, ValidatedKeyPackage, create_client, create_durable_client_with_storage,
    create_key_package_validator,
};
use session_protocol::{DepositCapability, LocalWelcomeDepositEndpoint, OpaqueEnvelope};
use storage_sqlcipher::{
    AuthorizationPolicy, AuthorizationShadowInput, AuthorizationState, InvitationOpeningState,
    InviterJoinTransaction, MembershipAuthorization, PersistenceFault, SqlCipherStorage,
    StoreError, VaultKey,
};
use zeroize::Zeroizing;

const NOW: u64 = 1_900_000_000;

struct TestDatabase(PathBuf);

impl TestDatabase {
    fn new(name: &str) -> Self {
        Self(std::env::temp_dir().join(format!(
            "session-chat-storage-sqlcipher-authorization-{name}-{}.sqlite3",
            std::process::id(),
        )))
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.0.with_extension("sqlite3-journal"));
    }
}

fn vault_key() -> VaultKey {
    VaultKey::new([0x83; 32]).expect("nonzero test key")
}

fn open_fixture_connection(path: &std::path::Path) -> Connection {
    let connection = Connection::open(path).expect("fixture database opens");
    connection
        .execute_batch(
            "PRAGMA key = \"x'8383838383838383838383838383838383838383838383838383838383838383'\";",
        )
        .expect("fixture key accepted");
    connection
}

#[derive(Clone)]
struct SubstitutingGroupStateStorage(SqlCipherStorage);

impl GroupStateStorage for SubstitutingGroupStateStorage {
    type Error = StoreError;

    fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        self.0.state(group_id)
    }

    fn epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        self.0.epoch(group_id, epoch_id)
    }

    fn write(
        &mut self,
        mut state: GroupState,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        state.data = Zeroizing::new(vec![0xee; 32]);
        self.0.write(state, epoch_inserts, epoch_updates)
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        self.0.max_epoch_id(group_id)
    }
}

fn shadow(
    invitation: &session_crypto_hpke::GeneratedCapabilityInvitationV2,
    request_marker: u8,
) -> AuthorizationShadowInput {
    shadow_at(invitation, request_marker, NOW)
}

fn shadow_at(
    invitation: &session_crypto_hpke::GeneratedCapabilityInvitationV2,
    request_marker: u8,
    now_unix_seconds: u64,
) -> AuthorizationShadowInput {
    AuthorizationShadowInput::new(
        *invitation.invitation().invitation_id(),
        *invitation.invitation().signature(),
        *invitation.invitation().join_challenge(),
        [request_marker; 16],
        [request_marker.wrapping_add(1); 32],
        *invitation.invitation().inviter_verifying_key(),
        [request_marker.wrapping_add(2); 32],
        [request_marker.wrapping_add(3); 32],
        [request_marker.wrapping_add(4); 32],
        [request_marker.wrapping_add(5); 32],
        now_unix_seconds,
        now_unix_seconds + 120,
        invitation.invitation().expires_at_unix_seconds(),
    )
    .expect("bounded authorization shadow")
}

fn validated_key_package() -> ValidatedKeyPackage {
    let client = create_client().expect("candidate client");
    let key_package = client
        .generate_key_package(NOW)
        .expect("candidate KeyPackage");
    create_key_package_validator()
        .validate_key_package(key_package.as_bytes(), NOW)
        .expect("validated KeyPackage")
}

fn shadow_for_validated(
    invitation: &session_crypto_hpke::GeneratedCapabilityInvitationV2,
    request_marker: u8,
    validated: &ValidatedKeyPackage,
) -> AuthorizationShadowInput {
    AuthorizationShadowInput::new(
        *invitation.invitation().invitation_id(),
        *invitation.invitation().signature(),
        *invitation.invitation().join_challenge(),
        [request_marker; 16],
        [request_marker.wrapping_add(1); 32],
        *invitation.invitation().inviter_verifying_key(),
        *validated.key_package_reference(),
        *validated.credential_identity(),
        *validated.leaf_signature_key(),
        [request_marker.wrapping_add(5); 32],
        NOW,
        NOW + 120,
        invitation.invitation().expires_at_unix_seconds(),
    )
    .expect("bounded authorization shadow")
}

#[derive(Clone, Copy)]
struct MembershipWriteOptions {
    fault: PersistenceFault,
    advance_group_before_write: bool,
}

impl MembershipWriteOptions {
    const NORMAL: Self = Self {
        fault: PersistenceFault::None,
        advance_group_before_write: false,
    };
}

fn matching_membership_write_succeeds(
    storage: &SqlCipherStorage,
    invitation: &session_crypto_hpke::GeneratedCapabilityInvitationV2,
    request_marker: u8,
    validated: ValidatedKeyPackage,
    membership: MembershipAuthorization,
    options: MembershipWriteOptions,
    before_write: impl FnOnce(),
) -> bool {
    matching_membership_write_succeeds_with_group_storage(
        storage.clone(),
        storage,
        invitation,
        request_marker,
        validated,
        membership,
        options,
        before_write,
    )
}

#[allow(clippy::too_many_arguments)]
fn matching_membership_write_succeeds_with_group_storage<G>(
    group_state_storage: G,
    storage: &SqlCipherStorage,
    invitation: &session_crypto_hpke::GeneratedCapabilityInvitationV2,
    request_marker: u8,
    validated: ValidatedKeyPackage,
    membership: MembershipAuthorization,
    options: MembershipWriteOptions,
    before_write: impl FnOnce(),
) -> bool
where
    G: GroupStateStorage + Clone,
{
    let transaction_id = *membership.transaction_id();
    let invitation_id = *invitation.invitation().invitation_id();
    let generation = *invitation.invitation().signature();
    let join_request_id = [request_marker; 16];
    let request_fingerprint = [request_marker.wrapping_add(5); 32];
    let group_id = SessionGroupId::new([0xb1; 32]).expect("group id");
    let alice = create_durable_client_with_storage(
        group_id,
        group_state_storage,
        storage.clone(),
        storage.clone(),
    )
    .expect("durable Alice client");
    let mut alice_group = alice.create_group(group_id, NOW).expect("Alice group");
    let addition = alice_group
        .prepare_add(validated, NOW)
        .expect("prepared Add")
        .apply()
        .expect("applied Add");
    let welcome = OpaqueEnvelope::new(
        [0xb2; 16],
        NOW + 180,
        addition.welcome().as_bytes().to_vec(),
    )
    .expect("Welcome envelope")
    .encode_canonical()
    .expect("canonical Welcome");
    let endpoint = LocalWelcomeDepositEndpoint::new(
        [0xb3; 16],
        [0xb4; 16],
        DepositCapability::new([0xb5; 32]).expect("deposit capability"),
        NOW + 240,
    )
    .expect("endpoint")
    .encode_canonical()
    .expect("canonical endpoint");
    let transaction = InviterJoinTransaction::new(
        transaction_id,
        invitation_id,
        generation,
        join_request_id,
        request_fingerprint,
        *alice_group.group_id(),
        0,
        1,
        vec![0xb6; 32],
        welcome,
        endpoint,
        NOW + 120,
    )
    .expect("bounded inviter transaction");
    if options.advance_group_before_write {
        alice_group
            .prepare_epoch_update(NOW + 3)
            .expect("prepared intervening update")
            .apply()
            .expect("applied intervening update");
    }
    addition
        .stage_and_write_to_storage(&mut alice_group, |binding| {
            storage.stage_authorized_inviter(
                membership,
                binding,
                transaction,
                NOW,
                options.fault,
            )?;
            before_write();
            Ok::<_, StoreError>(())
        })
        .is_ok()
}

fn commit_authorized_fixture(
    storage: &SqlCipherStorage,
    invitation: &session_crypto_hpke::GeneratedCapabilityInvitationV2,
    request_marker: u8,
) -> ([u8; 16], [u8; 16]) {
    let validated = validated_key_package();
    let pending = storage
        .reserve_authorization(
            &AwsLcInvitationJoinProtector::new(),
            shadow_for_validated(invitation, request_marker, &validated),
            NOW,
        )
        .expect("authorization reserved");
    let approved = storage
        .approve_authorization(pending, &AwsLcInvitationJoinProtector::new(), NOW + 1)
        .expect("authorization approved");
    let transaction_id = [request_marker.wrapping_add(0x10); 16];
    let membership = storage
        .begin_membership_authorization(
            approved,
            transaction_id,
            &AwsLcInvitationJoinProtector::new(),
            NOW + 2,
        )
        .expect("membership authorized");
    let attempt_id = *membership.attempt_id();
    assert!(matching_membership_write_succeeds(
        storage,
        invitation,
        request_marker,
        validated,
        membership,
        MembershipWriteOptions::NORMAL,
        || {},
    ));
    (attempt_id, transaction_id)
}

#[test]
fn reserve_is_atomic_with_exact_invitation_and_retains_replay_state() {
    let database = TestDatabase::new("reserve-replay");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("invitation issued");
    let invitation_id = *invitation.invitation().invitation_id();
    assert!(matches!(
        storage.reserve_authorization(&protector, shadow_at(&invitation, 0x20, NOW + 1), NOW),
        Err(StoreError::Rejected)
    ));
    assert_eq!(
        storage
            .invitation_opening_state(&invitation_id)
            .expect("future request leaves invitation unchanged"),
        Some(InvitationOpeningState::Available)
    );
    let first = storage
        .reserve_authorization(&protector, shadow(&invitation, 0x21), NOW)
        .expect("authorization reserved");

    assert_eq!(
        storage
            .authorization_state(first.attempt_id())
            .expect("authorization lookup"),
        Some(AuthorizationState::PendingApproval)
    );
    assert_eq!(
        storage
            .invitation_opening_state(&invitation_id)
            .expect("invitation lookup"),
        Some(InvitationOpeningState::Reserved)
    );
    assert!(matches!(
        storage.reserve_authorization(&protector, shadow(&invitation, 0x21), NOW + 1),
        Err(StoreError::Replay)
    ));
    assert_eq!(
        storage
            .authorization_state(first.attempt_id())
            .expect("authorization lookup"),
        Some(AuthorizationState::PendingApproval)
    );
}

#[test]
fn reserve_terminalizes_opening_context_decode_or_restore_failure_after_successful_load() {
    let database = TestDatabase::new("reserve-corruption-after-load");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let mut invitation_ids = Vec::new();
    for (request_marker, corrupted_key) in [(0x22, [0_u8; 32]), (0x23, [0x19_u8; 32])] {
        let invitation = storage
            .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
            .expect("invitation issued");
        let invitation_id = *invitation.invitation().invitation_id();
        storage
            .load_capability_invitation(&protector, &invitation_id, NOW)
            .expect("opening context initially validates")
            .expect("opening context exists");

        let connection = open_fixture_connection(&database.0);
        connection
            .execute(
                "UPDATE invitation_opening_contexts SET hpke_private_key = ?1
                 WHERE invitation_id = ?2",
                params![corrupted_key, invitation_id],
            )
            .expect("bounded corruption fixture");
        drop(connection);

        assert!(matches!(
            storage.reserve_authorization(&protector, shadow(&invitation, request_marker), NOW + 1),
            Err(StoreError::Rejected)
        ));
        assert_eq!(
            storage
                .invitation_opening_state(&invitation_id)
                .expect("opening state"),
            Some(InvitationOpeningState::Unusable)
        );
        invitation_ids.push(invitation_id);
    }
    drop(storage);

    let connection = open_fixture_connection(&database.0);
    for invitation_id in invitation_ids {
        let retained_key: Vec<u8> = connection
            .query_row(
                "SELECT hpke_private_key FROM invitation_opening_contexts
                 WHERE invitation_id = ?1",
                params![invitation_id],
                |row| row.get(0),
            )
            .expect("terminal key read");
        assert_eq!(retained_key, vec![0; 32]);
    }
}

#[test]
fn legacy_reservation_cannot_capture_a_durable_opening_generation() {
    let database = TestDatabase::new("legacy-opening-fence");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("invitation issued");

    assert!(matches!(
        storage.seed_reservation(
            *invitation.invitation().invitation_id(),
            *invitation.invitation().signature(),
            [0x22; 16],
            NOW + 120,
            NOW,
        ),
        Err(StoreError::Conflict)
    ));
    assert_eq!(
        storage
            .invitation_opening_state(invitation.invitation().invitation_id())
            .expect("opening state"),
        Some(InvitationOpeningState::Available)
    );
}

#[test]
fn explicit_rejection_releases_only_the_exact_generation_and_retains_replay() {
    let database = TestDatabase::new("reject-release");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("invitation issued");
    let invitation_id = *invitation.invitation().invitation_id();
    let pending = storage
        .reserve_authorization(&protector, shadow(&invitation, 0x31), NOW)
        .expect("authorization reserved");
    let rejected_attempt = *pending.attempt_id();

    storage
        .reject_authorization(pending, &protector, NOW + 1)
        .expect("exact pending authorization rejected");
    assert_eq!(
        storage
            .authorization_state(&rejected_attempt)
            .expect("authorization lookup"),
        Some(AuthorizationState::Rejected)
    );
    assert_eq!(
        storage
            .invitation_opening_state(&invitation_id)
            .expect("invitation lookup"),
        Some(InvitationOpeningState::Available)
    );
    assert!(matches!(
        storage.reserve_authorization(&protector, shadow(&invitation, 0x31), NOW + 2),
        Err(StoreError::Replay)
    ));
    storage
        .reserve_authorization(&protector, shadow(&invitation, 0x41), NOW + 2)
        .expect("different fresh request can reserve released generation");
}

#[test]
fn live_pending_attempt_can_be_abandoned_without_reopening_the_store() {
    let database = TestDatabase::new("pending-abandon");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("invitation issued");
    let invitation_id = *invitation.invitation().invitation_id();
    let pending = storage
        .reserve_authorization(&protector, shadow(&invitation, 0x32), NOW)
        .expect("authorization reserved");
    let attempt_id = *pending.attempt_id();

    storage
        .abandon_pending_authorization(pending, &protector, NOW + 1)
        .expect("live pending attempt abandoned");
    assert_eq!(
        storage
            .authorization_state(&attempt_id)
            .expect("authorization lookup"),
        Some(AuthorizationState::Abandoned)
    );
    assert_eq!(
        storage
            .invitation_opening_state(&invitation_id)
            .expect("opening lookup"),
        Some(InvitationOpeningState::Available)
    );
    assert!(matches!(
        storage.reserve_authorization(&protector, shadow(&invitation, 0x32), NOW + 2),
        Err(StoreError::Replay)
    ));
    storage
        .reserve_authorization(&protector, shadow(&invitation, 0x33), NOW + 2)
        .expect("fresh request reuses the released generation");
}

#[test]
fn restart_abandons_pending_and_approved_attempts_without_recreating_authority() {
    let database = TestDatabase::new("restart-abandon");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let pending_invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("pending invitation issued");
    let approved_invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("approved invitation issued");
    let pending = storage
        .reserve_authorization(&protector, shadow(&pending_invitation, 0x51), NOW)
        .expect("pending authorization reserved");
    let pending_attempt = *pending.attempt_id();
    let approved_pending = storage
        .reserve_authorization(&protector, shadow(&approved_invitation, 0x61), NOW)
        .expect("approved authorization reserved");
    let approved_attempt = *approved_pending.attempt_id();
    storage
        .approve_authorization(approved_pending, &protector, NOW + 1)
        .expect("explicit approval recorded");
    assert!(matches!(
        storage.recover_pre_membership_authorizations(&protector, NOW + 1),
        Err(StoreError::Conflict)
    ));
    assert_eq!(
        storage
            .authorization_state(&pending_attempt)
            .expect("live pending state"),
        Some(AuthorizationState::PendingApproval)
    );
    assert_eq!(
        storage
            .authorization_state(&approved_attempt)
            .expect("live approved state"),
        Some(AuthorizationState::ApprovedPendingMembership)
    );
    drop(pending);
    drop(storage);

    let reopened = SqlCipherStorage::open(&database.0, vault_key()).expect("storage reopens");
    assert_eq!(
        reopened
            .recover_pre_membership_authorizations(&protector, NOW + 2)
            .expect("restart recovery"),
        2
    );
    assert_eq!(
        reopened
            .authorization_state(&pending_attempt)
            .expect("pending state"),
        Some(AuthorizationState::Abandoned)
    );
    assert_eq!(
        reopened
            .authorization_state(&approved_attempt)
            .expect("approved state"),
        Some(AuthorizationState::Abandoned)
    );
    for invitation_id in [
        pending_invitation.invitation().invitation_id(),
        approved_invitation.invitation().invitation_id(),
    ] {
        assert_eq!(
            reopened
                .invitation_opening_state(invitation_id)
                .expect("invitation state"),
            Some(InvitationOpeningState::Available)
        );
    }
}

#[test]
fn membership_outcome_stays_locked_until_fresh_scope_recovery_proves_noncommit() {
    let database = TestDatabase::new("membership-outcome");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("invitation issued");
    let invitation_id = *invitation.invitation().invitation_id();
    let pending = storage
        .reserve_authorization(&protector, shadow(&invitation, 0x71), NOW)
        .expect("authorization reserved");
    let approved = storage
        .approve_authorization(pending, &protector, NOW + 1)
        .expect("authorization approved");
    let membership = storage
        .begin_membership_authorization(approved, [0x81; 16], &protector, NOW + 2)
        .expect("transaction id recorded before membership");
    let attempt_id = *membership.attempt_id();
    let transaction_id = *membership.transaction_id();

    assert_eq!(
        storage
            .authorization_state(&attempt_id)
            .expect("authorization state"),
        Some(AuthorizationState::MembershipOutcomeUnknown)
    );
    assert!(matches!(
        storage.recover_authorization_outcome(&attempt_id, &transaction_id, &protector, NOW + 3,),
        Err(StoreError::Conflict)
    ));
    assert_eq!(
        storage
            .invitation_opening_state(&invitation_id)
            .expect("invitation remains reserved"),
        Some(InvitationOpeningState::Reserved)
    );
    drop(storage);

    let reopened = SqlCipherStorage::open(&database.0, vault_key()).expect("storage reopens");
    assert!(matches!(
        reopened.recover_authorization_outcome(&attempt_id, &[0x82; 16], &protector, NOW + 4,),
        Err(StoreError::Conflict)
    ));
    assert_eq!(
        reopened
            .recover_authorization_outcome(&attempt_id, &transaction_id, &protector, NOW + 4,)
            .expect("fresh scope proves transaction absent"),
        AuthorizationState::Abandoned
    );
    assert_eq!(
        reopened
            .invitation_opening_state(&invitation_id)
            .expect("invitation released"),
        Some(InvitationOpeningState::Available)
    );
}

#[test]
fn exact_committed_membership_recovery_consumes_the_invitation_once() {
    let database = TestDatabase::new("membership-committed");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("invitation issued");
    let invitation_id = *invitation.invitation().invitation_id();
    let validated = validated_key_package();
    let pending = storage
        .reserve_authorization(
            &protector,
            shadow_for_validated(&invitation, 0x91, &validated),
            NOW,
        )
        .expect("authorization reserved");
    let approved = storage
        .approve_authorization(pending, &protector, NOW + 1)
        .expect("authorization approved");
    let membership = storage
        .begin_membership_authorization(approved, [0xa1; 16], &protector, NOW + 2)
        .expect("membership authorized");
    let attempt_id = *membership.attempt_id();
    let transaction_id = *membership.transaction_id();
    assert!(matching_membership_write_succeeds(
        &storage,
        &invitation,
        0x91,
        validated,
        membership,
        MembershipWriteOptions::NORMAL,
        || {},
    ));
    assert_eq!(
        storage
            .authorization_state(&attempt_id)
            .expect("same-scope committed state"),
        Some(AuthorizationState::Committed)
    );
    assert_eq!(
        storage
            .recover_authorization_outcome(&attempt_id, &transaction_id, &protector, NOW + 3,)
            .expect("same-scope exact committed result is idempotent"),
        AuthorizationState::Committed
    );
    assert_eq!(
        storage
            .invitation_opening_state(&invitation_id)
            .expect("invitation state"),
        Some(InvitationOpeningState::Consumed)
    );
    assert_eq!(
        storage
            .recover_authorization_outcome(&attempt_id, &transaction_id, &protector, NOW + 4,)
            .expect("repeated exact committed recovery"),
        AuthorizationState::Committed
    );
}

#[test]
fn membership_commit_rejects_an_unrelated_provider_applied_key_package() {
    let database = TestDatabase::new("membership-key-package-binding");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("invitation issued");
    let invitation_id = *invitation.invitation().invitation_id();
    let admitted = validated_key_package();
    let unrelated = validated_key_package();
    let pending = storage
        .reserve_authorization(
            &protector,
            shadow_for_validated(&invitation, 0x95, &admitted),
            NOW,
        )
        .expect("authorization reserved");
    let approved = storage
        .approve_authorization(pending, &protector, NOW + 1)
        .expect("authorization approved");
    let membership = storage
        .begin_membership_authorization(approved, [0xa5; 16], &protector, NOW + 2)
        .expect("membership authorized");
    let attempt_id = *membership.attempt_id();
    let transaction_id = *membership.transaction_id();

    assert!(!matching_membership_write_succeeds(
        &storage,
        &invitation,
        0x95,
        unrelated,
        membership,
        MembershipWriteOptions::NORMAL,
        || {},
    ));
    assert_eq!(
        storage
            .recover_authorization_outcome(&attempt_id, &transaction_id, &protector, NOW + 3,)
            .expect("rejected staging proves no durable membership"),
        AuthorizationState::Abandoned
    );
    assert_eq!(
        storage
            .invitation_opening_state(&invitation_id)
            .expect("opening state"),
        Some(InvitationOpeningState::Available)
    );
    assert!(
        storage
            .recover_inviter(&transaction_id)
            .expect("inviter recovery")
            .is_none()
    );
}

#[test]
fn membership_commit_rejects_an_intervening_group_transition() {
    let database = TestDatabase::new("membership-exact-post-add-state");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("invitation issued");
    let invitation_id = *invitation.invitation().invitation_id();
    let validated = validated_key_package();
    let pending = storage
        .reserve_authorization(
            &protector,
            shadow_for_validated(&invitation, 0x96, &validated),
            NOW,
        )
        .expect("authorization reserved");
    let approved = storage
        .approve_authorization(pending, &protector, NOW + 1)
        .expect("authorization approved");
    let membership = storage
        .begin_membership_authorization(approved, [0xa6; 16], &protector, NOW + 2)
        .expect("membership authorized");
    let attempt_id = *membership.attempt_id();
    let transaction_id = *membership.transaction_id();

    assert!(!matching_membership_write_succeeds(
        &storage,
        &invitation,
        0x96,
        validated,
        membership,
        MembershipWriteOptions {
            fault: PersistenceFault::None,
            advance_group_before_write: true,
        },
        || {},
    ));
    let recovery_scope =
        SqlCipherStorage::open(&database.0, vault_key()).expect("independent recovery opens");
    assert_eq!(
        recovery_scope
            .recover_authorization_outcome(&attempt_id, &transaction_id, &protector, NOW + 3,)
            .expect("stale Add snapshot leaves no durable membership"),
        AuthorizationState::Abandoned
    );
    assert_eq!(
        storage
            .invitation_opening_state(&invitation_id)
            .expect("opening state"),
        Some(InvitationOpeningState::Available)
    );
    assert!(
        storage
            .recover_inviter(&transaction_id)
            .expect("inviter recovery")
            .is_none()
    );
}

#[test]
fn membership_commit_observes_expiry_after_staging() {
    let database = TestDatabase::new("membership-fresh-commit-time");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("invitation issued");
    let invitation_id = *invitation.invitation().invitation_id();
    let validated = validated_key_package();
    let shadow = AuthorizationShadowInput::new(
        invitation_id,
        *invitation.invitation().signature(),
        *invitation.invitation().join_challenge(),
        [0x97; 16],
        [0x98; 32],
        *invitation.invitation().inviter_verifying_key(),
        *validated.key_package_reference(),
        *validated.credential_identity(),
        *validated.leaf_signature_key(),
        [0x9c; 32],
        NOW,
        NOW + 1,
        invitation.invitation().expires_at_unix_seconds(),
    )
    .expect("short-lived authorization shadow");
    let pending = storage
        .reserve_authorization(&protector, shadow, NOW)
        .expect("authorization reserved");
    let approved = storage
        .approve_authorization(pending, &protector, NOW)
        .expect("authorization approved");
    let membership = storage
        .begin_membership_authorization(approved, [0xa7; 16], &protector, NOW)
        .expect("membership authorized");
    let attempt_id = *membership.attempt_id();
    let transaction_id = *membership.transaction_id();

    assert!(!matching_membership_write_succeeds(
        &storage,
        &invitation,
        0x97,
        validated,
        membership,
        MembershipWriteOptions::NORMAL,
        || std::thread::sleep(std::time::Duration::from_millis(1_100)),
    ));
    assert_eq!(
        storage
            .recover_authorization_outcome(&attempt_id, &transaction_id, &protector, NOW + 2,)
            .expect("expired staged write leaves no durable membership"),
        AuthorizationState::Abandoned
    );
    assert_eq!(
        storage
            .invitation_opening_state(&invitation_id)
            .expect("opening state"),
        Some(InvitationOpeningState::Available)
    );
}

#[test]
fn membership_commit_rejects_a_non_provider_write_during_staging() {
    let database = TestDatabase::new("membership-provider-write-authority");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("invitation issued");
    let invitation_id = *invitation.invitation().invitation_id();
    let validated = validated_key_package();
    let pending = storage
        .reserve_authorization(
            &protector,
            shadow_for_validated(&invitation, 0x9a, &validated),
            NOW,
        )
        .expect("authorization reserved");
    let approved = storage
        .approve_authorization(pending, &protector, NOW + 1)
        .expect("authorization approved");
    let membership = storage
        .begin_membership_authorization(approved, [0xaa; 16], &protector, NOW + 2)
        .expect("membership authorized");
    let attempt_id = *membership.attempt_id();
    let transaction_id = *membership.transaction_id();
    let rogue_write_succeeded = std::cell::Cell::new(false);
    let mut rogue_storage = storage.clone();

    assert!(!matching_membership_write_succeeds(
        &storage,
        &invitation,
        0x9a,
        validated,
        membership,
        MembershipWriteOptions::NORMAL,
        || {
            rogue_write_succeeded.set(
                rogue_storage
                    .write(
                        GroupState {
                            id: vec![0xb1; 32],
                            data: Zeroizing::new(vec![0xff; 32]),
                        },
                        Vec::new(),
                        Vec::new(),
                    )
                    .is_ok(),
            );
        },
    ));
    assert!(!rogue_write_succeeded.get());
    let recovery_scope =
        SqlCipherStorage::open(&database.0, vault_key()).expect("independent recovery opens");
    assert_eq!(
        recovery_scope
            .recover_authorization_outcome(&attempt_id, &transaction_id, &protector, NOW + 3,)
            .expect("unauthorized callback leaves no durable membership"),
        AuthorizationState::Abandoned
    );
    assert_eq!(
        storage
            .invitation_opening_state(&invitation_id)
            .expect("opening state"),
        Some(InvitationOpeningState::Available)
    );
}

#[test]
fn membership_commit_rejects_state_substituted_by_a_delegating_storage() {
    let database = TestDatabase::new("membership-exact-provider-state");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("invitation issued");
    let invitation_id = *invitation.invitation().invitation_id();
    let validated = validated_key_package();
    let pending = storage
        .reserve_authorization(
            &protector,
            shadow_for_validated(&invitation, 0x9b, &validated),
            NOW,
        )
        .expect("authorization reserved");
    let approved = storage
        .approve_authorization(pending, &protector, NOW + 1)
        .expect("authorization approved");
    let membership = storage
        .begin_membership_authorization(approved, [0xab; 16], &protector, NOW + 2)
        .expect("membership authorized");
    let attempt_id = *membership.attempt_id();
    let transaction_id = *membership.transaction_id();

    assert!(!matching_membership_write_succeeds_with_group_storage(
        SubstitutingGroupStateStorage(storage.clone()),
        &storage,
        &invitation,
        0x9b,
        validated,
        membership,
        MembershipWriteOptions::NORMAL,
        || {},
    ));
    let recovery_scope =
        SqlCipherStorage::open(&database.0, vault_key()).expect("independent recovery opens");
    assert_eq!(
        recovery_scope
            .recover_authorization_outcome(&attempt_id, &transaction_id, &protector, NOW + 3,)
            .expect("substituted provider state leaves no durable membership"),
        AuthorizationState::Abandoned
    );
    assert_eq!(
        storage
            .invitation_opening_state(&invitation_id)
            .expect("opening state"),
        Some(InvitationOpeningState::Available)
    );
    assert!(
        storage
            .recover_inviter(&transaction_id)
            .expect("inviter recovery")
            .is_none()
    );
}

#[test]
fn concurrent_recovery_fences_a_staged_membership_commit() {
    let database = TestDatabase::new("membership-recovery-race");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("invitation issued");
    let invitation_id = *invitation.invitation().invitation_id();
    let validated = validated_key_package();
    let pending = storage
        .reserve_authorization(
            &protector,
            shadow_for_validated(&invitation, 0x92, &validated),
            NOW,
        )
        .expect("authorization reserved");
    let approved = storage
        .approve_authorization(pending, &protector, NOW + 1)
        .expect("authorization approved");
    let membership = storage
        .begin_membership_authorization(approved, [0xa2; 16], &protector, NOW + 2)
        .expect("membership authorized");
    let attempt_id = *membership.attempt_id();
    let transaction_id = *membership.transaction_id();
    let recovery_scope =
        SqlCipherStorage::open(&database.0, vault_key()).expect("independent scope opens");

    assert!(!matching_membership_write_succeeds(
        &storage,
        &invitation,
        0x92,
        validated,
        membership,
        MembershipWriteOptions::NORMAL,
        || {
            assert_eq!(
                recovery_scope
                    .recover_authorization_outcome(
                        &attempt_id,
                        &transaction_id,
                        &protector,
                        NOW + 3,
                    )
                    .expect("independent recovery proves no commit"),
                AuthorizationState::Abandoned
            );
        },
    ));
    assert_eq!(
        storage
            .authorization_state(&attempt_id)
            .expect("authorization state"),
        Some(AuthorizationState::Abandoned)
    );
    assert_eq!(
        storage
            .invitation_opening_state(&invitation_id)
            .expect("opening state"),
        Some(InvitationOpeningState::Available)
    );
    assert!(
        storage
            .recover_inviter(&transaction_id)
            .expect("inviter recovery")
            .is_none()
    );
}

#[test]
fn known_precommit_failure_can_be_finalized_in_the_same_scope() {
    let database = TestDatabase::new("membership-known-failure");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("invitation issued");
    let invitation_id = *invitation.invitation().invitation_id();
    let validated = validated_key_package();
    let pending = storage
        .reserve_authorization(
            &protector,
            shadow_for_validated(&invitation, 0x93, &validated),
            NOW,
        )
        .expect("authorization reserved");
    let approved = storage
        .approve_authorization(pending, &protector, NOW + 1)
        .expect("authorization approved");
    let membership = storage
        .begin_membership_authorization(approved, [0xa3; 16], &protector, NOW + 2)
        .expect("membership authorized");
    let attempt_id = *membership.attempt_id();
    let transaction_id = *membership.transaction_id();

    assert!(!matching_membership_write_succeeds(
        &storage,
        &invitation,
        0x93,
        validated,
        membership,
        MembershipWriteOptions {
            fault: PersistenceFault::BeforeCommit,
            advance_group_before_write: false,
        },
        || {},
    ));
    assert_eq!(
        storage
            .recover_authorization_outcome(&attempt_id, &transaction_id, &protector, NOW + 3,)
            .expect("same scope finalizes known failure"),
        AuthorizationState::Abandoned
    );
    assert_eq!(
        storage
            .invitation_opening_state(&invitation_id)
            .expect("opening state"),
        Some(InvitationOpeningState::Available)
    );
}

#[test]
fn ambiguous_postcommit_result_is_committed_in_the_same_scope() {
    let database = TestDatabase::new("membership-ambiguous-success");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("invitation issued");
    let invitation_id = *invitation.invitation().invitation_id();
    let validated = validated_key_package();
    let pending = storage
        .reserve_authorization(
            &protector,
            shadow_for_validated(&invitation, 0x94, &validated),
            NOW,
        )
        .expect("authorization reserved");
    let approved = storage
        .approve_authorization(pending, &protector, NOW + 1)
        .expect("authorization approved");
    let membership = storage
        .begin_membership_authorization(approved, [0xa4; 16], &protector, NOW + 2)
        .expect("membership authorized");
    let attempt_id = *membership.attempt_id();
    let transaction_id = *membership.transaction_id();

    assert!(!matching_membership_write_succeeds(
        &storage,
        &invitation,
        0x94,
        validated,
        membership,
        MembershipWriteOptions {
            fault: PersistenceFault::AfterCommit,
            advance_group_before_write: false,
        },
        || {},
    ));
    assert_eq!(
        storage
            .recover_authorization_outcome(&attempt_id, &transaction_id, &protector, NOW + 3,)
            .expect("same scope resolves ambiguous committed result"),
        AuthorizationState::Committed
    );
    assert_eq!(
        storage
            .invitation_opening_state(&invitation_id)
            .expect("opening state"),
        Some(InvitationOpeningState::Consumed)
    );
    assert!(
        storage
            .recover_inviter(&transaction_id)
            .expect("inviter recovery")
            .is_some()
    );
}

#[test]
fn persisted_policy_enforces_attempt_capacity_and_rejects_reinterpretation() {
    let database = TestDatabase::new("persisted-policy");
    let protector = AwsLcInvitationJoinProtector::new();
    let policy = AuthorizationPolicy::new(2, 1).expect("bounded policy");
    let storage =
        SqlCipherStorage::create_with_authorization_policy(&database.0, vault_key(), policy)
            .expect("storage created");
    let first_invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("first invitation issued");
    let second_invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("second invitation issued");
    assert!(matches!(
        storage.issue_capability_invitation(&protector, NOW, NOW + 300, NOW),
        Err(StoreError::CapacityExceeded)
    ));
    storage
        .reserve_authorization(&protector, shadow(&first_invitation, 0xc1), NOW)
        .expect("first authorization retained");
    assert!(matches!(
        storage.reserve_authorization(&protector, shadow(&second_invitation, 0xd1), NOW),
        Err(StoreError::CapacityExceeded)
    ));
    drop(storage);

    assert!(matches!(
        SqlCipherStorage::open(&database.0, vault_key()),
        Err(StoreError::Conflict)
    ));
    SqlCipherStorage::open_with_authorization_policy(&database.0, vault_key(), policy)
        .expect("matching stored policy reopens");
    assert!(AuthorizationPolicy::new(0, 1).is_err());
    assert!(AuthorizationPolicy::new(1, 9).is_err());
}

#[test]
fn approved_attempt_can_be_explicitly_abandoned_without_losing_replay() {
    let database = TestDatabase::new("approved-abandon");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("invitation issued");
    let invitation_id = *invitation.invitation().invitation_id();
    let pending = storage
        .reserve_authorization(&protector, shadow(&invitation, 0xe1), NOW)
        .expect("authorization reserved");
    let approved = storage
        .approve_authorization(pending, &protector, NOW + 1)
        .expect("authorization approved");
    let attempt_id = *approved.attempt_id();

    storage
        .abandon_approved_authorization(approved, &protector, NOW + 2)
        .expect("approved attempt abandoned");
    assert_eq!(
        storage
            .authorization_state(&attempt_id)
            .expect("authorization state"),
        Some(AuthorizationState::Abandoned)
    );
    assert_eq!(
        storage
            .invitation_opening_state(&invitation_id)
            .expect("invitation state"),
        Some(InvitationOpeningState::Available)
    );
    assert!(matches!(
        storage.reserve_authorization(&protector, shadow(&invitation, 0xe1), NOW + 3),
        Err(StoreError::Replay)
    ));
}

#[test]
fn expired_terminal_attempts_compact_before_reusing_bounded_capacity() {
    let database = TestDatabase::new("terminal-compaction");
    let protector = AwsLcInvitationJoinProtector::new();
    let policy = AuthorizationPolicy::new(1, 1).expect("bounded policy");
    let storage =
        SqlCipherStorage::create_with_authorization_policy(&database.0, vault_key(), policy)
            .expect("storage created");
    let expired_invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("first invitation issued");
    let expired_invitation_id = *expired_invitation.invitation().invitation_id();
    let pending = storage
        .reserve_authorization(&protector, shadow(&expired_invitation, 0xf1), NOW)
        .expect("authorization reserved");
    let expired_attempt_id = *pending.attempt_id();
    storage
        .reject_authorization(pending, &protector, NOW + 1)
        .expect("authorization terminalized");

    let next_now = NOW + 301;
    let next_invitation = storage
        .issue_capability_invitation(&protector, next_now, next_now + 300, next_now)
        .expect("expired terminal rows compact before new issuance");
    assert_eq!(
        storage
            .authorization_state(&expired_attempt_id)
            .expect("expired attempt lookup"),
        None
    );
    assert_eq!(
        storage
            .invitation_opening_state(&expired_invitation_id)
            .expect("expired invitation lookup"),
        None
    );
    storage
        .reserve_authorization(
            &protector,
            shadow_at(&next_invitation, 0xf2, next_now),
            next_now,
        )
        .expect("attempt capacity is reusable only after bounded compaction");
}

#[test]
fn expired_committed_authorization_compacts_without_removing_inviter_result() {
    let database = TestDatabase::new("committed-compaction");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("invitation issued");
    let invitation_id = *invitation.invitation().invitation_id();
    let (attempt_id, transaction_id) = commit_authorized_fixture(&storage, &invitation, 0x46);

    let next_now = NOW + 301;
    storage
        .issue_capability_invitation(&protector, next_now, next_now + 300, next_now)
        .expect("expired committed authorization compacts");
    assert_eq!(
        storage
            .authorization_state(&attempt_id)
            .expect("authorization lookup"),
        None
    );
    assert_eq!(
        storage
            .invitation_opening_state(&invitation_id)
            .expect("opening lookup"),
        None
    );
    assert!(
        storage
            .recover_inviter(&transaction_id)
            .expect("inviter recovery")
            .is_some()
    );
}

#[test]
fn expired_outcome_unknown_attempt_keeps_capacity_until_exact_recovery() {
    let database = TestDatabase::new("unknown-capacity");
    let protector = AwsLcInvitationJoinProtector::new();
    let policy = AuthorizationPolicy::new(2, 1).expect("bounded policy");
    let storage =
        SqlCipherStorage::create_with_authorization_policy(&database.0, vault_key(), policy)
            .expect("storage created");
    let first_invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("first invitation issued");
    let pending = storage
        .reserve_authorization(&protector, shadow(&first_invitation, 0xa7), NOW)
        .expect("authorization reserved");
    let approved = storage
        .approve_authorization(pending, &protector, NOW + 1)
        .expect("authorization approved");
    let membership = storage
        .begin_membership_authorization(approved, [0xa8; 16], &protector, NOW + 2)
        .expect("membership outcome becomes unknown");
    let attempt_id = *membership.attempt_id();
    let transaction_id = *membership.transaction_id();
    drop(storage);

    let next_now = NOW + 301;
    let reopened =
        SqlCipherStorage::open_with_authorization_policy(&database.0, vault_key(), policy)
            .expect("storage reopens");
    let next_invitation = reopened
        .issue_capability_invitation(&protector, next_now, next_now + 300, next_now)
        .expect("second invitation fits the opening-context bound");
    assert!(matches!(
        reopened.reserve_authorization(
            &protector,
            shadow_at(&next_invitation, 0xa9, next_now),
            next_now,
        ),
        Err(StoreError::CapacityExceeded)
    ));

    assert_eq!(
        reopened
            .recover_authorization_outcome(&attempt_id, &transaction_id, &protector, next_now,)
            .expect("exact absent membership transaction is recovered"),
        AuthorizationState::Abandoned
    );
    reopened
        .reserve_authorization(
            &protector,
            shadow_at(&next_invitation, 0xa9, next_now),
            next_now,
        )
        .expect("resolved terminal attempt compacts before capacity is reused");
}

#[test]
fn malformed_authorization_generation_fails_during_schema_validation() {
    let database = TestDatabase::new("malformed-generation");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("invitation issued");
    let pending = storage
        .reserve_authorization(&protector, shadow(&invitation, 0xb7), NOW)
        .expect("authorization reserved");
    let attempt_id = *pending.attempt_id();
    drop(pending);
    drop(storage);

    let connection = open_fixture_connection(&database.0);
    connection
        .execute(
            "UPDATE authorization_attempts SET generation = ?1 WHERE attempt_id = ?2",
            params![[0xee_u8; 64], attempt_id],
        )
        .expect("bounded malformed fixture");
    drop(connection);

    assert!(matches!(
        SqlCipherStorage::open(&database.0, vault_key()),
        Err(StoreError::Rejected)
    ));
}

#[test]
fn committed_authorization_without_inviter_result_fails_schema_validation() {
    let database = TestDatabase::new("committed-without-result");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("invitation issued");
    let (_, transaction_id) = commit_authorized_fixture(&storage, &invitation, 0x42);
    drop(invitation);
    drop(storage);
    let connection = open_fixture_connection(&database.0);
    connection
        .execute(
            "DELETE FROM inviter_joins WHERE transaction_id = ?1",
            params![transaction_id],
        )
        .expect("committed result removed");
    drop(connection);

    assert!(matches!(
        SqlCipherStorage::open(&database.0, vault_key()),
        Err(StoreError::Rejected)
    ));
}

#[test]
fn abandoned_authorization_with_inviter_result_fails_schema_validation() {
    let database = TestDatabase::new("abandoned-with-result");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("invitation issued");
    let (attempt_id, _) = commit_authorized_fixture(&storage, &invitation, 0x43);
    drop(invitation);
    drop(storage);
    let connection = open_fixture_connection(&database.0);
    connection
        .execute(
            "UPDATE authorization_attempts SET state = 6 WHERE attempt_id = ?1",
            params![attempt_id],
        )
        .expect("contradictory abandoned state created");
    drop(connection);

    assert!(matches!(
        SqlCipherStorage::open(&database.0, vault_key()),
        Err(StoreError::Rejected)
    ));
}

#[test]
fn committed_authorization_with_available_opening_fails_schema_validation() {
    let database = TestDatabase::new("committed-available-opening");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("invitation issued");
    let invitation_id = *invitation.invitation().invitation_id();
    commit_authorized_fixture(&storage, &invitation, 0x44);
    drop(invitation);
    drop(storage);
    let connection = open_fixture_connection(&database.0);
    connection
        .execute(
            "UPDATE invitation_opening_contexts SET state = 1 WHERE invitation_id = ?1",
            params![invitation_id],
        )
        .expect("contradictory opening state created");
    drop(connection);

    assert!(matches!(
        SqlCipherStorage::open(&database.0, vault_key()),
        Err(StoreError::Rejected)
    ));
}

#[test]
fn committed_authorization_with_unconsumed_reservation_fails_schema_validation() {
    let database = TestDatabase::new("committed-unconsumed-reservation");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("invitation issued");
    let invitation_id = *invitation.invitation().invitation_id();
    commit_authorized_fixture(&storage, &invitation, 0x45);
    drop(invitation);
    drop(storage);
    let connection = open_fixture_connection(&database.0);
    connection
        .execute(
            "UPDATE reservations SET state = 1 WHERE invitation_id = ?1",
            params![invitation_id],
        )
        .expect("contradictory reservation state created");
    drop(connection);

    assert!(matches!(
        SqlCipherStorage::open(&database.0, vault_key()),
        Err(StoreError::Rejected)
    ));
}

#[test]
fn expiry_during_approval_abandons_replay_and_releases_exact_invitation() {
    let database = TestDatabase::new("approval-expiry");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("invitation issued");
    let invitation_id = *invitation.invitation().invitation_id();
    let pending = storage
        .reserve_authorization(&protector, shadow(&invitation, 0xc7), NOW)
        .expect("authorization reserved");
    let attempt_id = *pending.attempt_id();

    assert!(matches!(
        storage.approve_authorization(pending, &protector, NOW + 120),
        Err(StoreError::Rejected)
    ));
    assert_eq!(
        storage
            .authorization_state(&attempt_id)
            .expect("authorization state"),
        Some(AuthorizationState::Abandoned)
    );
    assert_eq!(
        storage
            .invitation_opening_state(&invitation_id)
            .expect("invitation state"),
        Some(InvitationOpeningState::Available)
    );
    storage
        .reserve_authorization(
            &protector,
            shadow_at(&invitation, 0xc8, NOW + 120),
            NOW + 120,
        )
        .expect("a fresh request can use the safely released generation");
}

#[test]
fn expiry_before_membership_handoff_abandons_without_exposing_authority() {
    let database = TestDatabase::new("membership-handoff-expiry");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let invitation = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("invitation issued");
    let invitation_id = *invitation.invitation().invitation_id();
    let pending = storage
        .reserve_authorization(&protector, shadow(&invitation, 0xd7), NOW)
        .expect("authorization reserved");
    let approved = storage
        .approve_authorization(pending, &protector, NOW + 1)
        .expect("authorization approved");
    let attempt_id = *approved.attempt_id();

    assert!(matches!(
        storage.begin_membership_authorization(approved, [0xd8; 16], &protector, NOW + 120,),
        Err(StoreError::Rejected)
    ));
    assert_eq!(
        storage
            .authorization_state(&attempt_id)
            .expect("authorization state"),
        Some(AuthorizationState::Abandoned)
    );
    assert_eq!(
        storage
            .invitation_opening_state(&invitation_id)
            .expect("invitation state"),
        Some(InvitationOpeningState::Available)
    );
}
