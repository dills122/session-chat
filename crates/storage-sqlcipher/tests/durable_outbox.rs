use std::{
    future::Future,
    path::{Path, PathBuf},
    pin::pin,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use rusqlite::{Connection, params};
use session_crypto_mls::{
    DurableClientIdentityStorage, SessionGroupId, create_client, create_client_with_storage,
    create_key_package_validator,
};
use session_protocol::{DepositCapability, LocalWelcomeDepositEndpoint, OpaqueEnvelope};
use session_transport::{
    CoordinatorOutcome, CoordinatorPolicy, DispatchControl, EnvelopeTransport, LocalMailboxPolicy,
    LocalMemoryWelcomeTransport, LocalV1DepositEndpointResolver, OutboxPortError,
    WelcomeDeliveryCoordinator, WelcomeOutboxPort,
};
use storage_sqlcipher::{
    InvitationState, InviterJoinTransaction, MAXIMUM_WELCOME_DELIVERY_ATTEMPTS, PersistenceFault,
    SqlCipherStorage, VaultKey, WelcomeOutboxState,
};

const NOW: u64 = 1_900_000_000;
const TRANSACTION_ID: [u8; 16] = [4; 16];
const INVITATION_ID: [u8; 16] = [1; 16];
const V2_LEASED_TRANSACTION_ID: [u8; 16] = [51; 16];
const V2_DELIVERED_TRANSACTION_ID: [u8; 16] = [52; 16];
const V2_EXHAUSTED_TRANSACTION_ID: [u8; 16] = [53; 16];
const V2_STORE_ID: [u8; 16] = [54; 16];

struct TestDatabase(PathBuf);

impl TestDatabase {
    fn new(name: &str) -> Self {
        Self(std::env::temp_dir().join(format!(
            "session-chat-storage-sqlcipher-outbox-{name}-{}.sqlite3",
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

struct TestControl {
    monotonic_now: Instant,
    wall_now_unix_seconds: u64,
}

impl DispatchControl for TestControl {
    fn monotonic_now(&self) -> Instant {
        self.monotonic_now
    }

    fn wall_now_unix_seconds(&self) -> Option<u64> {
        Some(self.wall_now_unix_seconds)
    }

    fn is_cancelled(&self) -> bool {
        false
    }
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("local durable-outbox future unexpectedly pending"),
    }
}

fn vault_key() -> VaultKey {
    VaultKey::new([7; 32]).expect("nonzero test key")
}

fn canonical_endpoint(expires_at: u64) -> Vec<u8> {
    LocalWelcomeDepositEndpoint::new(
        [9; 16],
        [10; 16],
        DepositCapability::new([11; 32]).expect("deposit capability"),
        expires_at,
    )
    .expect("endpoint")
    .encode_canonical()
    .expect("canonical endpoint")
}

fn commit_real_mls_inviter(
    storage: &SqlCipherStorage,
    endpoint: Vec<u8>,
    envelope_id: [u8; 16],
    fault: PersistenceFault,
) -> (Vec<u8>, Result<(), ()>) {
    storage
        .seed_reservation(INVITATION_ID, [2; 64], [3; 16], NOW + 300, NOW)
        .expect("reservation stored");
    let alice = create_client_with_storage(storage.clone(), storage.clone()).expect("Alice client");
    let mut alice_group = alice
        .create_group(SessionGroupId::new([5; 32]).expect("group id"), NOW)
        .expect("Alice group");
    let bob = create_client().expect("Bob client");
    let bob_key_package = bob.generate_key_package(NOW).expect("Bob KeyPackage");
    let validated = create_key_package_validator()
        .validate_key_package(bob_key_package.as_bytes(), NOW)
        .expect("validated KeyPackage");
    let addition = alice_group
        .prepare_add(validated, NOW)
        .expect("prepared Add")
        .apply()
        .expect("applied Add");
    let welcome = OpaqueEnvelope::new(
        envelope_id,
        NOW + 180,
        addition.welcome().as_bytes().to_vec(),
    )
    .expect("Welcome envelope")
    .encode_canonical()
    .expect("canonical Welcome");
    let transaction = InviterJoinTransaction::new(
        TRANSACTION_ID,
        INVITATION_ID,
        [2; 64],
        [3; 16],
        [6; 32],
        *alice_group.group_id(),
        0,
        1,
        vec![7; 32],
        welcome.clone(),
        endpoint,
        NOW + 120,
    )
    .expect("bounded transaction");
    storage
        .stage_inviter(transaction, NOW, fault)
        .expect("transaction staged");
    let result = alice_group.write_to_storage().map_err(|_| ());
    drop(alice_group);
    drop(alice);
    drop(bob);
    (welcome, result)
}

fn committed_store(name: &str) -> (TestDatabase, SqlCipherStorage) {
    let database = TestDatabase::new(name);
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let (_welcome, result) = commit_real_mls_inviter(
        &storage,
        canonical_endpoint(NOW + 240),
        [8; 16],
        PersistenceFault::None,
    );
    result.expect("inviter transaction committed");
    (database, storage)
}

#[test]
fn schema_v1_fixture_migrates_atomically_to_pending_v3_work() {
    let database = TestDatabase::new("migration-v1");
    let welcome = OpaqueEnvelope::new([21; 16], NOW + 180, vec![22; 32])
        .expect("Welcome")
        .encode_canonical()
        .expect("canonical Welcome");
    let endpoint = canonical_endpoint(NOW + 240);
    create_schema_v1_fixture(&database.0, &welcome, &endpoint);

    let mut migrated = SqlCipherStorage::open(&database.0, vault_key()).expect("v1 migrates");
    assert_eq!(migrated.schema_version().expect("schema version"), 3);
    assert!(
        migrated
            .load_client_identity()
            .expect("identity lookup")
            .is_none()
    );
    let recovered = migrated
        .recover_inviter(&TRANSACTION_ID)
        .expect("recovery")
        .expect("committed fixture");
    assert_eq!(recovered.outbox_state, WelcomeOutboxState::Pending);
    assert_eq!(recovered.delivery_attempts, 0);
    let lease = migrated
        .lease_next(NOW, 10)
        .expect("lease transition")
        .expect("migrated work");
    migrated
        .report_failed(lease.discard_payload())
        .expect("migrated lease releases");
    drop(migrated);

    let connection = open_fixture_connection(&database.0);
    assert_eq!(
        connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .expect("application schema version"),
        3
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT maximum_delivery_attempts FROM inviter_joins
                 WHERE transaction_id = ?1",
                params![TRANSACTION_ID],
                |row| row.get::<_, i64>(0),
            )
            .expect("migrated attempt ceiling"),
        i64::from(MAXIMUM_WELCOME_DELIVERY_ATTEMPTS)
    );
    drop(connection);

    let reopened = SqlCipherStorage::open(&database.0, vault_key()).expect("v3 reopens");
    assert_eq!(reopened.schema_version().expect("schema version"), 3);
}

#[test]
fn frozen_schema_v2_fixture_preserves_nondefault_outbox_states_in_v3() {
    let database = TestDatabase::new("migration-v2");
    let welcome = OpaqueEnvelope::new([55; 16], NOW + 180, vec![56; 32])
        .expect("Welcome")
        .encode_canonical()
        .expect("canonical Welcome");
    create_schema_v2_fixture(&database.0, &welcome, &canonical_endpoint(NOW + 240));

    let migrated = SqlCipherStorage::open(&database.0, vault_key()).expect("v2 migrates");
    assert_eq!(migrated.schema_version().expect("schema version"), 3);
    assert!(
        migrated
            .load_client_identity()
            .expect("identity lookup")
            .is_none()
    );
    let leased = migrated
        .recover_inviter(&V2_LEASED_TRANSACTION_ID)
        .expect("leased recovery")
        .expect("leased fixture");
    assert_eq!(leased.outbox_state, WelcomeOutboxState::Leased);
    assert_eq!(leased.delivery_attempts, 2);
    let delivered = migrated
        .recover_inviter(&V2_DELIVERED_TRANSACTION_ID)
        .expect("delivered recovery")
        .expect("delivered fixture");
    assert_eq!(delivered.outbox_state, WelcomeOutboxState::Delivered);
    assert_eq!(delivered.delivery_attempts, 1);
    let exhausted = migrated
        .recover_inviter(&V2_EXHAUSTED_TRANSACTION_ID)
        .expect("exhausted recovery")
        .expect("exhausted fixture");
    assert_eq!(
        exhausted.outbox_state,
        WelcomeOutboxState::AttemptsExhausted
    );
    assert_eq!(exhausted.delivery_attempts, 3);
    drop(migrated);

    let connection = open_fixture_connection(&database.0);
    assert_eq!(fixture_versions(&connection), (3, 3));
    assert_eq!(fixture_store_id(&connection), V2_STORE_ID);
    assert_eq!(
        connection
            .query_row(
                "SELECT lease_generation, lease_id, lease_expires_at
                 FROM inviter_joins WHERE transaction_id = ?1",
                params![V2_LEASED_TRANSACTION_ID],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .expect("leased authority survives migration"),
        (4, vec![91_u8; 16], (NOW + 60) as i64)
    );
}

#[test]
fn failed_schema_v2_migration_restores_versions_and_outbox_rows() {
    let database = TestDatabase::new("migration-v2-rollback");
    let welcome = OpaqueEnvelope::new([57; 16], NOW + 180, vec![58; 32])
        .expect("Welcome")
        .encode_canonical()
        .expect("canonical Welcome");
    create_schema_v2_fixture(&database.0, &welcome, &canonical_endpoint(NOW + 240));
    let connection = open_fixture_connection(&database.0);
    connection
        .execute_batch(
            "CREATE TABLE mls_client_identity (
                 conflicting INTEGER PRIMARY KEY
             ) STRICT;",
        )
        .expect("conflicting future table");
    drop(connection);

    assert!(SqlCipherStorage::open(&database.0, vault_key()).is_err());
    let connection = open_fixture_connection(&database.0);
    assert_eq!(fixture_versions(&connection), (2, 2));
    assert_eq!(fixture_store_id(&connection), V2_STORE_ID);
    assert_eq!(
        connection
            .query_row(
                "SELECT outbox_state FROM inviter_joins WHERE transaction_id = ?1",
                params![V2_LEASED_TRANSACTION_ID],
                |row| row.get::<_, i64>(0),
            )
            .expect("leased fixture survives rollback"),
        2
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'storage_metadata_v2'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("temporary metadata table lookup"),
        0
    );
}

#[test]
fn invalid_v1_delivery_material_rolls_migration_back() {
    let database = TestDatabase::new("migration-v1-invalid");
    create_schema_v1_fixture(&database.0, &[0xff], &canonical_endpoint(NOW + 240));

    assert!(SqlCipherStorage::open(&database.0, vault_key()).is_err());
    let connection = open_fixture_connection(&database.0);
    assert_eq!(
        connection
            .query_row("SELECT schema_version FROM storage_metadata", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("v1 metadata survives failed migration"),
        1
    );
}

#[test]
fn schema_metadata_and_user_version_must_match() {
    let (database, storage) = committed_store("version-mismatch");
    drop(storage);
    let connection = open_fixture_connection(&database.0);
    connection
        .execute_batch("PRAGMA user_version = 1;")
        .expect("set mismatched application version");
    drop(connection);

    assert!(SqlCipherStorage::open(&database.0, vault_key()).is_err());
}

#[test]
fn close_and_reopen_reconstructs_the_sole_owner_ledger() {
    let (database, storage) = committed_store("restart");
    drop(storage);

    let mut reopened = SqlCipherStorage::open(&database.0, vault_key()).expect("store reopens");
    let lease = reopened
        .lease_next(NOW, 10)
        .expect("lease transition")
        .expect("pending Welcome");
    reopened
        .report_accepted(lease.discard_payload(), NOW)
        .expect("acceptance retained");
    drop(reopened);

    let final_store =
        SqlCipherStorage::open(&database.0, vault_key()).expect("store reopens again");
    let recovered = final_store
        .recover_inviter(&TRANSACTION_ID)
        .expect("recovery")
        .expect("committed transaction");
    assert_eq!(recovered.outbox_state, WelcomeOutboxState::Delivered);
    assert_eq!(recovered.delivery_attempts, 1);
    assert_eq!(recovered.epoch_after, 1);
    assert_eq!(
        final_store
            .invitation_state(&INVITATION_ID)
            .expect("invitation state"),
        Some(InvitationState::Consumed)
    );
}

#[test]
fn lease_from_a_previous_open_scope_cannot_report_a_result() {
    let (database, mut first_open) = committed_store("reopen-scope");
    let pre_reopen_lease = first_open
        .lease_next(NOW, 1)
        .expect("lease transition")
        .expect("pending Welcome")
        .discard_payload();

    let mut reopened = SqlCipherStorage::open(&database.0, vault_key()).expect("second open");
    assert_eq!(
        reopened.report_failed(pre_reopen_lease),
        Err(OutboxPortError::Conflict)
    );
    let replacement = reopened
        .lease_next(NOW + 1, 1)
        .expect("expired prior scope")
        .expect("replacement lease");
    reopened
        .report_failed(replacement.discard_payload())
        .expect("replacement released");
}

#[test]
fn stale_and_foreign_store_leases_fail_closed() {
    let (_database_a, mut store_a) = committed_store("lease-a");
    let (_database_b, mut store_b) = committed_store("lease-b");
    let foreign = store_a
        .lease_next(NOW, 1)
        .expect("first lease")
        .expect("work")
        .discard_payload();
    assert_eq!(
        store_b.report_failed(foreign),
        Err(OutboxPortError::Conflict)
    );

    let replacement_after_foreign = store_a
        .lease_next(NOW + 1, 1)
        .expect("expired lease can be replaced")
        .expect("replacement work");
    store_a
        .report_failed(replacement_after_foreign.discard_payload())
        .expect("owner replacement releases");

    let (_database_c, mut store_c) = committed_store("lease-c");
    let stale = store_c
        .lease_next(NOW, 1)
        .expect("stale lease")
        .expect("work")
        .discard_payload();
    let replacement = store_c
        .lease_next(NOW + 1, 1)
        .expect("replacement lease")
        .expect("work")
        .discard_payload();
    assert_eq!(store_c.report_failed(stale), Err(OutboxPortError::Conflict));
    store_c
        .report_accepted(replacement, NOW + 1)
        .expect("replacement accepted");
}

#[test]
fn persisted_attempt_ceiling_is_not_reinterpreted_after_reopen() {
    let (database, storage) = committed_store("persisted-attempt-ceiling");
    drop(storage);
    let connection = open_fixture_connection(&database.0);
    connection
        .execute(
            "UPDATE inviter_joins SET maximum_delivery_attempts = 1
             WHERE transaction_id = ?1",
            params![TRANSACTION_ID],
        )
        .expect("narrow retained attempt ceiling");
    drop(connection);

    let mut reopened = SqlCipherStorage::open(&database.0, vault_key()).expect("store reopens");
    let lease = reopened
        .lease_next(NOW, 1)
        .expect("first lease")
        .expect("one retained attempt");
    reopened
        .report_failed(lease.discard_payload())
        .expect("attempt terminalized");
    assert!(
        reopened
            .lease_next(NOW + 1, 1)
            .expect("terminal enumeration")
            .is_none()
    );
    assert_eq!(
        reopened
            .recover_inviter(&TRANSACTION_ID)
            .expect("recovery")
            .expect("transaction")
            .outbox_state,
        WelcomeOutboxState::AttemptsExhausted
    );
}

#[test]
fn failed_attempts_terminalize_at_the_persisted_bound() {
    let (_database, mut storage) = committed_store("exhaustion");
    for attempt in 0..MAXIMUM_WELCOME_DELIVERY_ATTEMPTS {
        let lease = storage
            .lease_next(NOW + u64::from(attempt), 1)
            .expect("lease transition")
            .expect("bounded attempt");
        storage
            .report_failed(lease.discard_payload())
            .expect("failure retained");
    }
    assert!(
        storage
            .lease_next(NOW + u64::from(MAXIMUM_WELCOME_DELIVERY_ATTEMPTS), 1)
            .expect("terminal enumeration")
            .is_none()
    );
    let recovered = storage
        .recover_inviter(&TRANSACTION_ID)
        .expect("recovery")
        .expect("transaction");
    assert_eq!(
        recovered.outbox_state,
        WelcomeOutboxState::AttemptsExhausted
    );
    assert_eq!(
        recovered.delivery_attempts,
        MAXIMUM_WELCOME_DELIVERY_ATTEMPTS
    );
}

#[test]
fn expiry_terminalizes_work_and_rejects_a_late_result() {
    let (_database, mut storage) = committed_store("expiry");
    let lease = storage
        .lease_next(NOW, 10)
        .expect("lease transition")
        .expect("live work")
        .discard_payload();
    assert_eq!(
        storage.report_accepted(lease, NOW + 120),
        Err(OutboxPortError::Conflict)
    );
    assert!(
        storage
            .lease_next(NOW + 120, 1)
            .expect("expired enumeration")
            .is_none()
    );
    assert_eq!(
        storage
            .recover_inviter(&TRANSACTION_ID)
            .expect("recovery")
            .expect("transaction")
            .outbox_state,
        WelcomeOutboxState::Expired
    );
}

#[test]
fn ambiguous_prior_acceptance_retries_byte_identically_after_restart() {
    let database = TestDatabase::new("ambiguous-restart");
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let mut adapter =
        LocalMemoryWelcomeTransport::new(LocalMailboxPolicy::new(600, 1).expect("mailbox policy"))
            .expect("local adapter");
    let (endpoint, receive, _acknowledgement) = adapter
        .create_welcome_mailbox(NOW + 300, NOW)
        .expect("Welcome mailbox")
        .into_parts();
    let (welcome, result) = commit_real_mls_inviter(
        &storage,
        endpoint.encode_canonical().expect("canonical endpoint"),
        [31; 16],
        PersistenceFault::None,
    );
    result.expect("inviter commit");

    let mut lease_owner = storage.clone();
    let _abandoned_lease = lease_owner
        .lease_next(NOW, 1)
        .expect("owner lease")
        .expect("pending Welcome")
        .discard_payload();
    let expected = OpaqueEnvelope::decode_canonical(&welcome).expect("Welcome decodes");
    let first_delivery = EnvelopeTransport::deposit(&mut adapter, &endpoint, expected, NOW)
        .expect("remote accepted before owner result");
    drop(storage);

    let mut reopened = SqlCipherStorage::open(&database.0, vault_key()).expect("store reopens");
    let coordinator = WelcomeDeliveryCoordinator::new(
        CoordinatorPolicy::new(Duration::from_secs(1), 1, 65_536).expect("coordinator policy"),
    );
    let control = TestControl {
        monotonic_now: Instant::now(),
        wall_now_unix_seconds: NOW + 1,
    };
    let mut resolver = LocalV1DepositEndpointResolver;
    assert_eq!(
        ready(coordinator.run_once(&mut reopened, &mut resolver, &mut adapter, &control))
            .expect("exact retry reconciles"),
        CoordinatorOutcome::Accepted
    );
    assert_eq!(
        adapter
            .receive(&receive, NOW + 1)
            .expect("receive")
            .expect("one logical Welcome")
            .delivery_id(),
        &first_delivery
    );
    let recovered = reopened
        .recover_inviter(&TRANSACTION_ID)
        .expect("recovery")
        .expect("transaction");
    assert_eq!(recovered.epoch_after, 1);
    assert_eq!(recovered.delivery_attempts, 2);
    assert_eq!(recovered.outbox_state, WelcomeOutboxState::Delivered);
    assert_eq!(
        reopened
            .invitation_state(&INVITATION_ID)
            .expect("invitation state"),
        Some(InvitationState::Consumed)
    );
}

#[test]
fn rolled_back_membership_exposes_no_outbox_work() {
    let database = TestDatabase::new("atomic-invisibility");
    let mut storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let (_welcome, result) = commit_real_mls_inviter(
        &storage,
        canonical_endpoint(NOW + 240),
        [41; 16],
        PersistenceFault::BeforeCommit,
    );
    assert!(result.is_err());
    assert!(
        storage
            .lease_next(NOW, 10)
            .expect("owner enumeration")
            .is_none()
    );
    assert!(
        storage
            .recover_inviter(&TRANSACTION_ID)
            .expect("recovery")
            .is_none()
    );
    assert_eq!(
        storage
            .invitation_state(&INVITATION_ID)
            .expect("invitation state"),
        Some(InvitationState::Reserved)
    );
}

fn create_schema_v1_fixture(path: &Path, welcome: &[u8], endpoint: &[u8]) {
    let connection = open_fixture_connection(path);
    connection
        .execute_batch(include_str!("fixtures/schema-v1.sql"))
        .expect("schema v1 fixture");
    connection
        .execute(
            "INSERT INTO reservations(invitation_id, generation, join_request_id, expires_at, state)
             VALUES (?1, ?2, ?3, ?4, 2)",
            params![
                INVITATION_ID,
                [2_u8; 64],
                [3_u8; 16],
                (NOW + 300) as i64
            ],
        )
        .expect("consumed reservation fixture");
    connection
        .execute(
            "INSERT INTO mls_groups(group_id, state) VALUES (?1, ?2)",
            params![[5_u8; 32], vec![42_u8; 64]],
        )
        .expect("MLS fixture");
    connection
        .execute(
            "INSERT INTO inviter_joins(
                 transaction_id, invitation_id, generation, join_request_id,
                 request_fingerprint, group_id, epoch_before, epoch_after,
                 approval_record, welcome, endpoint, outbox_expires_at, outbox_state
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 1, ?7, ?8, ?9, ?10, 1)",
            params![
                TRANSACTION_ID,
                INVITATION_ID,
                [2_u8; 64],
                [3_u8; 16],
                [6_u8; 32],
                [5_u8; 32],
                vec![7_u8; 32],
                welcome,
                endpoint,
                (NOW + 120) as i64,
            ],
        )
        .expect("inviter fixture");
}

fn create_schema_v2_fixture(path: &Path, welcome: &[u8], endpoint: &[u8]) {
    let connection = open_fixture_connection(path);
    connection
        .execute_batch(include_str!("fixtures/schema-v2.sql"))
        .expect("frozen schema v2 fixture");
    let rows = [
        (
            V2_LEASED_TRANSACTION_ID,
            [61_u8; 16],
            [71_u8; 16],
            [81_u8; 32],
            2_i64,
            2_i64,
            5_i64,
            4_i64,
            Some([91_u8; 16]),
            Some((NOW + 60) as i64),
        ),
        (
            V2_DELIVERED_TRANSACTION_ID,
            [62_u8; 16],
            [72_u8; 16],
            [82_u8; 32],
            3_i64,
            1_i64,
            5_i64,
            1_i64,
            None,
            None,
        ),
        (
            V2_EXHAUSTED_TRANSACTION_ID,
            [63_u8; 16],
            [73_u8; 16],
            [83_u8; 32],
            4_i64,
            3_i64,
            3_i64,
            3_i64,
            None,
            None,
        ),
    ];
    for (
        transaction_id,
        invitation_id,
        join_request_id,
        group_id,
        outbox_state,
        delivery_attempts,
        maximum_delivery_attempts,
        lease_generation,
        lease_id,
        lease_expires_at,
    ) in rows
    {
        connection
            .execute(
                "INSERT INTO reservations(
                     invitation_id, generation, join_request_id, expires_at, state
                 ) VALUES (?1, ?2, ?3, ?4, 2)",
                params![
                    invitation_id,
                    [2_u8; 64],
                    join_request_id,
                    (NOW + 300) as i64
                ],
            )
            .expect("v2 consumed reservation fixture");
        connection
            .execute(
                "INSERT INTO inviter_joins(
                     transaction_id, invitation_id, generation, join_request_id,
                     request_fingerprint, group_id, epoch_before, epoch_after,
                     approval_record, welcome, endpoint, outbox_expires_at,
                     outbox_state, delivery_attempts, maximum_delivery_attempts,
                     lease_generation, lease_id, lease_expires_at
                 ) VALUES (
                     ?1, ?2, ?3, ?4, ?5, ?6, 0, 1, ?7, ?8, ?9, ?10,
                     ?11, ?12, ?13, ?14, ?15, ?16
                 )",
                params![
                    transaction_id,
                    invitation_id,
                    [2_u8; 64],
                    join_request_id,
                    [6_u8; 32],
                    group_id,
                    vec![7_u8; 32],
                    welcome,
                    endpoint,
                    (NOW + 120) as i64,
                    outbox_state,
                    delivery_attempts,
                    maximum_delivery_attempts,
                    lease_generation,
                    lease_id,
                    lease_expires_at,
                ],
            )
            .expect("v2 inviter fixture");
    }
}

fn fixture_versions(connection: &Connection) -> (i64, i64) {
    (
        connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("application schema version"),
        connection
            .query_row("SELECT schema_version FROM storage_metadata", [], |row| {
                row.get(0)
            })
            .expect("metadata schema version"),
    )
}

fn fixture_store_id(connection: &Connection) -> [u8; 16] {
    connection
        .query_row("SELECT store_id FROM storage_metadata", [], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .expect("store identity")
        .try_into()
        .expect("exact store identity")
}

fn open_fixture_connection(path: &Path) -> Connection {
    let connection = Connection::open(path).expect("fixture database");
    connection
        .execute_batch(
            "PRAGMA key = \"x'0707070707070707070707070707070707070707070707070707070707070707'\";",
        )
        .expect("fixture key");
    connection
}
