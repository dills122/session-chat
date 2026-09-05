use std::path::PathBuf;

use rusqlite::{Connection, params};
use session_crypto_hpke::AwsLcInvitationJoinProtector;
use storage_sqlcipher::{
    AuthorizationPolicy, InvitationOpeningState, MAXIMUM_LIVE_INVITATION_OPENING_CONTEXTS,
    SqlCipherStorage, StoreError, VaultKey,
};

const NOW: u64 = 1_900_000_000;

struct TestDatabase(PathBuf);

impl TestDatabase {
    fn new(name: &str) -> Self {
        Self(std::env::temp_dir().join(format!(
            "session-chat-storage-sqlcipher-opening-{name}-{}.sqlite3",
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
    VaultKey::new([0x73; 32]).expect("nonzero test key")
}

fn open_fixture_connection(path: &std::path::Path) -> Connection {
    let connection = Connection::open(path).expect("fixture database opens");
    connection
        .execute_batch(
            "PRAGMA key = \"x'7373737373737373737373737373737373737373737373737373737373737373'\";",
        )
        .expect("fixture key accepted");
    connection
}

fn downgrade_fixture_to_schema_v4(path: &std::path::Path) {
    let connection = open_fixture_connection(path);
    connection
        .execute_batch(
            "BEGIN EXCLUSIVE;
             DROP TABLE authorization_attempts;
             DROP TABLE invitation_opening_contexts;
             ALTER TABLE storage_metadata RENAME TO storage_metadata_v5;
             CREATE TABLE storage_metadata (
                 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                 schema_version INTEGER NOT NULL CHECK(schema_version = 4),
                 store_id BLOB NOT NULL UNIQUE CHECK(length(store_id) = 16)
             ) STRICT;
             INSERT INTO storage_metadata(singleton, schema_version, store_id)
                 SELECT singleton, 4, store_id FROM storage_metadata_v5;
             DROP TABLE storage_metadata_v5;
             PRAGMA user_version = 4;
             COMMIT;",
        )
        .expect("v4 shape created");
}

#[test]
fn issued_opening_context_is_available_after_close_and_reopen() {
    let database = TestDatabase::new("round-trip");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let issued = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("issuance commits before returning");
    let invitation_id = *issued.invitation().invitation_id();
    let expected = issued
        .invitation()
        .encode_canonical()
        .expect("invitation encodes");
    assert_eq!(
        storage
            .invitation_opening_state(&invitation_id)
            .expect("state lookup"),
        Some(InvitationOpeningState::Available)
    );
    drop(issued);
    drop(storage);

    let reopened = SqlCipherStorage::open(&database.0, vault_key()).expect("storage reopens");
    let restored = reopened
        .load_capability_invitation(&protector, &invitation_id, NOW + 1)
        .expect("valid context reloads")
        .expect("context exists");
    assert_eq!(
        restored
            .invitation()
            .encode_canonical()
            .expect("restored invitation encodes"),
        expected
    );
}

#[test]
fn expired_opening_context_becomes_unusable_and_is_not_returned() {
    let database = TestDatabase::new("expired");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let issued = storage
        .issue_capability_invitation(&protector, NOW, NOW + 2, NOW)
        .expect("issuance commits");
    let invitation_id = *issued.invitation().invitation_id();
    drop(issued);

    assert!(matches!(
        storage.load_capability_invitation(&protector, &invitation_id, NOW + 3),
        Err(StoreError::Rejected)
    ));
    assert_eq!(
        storage
            .invitation_opening_state(&invitation_id)
            .expect("state lookup"),
        Some(InvitationOpeningState::Unusable)
    );
}

#[test]
fn invalid_issuance_time_fails_without_partial_state() {
    let database = TestDatabase::new("invalid-time");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");

    assert!(matches!(
        storage.issue_capability_invitation(&protector, NOW + 1, NOW + 300, NOW),
        Err(StoreError::Rejected)
    ));
}

#[test]
fn mismatched_stored_private_key_terminalizes_and_zeroes_the_context() {
    let database = TestDatabase::new("mismatched-key");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let issued = storage
        .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
        .expect("issuance commits");
    let invitation_id = *issued.invitation().invitation_id();
    drop(issued);
    drop(storage);

    let connection = open_fixture_connection(&database.0);
    connection
        .execute(
            "UPDATE invitation_opening_contexts SET hpke_private_key = ?1
             WHERE invitation_id = ?2",
            params![[0x19_u8; 32], invitation_id],
        )
        .expect("bounded corruption fixture");
    drop(connection);

    let reopened = SqlCipherStorage::open(&database.0, vault_key()).expect("storage reopens");
    assert!(matches!(
        reopened.load_capability_invitation(&protector, &invitation_id, NOW + 1),
        Err(StoreError::Rejected)
    ));
    assert_eq!(
        reopened
            .invitation_opening_state(&invitation_id)
            .expect("state lookup"),
        Some(InvitationOpeningState::Unusable)
    );
    drop(reopened);

    let connection = open_fixture_connection(&database.0);
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

#[test]
fn live_context_capacity_rejects_without_evicting_existing_state() {
    let database = TestDatabase::new("capacity");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let mut invitation_ids = Vec::new();
    for _ in 0..MAXIMUM_LIVE_INVITATION_OPENING_CONTEXTS {
        let issued = storage
            .issue_capability_invitation(&protector, NOW, NOW + 300, NOW)
            .expect("bounded live context issues");
        invitation_ids.push(*issued.invitation().invitation_id());
    }

    assert!(matches!(
        storage.issue_capability_invitation(&protector, NOW, NOW + 300, NOW),
        Err(StoreError::CapacityExceeded)
    ));
    for invitation_id in invitation_ids {
        assert_eq!(
            storage
                .invitation_opening_state(&invitation_id)
                .expect("retained state lookup"),
            Some(InvitationOpeningState::Available)
        );
    }
}

#[test]
fn expired_contexts_are_zeroed_and_compacted_before_new_issuance() {
    let database = TestDatabase::new("expiry-compaction");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    let mut expired_ids = Vec::new();
    for _ in 0..MAXIMUM_LIVE_INVITATION_OPENING_CONTEXTS {
        let issued = storage
            .issue_capability_invitation(&protector, NOW, NOW + 1, NOW)
            .expect("bounded expiring context issues");
        expired_ids.push(*issued.invitation().invitation_id());
    }

    storage
        .issue_capability_invitation(&protector, NOW + 2, NOW + 300, NOW + 2)
        .expect("expired contexts do not permanently exhaust capacity");
    for invitation_id in expired_ids {
        assert_eq!(
            storage
                .invitation_opening_state(&invitation_id)
                .expect("compacted state lookup"),
            None
        );
    }
}

#[test]
fn expired_unusable_contexts_are_compacted_without_touching_live_reservations() {
    let database = TestDatabase::new("unusable-compaction");
    let protector = AwsLcInvitationJoinProtector::new();
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    for _ in 0..MAXIMUM_LIVE_INVITATION_OPENING_CONTEXTS {
        storage
            .issue_capability_invitation(&protector, NOW, NOW + 1, NOW)
            .expect("bounded expiring context issues");
    }
    drop(storage);
    let connection = open_fixture_connection(&database.0);
    connection
        .execute(
            "UPDATE invitation_opening_contexts
             SET state = 4, hpke_private_key = zeroblob(32)",
            [],
        )
        .expect("unusable fixture state");
    drop(connection);

    let reopened = SqlCipherStorage::open(&database.0, vault_key()).expect("storage reopens");
    reopened
        .issue_capability_invitation(&protector, NOW + 2, NOW + 300, NOW + 2)
        .expect("expired unusable contexts do not exhaust live capacity");
}

#[test]
fn schema_v4_shape_migrates_to_v5() {
    let database = TestDatabase::new("migration-v4");
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    drop(storage);
    downgrade_fixture_to_schema_v4(&database.0);

    let migrated = SqlCipherStorage::open(&database.0, vault_key()).expect("v4 migrates");
    assert_eq!(migrated.schema_version().expect("schema version"), 5);
    assert_eq!(
        migrated
            .invitation_opening_state(&[0x51; 16])
            .expect("new table lookup"),
        None
    );
}

#[test]
fn schema_v4_migration_persists_the_requested_nondefault_policy() {
    let database = TestDatabase::new("migration-v4-policy");
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    drop(storage);
    downgrade_fixture_to_schema_v4(&database.0);
    let policy = AuthorizationPolicy::new(2, 3).expect("bounded policy");

    let migrated =
        SqlCipherStorage::open_with_authorization_policy(&database.0, vault_key(), policy)
            .expect("v4 migrates under the requested policy");
    assert_eq!(migrated.schema_version().expect("schema version"), 5);
    drop(migrated);
    assert!(matches!(
        SqlCipherStorage::open(&database.0, vault_key()),
        Err(StoreError::Conflict)
    ));
}

#[test]
fn failed_schema_v4_migration_rolls_back_version_and_metadata() {
    let database = TestDatabase::new("migration-v4-rollback");
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    drop(storage);
    downgrade_fixture_to_schema_v4(&database.0);
    let connection = open_fixture_connection(&database.0);
    connection
        .execute_batch(
            "CREATE TABLE invitation_opening_contexts (
                 fixture INTEGER PRIMARY KEY
             ) STRICT;",
        )
        .expect("conflicting fixture table created");
    drop(connection);

    assert!(SqlCipherStorage::open(&database.0, vault_key()).is_err());
    let connection = open_fixture_connection(&database.0);
    let user_version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("user version");
    let metadata_version: i64 = connection
        .query_row("SELECT schema_version FROM storage_metadata", [], |row| {
            row.get(0)
        })
        .expect("metadata version");
    let renamed_metadata_count: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_master
             WHERE type = 'table' AND name = 'storage_metadata_v4'",
            [],
            |row| row.get(0),
        )
        .expect("renamed metadata count");
    assert_eq!(
        (user_version, metadata_version, renamed_metadata_count),
        (4, 4, 0)
    );
}
