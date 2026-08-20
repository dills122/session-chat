use std::path::PathBuf;

use mls_rs_core::group::GroupStateStorage;
use session_crypto_mls::{
    SessionGroupId, create_client, create_client_with_storage, create_key_package_validator,
};
use storage_sqlcipher::{JoinerTransaction, PersistenceFault, SqlCipherStorage, VaultKey};

const NOW: u64 = 1_900_000_000;

struct TestDatabase(PathBuf);

impl TestDatabase {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "session-chat-storage-sqlcipher-joiner-{}.sqlite3",
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

#[test]
fn actual_joiner_write_atomically_persists_group_and_deletes_one_time_key_package() {
    let database = TestDatabase::new();
    let storage = SqlCipherStorage::create(
        &database.0,
        VaultKey::new([21; 32]).expect("nonzero test key"),
    )
    .expect("storage created");
    let bob = create_client_with_storage(storage.clone(), storage.clone()).expect("Bob client");
    let bob_key_package = bob.generate_key_package(NOW).expect("Bob KeyPackage");
    let validated = create_key_package_validator()
        .validate_key_package(bob_key_package.as_bytes(), NOW)
        .expect("validated KeyPackage");
    let key_package_reference = *validated.key_package_reference();
    assert!(
        storage
            .key_package_exists(&key_package_reference)
            .expect("KeyPackage lookup")
    );

    let alice = create_client().expect("Alice client");
    let mut alice_group = alice
        .create_group(SessionGroupId::new([31; 32]).expect("group id"), NOW)
        .expect("Alice group");
    let welcome = alice_group
        .prepare_add(validated, NOW)
        .expect("prepared Add")
        .apply()
        .expect("applied Add")
        .into_welcome();
    let mut bob_group = bob.join_group(welcome, NOW).expect("Bob joins");

    let failed = JoinerTransaction::new([41; 16], *bob_group.group_id(), key_package_reference)
        .expect("bounded joiner transaction");
    storage
        .stage_joiner(failed, PersistenceFault::BeforeCommit)
        .expect("joiner transaction staged");
    assert!(bob_group.write_to_storage().is_err());
    assert!(
        storage
            .state(bob_group.group_id())
            .expect("group lookup")
            .is_none()
    );
    assert!(
        storage
            .key_package_exists(&key_package_reference)
            .expect("KeyPackage lookup")
    );
    assert!(
        storage
            .recover_joiner(&[41; 16])
            .expect("recovery lookup")
            .is_none()
    );

    let retry = JoinerTransaction::new([41; 16], *bob_group.group_id(), key_package_reference)
        .expect("bounded retry");
    storage
        .stage_joiner(retry, PersistenceFault::AfterCommit)
        .expect("retry staged");
    assert!(bob_group.write_to_storage().is_err());

    assert!(
        storage
            .state(bob_group.group_id())
            .expect("group lookup")
            .is_some()
    );
    assert!(
        !storage
            .key_package_exists(&key_package_reference)
            .expect("KeyPackage lookup")
    );
    let recovered = storage
        .recover_joiner(&[41; 16])
        .expect("recovery lookup")
        .expect("joiner transaction committed");
    assert_eq!(recovered.group_id, *bob_group.group_id());

    let exact_recovery =
        JoinerTransaction::new([41; 16], *bob_group.group_id(), key_package_reference)
            .expect("bounded recovery");
    storage
        .stage_joiner(exact_recovery, PersistenceFault::None)
        .expect("recovery staged");
    bob_group
        .write_to_storage()
        .expect("committed join recovered idempotently");

    drop(bob_group);
    drop(bob);
    drop(storage);
    let reopened = SqlCipherStorage::open(
        &database.0,
        VaultKey::new([21; 32]).expect("nonzero test key"),
    )
    .expect("store reopens");
    assert_eq!(
        reopened
            .recover_joiner(&[41; 16])
            .expect("recovery after reopen"),
        Some(recovered)
    );
    assert!(
        !reopened
            .key_package_exists(&key_package_reference)
            .expect("KeyPackage lookup after reopen")
    );
}
