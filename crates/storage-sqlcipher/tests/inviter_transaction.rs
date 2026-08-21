use std::{
    path::PathBuf,
    sync::{Arc, Barrier},
};

use mls_rs_core::group::GroupStateStorage;
use session_crypto_mls::{
    SessionGroupId, create_client, create_client_with_storage, create_key_package_validator,
};
use storage_sqlcipher::{
    InvitationState, InviterJoinTransaction, PersistenceFault, SqlCipherStorage, VaultKey,
};

const NOW: u64 = 1_900_000_000;

struct TestDatabase(PathBuf);

impl TestDatabase {
    fn new(name: &str) -> Self {
        Self(std::env::temp_dir().join(format!(
            "session-chat-storage-sqlcipher-inviter-{name}-{}.sqlite3",
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
    VaultKey::new([7; 32]).expect("nonzero test key")
}

#[test]
fn keyed_database_rejects_wrong_key_and_closed_file_hides_fixture_plaintext() {
    let database = TestDatabase::new("keying");
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    assert!(!storage.cipher_version().expect("cipher version").is_empty());
    storage
        .seed_reservation([11; 16], [12; 64], [13; 16], NOW + 300, NOW)
        .expect("reservation stored");
    assert!(storage.integrity_check().expect("integrity check"));
    drop(storage);

    assert!(SqlCipherStorage::open(&database.0, VaultKey::new([9; 32]).expect("key")).is_err());
    let bytes = std::fs::read(&database.0).expect("closed database readable");
    assert!(!bytes.windows(64).any(|window| window == [12; 64]));
    assert!(
        !bytes
            .windows(b"SQLite format 3".len())
            .any(|window| window == b"SQLite format 3")
    );

    let reopened = SqlCipherStorage::open(&database.0, vault_key()).expect("correct key reopens");
    assert_eq!(
        reopened
            .invitation_state(&[11; 16])
            .expect("invitation lookup"),
        Some(InvitationState::Reserved)
    );
}

#[test]
fn concurrent_stores_serialize_the_process_global_provider_lifecycle() {
    let barrier = Arc::new(Barrier::new(3));
    let first_barrier = Arc::clone(&barrier);
    let second_barrier = Arc::clone(&barrier);

    let first = std::thread::spawn(move || {
        exercise_parallel_store("parallel-a", 21, first_barrier);
    });
    let second = std::thread::spawn(move || {
        exercise_parallel_store("parallel-b", 31, second_barrier);
    });

    barrier.wait();
    first.join().expect("first SQLCipher worker completed");
    second.join().expect("second SQLCipher worker completed");
}

fn exercise_parallel_store(name: &str, key_byte: u8, barrier: Arc<Barrier>) {
    let database = TestDatabase::new(name);
    let key = || VaultKey::new([key_byte; 32]).expect("nonzero parallel test key");
    barrier.wait();

    let storage = SqlCipherStorage::create(&database.0, key()).expect("parallel store created");
    storage
        .seed_reservation(
            [key_byte; 16],
            [key_byte.wrapping_add(1); 64],
            [key_byte.wrapping_add(2); 16],
            NOW + 300,
            NOW,
        )
        .expect("parallel reservation stored");
    assert!(storage.integrity_check().expect("parallel integrity check"));
    drop(storage);

    assert!(
        SqlCipherStorage::open(
            &database.0,
            VaultKey::new([key_byte.wrapping_add(3); 32]).expect("wrong parallel key"),
        )
        .is_err()
    );
    let reopened = SqlCipherStorage::open(&database.0, key()).expect("parallel store reopens");
    assert_eq!(
        reopened
            .invitation_state(&[key_byte; 16])
            .expect("parallel invitation lookup"),
        Some(InvitationState::Reserved)
    );
}

#[test]
fn actual_inviter_mls_write_is_atomic_with_join_and_welcome_outbox_state() {
    let database = TestDatabase::new("atomic");
    let storage = SqlCipherStorage::create(&database.0, vault_key()).expect("storage created");
    storage
        .seed_reservation([1; 16], [2; 64], [3; 16], NOW + 300, NOW)
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
    let transaction = InviterJoinTransaction::new(
        [4; 16],
        [1; 16],
        [2; 64],
        [3; 16],
        [6; 32],
        *alice_group.group_id(),
        0,
        1,
        vec![7; 32],
        addition.welcome().as_bytes().to_vec(),
        vec![8; 64],
        NOW + 120,
    )
    .expect("bounded transaction");

    storage
        .stage_inviter(transaction, NOW, PersistenceFault::BeforeCommit)
        .expect("transaction staged");
    assert!(alice_group.write_to_storage().is_err());
    assert!(
        storage
            .state(alice_group.group_id())
            .expect("group lookup")
            .is_none()
    );
    assert_eq!(
        storage
            .invitation_state(&[1; 16])
            .expect("invitation lookup"),
        Some(InvitationState::Reserved)
    );
    assert!(
        storage
            .recover_inviter(&[4; 16])
            .expect("recovery lookup")
            .is_none()
    );

    let retry = InviterJoinTransaction::new(
        [4; 16],
        [1; 16],
        [2; 64],
        [3; 16],
        [6; 32],
        *alice_group.group_id(),
        0,
        1,
        vec![7; 32],
        addition.welcome().as_bytes().to_vec(),
        vec![8; 64],
        NOW + 120,
    )
    .expect("bounded retry");
    storage
        .stage_inviter(retry, NOW, PersistenceFault::None)
        .expect("retry staged");
    alice_group
        .write_to_storage()
        .expect("shared transaction committed");

    assert!(
        storage
            .state(alice_group.group_id())
            .expect("group lookup")
            .is_some()
    );
    assert_eq!(
        storage
            .invitation_state(&[1; 16])
            .expect("invitation lookup"),
        Some(InvitationState::Consumed)
    );
    let recovered = storage
        .recover_inviter(&[4; 16])
        .expect("recovery lookup")
        .expect("transaction committed");
    assert_eq!(recovered.epoch_after, 1);
    assert!(recovered.welcome_pending);

    drop(alice_group);
    drop(alice);
    drop(storage);
    let reopened = SqlCipherStorage::open(&database.0, vault_key()).expect("store reopens");
    assert_eq!(
        reopened
            .recover_inviter(&[4; 16])
            .expect("recovery after reopen"),
        Some(recovered)
    );
}
