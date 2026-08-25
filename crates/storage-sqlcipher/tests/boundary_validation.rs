use std::path::PathBuf;

use mls_rs_core::{
    crypto::HpkeSecretKey,
    group::GroupStateStorage,
    key_package::{KeyPackageData, KeyPackageStorage},
};
use storage_sqlcipher::{
    InviterJoinTransaction, JoinerTransaction, PersistenceFault, SqlCipherStorage, StoreError,
    VaultKey,
};

const NOW: u64 = 1_900_000_000;

struct TestDatabase(PathBuf);

impl TestDatabase {
    fn new(name: &str) -> Self {
        Self(std::env::temp_dir().join(format!(
            "session-chat-storage-sqlcipher-boundary-{name}-{}.sqlite3",
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

fn create_storage(name: &str) -> (TestDatabase, SqlCipherStorage) {
    let database = TestDatabase::new(name);
    let storage = SqlCipherStorage::create(
        &database.0,
        VaultKey::new([0x55; 32]).expect("nonzero test key"),
    )
    .expect("storage created");
    (database, storage)
}

fn inviter_transaction(transaction_id: u8) -> InviterJoinTransaction {
    InviterJoinTransaction::new(
        [transaction_id; 16],
        [2; 16],
        [3; 64],
        [4; 16],
        [5; 32],
        [6; 32],
        0,
        1,
        vec![7],
        vec![8],
        vec![9],
        NOW + 60,
    )
    .expect("bounded inviter transaction")
}

#[test]
fn public_identifiers_and_time_bounds_fail_before_storage_mutation() {
    assert!(matches!(VaultKey::new([0; 32]), Err(StoreError::Rejected)));
    assert!(matches!(
        JoinerTransaction::new([0; 16], [1; 32], [2; 32]),
        Err(StoreError::Rejected)
    ));
    assert!(matches!(
        InviterJoinTransaction::new(
            [1; 16],
            [2; 16],
            [3; 64],
            [4; 16],
            [5; 32],
            [6; 32],
            1,
            1,
            vec![7],
            vec![8],
            vec![9],
            NOW + 60,
        ),
        Err(StoreError::Rejected)
    ));

    let (_database, storage) = create_storage("public-bounds");
    assert_eq!(
        storage.seed_reservation([1; 16], [2; 64], [3; 16], NOW, NOW),
        Err(StoreError::Rejected)
    );
    assert_eq!(storage.invitation_state(&[1; 16]).expect("lookup"), None);
}

#[test]
fn absent_reads_and_oversized_storage_inputs_are_bounded() {
    let (_database, storage) = create_storage("read-bounds");
    let group_id = [0x44; 32];

    assert!(storage.state(&group_id).expect("state lookup").is_none());
    assert!(storage.epoch(&group_id, 7).expect("epoch lookup").is_none());
    assert_eq!(
        storage.epoch(&group_id, u64::MAX),
        Err(StoreError::Rejected)
    );
    assert_eq!(storage.max_epoch_id(&group_id).expect("max epoch"), None);

    let mut key_packages = storage.clone();
    let package = KeyPackageData::new(
        vec![1],
        HpkeSecretKey::from(vec![2]),
        HpkeSecretKey::from(vec![3]),
        NOW,
    );
    assert_eq!(
        key_packages.insert(vec![4; 31], package),
        Err(StoreError::Rejected)
    );
    assert!(matches!(
        key_packages.get(&[5; 31]),
        Err(StoreError::Rejected)
    ));
    assert_eq!(key_packages.delete(&[6; 31]), Err(StoreError::Rejected));
    assert!(!storage.key_package_exists(&[7; 32]).expect("lookup"));
}

#[test]
fn only_one_owner_transaction_can_be_staged_at_a_time() {
    let (_database, storage) = create_storage("staging-conflict");
    storage
        .stage_inviter(inviter_transaction(1), NOW, PersistenceFault::None)
        .expect("first transaction staged");
    assert_eq!(
        storage.stage_inviter(inviter_transaction(10), NOW, PersistenceFault::None),
        Err(StoreError::Conflict)
    );
    assert_eq!(
        storage.stage_joiner(
            JoinerTransaction::new([11; 16], [12; 32], [13; 32]).expect("joiner transaction"),
            PersistenceFault::None,
        ),
        Err(StoreError::Conflict)
    );

    let (_database, storage) = create_storage("joiner-staging-conflict");
    storage
        .stage_joiner(
            JoinerTransaction::new([21; 16], [22; 32], [23; 32]).expect("joiner transaction"),
            PersistenceFault::None,
        )
        .expect("first joiner transaction staged");
    assert_eq!(
        storage.stage_joiner(
            JoinerTransaction::new([31; 16], [32; 32], [33; 32]).expect("joiner transaction"),
            PersistenceFault::None,
        ),
        Err(StoreError::Conflict)
    );
}
