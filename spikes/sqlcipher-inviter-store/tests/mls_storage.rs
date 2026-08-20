use std::path::PathBuf;

use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
use sqlcipher_inviter_store_spike::{
    CommitFault, InvitationState, JoinCommit, MlsTransactionalStorage, Reservation, SqlCipherStore,
    StoreError, VaultKey,
};
use zeroize::Zeroizing;

const NOW: u64 = 2_000;

struct TestDatabase(PathBuf);

impl TestDatabase {
    fn new(name: &str) -> Self {
        Self(std::env::temp_dir().join(format!(
            "session-chat-sqlcipher-mls-{name}-{}.sqlite3",
            std::process::id()
        )))
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.0.with_extension("sqlite3-journal"));
    }
}

fn key() -> VaultKey {
    VaultKey::new([21; 32]).expect("nonzero test key")
}

fn reservation() -> Reservation {
    Reservation::new([1; 16], [2; 64], [3; 16], NOW + 300).expect("valid reservation")
}

fn commit() -> JoinCommit {
    JoinCommit::new(
        [4; 16],
        [1; 16],
        [2; 64],
        [3; 16],
        [4; 32],
        vec![5; 16],
        7,
        8,
        vec![6; 32],
        vec![7; 512],
        vec![8; 256],
        vec![9; 64],
        NOW + 120,
    )
}

#[test]
fn mls_storage_hook_commits_group_epochs_and_join_rows_together() {
    let database = TestDatabase::new("atomic");
    let mut store = SqlCipherStore::create(&database.0, key()).expect("store created");
    store
        .seed_reservation(&reservation(), NOW)
        .expect("reservation stored");
    let mut storage = MlsTransactionalStorage::new(store);
    storage
        .stage_join(commit(), NOW, CommitFault::BeforeCommit)
        .expect("join staged");

    assert_eq!(
        storage.write(
            GroupState {
                id: vec![5; 16],
                data: Zeroizing::new(vec![7; 512]),
            },
            vec![EpochRecord::new(7, Zeroizing::new(vec![10; 64]))],
            Vec::new(),
        ),
        Err(StoreError::InjectedFailure)
    );
    assert!(storage.state(&[5; 16]).expect("state query").is_none());
    assert!(storage.epoch(&[5; 16], 7).expect("epoch query").is_none());
    assert!(storage.recover(&[4; 16]).expect("join query").is_none());
    assert_eq!(
        storage.invitation_state(&[1; 16]).expect("state query"),
        Some(InvitationState::Reserved)
    );

    storage
        .stage_join(commit(), NOW, CommitFault::None)
        .expect("join restaged");
    storage
        .write(
            GroupState {
                id: vec![5; 16],
                data: Zeroizing::new(vec![7; 512]),
            },
            vec![EpochRecord::new(7, Zeroizing::new(vec![10; 64]))],
            Vec::new(),
        )
        .expect("shared transaction commits");
    assert_eq!(
        storage
            .state(&[5; 16])
            .expect("state query")
            .unwrap()
            .as_slice(),
        &[7; 512]
    );
    assert_eq!(
        storage
            .epoch(&[5; 16], 7)
            .expect("epoch query")
            .unwrap()
            .as_slice(),
        &[10; 64]
    );
    assert!(storage.recover(&[4; 16]).expect("join query").is_some());
    assert_eq!(storage.max_epoch_id(&[5; 16]).expect("max epoch"), Some(7));
}
