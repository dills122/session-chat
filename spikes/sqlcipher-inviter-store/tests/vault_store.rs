use std::path::PathBuf;

use sqlcipher_inviter_store_spike::{
    CommitFault, CommitOutcome, InvitationState, JoinCommit, OutboxState, Reservation,
    SqlCipherStore, StoreError, VaultKey,
};

const NOW: u64 = 1_000;

struct TestDatabase(PathBuf);

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.0.with_extension("sqlite3-journal"));
        let _ = std::fs::remove_file(self.0.with_extension("sqlite3-wal"));
        let _ = std::fs::remove_file(self.0.with_extension("sqlite3-shm"));
    }
}

fn temporary_database(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "session-chat-sqlcipher-{name}-{}-{}.sqlite3",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ))
}

fn key() -> VaultKey {
    VaultKey::new([7; 32]).expect("nonzero test key")
}

fn reservation() -> Reservation {
    Reservation::new([1; 16], [2; 64], [3; 16], NOW + 300).expect("valid reservation")
}

fn join_commit(request_fingerprint: u8) -> JoinCommit {
    JoinCommit::new(
        [4; 16],
        [1; 16],
        [2; 64],
        [3; 16],
        [request_fingerprint; 32],
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
fn raw_vault_key_creates_encrypted_database_and_wrong_key_fails_closed() {
    let database = TestDatabase(temporary_database("wrong-key"));
    let path = &database.0;
    let key = VaultKey::new([7; 32]).expect("nonzero test key");
    let store = SqlCipherStore::create(path, key).expect("encrypted store created");

    assert!(!store.cipher_version().expect("cipher version").is_empty());
    drop(store);

    let wrong_key = VaultKey::new([8; 32]).expect("nonzero wrong key");
    assert!(SqlCipherStore::open(path, wrong_key).is_err());

    let reopened =
        SqlCipherStore::open(path, VaultKey::new([7; 32]).expect("same nonzero test key"))
            .expect("correct raw key reopens database");
    assert!(reopened.integrity_check().expect("integrity check"));
}

#[test]
fn precommit_failure_rolls_back_every_join_component() {
    let database = TestDatabase(temporary_database("rollback"));
    let mut store = SqlCipherStore::create(&database.0, key()).expect("store created");
    store
        .seed_reservation(&reservation(), NOW)
        .expect("reservation stored");

    assert_eq!(
        store.commit_join(&join_commit(10), NOW, CommitFault::BeforeCommit),
        Err(StoreError::InjectedFailure)
    );
    assert_eq!(
        store.invitation_state(&[1; 16]).expect("state query"),
        Some(InvitationState::Reserved)
    );
    assert!(store.recover(&[4; 16]).expect("recovery query").is_none());
    drop(store);

    let reopened = SqlCipherStore::open(&database.0, key()).expect("store reopens");
    assert_eq!(
        reopened.invitation_state(&[1; 16]).expect("state query"),
        Some(InvitationState::Reserved)
    );
    assert!(
        reopened
            .recover(&[4; 16])
            .expect("recovery query")
            .is_none()
    );
}

#[test]
fn lost_commit_response_recovers_complete_join_and_exact_retry() {
    let database = TestDatabase(temporary_database("ambiguous"));
    let mut store = SqlCipherStore::create(&database.0, key()).expect("store created");
    store
        .seed_reservation(&reservation(), NOW)
        .expect("reservation stored");
    let exact = join_commit(10);

    assert_eq!(
        store.commit_join(&exact, NOW, CommitFault::AfterCommit),
        Err(StoreError::OutcomeUnknown)
    );
    drop(store);

    let mut reopened = SqlCipherStore::open(&database.0, key()).expect("store reopens");
    let recovered = reopened
        .recover(&[4; 16])
        .expect("recovery query")
        .expect("commit exists");
    assert_eq!(recovered.epoch_after, 8);
    assert_eq!(recovered.outbox_state, OutboxState::Pending);
    assert_eq!(recovered.delivery_attempts, 0);
    assert_eq!(
        reopened.invitation_state(&[1; 16]).expect("state query"),
        Some(InvitationState::Consumed)
    );
    assert_eq!(
        reopened.commit_join(&exact, NOW, CommitFault::None),
        Ok(CommitOutcome::AlreadyCommitted)
    );
    assert_eq!(
        reopened.commit_join(&join_commit(99), NOW, CommitFault::None),
        Err(StoreError::Conflict)
    );
}
