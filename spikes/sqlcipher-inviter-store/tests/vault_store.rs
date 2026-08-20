use std::path::PathBuf;

use sqlcipher_inviter_store_spike::{SqlCipherStore, VaultKey};

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

#[test]
fn raw_vault_key_creates_encrypted_database_and_wrong_key_fails_closed() {
    let database = TestDatabase(temporary_database("wrong-key"));
    let path = &database.0;
    let key = VaultKey::new([7; 32]).expect("nonzero test key");
    let store = SqlCipherStore::create(&path, key).expect("encrypted store created");

    assert!(!store.cipher_version().expect("cipher version").is_empty());
    drop(store);

    let wrong_key = VaultKey::new([8; 32]).expect("nonzero wrong key");
    assert!(SqlCipherStore::open(&path, wrong_key).is_err());

    let reopened = SqlCipherStore::open(
        &path,
        VaultKey::new([7; 32]).expect("same nonzero test key"),
    )
    .expect("correct raw key reopens database");
    assert!(reopened.integrity_check().expect("integrity check"));
}
