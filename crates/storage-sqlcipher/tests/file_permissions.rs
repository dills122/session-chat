#![cfg(unix)]

use std::{
    ffi::OsString,
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    process::Command,
};

use rusqlite::Connection;
use storage_sqlcipher::{SqlCipherStorage, VaultKey};
use test_private_dir::TestDatabase;

const CHILD: &str = "SESSION_CHAT_STORAGE_PERMISSION_TEST_CHILD";
const DATABASE_PATH: &str = "SESSION_CHAT_STORAGE_PERMISSION_TEST_DATABASE";

fn sidecar_path(path: &std::path::Path, suffix: &str) -> PathBuf {
    let mut value = OsString::from(path.as_os_str());
    value.push(suffix);
    PathBuf::from(value)
}

#[test]
fn vault_and_journal_are_owner_only_under_permissive_umask() {
    if std::env::var_os(CHILD).is_none() {
        let database = TestDatabase::new("permissions");
        let executable = std::env::current_exe().expect("test executable");
        let status = Command::new("sh")
            .args(["-c", "umask 000; exec \"$@\"", "sh"])
            .arg(executable)
            .args([
                "--exact",
                "vault_and_journal_are_owner_only_under_permissive_umask",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env(DATABASE_PATH, &database.0)
            .status()
            .expect("permission child runs");
        assert!(status.success());
        return;
    }

    let path = PathBuf::from(std::env::var_os(DATABASE_PATH).expect("database path supplied"));
    let storage =
        SqlCipherStorage::create(&path, VaultKey::new([0x91; 32]).expect("nonzero test key"))
            .expect("storage created");
    assert_eq!(
        fs::metadata(&path)
            .expect("database metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let connection = Connection::open(&path).expect("probe connection opens");
    connection
        .execute_batch(
            "PRAGMA key = \"x'9191919191919191919191919191919191919191919191919191919191919191'\";
             BEGIN IMMEDIATE;
             CREATE TABLE permission_probe(value INTEGER);",
        )
        .expect("probe transaction opens");
    let journal = sidecar_path(&path, "-journal");
    assert_eq!(
        fs::metadata(journal)
            .expect("live journal metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    connection
        .execute_batch("ROLLBACK;")
        .expect("probe transaction rolls back");
    drop(connection);
    drop(storage);
}

#[test]
fn opening_an_existing_vault_tightens_its_mode_before_sqlcipher_access() {
    let database = TestDatabase::new("existing-permissions");
    let storage = SqlCipherStorage::create(
        &database.0,
        VaultKey::new([0x92; 32]).expect("nonzero test key"),
    )
    .expect("storage created");
    drop(storage);
    fs::set_permissions(&database.0, fs::Permissions::from_mode(0o644))
        .expect("fixture made permissive");

    let reopened = SqlCipherStorage::open(
        &database.0,
        VaultKey::new([0x92; 32]).expect("nonzero test key"),
    )
    .expect("storage reopened");
    assert_eq!(
        fs::metadata(&database.0)
            .expect("database metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    drop(reopened);
}

#[test]
fn creation_rejects_a_preexisting_symlink_without_touching_its_target() {
    let database = TestDatabase::new("symlink-collision");
    let target = database.0.parent().expect("private parent").join("target");
    fs::write(&target, b"unchanged").expect("target created");
    symlink(&target, &database.0).expect("database symlink created");

    assert!(
        SqlCipherStorage::create(
            &database.0,
            VaultKey::new([0x93; 32]).expect("nonzero test key"),
        )
        .is_err()
    );
    assert_eq!(fs::read(target).expect("target readable"), b"unchanged");
}

#[test]
fn opening_a_vault_through_a_symlink_fails_closed() {
    let database = TestDatabase::new("open-symlink");
    let storage = SqlCipherStorage::create(
        &database.0,
        VaultKey::new([0x94; 32]).expect("nonzero test key"),
    )
    .expect("storage created");
    drop(storage);
    let link = database
        .0
        .parent()
        .expect("private parent")
        .join("vault-link");
    symlink(&database.0, &link).expect("database symlink created");

    assert!(
        SqlCipherStorage::open(&link, VaultKey::new([0x94; 32]).expect("nonzero test key"),)
            .is_err()
    );
}

#[test]
fn opening_rejects_a_symlinked_sidecar_without_touching_its_target() {
    let database = TestDatabase::new("sidecar-symlink");
    let storage = SqlCipherStorage::create(
        &database.0,
        VaultKey::new([0x95; 32]).expect("nonzero test key"),
    )
    .expect("storage created");
    drop(storage);
    let target = database
        .0
        .parent()
        .expect("private parent")
        .join("sidecar-target");
    fs::write(&target, b"unchanged").expect("sidecar target created");
    symlink(&target, sidecar_path(&database.0, "-journal")).expect("sidecar symlink created");

    assert!(
        SqlCipherStorage::open(
            &database.0,
            VaultKey::new([0x95; 32]).expect("nonzero test key"),
        )
        .is_err()
    );
    assert_eq!(fs::read(target).expect("target readable"), b"unchanged");
}
