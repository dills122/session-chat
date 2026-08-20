#![forbid(unsafe_code)]

//! Disposable SQLCipher compatibility experiment for inviter-owned state.

use std::path::Path;

use rusqlite::{Connection, OpenFlags};
use thiserror::Error;
use zeroize::Zeroize;

/// Exact raw key released only while the client vault is unsealed.
pub struct VaultKey([u8; 32]);

impl VaultKey {
    /// Accepts a nonzero 256-bit raw database key.
    pub fn new(key: [u8; 32]) -> Result<Self, StoreError> {
        if key.iter().all(|byte| *byte == 0) {
            return Err(StoreError::Rejected);
        }
        Ok(Self(key))
    }

    fn raw_key_pragma(&self) -> String {
        let mut hex = String::with_capacity(64);
        for byte in self.0 {
            use std::fmt::Write as _;
            write!(&mut hex, "{byte:02X}").expect("writing to a String cannot fail");
        }
        // SQLCipher requires this exact BLOB-literal wrapper for raw key data.
        // Every interpolated character is generated from the fixed hex alphabet.
        format!("PRAGMA key = \"x'{hex}'\";")
    }
}

impl Drop for VaultKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Coarse failure from the disposable storage boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StoreError {
    /// The key, database, configuration, or integrity check was rejected.
    #[error("encrypted store operation rejected")]
    Rejected,
}

impl From<rusqlite::Error> for StoreError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Rejected
    }
}

/// Keyed SQLCipher connection owned only while the vault is unsealed.
pub struct SqlCipherStore {
    connection: Connection,
}

impl SqlCipherStore {
    /// Creates or initializes one encrypted spike database.
    pub fn create(path: &Path, key: VaultKey) -> Result<Self, StoreError> {
        Self::open_internal(path, key, true)
    }

    /// Opens an existing encrypted spike database.
    pub fn open(path: &Path, key: VaultKey) -> Result<Self, StoreError> {
        Self::open_internal(path, key, false)
    }

    /// Returns the active SQLCipher version, rejecting plaintext SQLite builds.
    pub fn cipher_version(&self) -> Result<String, StoreError> {
        self.connection
            .query_row("PRAGMA cipher_version;", [], |row| row.get(0))
            .map_err(Into::into)
    }

    /// Runs SQLCipher's independent per-page HMAC verification.
    pub fn integrity_check(&self) -> Result<bool, StoreError> {
        let mut statement = self.connection.prepare("PRAGMA cipher_integrity_check;")?;
        let mut rows = statement.query([])?;
        Ok(rows.next()?.is_none())
    }

    fn open_internal(path: &Path, key: VaultKey, create: bool) -> Result<Self, StoreError> {
        let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        if create {
            flags |= OpenFlags::SQLITE_OPEN_CREATE;
        }
        let connection = Connection::open_with_flags(path, flags)?;

        // Source: https://www.zetetic.net/sqlcipher/sqlcipher-api/#pragma-key
        connection.execute_batch(&key.raw_key_pragma())?;
        connection.execute_batch("PRAGMA cipher_memory_security = ON;")?;

        // SQLCipher defers key validation until the first page read.
        let _: i64 =
            connection.query_row("SELECT count(*) FROM sqlite_master;", [], |row| row.get(0))?;
        let cipher_version: String =
            connection.query_row("PRAGMA cipher_version;", [], |row| row.get(0))?;
        if cipher_version.is_empty() {
            return Err(StoreError::Rejected);
        }

        connection.execute_batch(
            "PRAGMA journal_mode = DELETE;
             PRAGMA synchronous = FULL;
             PRAGMA temp_store = MEMORY;
             PRAGMA secure_delete = ON;
             PRAGMA trusted_schema = OFF;
             PRAGMA foreign_keys = ON;",
        )?;
        if create {
            connection.execute_batch(
                "CREATE TABLE IF NOT EXISTS spike_metadata (
                     schema_version INTEGER NOT NULL CHECK (schema_version = 1)
                 ) STRICT;
                 INSERT INTO spike_metadata(schema_version)
                 SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM spike_metadata);",
            )?;
        }
        Ok(Self { connection })
    }
}
