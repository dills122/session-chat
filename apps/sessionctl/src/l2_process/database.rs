//! SQLCipher connection, schema, and evidence artifact inspection.

use super::*;

pub(super) fn verify_connection_configuration(
    connection: &Connection,
) -> Result<(), SessionCtlError> {
    let journal: String = connection
        .query_row("PRAGMA journal_mode;", [], |row| row.get(0))
        .map_err(|_| stage("L2 configuration"))?;
    let values = [
        pragma_i64(connection, "PRAGMA synchronous;")?,
        pragma_i64(connection, "PRAGMA temp_store;")?,
        pragma_i64(connection, "PRAGMA secure_delete;")?,
        pragma_i64(connection, "PRAGMA trusted_schema;")?,
        pragma_i64(connection, "PRAGMA foreign_keys;")?,
    ];
    if journal != "delete" || values != [2, 2, 1, 0, 1] {
        return Err(stage("L2 configuration"));
    }
    Ok(())
}

pub(super) fn pragma_i64(connection: &Connection, pragma: &str) -> Result<i64, SessionCtlError> {
    connection
        .query_row(pragma, [], |row| row.get(0))
        .map_err(|_| stage("L2 configuration"))
}

pub(super) fn schema_fingerprint(connection: &Connection) -> Result<String, SessionCtlError> {
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name, coalesce(sql, '') FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )
        .map_err(|_| stage("L2 schema"))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|_| stage("L2 schema"))?;
    let mut canonical = Vec::new();
    for row in rows {
        let (kind, name, table, sql) = row.map_err(|_| stage("L2 schema"))?;
        for field in [kind, name, table, sql] {
            canonical.extend_from_slice(field.as_bytes());
            canonical.push(0);
        }
        canonical.push(b'\n');
    }
    Ok(hex(digest(&SHA256, &canonical).as_ref()))
}

pub(super) struct L2ArtifactSnapshot {
    pub(super) digest: [u8; 32],
    pub(super) bytes: Vec<u8>,
}

pub(super) fn encrypted_artifact_snapshot(
    root: &Path,
) -> Result<L2ArtifactSnapshot, SessionCtlError> {
    let mut canonical = Vec::new();
    let mut artifact_bytes = Vec::new();
    let mut found_database = false;
    for name in [
        DATABASE_NAME,
        "case.sqlite3-journal",
        "case.sqlite3-wal",
        "case.sqlite3-shm",
    ] {
        let path = root.join(name);
        if !path.exists() {
            continue;
        }
        validate_owned_file(&path, None)?;
        let bytes = read_bounded_repository_file(&path, MAX_DATABASE_BYTES)
            .ok_or_else(|| stage("L2 encrypted artifact"))?;
        if name == DATABASE_NAME {
            found_database = true;
        }
        if artifact_bytes.len().saturating_add(bytes.len()) > MAX_DATABASE_BYTES {
            return Err(stage("L2 encrypted artifact bound"));
        }
        canonical.extend_from_slice(name.as_bytes());
        canonical.push(0);
        canonical.extend_from_slice(
            &u64::try_from(bytes.len())
                .map_err(|_| stage("L2 encrypted artifact"))?
                .to_be_bytes(),
        );
        canonical.extend_from_slice(&bytes);
        artifact_bytes.extend_from_slice(&bytes);
    }
    if !found_database || canonical.is_empty() {
        return Err(stage("L2 encrypted artifact"));
    }
    Ok(L2ArtifactSnapshot {
        digest: digest(&SHA256, &canonical)
            .as_ref()
            .try_into()
            .map_err(|_| stage("L2 encrypted artifact"))?,
        bytes: artifact_bytes,
    })
}

pub(super) fn collect_evidence_binding(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    fixture: &CaseFixture,
    welcome_canary: Option<&[u8]>,
    baseline: L2ArtifactSnapshot,
    surfaces: &[&[u8]],
) -> Result<L2EvidenceBinding, SessionCtlError> {
    let post_recovery = encrypted_artifact_snapshot(root)?;
    let connection = open_keyed_connection(&root.join(DATABASE_NAME), key)?;
    let sqlcipher_version: String = connection
        .query_row("PRAGMA cipher_version;", [], |row| row.get(0))
        .map_err(|_| stage("L2 evidence SQLCipher version"))?;
    let sqlite_version: String = connection
        .query_row("SELECT sqlite_version();", [], |row| row.get(0))
        .map_err(|_| stage("L2 evidence SQLite version"))?;
    drop(connection);
    let mut scanned = Vec::with_capacity(surfaces.len() + 2);
    scanned.extend_from_slice(surfaces);
    scanned.push(baseline.bytes.as_slice());
    scanned.push(post_recovery.bytes.as_slice());
    let endpoint = fixture_endpoint()?;
    let mut secrets = vec![
        key.as_slice(),
        fixture.invitation_id.as_slice(),
        fixture.invitation_generation.as_slice(),
        fixture.join_request_id.as_slice(),
        fixture.request_fingerprint.as_slice(),
        fixture.transaction_id.as_slice(),
        fixture.group_id.as_slice(),
        fixture.key_package_reference.as_slice(),
        fixture.credential_identity.as_slice(),
        APPROVAL_RECORD,
        endpoint.as_slice(),
    ];
    if let Some(welcome) = welcome_canary {
        secrets.push(welcome);
    }
    evidence::scan_secret_values(scanned, secrets)?;
    Ok(L2EvidenceBinding {
        executables: None,
        sqlcipher_version,
        sqlite_version,
        baseline_artifact_digest: baseline.digest,
        post_recovery_artifact_digest: post_recovery.digest,
        redaction: true,
    })
}

pub(super) fn prove_database_handle_cleanup(root: &Path) -> Result<bool, SessionCtlError> {
    let database = root.join(DATABASE_NAME);
    let guard = root.join("case.handle-guard");
    fs::rename(&database, &guard).map_err(|_| stage("L2 handle cleanup"))?;
    fs::rename(&guard, &database).map_err(|_| stage("L2 handle cleanup"))?;
    Ok(true)
}

pub(super) fn table_count(connection: &Connection, table: &str) -> Result<i64, SessionCtlError> {
    let sql = match table {
        "reservations" => "SELECT count(*) FROM reservations",
        "inviter_joins" => "SELECT count(*) FROM inviter_joins",
        "mls_groups" => "SELECT count(*) FROM mls_groups",
        "mls_epochs" => "SELECT count(*) FROM mls_epochs",
        "key_packages" => "SELECT count(*) FROM key_packages",
        "joiner_commits" => "SELECT count(*) FROM joiner_commits",
        "mls_client_identity" => "SELECT count(*) FROM mls_client_identity",
        _ => return Err(stage("L2 semantic table")),
    };
    connection
        .query_row(sql, [], |row| row.get(0))
        .map_err(|_| stage("L2 semantic oracle"))
}

pub(super) fn open_keyed_connection(
    path: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
) -> Result<Connection, SessionCtlError> {
    validate_owned_file(path, None)?;
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| stage("L2 verifier open"))?;
    let mut pragma = Zeroizing::new(String::from("PRAGMA key = \"x'"));
    for byte in key.iter() {
        write!(&mut pragma, "{byte:02X}").map_err(|_| stage("L2 verifier key"))?;
    }
    pragma.push_str("'\";");
    connection
        .execute_batch(&pragma)
        .map_err(|_| stage("L2 verifier key"))?;
    pragma.zeroize();
    let _: i64 = connection
        .query_row("SELECT count(*) FROM sqlite_master;", [], |row| row.get(0))
        .map_err(|_| stage("L2 verifier key"))?;
    let cipher_version: String = connection
        .query_row("PRAGMA cipher_version;", [], |row| row.get(0))
        .map_err(|_| stage("L2 verifier cipher"))?;
    if cipher_version.is_empty() {
        return Err(stage("L2 verifier cipher"));
    }
    connection
        .execute_batch(
            "PRAGMA journal_mode = DELETE;
             PRAGMA synchronous = FULL;
             PRAGMA temp_store = MEMORY;
             PRAGMA secure_delete = ON;
             PRAGMA trusted_schema = OFF;
             PRAGMA foreign_keys = ON;",
        )
        .map_err(|_| stage("L2 verifier configuration"))?;
    Ok(connection)
}
