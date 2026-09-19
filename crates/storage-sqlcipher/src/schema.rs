//! Schema creation, migrations, and connection invariants for the SQLCipher store.

use rusqlite::{Connection, params};
use session_crypto_mls::SESSION_GROUP_ID_BYTES;

use super::{
    AUTHORIZATION_ABANDONED, AUTHORIZATION_APPROVED_PENDING_MEMBERSHIP, AUTHORIZATION_COMMITTED,
    AUTHORIZATION_MEMBERSHIP_OUTCOME_UNKNOWN, AUTHORIZATION_PENDING_APPROVAL, AuthorizationPolicy,
    OPENING_AVAILABLE, OPENING_CONSUMED, OPENING_RESERVED, OPENING_UNUSABLE, SCHEMA_VERSION,
    STORE_ID_BYTES, StoreError, all_zero, random_nonzero_identifier, rollback,
    validate_delivery_material,
};

pub(super) fn create_schema(
    connection: &Connection,
    authorization_policy: AuthorizationPolicy,
) -> Result<(), StoreError> {
    let store_id = random_nonzero_identifier(connection)?;
    connection.execute_batch(
        "BEGIN IMMEDIATE;
         CREATE TABLE storage_metadata (
             singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
             schema_version INTEGER NOT NULL CHECK(schema_version = 6),
             store_id BLOB NOT NULL UNIQUE CHECK(length(store_id) = 16),
             maximum_live_invitations INTEGER NOT NULL
                 CHECK(maximum_live_invitations BETWEEN 1 AND 8),
             maximum_live_authorization_attempts INTEGER NOT NULL
                 CHECK(maximum_live_authorization_attempts BETWEEN 1 AND 8),
             maximum_retained_attempts_per_generation INTEGER NOT NULL
                 CHECK(maximum_retained_attempts_per_generation BETWEEN 1 AND 8),
             maximum_total_authorization_attempts INTEGER NOT NULL
                 CHECK(maximum_total_authorization_attempts BETWEEN 1 AND 64)
         ) STRICT;

         CREATE TABLE reservations (
             invitation_id BLOB PRIMARY KEY CHECK(length(invitation_id) = 16),
             generation BLOB NOT NULL CHECK(length(generation) = 64),
             join_request_id BLOB NOT NULL CHECK(length(join_request_id) = 16),
             expires_at INTEGER NOT NULL CHECK(expires_at > 0),
             state INTEGER NOT NULL CHECK(state IN (1, 2))
         ) STRICT;

         CREATE TABLE authorization_attempts (
             attempt_id BLOB PRIMARY KEY CHECK(length(attempt_id) = 16),
             invitation_id BLOB NOT NULL REFERENCES invitation_opening_contexts(invitation_id),
             generation BLOB NOT NULL CHECK(length(generation) = 64),
             invitation_challenge BLOB NOT NULL CHECK(length(invitation_challenge) = 32),
             join_request_id BLOB NOT NULL CHECK(length(join_request_id) = 16),
             request_nonce BLOB NOT NULL CHECK(length(request_nonce) = 32),
             intended_verifier BLOB NOT NULL CHECK(length(intended_verifier) = 32),
             key_package_reference BLOB NOT NULL CHECK(length(key_package_reference) = 32),
             mls_protocol_version INTEGER NOT NULL CHECK(mls_protocol_version = 1),
             mls_ciphersuite INTEGER NOT NULL CHECK(mls_ciphersuite = 1),
             credential_type INTEGER NOT NULL CHECK(credential_type = 1),
             credential_identity BLOB NOT NULL CHECK(length(credential_identity) = 32),
             leaf_signature_key BLOB NOT NULL CHECK(length(leaf_signature_key) = 32),
             admission_proof_version INTEGER NOT NULL CHECK(admission_proof_version = 1),
             request_fingerprint BLOB NOT NULL CHECK(length(request_fingerprint) = 32),
             request_issued_at INTEGER NOT NULL CHECK(request_issued_at > 0),
             request_expires_at INTEGER NOT NULL CHECK(request_expires_at > request_issued_at),
             invitation_expires_at INTEGER NOT NULL
                 CHECK(invitation_expires_at >= request_expires_at),
             state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 6),
             transaction_id BLOB CHECK(transaction_id IS NULL OR length(transaction_id) = 16),
             UNIQUE(transaction_id),
             UNIQUE(generation, join_request_id),
             UNIQUE(generation, request_nonce),
             UNIQUE(generation, request_fingerprint),
             CHECK(
                 (state IN (1, 2, 5) AND transaction_id IS NULL)
                 OR (state IN (3, 4) AND transaction_id IS NOT NULL)
                 OR state = 6
             )
         ) STRICT;

         CREATE TABLE invitation_opening_contexts (
             invitation_id BLOB PRIMARY KEY CHECK(length(invitation_id) = 16),
             generation BLOB NOT NULL UNIQUE CHECK(length(generation) = 64),
             signed_invitation BLOB NOT NULL
                 CHECK(length(signed_invitation) BETWEEN 1 AND 512),
             hpke_private_key BLOB NOT NULL CHECK(length(hpke_private_key) = 32),
             issued_at INTEGER NOT NULL CHECK(issued_at > 0),
             expires_at INTEGER NOT NULL CHECK(expires_at > issued_at),
             state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 4)
         ) STRICT;

         CREATE TABLE inviter_joins (
             transaction_id BLOB PRIMARY KEY CHECK(length(transaction_id) = 16),
             invitation_id BLOB NOT NULL UNIQUE REFERENCES reservations(invitation_id),
             generation BLOB NOT NULL CHECK(length(generation) = 64),
             join_request_id BLOB NOT NULL UNIQUE CHECK(length(join_request_id) = 16),
             request_fingerprint BLOB NOT NULL CHECK(length(request_fingerprint) = 32),
             group_id BLOB NOT NULL CHECK(length(group_id) = 32),
             epoch_before INTEGER NOT NULL CHECK(epoch_before >= 0),
             epoch_after INTEGER NOT NULL CHECK(epoch_after = epoch_before + 1),
             approval_record BLOB NOT NULL CHECK(length(approval_record) BETWEEN 1 AND 4096),
             welcome BLOB NOT NULL CHECK(length(welcome) BETWEEN 1 AND 65536),
             endpoint BLOB NOT NULL CHECK(length(endpoint) BETWEEN 1 AND 4096),
             outbox_expires_at INTEGER NOT NULL CHECK(outbox_expires_at > 0),
             outbox_state INTEGER NOT NULL CHECK(outbox_state BETWEEN 1 AND 5),
             delivery_attempts INTEGER NOT NULL
                 CHECK(delivery_attempts BETWEEN 0 AND 32),
             maximum_delivery_attempts INTEGER NOT NULL
                 CHECK(maximum_delivery_attempts BETWEEN 1 AND 32),
             lease_generation INTEGER NOT NULL CHECK(lease_generation >= 0),
             lease_id BLOB CHECK(lease_id IS NULL OR length(lease_id) = 16),
             lease_expires_at INTEGER CHECK(lease_expires_at IS NULL OR lease_expires_at > 0),
             CHECK(
                 (outbox_state = 2 AND lease_id IS NOT NULL AND lease_expires_at IS NOT NULL)
                 OR (outbox_state IN (1, 3, 4, 5) AND lease_id IS NULL AND lease_expires_at IS NULL)
             ),
             CHECK(delivery_attempts <= maximum_delivery_attempts),
             CHECK(outbox_state != 4 OR delivery_attempts = maximum_delivery_attempts)
         ) STRICT;

         CREATE TABLE mls_groups (
             group_id BLOB PRIMARY KEY CHECK(length(group_id) BETWEEN 1 AND 255),
             state BLOB NOT NULL CHECK(length(state) BETWEEN 1 AND 2097152)
         ) STRICT;

         CREATE TABLE mls_epochs (
             group_id BLOB NOT NULL REFERENCES mls_groups(group_id),
             epoch_id INTEGER NOT NULL CHECK(epoch_id >= 0),
             data BLOB NOT NULL CHECK(length(data) BETWEEN 1 AND 2097152),
             PRIMARY KEY(group_id, epoch_id)
         ) STRICT;

         CREATE TABLE key_packages (
             key_package_ref BLOB PRIMARY KEY CHECK(length(key_package_ref) = 32),
             key_package BLOB NOT NULL CHECK(length(key_package) BETWEEN 1 AND 16384),
             init_key BLOB NOT NULL CHECK(length(init_key) BETWEEN 1 AND 4096),
             leaf_key BLOB NOT NULL CHECK(length(leaf_key) BETWEEN 1 AND 4096),
             expires_at INTEGER NOT NULL CHECK(expires_at > 0)
         ) STRICT;

         CREATE TABLE joiner_commits (
             transaction_id BLOB PRIMARY KEY CHECK(length(transaction_id) = 16),
             group_id BLOB NOT NULL UNIQUE CHECK(length(group_id) = 32),
             key_package_ref BLOB NOT NULL UNIQUE CHECK(length(key_package_ref) = 32)
         ) STRICT;

         CREATE TABLE mls_client_identity (
             singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
             group_id BLOB NOT NULL UNIQUE CHECK(length(group_id) = 32),
             identity_record BLOB NOT NULL CHECK(length(identity_record) = 141)
         ) STRICT;
         PRAGMA user_version = 6;",
    )?;
    let maximum_total_authorization_attempts = authorization_policy
        .maximum_live_invitations
        .checked_mul(authorization_policy.maximum_retained_attempts)
        .ok_or(StoreError::Rejected)?;
    if connection
        .execute(
            "INSERT INTO storage_metadata(
                 singleton, schema_version, store_id,
                 maximum_live_invitations, maximum_live_authorization_attempts,
                 maximum_retained_attempts_per_generation,
                 maximum_total_authorization_attempts
             ) VALUES (1, 6, ?1, ?2, ?3, ?3, ?4)",
            params![
                store_id,
                authorization_policy.maximum_live_invitations as i64,
                authorization_policy.maximum_retained_attempts as i64,
                maximum_total_authorization_attempts as i64,
            ],
        )
        .is_err()
    {
        rollback(connection);
        return Err(StoreError::Rejected);
    }
    connection.execute_batch("COMMIT;")?;
    Ok(())
}

pub(super) fn migrate_schema_v1_to_v2(connection: &Connection) -> Result<(), StoreError> {
    let store_id = random_nonzero_identifier(connection)?;
    connection.execute_batch(
        "BEGIN EXCLUSIVE;
         ALTER TABLE storage_metadata RENAME TO storage_metadata_v1;
         CREATE TABLE storage_metadata (
             singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
             schema_version INTEGER NOT NULL CHECK(schema_version = 2),
             store_id BLOB NOT NULL UNIQUE CHECK(length(store_id) = 16)
         ) STRICT;

         ALTER TABLE inviter_joins RENAME TO inviter_joins_v1;
         CREATE TABLE inviter_joins (
             transaction_id BLOB PRIMARY KEY CHECK(length(transaction_id) = 16),
             invitation_id BLOB NOT NULL UNIQUE REFERENCES reservations(invitation_id),
             generation BLOB NOT NULL CHECK(length(generation) = 64),
             join_request_id BLOB NOT NULL UNIQUE CHECK(length(join_request_id) = 16),
             request_fingerprint BLOB NOT NULL CHECK(length(request_fingerprint) = 32),
             group_id BLOB NOT NULL CHECK(length(group_id) = 32),
             epoch_before INTEGER NOT NULL CHECK(epoch_before >= 0),
             epoch_after INTEGER NOT NULL CHECK(epoch_after = epoch_before + 1),
             approval_record BLOB NOT NULL CHECK(length(approval_record) BETWEEN 1 AND 4096),
             welcome BLOB NOT NULL CHECK(length(welcome) BETWEEN 1 AND 65536),
             endpoint BLOB NOT NULL CHECK(length(endpoint) BETWEEN 1 AND 4096),
             outbox_expires_at INTEGER NOT NULL CHECK(outbox_expires_at > 0),
             outbox_state INTEGER NOT NULL CHECK(outbox_state BETWEEN 1 AND 5),
             delivery_attempts INTEGER NOT NULL
                 CHECK(delivery_attempts BETWEEN 0 AND 32),
             maximum_delivery_attempts INTEGER NOT NULL
                 CHECK(maximum_delivery_attempts BETWEEN 1 AND 32),
             lease_generation INTEGER NOT NULL CHECK(lease_generation >= 0),
             lease_id BLOB CHECK(lease_id IS NULL OR length(lease_id) = 16),
             lease_expires_at INTEGER CHECK(lease_expires_at IS NULL OR lease_expires_at > 0),
             CHECK(
                 (outbox_state = 2 AND lease_id IS NOT NULL AND lease_expires_at IS NOT NULL)
                 OR (outbox_state IN (1, 3, 4, 5) AND lease_id IS NULL AND lease_expires_at IS NULL)
             ),
             CHECK(delivery_attempts <= maximum_delivery_attempts),
             CHECK(outbox_state != 4 OR delivery_attempts = maximum_delivery_attempts)
         ) STRICT;",
    )?;
    let migration = (|| {
        connection.execute(
            "INSERT INTO storage_metadata(singleton, schema_version, store_id)
             VALUES (1, 2, ?1)",
            params![store_id],
        )?;
        connection.execute_batch(
            "INSERT INTO inviter_joins(
                 transaction_id, invitation_id, generation, join_request_id,
                 request_fingerprint, group_id, epoch_before, epoch_after,
                 approval_record, welcome, endpoint, outbox_expires_at, outbox_state,
                 delivery_attempts, maximum_delivery_attempts, lease_generation,
                 lease_id, lease_expires_at
             )
             SELECT transaction_id, invitation_id, generation, join_request_id,
                    request_fingerprint, group_id, epoch_before, epoch_after,
                    approval_record, welcome, endpoint, outbox_expires_at, 1,
                    0, 3, 0, NULL, NULL
             FROM inviter_joins_v1;",
        )?;
        {
            let mut statement = connection
                .prepare("SELECT welcome, endpoint, outbox_expires_at FROM inviter_joins")?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let welcome = row.get::<_, Vec<u8>>(0)?;
                let endpoint = row.get::<_, Vec<u8>>(1)?;
                let outbox_expires_at =
                    u64::try_from(row.get::<_, i64>(2)?).map_err(|_| StoreError::Rejected)?;
                validate_delivery_material(&welcome, &endpoint, outbox_expires_at)?;
            }
        }
        connection.execute_batch(
            "DROP TABLE inviter_joins_v1;
             DROP TABLE storage_metadata_v1;
             PRAGMA user_version = 2;
             COMMIT;",
        )?;
        Ok(())
    })();
    if migration.is_err() {
        rollback(connection);
    }
    migration
}

pub(super) fn migrate_schema_v2_to_v3(connection: &Connection) -> Result<(), StoreError> {
    let migration = (|| {
        connection.execute_batch(
            "BEGIN EXCLUSIVE;
             ALTER TABLE storage_metadata RENAME TO storage_metadata_v2;
             CREATE TABLE storage_metadata (
                 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                 schema_version INTEGER NOT NULL CHECK(schema_version = 3),
                 store_id BLOB NOT NULL UNIQUE CHECK(length(store_id) = 16)
             ) STRICT;
             INSERT INTO storage_metadata(singleton, schema_version, store_id)
                 SELECT singleton, 3, store_id FROM storage_metadata_v2;
             CREATE TABLE mls_client_identity (
                 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                 identity_record BLOB NOT NULL CHECK(length(identity_record) = 141)
             ) STRICT;
             DROP TABLE storage_metadata_v2;
             PRAGMA user_version = 3;
             COMMIT;",
        )?;
        Ok(())
    })();
    if migration.is_err() {
        rollback(connection);
    }
    migration
}

pub(super) fn migrate_schema_v3_to_v4(connection: &Connection) -> Result<(), StoreError> {
    let migration = (|| {
        connection.execute_batch(
            "BEGIN EXCLUSIVE;
             ALTER TABLE storage_metadata RENAME TO storage_metadata_v3;
             CREATE TABLE storage_metadata (
                 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                 schema_version INTEGER NOT NULL CHECK(schema_version = 4),
                 store_id BLOB NOT NULL UNIQUE CHECK(length(store_id) = 16)
             ) STRICT;
             INSERT INTO storage_metadata(singleton, schema_version, store_id)
                 SELECT singleton, 4, store_id FROM storage_metadata_v3;
             ALTER TABLE mls_client_identity RENAME TO mls_client_identity_v3;
             CREATE TABLE mls_client_identity (
                 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                 group_id BLOB NOT NULL UNIQUE CHECK(length(group_id) = 32),
                 identity_record BLOB NOT NULL CHECK(length(identity_record) = 141)
             ) STRICT;",
        )?;
        let identity_count: i64 =
            connection.query_row("SELECT count(*) FROM mls_client_identity_v3", [], |row| {
                row.get(0)
            })?;
        if identity_count > 1 {
            return Err(StoreError::Rejected);
        }
        if identity_count == 1 {
            let (group_count, group_id): (i64, Option<Vec<u8>>) = connection.query_row(
                "SELECT count(*), min(group_id) FROM mls_groups",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let group_id = group_id.ok_or(StoreError::Rejected)?;
            if group_count != 1 || group_id.len() != SESSION_GROUP_ID_BYTES || all_zero(&group_id) {
                return Err(StoreError::Rejected);
            }
            connection.execute(
                "INSERT INTO mls_client_identity(singleton, group_id, identity_record)
                 SELECT singleton, ?1, identity_record FROM mls_client_identity_v3",
                params![group_id],
            )?;
        }
        connection.execute_batch(
            "DROP TABLE mls_client_identity_v3;
             DROP TABLE storage_metadata_v3;
             PRAGMA user_version = 4;
             COMMIT;",
        )?;
        Ok(())
    })();
    if migration.is_err() {
        rollback(connection);
    }
    migration
}

pub(super) fn migrate_schema_v4_to_v5(
    connection: &Connection,
    authorization_policy: AuthorizationPolicy,
) -> Result<(), StoreError> {
    let migration = (|| {
        connection.execute_batch(
            "BEGIN EXCLUSIVE;
             ALTER TABLE storage_metadata RENAME TO storage_metadata_v4;
             CREATE TABLE storage_metadata (
                 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                 schema_version INTEGER NOT NULL CHECK(schema_version = 5),
                 store_id BLOB NOT NULL UNIQUE CHECK(length(store_id) = 16),
                 maximum_live_invitations INTEGER NOT NULL
                     CHECK(maximum_live_invitations BETWEEN 1 AND 8),
                 maximum_retained_attempts INTEGER NOT NULL
                     CHECK(maximum_retained_attempts BETWEEN 1 AND 8)
             ) STRICT;",
        )?;
        connection.execute(
            "INSERT INTO storage_metadata(
                 singleton, schema_version, store_id,
                 maximum_live_invitations, maximum_retained_attempts
             ) SELECT singleton, 5, store_id, ?1, ?2 FROM storage_metadata_v4",
            params![
                authorization_policy.maximum_live_invitations as i64,
                authorization_policy.maximum_retained_attempts as i64,
            ],
        )?;
        connection.execute_batch(
            "CREATE TABLE invitation_opening_contexts (
                 invitation_id BLOB PRIMARY KEY CHECK(length(invitation_id) = 16),
                 generation BLOB NOT NULL UNIQUE CHECK(length(generation) = 64),
                 signed_invitation BLOB NOT NULL
                     CHECK(length(signed_invitation) BETWEEN 1 AND 512),
                 hpke_private_key BLOB NOT NULL CHECK(length(hpke_private_key) = 32),
                 issued_at INTEGER NOT NULL CHECK(issued_at > 0),
                 expires_at INTEGER NOT NULL CHECK(expires_at > issued_at),
                 state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 4)
             ) STRICT;
             CREATE TABLE authorization_attempts (
                 attempt_id BLOB PRIMARY KEY CHECK(length(attempt_id) = 16),
                 invitation_id BLOB NOT NULL REFERENCES invitation_opening_contexts(invitation_id),
                 generation BLOB NOT NULL CHECK(length(generation) = 64),
                 invitation_challenge BLOB NOT NULL CHECK(length(invitation_challenge) = 32),
                 join_request_id BLOB NOT NULL CHECK(length(join_request_id) = 16),
                 request_nonce BLOB NOT NULL CHECK(length(request_nonce) = 32),
                 intended_verifier BLOB NOT NULL CHECK(length(intended_verifier) = 32),
                 key_package_reference BLOB NOT NULL CHECK(length(key_package_reference) = 32),
                 mls_protocol_version INTEGER NOT NULL CHECK(mls_protocol_version = 1),
                 mls_ciphersuite INTEGER NOT NULL CHECK(mls_ciphersuite = 1),
                 credential_type INTEGER NOT NULL CHECK(credential_type = 1),
                 credential_identity BLOB NOT NULL CHECK(length(credential_identity) = 32),
                 leaf_signature_key BLOB NOT NULL CHECK(length(leaf_signature_key) = 32),
                 admission_proof_version INTEGER NOT NULL CHECK(admission_proof_version = 1),
                 request_fingerprint BLOB NOT NULL CHECK(length(request_fingerprint) = 32),
                 request_issued_at INTEGER NOT NULL CHECK(request_issued_at > 0),
                 request_expires_at INTEGER NOT NULL
                     CHECK(request_expires_at > request_issued_at),
                 invitation_expires_at INTEGER NOT NULL
                     CHECK(invitation_expires_at >= request_expires_at),
                 state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 6),
                 transaction_id BLOB CHECK(transaction_id IS NULL OR length(transaction_id) = 16),
                 UNIQUE(transaction_id),
                 UNIQUE(generation, join_request_id),
                 UNIQUE(generation, request_nonce),
                 UNIQUE(generation, request_fingerprint),
                 CHECK(
                     (state IN (1, 2, 5) AND transaction_id IS NULL)
                     OR (state IN (3, 4) AND transaction_id IS NOT NULL)
                     OR state = 6
                 )
             ) STRICT;
             DROP TABLE storage_metadata_v4;
             PRAGMA user_version = 5;
             COMMIT;",
        )?;
        Ok(())
    })();
    if migration.is_err() {
        rollback(connection);
    }
    migration
}

pub(super) fn migrate_schema_v5_to_v6(connection: &Connection) -> Result<(), StoreError> {
    let migration = (|| {
        connection.execute_batch(
            "BEGIN EXCLUSIVE;
             ALTER TABLE storage_metadata RENAME TO storage_metadata_v5;
             CREATE TABLE storage_metadata (
                 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                 schema_version INTEGER NOT NULL CHECK(schema_version = 6),
                 store_id BLOB NOT NULL UNIQUE CHECK(length(store_id) = 16),
                 maximum_live_invitations INTEGER NOT NULL
                     CHECK(maximum_live_invitations BETWEEN 1 AND 8),
                 maximum_live_authorization_attempts INTEGER NOT NULL
                     CHECK(maximum_live_authorization_attempts BETWEEN 1 AND 8),
                 maximum_retained_attempts_per_generation INTEGER NOT NULL
                     CHECK(maximum_retained_attempts_per_generation BETWEEN 1 AND 8),
                 maximum_total_authorization_attempts INTEGER NOT NULL
                     CHECK(maximum_total_authorization_attempts BETWEEN 1 AND 64)
             ) STRICT;
             INSERT INTO storage_metadata(
                 singleton, schema_version, store_id,
                 maximum_live_invitations, maximum_live_authorization_attempts,
                 maximum_retained_attempts_per_generation,
                 maximum_total_authorization_attempts
             )
             SELECT singleton, 6, store_id,
                    maximum_live_invitations, maximum_retained_attempts,
                    maximum_retained_attempts,
                    maximum_live_invitations * maximum_retained_attempts
             FROM storage_metadata_v5;
             DROP TABLE storage_metadata_v5;
             PRAGMA user_version = 6;
             COMMIT;",
        )?;
        Ok(())
    })();
    if migration.is_err() {
        rollback(connection);
    }
    migration
}

pub(super) fn validate_schema_v6(
    connection: &Connection,
    authorization_policy: AuthorizationPolicy,
) -> Result<(), StoreError> {
    let rows = connection.query_row(
        "SELECT count(*), min(schema_version), max(schema_version), min(store_id),
                min(maximum_live_invitations),
                min(maximum_live_authorization_attempts),
                min(maximum_retained_attempts_per_generation),
                min(maximum_total_authorization_attempts)
         FROM storage_metadata",
        [],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, Option<i64>>(7)?,
            ))
        },
    )?;
    let store_id = rows.3.ok_or(StoreError::Rejected)?;
    if application_schema_version(connection)? != SCHEMA_VERSION
        || rows.0 != 1
        || rows.1 != Some(i64::from(SCHEMA_VERSION))
        || rows.2 != Some(i64::from(SCHEMA_VERSION))
        || store_id.len() != STORE_ID_BYTES
        || all_zero(&store_id)
    {
        return Err(StoreError::Rejected);
    }
    let maximum_authorization_rows = authorization_policy
        .maximum_live_invitations
        .checked_mul(authorization_policy.maximum_retained_attempts)
        .ok_or(StoreError::Rejected)?;
    if rows.4 != Some(authorization_policy.maximum_live_invitations as i64)
        || rows.5 != Some(authorization_policy.maximum_retained_attempts as i64)
        || rows.6 != Some(authorization_policy.maximum_retained_attempts as i64)
        || rows.7 != Some(maximum_authorization_rows as i64)
    {
        return Err(StoreError::Conflict);
    }
    let invalid_identity_rows: i64 = connection.query_row(
        "SELECT count(*) FROM mls_client_identity
         WHERE length(group_id) != 32 OR group_id = zeroblob(32)",
        [],
        |row| row.get(0),
    )?;
    if invalid_identity_rows != 0 {
        return Err(StoreError::Rejected);
    }
    let invalid_opening_rows: i64 = connection.query_row(
        "SELECT count(*) FROM invitation_opening_contexts
         WHERE invitation_id = zeroblob(16)
            OR generation = zeroblob(64)
            OR (state IN (?1, ?2) AND hpke_private_key = zeroblob(32))
            OR (state IN (?3, ?4) AND hpke_private_key != zeroblob(32))",
        params![
            OPENING_AVAILABLE,
            OPENING_RESERVED,
            OPENING_CONSUMED,
            OPENING_UNUSABLE,
        ],
        |row| row.get(0),
    )?;
    if invalid_opening_rows != 0 {
        return Err(StoreError::Rejected);
    }
    let opening_rows: i64 = connection.query_row(
        "SELECT count(*) FROM invitation_opening_contexts",
        [],
        |row| row.get(0),
    )?;
    let authorization_rows: i64 =
        connection.query_row("SELECT count(*) FROM authorization_attempts", [], |row| {
            row.get(0)
        })?;
    let live_authorization_rows: i64 = connection.query_row(
        "SELECT count(*) FROM authorization_attempts WHERE state IN (?1, ?2, ?3)",
        params![
            AUTHORIZATION_PENDING_APPROVAL,
            AUTHORIZATION_APPROVED_PENDING_MEMBERSHIP,
            AUTHORIZATION_MEMBERSHIP_OUTCOME_UNKNOWN,
        ],
        |row| row.get(0),
    )?;
    let maximum_generation_rows: i64 = connection.query_row(
        "SELECT coalesce(max(generation_rows), 0)
         FROM (
             SELECT count(*) AS generation_rows
             FROM authorization_attempts
             GROUP BY invitation_id, generation
         )",
        [],
        |row| row.get(0),
    )?;
    if opening_rows < 0
        || opening_rows as usize > authorization_policy.maximum_live_invitations
        || authorization_rows < 0
        || authorization_rows as usize > maximum_authorization_rows
        || live_authorization_rows < 0
        || live_authorization_rows as usize > authorization_policy.maximum_retained_attempts
        || maximum_generation_rows < 0
        || maximum_generation_rows as usize > authorization_policy.maximum_retained_attempts
    {
        return Err(StoreError::Rejected);
    }
    let invalid_authorization_rows: i64 = connection.query_row(
        "SELECT count(*)
         FROM authorization_attempts AS a
         LEFT JOIN invitation_opening_contexts AS i
           ON i.invitation_id = a.invitation_id AND i.generation = a.generation
         WHERE i.invitation_id IS NULL
            OR a.attempt_id = zeroblob(16)
            OR a.invitation_id = zeroblob(16)
            OR a.generation = zeroblob(64)
            OR a.invitation_challenge = zeroblob(32)
            OR a.join_request_id = zeroblob(16)
            OR a.request_nonce = zeroblob(32)
            OR a.intended_verifier = zeroblob(32)
            OR a.key_package_reference = zeroblob(32)
            OR a.credential_identity = zeroblob(32)
            OR a.leaf_signature_key = zeroblob(32)
            OR a.request_fingerprint = zeroblob(32)
            OR a.invitation_expires_at != i.expires_at
            OR (a.transaction_id IS NOT NULL AND a.transaction_id = zeroblob(16))",
        [],
        |row| row.get(0),
    )?;
    if invalid_authorization_rows != 0 {
        return Err(StoreError::Rejected);
    }
    let invalid_authorization_ownership: i64 = connection.query_row(
        "SELECT count(*) FROM invitation_opening_contexts AS i
         WHERE (
             i.state = ?1 AND 1 != (
                 SELECT count(*) FROM authorization_attempts AS a
                 WHERE a.invitation_id = i.invitation_id
                   AND a.generation = i.generation
                   AND a.state IN (?2, ?3, ?4)
             )
         ) OR (
             i.state != ?1 AND EXISTS (
                 SELECT 1 FROM authorization_attempts AS a
                 WHERE a.invitation_id = i.invitation_id
                   AND a.generation = i.generation
                   AND a.state IN (?2, ?3, ?4)
             )
         )",
        params![
            OPENING_RESERVED,
            AUTHORIZATION_PENDING_APPROVAL,
            AUTHORIZATION_APPROVED_PENDING_MEMBERSHIP,
            AUTHORIZATION_MEMBERSHIP_OUTCOME_UNKNOWN,
        ],
        |row| row.get(0),
    )?;
    if invalid_authorization_ownership != 0 {
        return Err(StoreError::Rejected);
    }
    let invalid_committed_authorizations: i64 = connection.query_row(
        "SELECT count(*) FROM authorization_attempts AS a
         LEFT JOIN invitation_opening_contexts AS i
           ON i.invitation_id = a.invitation_id AND i.generation = a.generation
         LEFT JOIN inviter_joins AS j
           ON j.transaction_id = a.transaction_id
          AND j.invitation_id = a.invitation_id AND j.generation = a.generation
          AND j.join_request_id = a.join_request_id
          AND j.request_fingerprint = a.request_fingerprint
         LEFT JOIN reservations AS r
           ON r.invitation_id = a.invitation_id AND r.generation = a.generation
          AND r.join_request_id = a.join_request_id
         WHERE a.state = ?1
           AND (i.state IS NULL OR i.state != ?2 OR j.transaction_id IS NULL
                OR r.state IS NULL OR r.state != 2)",
        params![AUTHORIZATION_COMMITTED, OPENING_CONSUMED],
        |row| row.get(0),
    )?;
    let invalid_abandoned_authorizations: i64 = connection.query_row(
        "SELECT count(*) FROM authorization_attempts AS a
         JOIN inviter_joins AS j ON j.transaction_id = a.transaction_id
         WHERE a.state = ?1",
        params![AUTHORIZATION_ABANDONED],
        |row| row.get(0),
    )?;
    let invalid_opening_owned_results: i64 = connection.query_row(
        "SELECT count(*) FROM inviter_joins AS j
         JOIN invitation_opening_contexts AS i
           ON i.invitation_id = j.invitation_id AND i.generation = j.generation
         LEFT JOIN authorization_attempts AS a
           ON a.transaction_id = j.transaction_id
          AND a.invitation_id = j.invitation_id AND a.generation = j.generation
          AND a.join_request_id = j.join_request_id
          AND a.request_fingerprint = j.request_fingerprint
          AND a.state = ?1
         WHERE a.attempt_id IS NULL",
        params![AUTHORIZATION_COMMITTED],
        |row| row.get(0),
    )?;
    let invalid_consumed_openings: i64 = connection.query_row(
        "SELECT count(*) FROM invitation_opening_contexts AS i
         WHERE i.state = ?1 AND NOT EXISTS (
             SELECT 1 FROM authorization_attempts AS a
             WHERE a.invitation_id = i.invitation_id AND a.generation = i.generation
               AND a.state = ?2
         )",
        params![OPENING_CONSUMED, AUTHORIZATION_COMMITTED],
        |row| row.get(0),
    )?;
    if invalid_committed_authorizations != 0
        || invalid_abandoned_authorizations != 0
        || invalid_opening_owned_results != 0
        || invalid_consumed_openings != 0
    {
        return Err(StoreError::Rejected);
    }
    Ok(())
}

pub(super) fn schema_versions(connection: &Connection) -> Result<(u32, i64), StoreError> {
    Ok((
        application_schema_version(connection)?,
        connection.query_row("SELECT schema_version FROM storage_metadata", [], |row| {
            row.get(0)
        })?,
    ))
}

fn application_schema_version(connection: &Connection) -> Result<u32, StoreError> {
    let version = connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?;
    u32::try_from(version).map_err(|_| StoreError::Rejected)
}

pub(super) fn validate_connection_configuration(connection: &Connection) -> Result<(), StoreError> {
    let journal_mode =
        connection.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))?;
    let synchronous = connection.query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))?;
    let temp_store = connection.query_row("PRAGMA temp_store", [], |row| row.get::<_, i64>(0))?;
    let secure_delete =
        connection.query_row("PRAGMA secure_delete", [], |row| row.get::<_, i64>(0))?;
    let trusted_schema =
        connection.query_row("PRAGMA trusted_schema", [], |row| row.get::<_, i64>(0))?;
    let foreign_keys =
        connection.query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))?;
    if !journal_mode.eq_ignore_ascii_case("delete")
        || synchronous != 2
        || temp_store != 2
        || secure_delete != 1
        || trusted_schema != 0
        || foreign_keys != 1
    {
        return Err(StoreError::Rejected);
    }
    Ok(())
}
