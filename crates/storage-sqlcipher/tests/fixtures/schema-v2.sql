-- Frozen from storage-sqlcipher schema v2 at
-- d39fb05b390e72f5982dbbd48849c95c4d7c933f.
BEGIN IMMEDIATE;

CREATE TABLE storage_metadata (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    schema_version INTEGER NOT NULL CHECK(schema_version = 2),
    store_id BLOB NOT NULL UNIQUE CHECK(length(store_id) = 16)
) STRICT;

INSERT INTO storage_metadata(singleton, schema_version, store_id)
VALUES (1, 2, X'36363636363636363636363636363636');

CREATE TABLE reservations (
    invitation_id BLOB PRIMARY KEY CHECK(length(invitation_id) = 16),
    generation BLOB NOT NULL CHECK(length(generation) = 64),
    join_request_id BLOB NOT NULL CHECK(length(join_request_id) = 16),
    expires_at INTEGER NOT NULL CHECK(expires_at > 0),
    state INTEGER NOT NULL CHECK(state IN (1, 2))
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

PRAGMA user_version = 2;

COMMIT;
