BEGIN IMMEDIATE;

PRAGMA user_version = 0;

CREATE TABLE storage_metadata (
    schema_version INTEGER NOT NULL CHECK(schema_version = 1)
) STRICT;

INSERT INTO storage_metadata(schema_version) VALUES (1);

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
    outbox_state INTEGER NOT NULL CHECK(outbox_state = 1)
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

COMMIT;
