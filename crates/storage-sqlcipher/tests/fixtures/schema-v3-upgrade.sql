-- Frozen schema-v2 -> schema-v3 migration retained before group binding was
-- added. Tests apply this exact historical transition to schema-v2.sql.
BEGIN EXCLUSIVE;
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
COMMIT;
