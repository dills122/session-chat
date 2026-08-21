# ADR 0017: Use SQLCipher for the durable storage laboratory

Status: accepted for a bounded durable laboratory; not production storage

Date: 2026-08-20

## Context

ADR 0016 requires an encrypted transaction engine whose key remains outside a
copied database. ADR 0012 separately requires an inviter-local transaction and
a joiner-local transaction through the real MLS storage calls. The isolated
SQLCipher spike passed on macOS, but did not exercise Session Chat's adapter or
justify platform-vault and production claims.

## Decision

Use exact `rusqlite` 0.40.1 with bundled SQLCipher 4.14.0 in the isolated
`storage-sqlcipher` workspace adapter for the next durability laboratory.

- The database accepts only an externally supplied nonzero 32-byte raw key.
- One keyed connection uses rollback-journal mode, `synchronous=FULL`,
  memory-only temporary storage, secure deletion, disabled trusted schemas,
  foreign keys, strict tables, parameterized values, and coarse public errors.
- The inviter stages its bounded application metadata and commits it only from
  the actual `Group::write_to_storage` provider call.
- The joiner coordinates the upstream group-storage write and subsequent exact
  KeyPackage deletion behind one shared SQL transaction.
- Transaction IDs provide recovery after ambiguous commit results; exact retry
  is idempotent and conflicting state fails closed.
- Secret-bearing input types omit `Clone`, `Debug`, and `Display`, and retained
  Rust buffers use zeroization where their types permit it.

The adapter is compiled into the workspace for testing, but no client opens it
and no platform protector supplies its raw key. SQLCipher is not a rollback
anchor and this decision makes no production, cross-platform, secure-deletion,
or power-loss claim.

## Platform protector direction

Use the factual capability contract in `session-storage`; do not select one
generic keychain guarantee. The companion platform decision packet selects
macOS Keychain Services as the first fresh-user-presence probe. Windows and
Linux require separately named and measured modes before implementation.

## Required next gates

- build and test the exact native graph on every supported target;
- add macOS native key creation/unseal/delete probes and lifecycle tests;
- investigate Windows Hello/CNG beyond DPAPI and concrete Linux Secret Service
  implementations;
- test process kill at every production adapter write boundary, disk full,
  truncation, tampering, migration, rekey, backup, and deletion;
- add durable Welcome leasing/delivery state and recovery;
- select or explicitly defer a trusted monotonic rollback anchor; and
- independently review the exact MLS, SQLCipher, and platform-protector boundary.

## Alternatives

Plain SQLite, redb, and custom encrypted snapshots remain rejected for the
first adapter because they require Session Chat to design record encryption or
do not protect copied files. The disposable SQLCipher spike remains historical
compatibility evidence; production code must use the workspace adapter and its
real MLS integration tests.
