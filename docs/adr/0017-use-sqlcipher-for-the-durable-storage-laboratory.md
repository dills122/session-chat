# ADR 0017: Use SQLCipher for the durable storage laboratory

Status: accepted for a bounded durable laboratory; inviter/joiner transactions
and durable Welcome-owner port implemented; not production storage

Date: 2026-08-20

## Context

ADR 0016 requires an encrypted transaction engine whose key remains outside a
copied database. ADR 0012 separately requires an inviter-local transaction and
a joiner-local transaction through the real MLS storage calls. The isolated
SQLCipher spike passed on macOS, but did not exercise Session Chat's adapter or
justify platform-vault and production claims.

## Decision

Use exact `rusqlite` 0.40.1 with bundled SQLCipher 4.14.0 and its
`bundled-sqlcipher-vendored-openssl` feature in the isolated
`storage-sqlcipher` workspace adapter for the next durability laboratory. The
vendored OpenSSL graph avoids relying on differently discovered system crypto
libraries across the three required CI operating systems.

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
- Schema version 2 persists one nonzero store identity and the exact canonical
  Welcome/LocalV1 endpoint beside bounded delivery state, attempt count,
  monotonic lease generation, opaque lease identity, and lease expiry. Valid
  version-1 pending rows migrate atomically; invalid legacy delivery material
  rolls the migration back.
- The adapter implements the sole-owner `WelcomeOutboxPort`. Each lease,
  acceptance, and failure transition uses one immediate SQL transaction;
  restart reconstructs work from this ledger, and stale or foreign lease
  results fail closed.
- The real capability-admission/MLS composition uses an explicit
  durability-pending one-shot value. A proven SQL rollback releases its
  in-memory admission reservations and requires the transient MLS group to be
  discarded; an ambiguous result preserves them until recovery proves commit
  or rollback. No Welcome is exposed before committed recovery.
- The adapter retains SQLCipher's default memory policy, which locks and
  sanitizes its internal cryptographic allocations without enabling the
  optional process-wide wiping of every SQLite allocation.

The adapter is compiled into the workspace for testing, but no client opens it
and no platform protector supplies its raw key. SQLCipher is not a rollback
anchor and this decision makes no production, cross-platform, secure-deletion,
or power-loss claim. Vendoring OpenSSL increases the audited source, native
build, license, advisory, and compile-time surface; the locked graph and
dependency policy must therefore cover it explicitly.

## Platform protector direction

Use the factual capability contract in `session-storage`; do not select one
generic keychain guarantee. ADR 0018 supersedes the earlier macOS-first
implementation order: select and prove one portable baseline on macOS, Windows,
and Linux before adding any native enhanced protector.

## Required next gates

- pass the exact SQLCipher graph on required Linux, macOS, and Windows CI;
- select and test one portable key-protection baseline on all three families;
- only then investigate enhanced macOS Keychain, Windows Hello/CNG, and concrete
  Linux Secret Service implementations in parallel;
- test process kill at every production adapter write boundary, disk full,
  truncation, tampering, migration, rekey, backup, and deletion;
- extend the proven single-process headless composition into the
  independent-process L1 runner and full durable-client identity recovery;
- select or explicitly defer a trusted monotonic rollback anchor; and
- independently review the exact MLS, SQLCipher, and platform-protector boundary.

## Alternatives

Plain SQLite, redb, and custom encrypted snapshots remain rejected for the
first adapter because they require Session Chat to design record encryption or
do not protect copied files. The disposable SQLCipher spike remains historical
compatibility evidence; production code must use the workspace adapter and its
real MLS integration tests.
