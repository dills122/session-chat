# ADR 0017: Use SQLCipher for the durable storage laboratory

Status: accepted for a bounded durable laboratory; inviter/joiner transactions,
durable Welcome-owner port, and client identity/group reload implemented; not
production storage

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
  persisted attempt ceiling, monotonic lease generation, opaque lease identity,
  and lease expiry. SQLite `user_version` must agree with the singleton schema
  metadata. Valid version-1 pending rows migrate in one exclusive transaction;
  invalid legacy delivery material rolls the migration back.
- The adapter implements the sole-owner `WelcomeOutboxPort`. Each lease,
  acceptance, and failure transition uses one immediate SQL transaction;
  restart reconstructs work from this ledger, and old-open-scope, stale, or
  foreign lease results fail closed.
- Schema version 3 retains those semantics and adds one exact 141-byte,
  versioned MLS client-identity record. Version 4 adds one exact nonzero 32-byte
  group binding. The public storage boundary carries the record only in an opaque
  secret type with no `Clone`, `Debug`, or `Display`. The record binds MLS 1.0, the selected
  ciphersuite, the pinned AWS-LC representation, the session-scoped credential,
  and the matching signing public/secret key. Creation refuses replacement;
  reload never generates fallback material or accepts another group; durable
  group creation and join enforce the same scope; derived-public-key validation
  and a local-member credential/public-key check precede use of loaded group state.
  Versions 2 and 3 migrate in exclusive transactions. A frozen version-2 fixture
  retains leased, delivered, and attempts-exhausted outbox states plus the
  store identity through version 4, and a forced table conflict proves failed
  migration restores both schema versions and the original rows. A valid
  version-1 store advances through every retained migration. A frozen version-3
  fixture proves that a real identity/group pair remains reloadable when exactly
  one structurally valid nonzero group identifier exists. The storage migration
  does not decode provider-owned MLS state; malformed state may bind structurally
  but the MLS reload boundary still rejects it. Missing or ambiguous group scope
  rolls the migration back intact. Migration does not
  invent missing identity material: a legacy store has no reloadable client
  identity and must fail closed rather than pair a new signer with its old group.
- The real capability-admission/MLS composition uses an explicit
  durability-pending one-shot value. A proven SQL rollback releases its
  in-memory admission reservations and requires the transient MLS group to be
  discarded; an ambiguous result preserves them until recovery proves commit
  or rollback. No Welcome is exposed before committed recovery.
- The adapter retains SQLCipher's default memory policy, which locks and
  sanitizes its internal cryptographic allocations without enabling the
  optional process-wide wiping of every SQLite allocation.

The headless `sessionctl` laboratory now opens this adapter with a disposable
random raw key and proves exact identity/group reload after a real close/reopen
inside one process. The ADR 0021 runner additionally proves the same reload
contract after graceful Alice process exit and a fresh Alice process while Bob
and an untrusted forwarder remain separate. No platform protector supplies the
disposable raw key. SQLCipher is not a rollback anchor. The separate checked L2
laboratory now covers baseline-derived SQLite-visible failures, selected engine
commit-window writer kills, and local process kills at every baseline-observed
inviter and joiner application checkpoint. Raw observations remain non-public;
the retained L2-8 matrix lets only sealed complete aggregates emit canonical
per-case bundles after actual compiler/GitHub-run/runner-tuple and artifact
binding plus multi-surface secret/canary scans. Portable
passage remains conditional on the exact revision's required three-OS result;
this decision makes no production, secure-deletion, power-loss, filesystem,
rollback-resistance, product-recovery, or broader-platform claim. Vendoring
OpenSSL increases the audited source, native build, license, advisory, and
compile-time surface; the locked graph and dependency policy must therefore
cover it explicitly.

The durable client-identity record has this closed layout:

| Offset | Length | Meaning |
| ---: | ---: | --- |
| 0 | 8 | ASCII magic `SCMLSID1` |
| 8 | 1 | record version `1` |
| 9 | 1 | MLS protocol identifier `1` (MLS 1.0) |
| 10 | 2 | big-endian ciphersuite identifier `1` (`CURVE25519_AES128`) |
| 12 | 1 | provider representation identifier `1` (pinned AWS-LC adapter) |
| 13 | 32 | nonzero session-scoped BasicCredential identity |
| 45 | 32 | Ed25519 signing public key |
| 77 | 64 | AWS-LC Ed25519 signing secret representation |

The record is storage-internal, not a wire object. Unknown identifiers, wrong
length, zero fields, inconsistent key halves, or a failed domain-separated
sign/verify self-check are rejected before a client or group is returned.
A separate schema column binds the unchanged version-1 record to one group, so
the frozen identity format remains compatible without permitting a caller to
reinterpret the signer under a different group identifier.
A committed identity-v1 hex fixture uses RFC 8032 test-only Ed25519 material;
the load-only path must recover its exact credential and public key and produce
a KeyPackage accepted by the separate validator.

## Platform protector direction

Use the factual capability contract in `session-storage`; do not select one
generic keychain guarantee. ADR 0018 supersedes the earlier macOS-first
implementation order: select and prove one portable baseline on macOS, Windows,
and Linux before adding any native enhanced protector.

## Required next gates

- pass the checked L2 process-kill and SQLite-visible fault suites on required
  Linux, macOS, and Windows CI, with exact provenance and canary scanning before
  promoting their internal observations to public evidence;
- select and test one portable key-protection baseline on all three families;
- only then investigate enhanced macOS Keychain, Windows Hello/CNG, and concrete
  Linux Secret Service implementations in parallel;
- extend process-kill testing to the remaining production adapter write
  boundaries, outbox delivery, and migration/restore, plus disk full,
  truncation, tampering, rekey, backup, and deletion;
- extend the graceful independent-process identity/group reload beyond the
  checked local L2 process-kill laboratory with portable/public abrupt-kill,
  disk-full, and power-loss recovery evidence;
- select or explicitly defer a trusted monotonic rollback anchor; and
- independently review the exact MLS, SQLCipher, and platform-protector boundary.

## Alternatives

Plain SQLite, redb, and custom encrypted snapshots remain rejected for the
first adapter because they require Session Chat to design record encryption or
do not protect copied files. The disposable SQLCipher spike remains historical
compatibility evidence; production code must use the workspace adapter and its
real MLS integration tests.
