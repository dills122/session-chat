# Inviter transaction storage and vault-key decision packet

Status: recommendation awaiting architecture-owner approval; no storage
dependency selected or added

Reviewed: 2026-08-20

## Decision question

Which embedded storage approach should be spiked for the inviter-local ADR 0008
transaction while preserving the client-vault requirement that copied state is
not useful without an externally unsealed key?

The project owner decides whether to authorize the dependency spike. This packet
does not authorize production storage, a public durability claim, or a release
dependency.

## Executive conclusion

Run a bounded SQLCipher Community Edition compatibility spike through exact
`rusqlite` 0.40.1 bindings. Supply a raw 32-byte database key from a separate
vault-key interface; never derive or retain that key in the database. Start with
one connection, rollback-journal mode, full synchronization, and one SQL
transaction containing the MLS storage write plus invitation, replay, approval,
result, and encrypted Welcome outbox rows.

Do not adopt the spike unless it proves all of the following:

- Linux, macOS, and Windows builds can be pinned and reproduced in CI;
- the resolved SQLCipher, native crypto, and transitive dependency graph passes
  license, advisory, source, and duplicate review;
- a copied main database, rollback journal, WAL, and temporary artifact reveal
  no Session Chat state without the external key;
- wrong-key, tampering, truncation, disk-full, process-kill, and power-loss
  simulations fail closed to either the old complete state or the new complete
  state;
- the pinned `mls-rs` group snapshot and epoch records participate in the same
  SQL transaction as every Session Chat row; and
- unlock, lock, rekey, backup, migration, and deletion behavior satisfy the
  client-vault contract.

This is a high-confidence recommendation for the next experiment, not yet a
production selection. SQLCipher does not provide rollback resistance against a
valid older database copy; that still needs a trusted monotonic anchor or an
explicitly documented limitation.

## Method and scope

Preferred evidence was current primary documentation from SQLite, SQLCipher,
`rusqlite`, redb, and the exact locally pinned `mls-rs` source. The comparison
criteria were:

1. one crash-recoverable local transaction across every inviter-owned value;
2. confidentiality and integrity of copied files while the app vault is sealed;
3. compatibility with a raw externally managed vault key;
4. a narrow, replaceable Rust adapter surface;
5. cross-platform build and dependency-governance cost; and
6. an honest path to fault injection and retained evidence.

Hosted databases, remote key services, server persistence, multi-device sync,
and a final platform keychain choice were outside scope.

## Evidence

### SQLite and `rusqlite`

**Documented fact.** SQLite describes atomic commit as all database changes
appearing together even across operating-system crash or power failure, subject
to its VFS, filesystem, and hardware assumptions. Its detailed atomic-commit
paper covers rollback-journal mode; WAL uses a different mechanism.
[SQLite atomic commit](https://www.sqlite.org/atomiccommit.html)

**Documented fact.** WAL with `synchronous=NORMAL` can lose durability after a
power loss because commits need not issue an I/O barrier. Performance-oriented
defaults therefore cannot be copied into this security boundary without an
explicit durability configuration and fault tests.
[SQLite WAL documentation](https://www.sqlite.org/wal.html)

**Documented fact.** The current `rusqlite` README identifies 0.40.1 and says
the `bundled` feature is normally appropriate for applications that control
their own database. It separately exposes `bundled-sqlcipher` and
`bundled-sqlcipher-vendored-openssl`; the former needs a platform crypto library
and the latter adds vendored OpenSSL.
[`rusqlite` README](https://github.com/rusqlite/rusqlite/blob/master/README.md)

**Inference.** Plain bundled SQLite is a good atomicity oracle but is not an
acceptable vault store by itself. Encrypting selected application values would
leave schema and access metadata visible and would create a separate nonce,
key-derivation, migration, and deletion protocol. That option should be kept as
a fallback only if the full-database spike fails.

### SQLCipher

**Documented fact.** SQLCipher encrypts database pages and authenticates each
page with an HMAC. It supports raw binary key material specifically for vaulted
keys. Its documentation states that rollback-journal and WAL page data are
encrypted with the database key, subject to the documented temporary-store
build configuration.
[SQLCipher design](https://www.zetetic.net/sqlcipher/design/)

**Documented fact.** SQLCipher Community Edition uses a BSD-style license with
user-accessible attribution requirements. Commercial editions add packaged
builds and private support; those claims are not inherited by the community
edition.
[SQLCipher license](https://www.zetetic.net/sqlcipher/license/)

**Inference.** SQLCipher best matches the sealed-vault copied-file requirement
without inventing Session Chat record encryption. The trade-off is a native
cryptographic provider and packaging surface that must remain isolated behind a
storage adapter and tested on every supported platform.

**Unknown.** The exact resolved SQLCipher source revision, native provider, and
license graph for the proposed feature combination have not entered
`Cargo.lock`. They must be recorded by the spike rather than inferred from the
wrapper version.

### redb

**Documented fact.** redb describes itself as a stable, pure-Rust, ACID,
crash-safe embedded store with transactions and savepoints.
[redb repository](https://github.com/cberner/redb)

**Documented fact.** redb's default durable commit uses a non-cryptographic
XXH3 checksum. Its own API documentation describes a theoretical malicious
workload/crash attack and offers a two-phase mode with additional `fsync`, while
also stating the remaining hardware persistence limitation.
[redb write transactions](https://docs.rs/redb/latest/redb/struct.WriteTransaction.html)

**Inference.** redb remains a credible pure-Rust transaction engine but does
not solve at-rest confidentiality. Adding application encryption would recreate
the same custom record-crypto problem as plain SQLite, and its documented
malicious-crash caveat adds a configuration burden at this attacker-controlled
boundary. It is not the preferred first spike.

### Exact `mls-rs` storage boundary

**Observation.** At repository commit
`52a73dcaf0a3b122050922406dedf51eb7049c21`, the locked graph contains
`mls-rs` 0.56.0 and `mls-rs-core` 0.27.0. The local source exposes one
`GroupStateStorage::write` call containing a complete `GroupState`, epoch
inserts, and epoch updates. `Group::write_to_storage` serializes a snapshot and
invokes that provider hook. The current Session Chat adapter deliberately does
not expose durable group writes.

**Inference.** The future SQLCipher adapter must implement this provider hook
as a participant in an already-open inviter transaction. A provider that opens
and commits an independent database transaction cannot satisfy ADR 0008. The
join result also cannot be exposed as committed until that shared transaction
returns a known success or is recovered by transaction ID.

## Option comparison

| Option | Atomicity | Sealed copied files | Integration cost | Result |
| --- | --- | --- | --- | --- |
| Plain SQLite | Strong engine evidence | No | Low | Test oracle only |
| SQLite plus record AEAD | Strong engine evidence | Partial/design-dependent | High custom protocol cost | Fallback |
| SQLCipher through `rusqlite` | Strong engine evidence | Best documented fit | Native build/provider cost | Recommended spike |
| redb | ACID; documented crash modes | No | Low Rust cost, high crypto-design cost | Do not spike first |
| Custom encrypted snapshot files | Must be designed and proved | Design-dependent | Highest correctness cost | Reject |

## Proposed spike boundary

The spike should add no product API. It should implement a private adapter for
the `session-inviter-transaction` conformance contract and the exact `mls-rs`
storage hook, then run only deterministic fixtures and destructive temporary
database tests.

Required configuration and checks:

- exact dependency pins and committed lockfile;
- dynamic extension loading disabled;
- file-backed temporary stores disabled or proven encrypted;
- one connection and one writer for Phase 1;
- rollback journal plus full synchronization for the first evidence baseline;
- raw key injection only after vault unlock, immediate close on lock;
- key and plaintext buffers excluded from `Debug`, logs, panic messages, and
  generic serialization;
- schema versioning and fail-closed migrations;
- explicit size, row-count, retry, lease, and transaction-duration limits;
- process-kill fault points before, during, and after commit;
- byte inspection of every created file while closed; and
- recovery that never repeats MLS Add or releases a committed invitation.

## Evidence that would change the recommendation

- A cross-platform build or license blocker in the exact SQLCipher graph would
  move the fallback comparison to plain SQLite versus redb plus a reviewed
  application-encryption format.
- Proof that the `mls-rs` hook cannot participate in the same open transaction
  would stop this integration and require a different MLS persistence boundary.
- A platform vault that can securely mount an encrypted transactional store
  with stronger lifecycle guarantees could remove the SQLCipher dependency,
  but must still pass the same copied-file and crash tests.

## Required owner decision

Approve or reject a disposable SQLCipher compatibility spike. Approval means
the exact dependency graph may be added on a feature branch for evaluation; it
does not approve production use, a release claim, or a permanent provider.
