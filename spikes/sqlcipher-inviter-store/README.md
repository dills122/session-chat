# SQLCipher inviter-store compatibility spike

Status: local compatibility experiment passed; disposable and not production
storage

This isolated crate evaluates the exact stop conditions in
`docs/research/INVITER_STORAGE_ENGINE.md`. Production workspace crates do not
depend on it, and its independent lockfile records the native dependency graph
under evaluation.

The spike must not be used to claim product durability, rollback resistance,
or client-vault security. Its retained evidence is limited to the exact tested
platform, dependency graph, database configuration, and fault cases.

## Tested baseline

- macOS Darwin 25.5.0 on Apple silicon (`aarch64-apple-darwin`)
- Rust and Cargo 1.97.1
- `rusqlite` 0.40.1 with `bundled-sqlcipher`
- `libsqlite3-sys` 0.38.2
- bundled SQLCipher 4.14.0 Community Edition
- `mls-rs-core` 0.27.0

The independent `Cargo.lock` is part of the evidence. The production workspace
does not depend on this crate or its native dependency graph.

## What the spike proves

The retained tests show, on the tested baseline, that:

- an externally supplied, nonzero 32-byte raw vault key opens an encrypted
  database, while a different key fails before application data is read;
- the exact `mls-rs-core::group::GroupStateStorage` write, MLS epoch changes,
  invitation consumption, replay and approval records, result, endpoint, and a
  pending encrypted Welcome outbox row commit in one SQL transaction;
- a deterministic pre-commit failure rolls all those writes back, while a lost
  response after commit is recovered as the same complete transaction;
- an exact retry is idempotent and a changed retry conflicts;
- the closed main database does not contain the distinctive fixture plaintext
  or the normal SQLite header;
- a one-byte page mutation is rejected at open or by SQLCipher's integrity
  check; and
- a helper process exiting before SQL commit leaves the old complete state and
  a database that passes the integrity check after reopen.

The adapter uses one connection, rollback-journal mode, `synchronous=FULL`,
in-memory temporary storage, secure deletion, disabled trusted schemas, and
foreign-key enforcement. Public errors are coarse, application values use
bound SQL parameters, and retained sensitive Rust buffers are zeroized on drop.

## Run the retained evidence

From the repository root:

```sh
cargo fmt --manifest-path spikes/sqlcipher-inviter-store/Cargo.toml --check
cargo clippy --manifest-path spikes/sqlcipher-inviter-store/Cargo.toml \
  --all-targets --locked --offline -- -D warnings
cargo test --manifest-path spikes/sqlcipher-inviter-store/Cargo.toml \
  --locked --offline
```

## Limits and next gates

This result does **not** prove:

- Linux or Windows build, packaging, crypto-provider, or fault behavior;
- survival of power loss, dishonest storage flushes, disk exhaustion, or file
  truncation;
- a platform keychain, secure-hardware, or user-presence vault adapter—the test
  caller supplies the raw key;
- unlock, relock, rekey, backup, migration, deletion, or cryptographic-erasure
  lifecycle behavior;
- rollback resistance when an attacker restores a valid older encrypted copy;
- durable outbox leasing and acknowledgement beyond atomically creating the
  pending outbox row;
- the joining device's separate KeyPackage-deletion transaction; or
- a call from Session Chat's MLS adapter through an actual
  `Group::write_to_storage` operation. The spike directly exercises its exact
  `GroupStateStorage::write` provider boundary.

The abrupt-exit fixture models an application-process crash, not power loss or
hardware persistence. SQLCipher Community Edition also carries its own
BSD-style attribution requirements. Before production selection, the same
dependency pins and fault model need cross-platform CI, dependency and license
review, a real platform-vault adapter, and integration through the Session Chat
MLS adapter.

Primary design references:

- [SQLCipher API: keying and raw keys](https://www.zetetic.net/sqlcipher/sqlcipher-api/#pragma-key)
- [SQLCipher design](https://www.zetetic.net/sqlcipher/design/)
- [SQLCipher licensing](https://www.zetetic.net/sqlcipher/license/)
- [SQLite atomic commit](https://www.sqlite.org/atomiccommit.html)
