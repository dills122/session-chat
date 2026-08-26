# SQLCipher durable Welcome-outbox fault decision packet

Status: bounded implementation input; no durable-outbox or power-loss claim

Date: 2026-08-25

## Decision summary

Evolve `storage-sqlcipher` from schema version 1 to version 2 before implementing
`WelcomeOutboxPort`. Version 2 should give the Welcome a single authoritative
outbox row, retain the exact encrypted envelope and deposit endpoint, and add a
durable store identifier, per-row delivery-attempt count, per-row monotonic
lease generation, lease expiry, configured attempt ceiling, and explicit
pending, leased, delivered, and attempts-exhausted states.

Use one `BEGIN IMMEDIATE` transaction for each lease acquisition or result
transition. Use one `BEGIN EXCLUSIVE` transaction for the v1-to-v2 schema
migration. Preserve the current rollback-journal `DELETE` mode and
`synchronous=FULL` baseline for this increment. A move to WAL or
`synchronous=EXTRA` changes the retained storage contract and should be a later
explicit decision supported by its own sidecar, backup, performance, and fault
evidence.

The implementation gate should contain three complementary kinds of evidence:

1. deterministic state-transition faults in ordinary Rust tests;
2. a cross-platform child-process harness that kills a disposable writer only
   after an explicit boundary handshake; and
3. a test-only SQLite VFS shim that injects `SQLITE_FULL` and extended
   `SQLITE_IOERR_*` results at named file operations.

A privileged device-mapper lab is useful additional Linux evidence. It is not
a substitute for the portable suite and must never target a user database or a
developer's normal filesystem.

The strongest honest result from this spine is: after an application-process
kill or injected SQLite-visible storage error, reopen exposes either the old
complete owner state or the new complete owner state, and coordinator recovery
does not repeat MLS membership mutation. It cannot establish resistance to a
lying drive, real power loss, filesystem firmware defects, stale but valid
database restoration, secure deletion, production packaging, or broad
hardware compatibility.

## Scope and evidence labels

This packet owns research and repository inspection only. It does not change a
schema, production code, tests, manifests, plans, ADRs, or CI.

The following labels are used deliberately:

- **Sourced fact** is supported by an upstream primary source.
- **Repository observation** describes `origin/master` at
  `ca330027703c175775d1300e8758a84db4adff47`.
- **Recommendation** is a concrete implementation input derived from those
  facts and observations.
- **Unresolved risk** is not converted into a security or durability claim.

## Repository observations

- `storage-sqlcipher` pins `rusqlite` 0.40.1 and bundled SQLCipher 4.14.0 with
  vendored OpenSSL. The bundled source identifies SQLite 3.51.3.
- `SqlCipherStorage` owns one `Connection` behind a mutex, opens it with
  `SQLITE_OPEN_READ_WRITE | SQLITE_OPEN_NO_MUTEX`, and adds `CREATE` only for a
  new database.
- Every open sets rollback-journal `DELETE`, `synchronous=FULL`,
  `temp_store=MEMORY`, `secure_delete=ON`, `trusted_schema=OFF`, and
  `foreign_keys=ON`, but does not read back every requested value.
- Schema v1 stores exactly one integer in `storage_metadata`, but the table has
  no singleton key and can physically contain multiple rows. Open reads one
  unspecified row and requires value 1.
- Schema v1 keeps Welcome bytes, endpoint bytes, expiry, and
  `outbox_state` in `inviter_joins`; the only permitted outbox state is 1.
- The real MLS inviter write, invitation consumption, approval/replay values,
  and pending Welcome are already committed in one `BEGIN IMMEDIATE`
  transaction. Deterministic tests cover a known pre-commit rollback and an
  artificial result lost after a successful commit.
- The current adapter has no migration path, no durable lease/result methods,
  no process-kill harness, no storage-I/O fault harness, and no stale-snapshot
  detection.
- The in-memory owner model now has pending, leased, delivered, and
  attempts-exhausted states. Leasing increments attempts, issues a scoped
  monotonic identity, permits an expired lease to be replaced, and rejects
  stale or foreign results. `WelcomeOutboxPort` consumes an opaque lease and
  keeps the coordinator free of a second ledger.
- Current CI already runs the complete Rust workspace on `ubuntu-24.04` x64,
  `macos-15` arm64, and `windows-2025` x64 with Rust 1.97.1.

These observations mean a thin trait implementation over schema v1 would be
misleading. It could not preserve the already accepted owner semantics across
reopen.

## Primary-source findings

### Transactions and ambiguous outcomes

**Sourced fact.** SQLite permits one writer at a time. `BEGIN IMMEDIATE` starts
the write transaction immediately and may return `SQLITE_BUSY`; in rollback
journal mode, `BEGIN EXCLUSIVE` additionally blocks other readers. A reader
that keeps a read transaction open continues to see its historical snapshot
until that transaction ends. [SQLite transaction documentation](https://www.sqlite.org/lang_transaction.html)

**Sourced fact.** `SQLITE_FULL`, `SQLITE_IOERR`, interruption, and out-of-memory
errors may roll back the current statement or the complete transaction,
depending on where they occur. SQLite tells C callers to inspect autocommit or
transaction state and says an explicit rollback is a safe way to normalize the
post-error state. [SQLite transaction error behavior](https://www.sqlite.org/lang_transaction.html#response_to_errors_within_a_transaction),
[autocommit state](https://www.sqlite.org/c3ref/get_autocommit.html), and
[transaction state](https://www.sqlite.org/c3ref/txn_state.html)

**Sourced fact.** `rusqlite` 0.40.1 maps `TransactionBehavior::Immediate` and
`Exclusive` to the corresponding `BEGIN` forms. Its transaction owner rolls
back on drop by default, while `commit()` is an explicit consuming operation.
It also exposes the underlying SQLite extended error code.
[`rusqlite` 0.40.1 transaction source](https://github.com/rusqlite/rusqlite/blob/v0.40.1/src/transaction.rs)

**Recommendation.** Treat every failure after COMMIT has been invoked as an
ambiguous result at the Session Chat boundary, even if the immediate SQLite
connection can report its current transaction state. Close the connection
without making a different state transition, reopen with the same key, run the
integrity gates, and recover by the exact transaction or lease identity. An
in-process status check is useful diagnostic evidence, not a substitute for
reopen recovery after a process could have died.

### Rollback journal, WAL, and filesystem assumptions

**Sourced fact.** In rollback-journal mode with full synchronization, SQLite
flushes the rollback journal, writes and flushes database pages, and uses the
journal's existence as the apparent commit boundary. On reopen, a hot journal
is played back before normal access. The guarantee depends on correct VFS,
filesystem, and device behavior; SQLite explicitly documents incomplete flush,
partial delete, and garbage-write failure modes.
[SQLite atomic commit](https://www.sqlite.org/atomiccommit.html)

**Sourced fact.** `synchronous=EXTRA` adds a directory sync after unlinking the
rollback journal in `DELETE` mode. SQLite says this can prevent a just-committed
transaction from being rolled back after closely following power loss on some
filesystems; without it, SQLite says the database should not become corrupt.
[SQLite synchronous pragma](https://www.sqlite.org/pragma.html#pragma_synchronous)

**Recommendation.** Retain ADR 0017's `FULL` setting for this bounded process-
restart spine and state that it does not prove real power-loss durability. Do
not silently switch to `EXTRA`; measure it and revise the storage decision if a
future claim requires the stronger directory-sync behavior.

**Sourced fact.** In WAL mode, a commit record is appended to the WAL and later
checkpointed to the main database. The WAL is persistent database state; moving
or copying the main file without its WAL can lose committed transactions or
corrupt the database. Long-lived readers can also prevent a checkpoint from
finishing. [SQLite WAL documentation](https://www.sqlite.org/wal.html)

**Sourced fact.** SQLCipher documents that database, rollback-journal, and WAL
page data are encrypted with the database key when its documented temporary-
store requirements are satisfied. `cipher_integrity_check` verifies page HMACs
and reports one row per invalid page or size error.
[SQLCipher design](https://www.zetetic.net/sqlcipher/design/) and
[SQLCipher API](https://www.zetetic.net/sqlcipher/sqlcipher-api/#pragma-cipher-integrity-check)

**Recommendation.** Keep `DELETE` as the only accepted runtime mode in this
increment and verify that the returned mode is exactly `delete`. Add a separate
WAL laboratory fixture solely to prove that the harness preserves `-wal` and
`-shm` as a unit and detects a missing sidecar. Do not use WAL results to claim
the product path is WAL-safe.

### Application-schema migration

**Sourced fact.** SQLite reserves `PRAGMA user_version` for application use but
does not interpret it. SQLite's safe general table-rebuild procedure creates a
new table, copies data, drops the old table, renames the new table, performs a
foreign-key check, and commits the surrounding transaction. It warns against
editing `sqlite_schema` directly unless the exact specialized procedure is
followed. [SQLite pragma documentation](https://www.sqlite.org/pragma.html#pragma_user_version)
and [ALTER TABLE procedure](https://www.sqlite.org/lang_altertable.html#making_other_kinds_of_table_schema_changes)

**Sourced fact.** `PRAGMA integrity_check` does not report foreign-key errors;
`PRAGMA foreign_key_check` is separate. Unknown pragmas are silently ignored,
so setting a pragma without reading back its result is not enough evidence.
[SQLite pragma documentation](https://www.sqlite.org/pragma.html)

**Sourced fact.** SQLCipher's `cipher_migrate` migrates databases created with
older SQLCipher major-version defaults. It is not an application table-schema
migrator, and custom cipher settings require a different export procedure.
[SQLCipher migration API](https://www.zetetic.net/sqlcipher/sqlcipher-api/#pragma-cipher-migrate)

**Recommendation.** Do not call `cipher_migrate` for schema v1 to v2. The
pinned SQLCipher format is unchanged; this is a Session Chat schema migration.

### Fault injection and process termination

**Sourced fact.** SQLite's VFS interface owns file operations including read,
write, truncate, sync, locking, shared-memory, and device-characteristic
reporting. SQLite documents test VFS shims that impose quotas and return
`SQLITE_FULL`, check journal/sync ordering, and simulate filesystem faults.
SQLite's own I/O tests advance a deterministic fail point, run both one-shot
and persistent failures, disable the fault, then run integrity checks. Its
crash tests use another VFS and a separate process.
[SQLite VFS](https://www.sqlite.org/vfs.html),
[VFS I/O methods](https://www.sqlite.org/c3ref/io_methods.html), and
[SQLite testing](https://www.sqlite.org/testing.html#io_error_testing)

**Sourced fact.** SQLite distinguishes `SQLITE_FULL` from `SQLITE_IOERR` and
publishes extended I/O codes for read, write, sync, truncate, delete, directory
sync, locking, and other operations. A full disk normally returns
`SQLITE_FULL`; it may refer to a temporary filesystem rather than the main
database filesystem. [SQLite result codes](https://www.sqlite.org/rescode.html)

**Sourced fact.** Rust's `Child::kill()` forces a child to exit and is
equivalent to `SIGKILL` on Unix. On Windows, `TerminateProcess` stops all
threads, requests cancellation of pending I/O, and is asynchronous until the
caller waits for termination.
[Rust `Child::kill`](https://doc.rust-lang.org/std/process/struct.Child.html#method.kill)
and [Windows `TerminateProcess`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess)

**Recommendation.** Use a parent/child handshake rather than sleeps: the child
reports a named boundary over inherited IPC, the parent acknowledges it, kills
the child, waits for termination, then opens the same disposable database in a
fresh verifier process. This is deterministic at Session Chat boundaries. A
VFS fault at `xWrite`, `xSync`, `xTruncate`, or `xDelete` covers engine-internal
write boundaries that an application hook cannot name.

**Sourced fact.** Linux `dm-flakey` is specifically intended to simulate an
unreliable block device and can fail reads, fail writes, silently drop writes,
or corrupt selected I/O during configured intervals.
[Linux kernel `dm-flakey` documentation](https://docs.kernel.org/admin-guide/device-mapper/dm-flakey.html)

**Recommendation.** Use only `error_reads` and `error_writes` in the first
privileged lab. Defer `drop_writes` and corruption until the harness has a
reviewed expected-state oracle; silent loss deliberately violates the VFS
assumptions and must not be mislabeled as ordinary SQLite-visible I/O failure.

### Three-OS evidence and reproducibility

**Sourced fact.** GitHub publishes Ubuntu, macOS, and Windows hosted runner
images, but updates GA images weekly and tells users to recover the exact image
version and software versions from the job setup log. Fixed OS labels avoid a
`-latest` major-OS migration but do not freeze the hosted image contents.
[GitHub runner-images](https://github.com/actions/runner-images)

**Recommendation.** Continue the repository's explicit
`ubuntu-24.04`/`macos-15`/`windows-2025` matrix, and put the runner image
version, OS/kernel version, architecture, Rust verbose version, Cargo.lock
digest, SQLCipher/SQLite/provider versions, journal/synchronous readback, test
binary hash, scenario ID, fault point, seed, and database-artifact hashes in
the bounded evidence manifest. This establishes repeatable inputs and traceable
hosted runs, not bit-for-bit runner or binary reproducibility.

## Exact schema-v2 recommendation

Use stable numeric values in the database and closed Rust enums at the API:

| Value | Meaning |
| ---: | --- |
| 1 | pending |
| 2 | leased |
| 3 | delivered (adapter acceptance recorded) |
| 4 | attempts exhausted |

Rebuild `storage_metadata` as a singleton:

```sql
CREATE TABLE storage_metadata_v2 (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    schema_version INTEGER NOT NULL CHECK(schema_version = 2),
    store_instance_id BLOB NOT NULL UNIQUE
        CHECK(length(store_instance_id) = 16)
) STRICT;
```

Rebuild `inviter_joins` without Welcome-delivery columns, retaining all current
membership, invitation, replay, approval, and exact-retry constraints. Create
one authoritative one-to-one outbox table:

```sql
CREATE TABLE welcome_outbox_v2 (
    transaction_id BLOB NOT NULL PRIMARY KEY
        REFERENCES inviter_joins_v2(transaction_id) ON DELETE RESTRICT
        CHECK(length(transaction_id) = 16),
    welcome BLOB NOT NULL CHECK(length(welcome) BETWEEN 1 AND 65536),
    endpoint BLOB NOT NULL CHECK(length(endpoint) BETWEEN 1 AND 4096),
    outbox_expires_at INTEGER NOT NULL CHECK(outbox_expires_at > 0),
    state INTEGER NOT NULL CHECK(state IN (1, 2, 3, 4)),
    delivery_attempts INTEGER NOT NULL
        CHECK(delivery_attempts BETWEEN 0 AND 32),
    maximum_delivery_attempts INTEGER NOT NULL
        CHECK(maximum_delivery_attempts BETWEEN 1 AND 32),
    lease_generation INTEGER NOT NULL CHECK(lease_generation >= 0),
    lease_expires_at INTEGER,
    CHECK(lease_generation = delivery_attempts),
    CHECK(lease_expires_at IS NULL OR lease_expires_at > 0),
    CHECK(lease_expires_at IS NULL OR lease_expires_at <= outbox_expires_at),
    CHECK(
        (state = 1 AND lease_expires_at IS NULL
                   AND delivery_attempts < maximum_delivery_attempts)
        OR (state = 2 AND lease_expires_at IS NOT NULL
                      AND delivery_attempts BETWEEN 1 AND maximum_delivery_attempts)
        OR (state = 3 AND lease_expires_at IS NULL
                      AND delivery_attempts BETWEEN 1 AND maximum_delivery_attempts)
        OR (state = 4 AND lease_expires_at IS NULL
                      AND delivery_attempts = maximum_delivery_attempts)
    )
) STRICT;
```

The implementation may choose different temporary table names, but should not
weaken these relationships. `maximum_delivery_attempts` belongs in the row so a
configuration change after restart cannot reinterpret already committed work.
The initial inviter transaction must insert state 1, attempts 0, generation 0,
NULL lease expiry, and the bounded attempt ceiling in the same transaction as
MLS state and invitation consumption.

The opaque lease should contain, without diagnostics or serialization:

- a process-local `Arc` scope shared only by clones of one open store;
- the 16-byte durable store instance identifier;
- the 16-byte inviter transaction identifier; and
- the exact nonzero lease generation returned by the acquisition transaction.

The process scope rejects a token retained across close/reopen in the same
process. The durable store identifier rejects a token from a different
database. The transaction ID and generation reject ABA after re-lease. A copied
stale database also copies its store identifier, so this construction does not
provide rollback detection.

## Exact v1-to-v2 migration transaction

### Entry classification

After keying and proving a nonempty `cipher_version`, classify before mutation:

- accept v1 only when `PRAGMA user_version` is 0, exactly one metadata row says
  1, and the complete structural v1 fingerprint matches;
- accept v2 only when `PRAGMA user_version` is 2, exactly one singleton row says
  2 with a valid nonzero 16-byte store identifier, and the complete structural
  v2 fingerprint matches;
- reject all future versions, duplicate/missing metadata rows, version pairs
  other than `(0, 1)` and `(2, 2)`, and any schema/version mismatch;
- never infer a version from “most of the expected columns” and never repair a
  partial migration in place.

The structural fingerprint should enumerate `sqlite_schema`, `table_xinfo`,
`foreign_key_list`, and `index_list` for every owned table. It should validate
closed table/index names and exact column order, affinity, nullability, primary
keys, foreign keys, and critical CHECK constraints. A hash of raw SQL text may
be retained as fixture evidence, but should not be the only runtime check.

### Transaction body

Run the following logical sequence through
`TransactionBehavior::Exclusive`; do not use `execute_batch` in a way that
hides which assertion failed:

1. Recheck the exact v1 classification inside the transaction.
2. Generate one nonzero random 16-byte store identifier. It is an identifier,
   not a database encryption key or rollback anchor.
3. Create `storage_metadata_v2`, `inviter_joins_v2`, and
   `welcome_outbox_v2` with exact closed definitions.
4. Copy the one metadata record as version 2 plus the new store identifier.
5. Copy every inviter membership record to `inviter_joins_v2`.
6. Copy every v1 Welcome, endpoint, and expiry to `welcome_outbox_v2` as
   pending with attempts/generation 0, NULL lease expiry, and the selected
   bounded attempt ceiling.
7. Prove old/new inviter and outbox row counts match; prove every v1 inviter
   maps to exactly one v2 outbox row; and prove all copied byte values and
   scalar values compare exactly.
8. Drop the old `inviter_joins` and `storage_metadata` tables, then rename
   `inviter_joins_v2`, `welcome_outbox_v2`, and `storage_metadata_v2` to their
   final names. Recreate only the reviewed v2 indices.
9. Run `PRAGMA foreign_key_check` and reject any returned row.
10. Set `PRAGMA user_version = 2`, read it back as 2, and re-run the complete
    v2 structural and relational assertions inside the transaction.
11. Commit exactly once.

After commit, close and reopen. Require exact v2 classification,
`cipher_integrity_check` with no rows, `quick_check` equal to `ok`, an empty
`foreign_key_check`, exact recovery of every membership/outbox fixture, and
successful idempotent open without another migration.

If any statement or assertion before COMMIT fails, explicitly roll back and
close. If COMMIT returns an error or the process dies after entering it, classify
the outcome only by reopening: exact v1 is a clean rollback, exact v2 is a clean
commit, and anything else is a hard failure retained for investigation. Do not
write a marker outside the database and do not “finish” a mixed schema.

## Compatibility-fixture strategy

Retain all fixtures under an obviously non-production test key and generated
identity set. No fixture may contain a real invitation, MLS state, capability,
or user database.

1. **Immutable encrypted v1 binary.** Retain one closed SQLCipher v1 database,
   its public test key in test code, SHA-256 digest, creator command, SQLCipher
   4.14.0/SQLite 3.51.3 settings, and a secret-free manifest of expected rows.
   This detects accidental loss of actual on-disk compatibility.
2. **Fresh v1 builder.** Build the exact v1 DDL at test time and populate empty,
   one-row, maximum-size, and multi-row bounded cases. This makes boundary
   failures understandable without hand-editing ciphertext.
3. **Canonical v2 builder.** Create a fresh v2 database and compare its
   structural manifest and behavior to migrated v1 fixtures.
4. **Negative version fixtures.** Construct disposable keyed databases for
   missing/duplicate metadata, future version, v1 schema with version 2, v2
   schema with version 1, incomplete v2 tables, illegal state tuples, orphaned
   outbox rows, and out-of-range lengths. Each must fail before application
   mutation.
5. **Migration fault fixtures.** Kill or fault a child at every numbered
   migration boundary. Reopen must classify as exact v1 or exact v2 only. Keep
   no pre-mutated fixture between test cases; copy the immutable fixture into a
   unique disposable directory first.
6. **Forward-open fixture.** Version 3 must fail with an explicit unsupported-
   version category, never a wrong-key or generic “new database” path.

Do not generate the only v1 fixture using the new migration code. Do not mutate
checked-in encrypted bytes to simulate partial schemas; construct malformed
databases with known test DDL so failures are intentional and reviewable.

## Durable lease and result semantics

### Lease acquisition

In one `BEGIN IMMEDIATE` transaction:

1. terminalize an expired last-attempt lease as attempts exhausted;
2. select at most one eligible row in deterministic transaction-ID order;
3. require `outbox_expires_at > now + lease_seconds`, attempts below the stored
   ceiling, and either pending state or a lease whose expiry is at or before
   `now`;
4. compare-and-set that exact row to leased, increment attempts and generation
   exactly once, set the exact lease expiry, and return the exact stored bytes;
5. require exactly one changed row, commit, and only then construct
   `LeasedWelcome`.

No row is eligible when its outbox has expired, its live lease has not expired,
it is delivered, or it is exhausted. A storage error must not cause the caller
to receive bytes without a committed lease.

### Accepted result

In one `BEGIN IMMEDIATE` transaction, first compare the process scope and then
the durable store identifier. Update only the exact transaction in leased state
with the exact generation while both the lease and outbox remain unexpired.
Set delivered and clear lease expiry. An already-delivered row with the same
generation is idempotent success; every other state/generation is a conflict.
Membership, reservation, replay, approval, envelope, endpoint, expiry, attempts,
and generation remain unchanged.

If COMMIT is ambiguous, the store should immediately recover internally when
possible. Delivered with the same generation is success; the exact lease still
present is an unknown result that may later expire; any other generation is a
conflict. The public owner-port error can remain coarse. Safety does not require
the coordinator to own a recovery ledger.

### Failed result

In one `BEGIN IMMEDIATE` transaction, change only the exact live generation.
Return it to pending with NULL lease expiry when attempts remain; otherwise set
attempts exhausted with NULL lease expiry. A result from an older generation,
another store, a delivered row, or a row already re-leased is rejected.

If this COMMIT is ambiguous, reopen may show pending/exhausted or the old lease.
Both are safe: only the owner store decides later eligibility, and membership
never changes. Exact state is recovered rather than guessed.

### Adapter acceptance ambiguity

Adapter acceptance and local delivered-state commit cannot be one atomic
transaction. If the process dies after remote acceptance but before the local
result commits, the row remains leased. After expiry it is retried with the
byte-identical envelope and endpoint. The LocalV1 adapter's exact-envelope
idempotency must collapse that retry. This is duplicate-tolerant acceptance,
not exactly-once network delivery, recipient receipt, or recipient processing.

## Write-boundary fault matrix

Each row runs against a unique disposable copy, disables the fault before
verification, closes every surviving handle, reopens in a fresh verifier
process, and runs SQLCipher HMAC, SQLite quick, foreign-key, schema, and semantic
checks.

| Boundary or fault | Injection | Required reopen result | Stable scenario |
| --- | --- | --- | --- |
| Before owner transaction begins | application hook + child kill | reservation only; no MLS, join, or outbox row | `E2E-TXN-001` |
| After MLS pages are staged | hook, VFS `xWrite`, kill | exact old state or complete committed state; never MLS without consumed invitation/outbox | `E2E-TXN-001` |
| After inviter row is staged | hook + kill | exact old or complete new state | `E2E-TXN-001` |
| After outbox row is staged | hook + kill | exact old or complete new state | `E2E-TXN-001` |
| After reservation consumption is staged | hook + kill | exact old or complete new state | `E2E-TXN-001` |
| Journal write/sync, main write/sync, journal delete | VFS fail point + kill sweep | old complete or new complete; hot journal recovers; no mixed visibility | `E2E-TXN-001` |
| COMMIT returned, caller result lost | hook + kill | complete new state; exact transaction retry does not repeat MLS | `E2E-TXN-001` |
| Lease selected but not updated | hook + kill | previous pending/expired-lease state | `E2E-MSG-002` |
| Lease update before commit | hook/VFS/kill | old eligibility or one committed new generation; attempts increment at most once | `E2E-MSG-002` |
| Lease COMMIT result lost | hook + kill | new lease recovered; no second lease until expiry | `E2E-MSG-002` |
| Stale result after re-lease | deterministic two-worker schedule | old generation cannot deliver or release new generation | `E2E-MSG-002` |
| Foreign-store result | lease from separately created database | no mutation | `E2E-AUTH-001` |
| Adapter failed before acceptance | coordinator fault + result transaction faults | exact lease becomes pending/exhausted or remains until expiry | `E2E-MSG-002` |
| Adapter accepted, process killed before report | adapter handshake + kill | lease expires; byte-identical retry; one membership commit | `E2E-MSG-002` |
| Accepted-result update before/during/after commit | hook/VFS/kill | leased or delivered at same generation; never pending through success path | `E2E-MSG-002` |
| Failed-result update before/during/after commit | hook/VFS/kill | leased, pending, or exhausted according to one committed transition | `E2E-MSG-002` |
| Last attempt crashes then lease expires | hook + explicit clock | next acquisition terminalizes exhausted and emits no work | `E2E-RETENTION-001` |
| `SQLITE_FULL` on journal/main write; unexpected file-backed temp | quota VFS, every operation index | coarse failure; old/new complete state; no leaked work; baseline proves no file-backed temp | `E2E-TXN-001`, `E2E-ABUSE-001` |
| Extended I/O failure on read/write/sync/truncate/delete/lock | VFS, one-shot and persistent modes | no mixed state; persistent error fails closed; clean reopen after disabling fault | `E2E-TXN-001` |
| Read transaction held across writer commit | two connections + barrier | old reader keeps old snapshot; new transaction/reopen sees new complete state | `E2E-TXN-001` |
| v1 migration at every numbered step | hook/VFS/kill | exact v1 or exact v2 only | `E2E-UPGRADE-001` |
| WAL commit before/after checkpoint | WAL-only lab with complete sidecar set | complete state when all sidecars retained | `E2E-UPGRADE-001` |
| WAL main file copied without sidecars | intentionally defective lab copy | harness detects loss/rejection; never accepted as valid backup method | `E2E-UPGRADE-001` |
| Restore a valid older closed snapshot | replace only disposable test directory | current design reopens old state; record missing rollback detection as expected gap | `E2E-RESTORE-001` |
| Fault while recovering a prior hot journal | stacked VFS fault | fail closed; next clean reopen remains recoverable or emits a retained hard failure | `E2E-TXN-001` |

For every atomicity case, assert the full cross-product, not just row counts:
reservation state, exact MLS snapshot/epoch, inviter transaction identity,
approval/replay values, outbox bytes, state, attempts, generation, and lease
expiry. “Integrity check passed” alone does not prove Session Chat atomicity.

## Safe harness design

### Portable required suite

- Put faulting native/VFS support in a test-only support crate or reviewed C
  shim. `storage-sqlcipher` forbids unsafe Rust; do not weaken that production
  boundary to register a VFS.
- Select the named VFS through `rusqlite`'s existing
  `open_with_flags_and_vfs` path. Never register it as the process default for
  unrelated tests.
- Tag each SQLite file role (main database, rollback journal, WAL, shared
  memory, and temporary) and operation index. Sweep one-shot failure at every
  observed operation, then persistent failure from every observed operation,
  matching SQLite's upstream test method.
- Return actual SQLite primary/extended codes. Do not emulate disk full by
  throwing a Rust error before SQLite writes; that does not exercise rollback
  or reopen behavior.
- Bound maximum fail points, file bytes, child lifetime, output, and artifact
  retention. Record the last fully explored fail point; never hide a partial
  sweep as a pass.
- Use explicit IPC barriers for child kill and concurrent reader/writer tests.
  Time is a supplied value for lease logic; sleeps are only outer watchdogs.
- Copy a checked-in fixture into a newly created test directory. Refuse a path
  outside that directory, refuse symlinks/reparse-point escapes, and print only
  a redacted test case ID plus hashes.
- After a kill, wait for confirmed child termination before reopening. Ensure
  teardown proves no child process, mounted image, open handle, or lease remains.

### Linux-only supplemental lab

Use a newly created sparse backing file, loop device, disposable filesystem,
and device-mapper target under a dedicated self-hosted/lab runner. Resolve and
validate every device and mount path before formatting. Unmount and remove only
the exact resources created by that run. Start with finite-filesystem
`ENOSPC`, then `dm-flakey error_writes` and `error_reads`.

Do not run destructive device setup on ordinary PR runners, do not fill the
runner root volume, and do not depend on time-periodic flakiness for the
assertion. The lab controller must arm the device only after a boundary
handshake and retain the exact device-mapper table and kernel/filesystem
versions.

macOS sparse images and Windows VHDX can provide additional platform labs later,
but their privilege, caching, and teardown behavior is different. Until those
are independently specified and retained, call only the VFS and process harness
portable—not the block-device lab.

## Candidate commands and scenario mapping

These commands are candidate inputs for the implementation spine. They do not
exist or pass merely because this research names them.

| Stable scenario | Candidate command | Required platforms |
| --- | --- | --- |
| `E2E-UPGRADE-001` | `cargo test -p storage-sqlcipher --test schema_migration --all-features --locked --offline -- --test-threads=1` | Linux, macOS, Windows |
| `E2E-TXN-001` | `cargo test -p storage-sqlcipher --test crash_restart --all-features --locked --offline -- --test-threads=1` | Linux, macOS, Windows |
| `E2E-TXN-001` | `cargo test -p storage-sqlcipher --test io_faults --all-features --locked --offline -- --test-threads=1` | Linux, macOS, Windows |
| `E2E-MSG-002`, `E2E-AUTH-001`, `E2E-RETENTION-001` | `cargo test -p storage-sqlcipher --test durable_outbox --all-features --locked --offline -- --test-threads=1` | Linux, macOS, Windows |
| `E2E-RESTORE-001` | `cargo test -p storage-sqlcipher --test stale_snapshot --all-features --locked --offline -- --test-threads=1` | Linux, macOS, Windows |
| `E2E-TXN-001`, `E2E-ABUSE-001` | `sudo ./scripts/sqlcipher-storage-fault-lab-linux.sh --scenario all` | Dedicated Linux lab only |

The ordinary affected gate remains:

```sh
cargo test -p storage-sqlcipher --all-features --locked --offline
cargo test -p session-transport -p session-inviter-transaction -p storage-sqlcipher --all-features --locked --offline
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo test --workspace --all-features --locked --offline
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked --offline
node scripts/check-repository.mjs
node --test scripts/check-repository.test.mjs scripts/setup-codex-links.test.mjs
```

Each fault command should emit the bounded evidence manifest required by
`docs/plans/REAL_WORLD_E2E_TESTING.md`, including an explicit assertion that
captured stdout, stderr, SQLite diagnostics, and crash output omit known fixture
keys, invitation generations, approval bytes, MLS state, Welcome bytes, and
endpoint capabilities.

## Portable evidence, Linux-only evidence, and prohibited claims

| Evidence | Honest scope |
| --- | --- |
| Exact schema migration and fixtures | Portable application/SQLCipher behavior when green on all three pinned CI labels |
| Deterministic state faults | Portable Session Chat transition evidence; not native storage-failure evidence |
| Named VFS FULL/IOERR sweep | Portable SQLite-visible fault evidence for the exact bundled graph and tested default VFS delegation |
| Child kill at explicit boundaries | Portable application-process crash/restart evidence; not OS crash or power loss |
| Rollback-journal hot-reopen tests | Exact tested SQLCipher/SQLite/filesystem combinations only |
| GitHub three-OS matrix | Hosted-runner compatibility and traceability; not reproducible binaries or consumer hardware coverage |
| Finite loop filesystem and `dm-flakey` | Linux-only lab evidence for the recorded kernel/filesystem/device-mapper setup |
| WAL sidecar laboratory | Harness/compatibility evidence only; not authorization to change the product journal mode |
| Valid stale snapshot restore | Evidence that rollback detection is absent until an external monotonic anchor exists |

Do not claim exactly-once delivery, recipient receipt, power-loss safety,
rollback resistance, secure deletion, production durability, filesystem-
independent behavior, bit-reproducible builds, or complete supported-platform
coverage from this work.

## Decisions, confidence, and unresolved risks

### Decisions with high confidence

- Schema migration must precede the durable owner-port implementation.
- One authoritative outbox table and one transaction per lease/result transition
  preserve the existing authority split.
- Version and schema mismatches must fail closed; partial migration must never
  be silently accepted or repaired.
- Deterministic VFS fault injection plus explicit child-process kills is the
  safest portable evidence strategy.
- Stale valid copies cannot be rejected using the encrypted database alone.

### Decisions with medium confidence

- The proposed v2 column set and constraints are the smallest complete match
  for the current in-memory semantics. The implementation review may find a
  reason to retain payload columns in `inviter_joins`, but it must still avoid
  two authoritative copies.
- Keeping `FULL` and `DELETE` is the lowest-risk bounded increment because it
  preserves ADR 0017. A later measured decision may select `EXTRA` or WAL.
- A 16-byte random durable store identifier plus process-local scope and
  per-row generation is sufficient for foreign/stale lease rejection except
  database-copy rollback.

### Unresolved risks

- No trusted monotonic rollback anchor is selected. A restored valid older
  database can resurrect prior pending or leased work and its store identifier.
- SQLite/SQLCipher's documented algorithm still depends on truthful VFS,
  filesystem, firmware, and hardware flush behavior. Hosted VMs do not prove
  consumer-device power-loss behavior.
- The exact test-only VFS implementation language, audit boundary, and build
  packaging are not selected. It must not weaken `#![forbid(unsafe_code)]` in
  the production crate.
- `WelcomeOutboxPort` has only coarse errors and consumes the lease on a report.
  Internal reopen recovery is enough for safety, but implementation tests must
  confirm that persistent owner-store failure cannot create an unbounded hot
  loop.
- Wall time is not rollback-safe. Lease expiry depends on supplied time; a
  durable monotonic-time policy across process restart remains a separate
  decision.
- No three-OS VFS or child-kill implementation exists yet, so portability is a
  recommended gate, not observed evidence.
- No macOS or Windows block-device failure lab is specified. The Linux lab must
  not be generalized to those platforms.

## Smallest concrete inputs for the implementation spine

1. Adopt schema version 2, the four closed state codes, the singleton metadata
   row, random 16-byte store identifier, per-row stored attempt ceiling,
   attempts, lease generation, and nullable lease expiry.
2. Add `maximum_delivery_attempts` to the atomic inviter commit input; keep
   lease duration and caller-supplied `now` as bounded acquisition inputs.
3. Rebuild v1 tables inside one exclusive transaction and set both metadata
   version 2 and `PRAGMA user_version=2` before the single commit.
4. Accept only exact `(user_version, metadata_version)` pairs `(0,1)` and
   `(2,2)` plus their complete structural fingerprints.
5. Implement acquisition, accepted result, and failed result as separate
   immediate transactions with exact changed-row and generation checks.
6. Preserve process-local lease scope in addition to durable store ID,
   transaction ID, and generation.
7. Retain `journal_mode=DELETE` and `synchronous=FULL`, read both back, and
   withhold power-loss/WAL claims.
8. Land the immutable v1 fixture and failing migration/durable-outbox tests
   before the adapter implementation.
9. Make the portable child/VFS suite green on Linux, macOS, and Windows before
   marking Task 9's durable checkpoint complete.
10. Record stale-snapshot restoration as an expected failed security gate until
    a rollback anchor or explicit trust-reset protocol is selected.
