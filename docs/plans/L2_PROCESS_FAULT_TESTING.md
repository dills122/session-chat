# L2 process and storage fault testing plan

Status: L2-0 through L2-5 and the L2-8 portable evidence gate are retained;
L2-2/L2-3 are locally green and promote only on a clean required CI runner;
each revision still requires a green three-OS Checkpoint C result; no
production durability claim

Date: 2026-08-26

## Active execution index

| Work item | Delivery unit and owned path | Dependencies | Acceptance | Status |
| --- | --- | --- | --- | --- |
| L2-2 inviter crash/restart atomicity | Lead-owned integration; `apps/sessionctl/tests/l2_crash_restart_inviter.rs` | Retained L2-0/L2-1 | Every baseline-observed inviter checkpoint is exactly I0 or I1 as specified; missing/duplicate coverage, mixed state, and conflicting retry are rejected | Locally green; public promotion requires the per-revision three-OS L2 job |
| L2-3 joiner crash/restart atomicity | Lead-owned integration; `apps/sessionctl/tests/l2_crash_restart_joiner.rs` | Retained L2-0/L2-1 | Every baseline-observed joiner checkpoint is exactly J0 or J1 as specified; missing/duplicate coverage, retained KeyPackage, and conflicting retry are rejected | Locally green; public promotion requires the per-revision three-OS L2 job |
| L2-8 portable evidence gate | Lead-owned integration; `apps/sessionctl/src/l2_process/evidence.rs`, checked suite promotion seams, `.github/workflows/ci.yml`, canonical claims | Retained L2-2/L2-3/L2-5 | Sealed complete aggregates emit canonical per-case `l2-evidence-v1` bundles bound to actual compiler, GitHub run/workflow, engine, binary, and artifact provenance; seeded canaries and actual case secrets are absent from every bounded surface; PR smoke catches defective evidence | Gate retained; passing portability evidence remains CI-owned per revision |

The lead task owns shared controller changes, canonical documentation,
integration verification, commits, and the eventual pull request. Both lanes
must reuse the retained L2-1 controller/oracle and must not duplicate process
supervision or edit `storage-sqlcipher`.

## Objective

Retain bounded, deterministic evidence for `E2E-TXN-001` against the real
SQLCipher inviter and joiner transactions. A fresh verifier process must see
either the exact old complete owner state or the exact new complete owner state
after an explicitly supervised application-process kill or SQLite-visible
storage failure. It must never see partial membership, a Welcome without the
matching membership commit, a consumed invitation without that commit, or a
joined group while its one-time KeyPackage remains usable.

This plan froze the implementation contract before runtime work began. The
retained L2 implementation does not relabel graceful L1 evidence, and it does
not authorize production, power-loss, rollback-resistance, secure-deletion, or
platform-key-custody claims.

The canonical scenario and layer definitions remain in
[`REAL_WORLD_E2E_TESTING.md`](REAL_WORLD_E2E_TESTING.md). ADR 0017 retains the
SQLCipher laboratory decision, and ADR 0021 retains the existing graceful L1
process topology. This document defines the retained fault-testing increment.

The plan was reconciled against the current implementations in
[`storage-sqlcipher/src/lib.rs`](../../crates/storage-sqlcipher/src/lib.rs) and
[`sessionctl/src/l1_process.rs`](../../apps/sessionctl/src/l1_process.rs), the
retained inviter, joiner, capability-composition, and durable-outbox tests under
[`storage-sqlcipher/tests`](../../crates/storage-sqlcipher/tests), the
[`inviter join transaction v1`](../specs/INVITER_JOIN_TRANSACTION_V1.md)
contract, and the retained
[`SQLCipher durable-outbox fault decision packet`](../research/SQLCIPHER_DURABLE_OUTBOX_FAULTS_2026-08-25.md).
The requested `SQLCIPHER_DURABILITY_FAULT_RECONCILIATION_2026-08-25.md` source
does not exist in this checkout; this plan does not imply that it was reviewed.

## Retained baseline and exact scope

The implementation must exercise the current adapter rather than reproduce its
behavior in a model:

- `storage-sqlcipher` uses SQLCipher with rollback-journal `DELETE`,
  `synchronous=FULL`, and one keyed connection behind a mutex. Ordinary opens
  still use `Connection::open_with_flags`; only the checked L2 entry point can
  select the closed non-default fault-VFS name.
- The inviter transaction starts with one already committed `Reserved`
  reservation. One `BEGIN IMMEDIATE` transaction writes MLS group/epoch state,
  inserts the `inviter_joins` row, and marks the reservation `Consumed` before
  one commit. The `inviter_joins` insert also creates the authoritative pending
  Welcome state; there is no separate outbox-table write in schema version 4.
- The joiner transaction starts with one already committed one-time KeyPackage.
  It begins one immediate transaction, writes group/epoch state and the
  `joiner_commits` row, then holds that transaction across the MLS provider's
  exact KeyPackage deletion. The deletion and commit occur in the subsequent
  `KeyPackageStorage::delete` call.
- Existing `PersistenceFault::BeforeCommit` and `AfterCommit` tests prove
  deterministic in-process rollback and ambiguous-result recovery. They do not
  terminate a process or inject SQLite-visible I/O errors.
- The current independent-process L1 runner proves graceful Alice exit and
  exact close/reopen only. L2 reuses its bounded-supervision principles, not its
  positive result as crash evidence.

The first required L2 gate covers:

1. the initial inviter membership/Welcome commit;
2. the joiner's group/KeyPackage-consumption commit;
3. exact retry and recovery after the result of either commit is lost; and
4. SQLite-visible full/I/O failures during those transactions and their reopen.

Welcome lease/result crash cases are the next slice under `E2E-MSG-002`,
`E2E-AUTH-001`, and `E2E-RETENTION-001`. Schema-migration crash cases remain
`E2E-UPGRADE-001`. They share this scheduler and evidence format but cannot be
used to mark `E2E-TXN-001` complete unless both inviter and joiner gates pass.

## Fault taxonomy and claim boundary

| Event | Required mechanism | What green evidence means | What it does not mean |
| --- | --- | --- | --- |
| Graceful exit | Child closes handles and exits normally | Existing close/reopen behavior remains intact | Crash recovery |
| Application-process kill | Child reaches a named barrier; parent invokes the portable Rust child-termination API, waits for confirmed exit, then starts a fresh verifier | Recovery after termination of the exact tested application process | OS crash, kernel failure, or power loss |
| OS crash | Future disposable-VM reset with a separately reviewed oracle | Nothing in this plan until such a lab exists | Process-kill evidence cannot be relabeled as OS-crash evidence |
| `SQLITE_FULL` | Test-only quota VFS returns the real SQLite primary code at an observed file operation | Recovery from SQLite-visible full conditions for the exact bundled graph and delegated VFS behavior | A physically full consumer device or truthful persistence below the VFS |
| `SQLITE_IOERR_*` | Test-only VFS returns named extended read/write/sync/truncate/delete/lock failures in one-shot and persistent modes | Fail-closed behavior and clean-reopen classification for the injected operation | Firmware, filesystem, or hardware correctness |
| Real finite filesystem / block I/O | Optional dedicated Linux lab using only newly created disposable devices | Supplemental evidence for the recorded kernel/filesystem setup | Portable three-OS or power-loss evidence |
| Power loss | Future hardware/VM cut with explicit cache/flush assumptions | Nothing in this plan | `synchronous=FULL` plus process kill is not power-loss proof |
| SQL transaction rollback | Application checkpoint or SQLite-visible fault before a successful commit | Exact old complete state | Stale-snapshot rollback resistance |
| Valid stale snapshot | Restore a previously closed disposable copy | The current expected result is that the old valid state can reopen; the run records the missing rollback anchor | Rollback detection or resistance |

The terms `rollback` and `rollback detection` must not be conflated. This plan
tests SQLite transaction rollback. A valid older encrypted database copies its
store identifier and remains indistinguishable without a trusted monotonic
anchor; that remains a known failed security gate.

## State oracle

Each case starts from a freshly created, gracefully closed baseline under a
controller-owned marked directory. Test-only fixture values are deterministic
or controller generated, but cryptographic production randomness is not
weakened. Secret values may enter only the disposable child/verifier channels.
The evidence manifest receives assertion results and digests, never the values.

### Inviter old state `I0`

- The exact group-bound client identity exists and validates.
- The exact invitation generation is `Reserved` by the expected join request.
- No row exists for the inviter transaction ID.
- No durable MLS group snapshot or epoch row exists for the new group.
- No pending, leased, delivered, exhausted, or expired Welcome work exists for
  the transaction.
- The verifier observes no second or conflicting transaction under the same
  invitation or request identifiers.

### Inviter new state `I1`

- The same client identity remains bound to the same group.
- The exact invitation generation is `Consumed`.
- The exact inviter transaction exists at epoch 1.
- The exact MLS snapshot reloads as the intended two-member epoch-1 group.
- The authoritative Welcome state is `Pending`, with attempts `0`, lease
  generation `0`, and no lease identity/expiry.
- Approval, request fingerprint, invitation generation, canonical Welcome,
  endpoint, and expiry compare byte-for-byte with the private fixture inside
  the verifier.
- Exact transaction recovery/retry returns the committed state without another
  MLS Add and without changing any durable digest.

### Joiner old state `J0`

- The exact one-time KeyPackage exists.
- No joined MLS group/epoch state exists for the target group.
- No `joiner_commits` row exists for the transaction ID.

### Joiner new state `J1`

- The exact one-time KeyPackage no longer exists.
- The exact joined group and its epoch state exist.
- The exact `joiner_commits` row binds the transaction, group, and KeyPackage
  reference.
- Exact transaction recovery/retry succeeds without a second join or a second
  deletion and leaves the complete-state digest unchanged.

### Unacceptable mixed states

Any of the following is a hard test failure, even when SQLCipher's page-HMAC or
SQLite's structural checks pass:

- MLS state without the matching inviter transaction, consumed reservation,
  and pending Welcome;
- an inviter transaction or pending Welcome while the reservation remains
  `Reserved`;
- `Consumed` without the exact membership/outbox commit;
- a joined group without `joiner_commits`, or `joiner_commits` without the
  group;
- a joined group while the consumed one-time KeyPackage remains present;
- loss or substitution of the group-bound durable identity;
- a second membership transition, a changed transaction digest, an invented
  lease, or any secret-bearing diagnostic output; or
- a schema/user-version mismatch, failed integrity gate, orphaned relation, or
  state outside the schema's closed enums.

The fresh verifier must run SQLCipher `cipher_integrity_check`, SQLite
`quick_check`, `foreign_key_check`, exact schema/user-version validation, and
the semantic oracle. Integrity checks alone are insufficient.

## Named application checkpoints

The fault protocol uses a closed enum, not caller-supplied checkpoint strings.
Each frame contains only protocol version, scenario, role, checkpoint code,
bounded occurrence index, and case ID. It contains no database path, authority,
key, MLS bytes, Welcome bytes, endpoint, identity, invitation generation,
approval record, or request fingerprint.

At a checkpoint the child must flush the bounded control frame and block
without beginning the next storage action. An acknowledgement is exclusively
a continue command: the parent sends it only for a confirmed non-target
checkpoint, and the child validates it before proceeding. At the target
checkpoint the parent sends no acknowledgement; it terminates and reaps the
still-blocked child, confirms termination, and only then launches the verifier.
The controller must fail if a targeted writer reports or reaches any later
checkpoint before confirmed termination. Sleeps are outer watchdogs, never the
scheduler.

### Inviter transaction checkpoints

The current write order in `commit_inviter` defines these checkpoints:

| Code | Exact location | Required result after kill |
| --- | --- | --- |
| `INVITER_BEFORE_BEGIN` | Reservation and identity baseline is closed; before `BEGIN IMMEDIATE` | `I0` |
| `INVITER_AFTER_GROUP_UPSERT` | After `mls_groups` insert/update inside the open transaction | `I0` |
| `INVITER_AFTER_EPOCH_INSERT(n)` | After each observed epoch insert, `0 <= n < 64` | `I0` |
| `INVITER_AFTER_EPOCH_UPDATE(n)` | After each observed epoch update, `0 <= n < 64` | `I0` |
| `INVITER_AFTER_JOIN_INSERT` | After the schema-v4 `inviter_joins` insert, which also stages pending Welcome state | `I0` |
| `INVITER_AFTER_RESERVATION_CONSUMED` | After the exact reservation update from reserved to consumed | `I0` |
| `INVITER_BEFORE_COMMIT` | After every application statement, before invoking commit | `I0` |
| `INVITER_AFTER_COMMIT_RETURN` | SQL commit returned, before the caller finalizes the in-memory admission shadow | `I1` |
| `INVITER_BEFORE_SHADOW_FINALIZE` | Process composition checkpoint immediately before `finalize_committed` | `I1`; fresh recovery drives only the committed branch |

An initial Add may not exercise every possible epoch occurrence. The evidence
records the observed occurrence count and fails if it exceeds the adapter's
bound; it does not invent unobserved checkpoint coverage.

### Joiner transaction checkpoints

The current `begin_joiner`/`KeyPackageStorage::delete` split defines:

| Code | Exact location | Required result after kill |
| --- | --- | --- |
| `JOINER_BEFORE_BEGIN` | Durable KeyPackage baseline is closed; before `BEGIN IMMEDIATE` | `J0` |
| `JOINER_AFTER_GROUP_UPSERT` | After `mls_groups` insert/update | `J0` |
| `JOINER_AFTER_EPOCH_INSERT(n)` | After each observed epoch insert, `0 <= n < 64` | `J0` |
| `JOINER_AFTER_EPOCH_UPDATE(n)` | After each observed epoch update, `0 <= n < 64` | `J0` |
| `JOINER_AFTER_COMMIT_INSERT` | After the `joiner_commits` insert | `J0` |
| `JOINER_BEFORE_KEY_PACKAGE_DELETE` | Transaction remains open across the provider callback, immediately before exact deletion | `J0` |
| `JOINER_AFTER_KEY_PACKAGE_DELETE` | Exact KeyPackage delete completed inside the transaction | `J0` |
| `JOINER_BEFORE_COMMIT` | Before invoking the explicit `COMMIT` batch | `J0` |
| `JOINER_AFTER_COMMIT_RETURN` | Commit returned before the caller observes success | `J1` |

For application checkpoints before commit, confirmed process termination must
reopen as the exact old state. The SQLite/VFS commit-window sweep below permits
either old or new complete state because the process cannot reliably observe
the engine's durable commit point. It never permits a mixed state.

### Bootstrap checkpoints

Identity insertion, reservation seeding, and one-time KeyPackage insertion are
autocommit writes that precede `E2E-TXN-001`. A separate bootstrap slice must
classify each as absent or exact-present after an engine-window kill and prove
that no partial or substituted row is accepted. These cases are required before
the process harness is reused as product bootstrap evidence, but they do not
replace the inviter/joiner atomicity gate above.

The L2 controller must generate or retain the disposable database key and
expected public identifiers before starting a killable child. It must not rely
on the L1 pattern where Alice creates the key and writes a resume file only
after commit; killing that child earlier would make the test database
unverifiable. This test-only controller channel has the same-account limitation
as ADR 0021 and is not a vault or process-isolation claim.

## SQLite-visible fault sweep

Application checkpoints cover Session Chat statement boundaries. Engine
boundaries require a test-only named VFS that delegates to the selected default
VFS and can pause, count, or return actual SQLite codes for one disposable
connection. It must not be registered as the process default and must not
weaken `storage-sqlcipher`'s `#![forbid(unsafe_code)]`; any native/unsafe bridge
belongs in an isolated publish-disabled test-support crate with documented
safety invariants.

L2-0 owns the missing connection-selection seam before the VFS lane begins. A
private `storage-sqlcipher` open path selects either the existing default VFS or,
only under `cfg(session_chat_storage_fault_testing)`, one closed constant name
through `Connection::open_with_flags_and_vfs`. The cfg-only `fault_testing`
module exposes the minimum doc-hidden create/open entry points required by the
L2 writer and verifier; the VFS name does not come from a CLI argument,
environment variable, fixture, or other runtime input. Ordinary `create` and
`open` continue to use the default path. A compile-fail fixture must prove the
fault module is absent without the custom cfg, while named-VFS tests must prove
registration does not replace the process default and that only the explicitly
opened disposable connection reaches the delegator.

Required file roles are main database, rollback journal, and any unexpected
temporary file. WAL and shared-memory roles are recognized only so their
appearance fails the retained `journal_mode=DELETE` baseline; they are not a
WAL safety test.

Required operations and modes:

- quota exhaustion returning `SQLITE_FULL` from observed journal/main writes;
- `SQLITE_IOERR_READ`, `WRITE`, `FSYNC`, `TRUNCATE`, `DELETE`, and lock-family
  extended errors at the corresponding delegated operations;
- one-shot failure at every observed ordinal after the fault is armed;
- persistent failure beginning at every observed ordinal; and
- a commit-window child kill at observed journal write/sync, main-file
  write/sync, and journal delete checkpoints.

Each unique case starts from a fresh closed baseline. The controller disables
the VFS fault before verification, closes or kills the writer, waits for exit,
and opens the same database in a fresh verifier process. Inviter verification
accepts only `I0` or `I1`; joiner verification accepts only `J0` or `J1`.
Persistent-error cases may fail closed while the fault remains armed, but the
subsequent clean verifier must still classify a complete state or retain a
bounded hard-failure artifact for investigation. No automatic repair, blind
retry, or deletion of a hot journal is allowed.

The first retained sweep is bounded to 4,096 observed VFS operations per case,
192 application checkpoints, 4 KiB per control frame, 8 KiB per public
manifest, 64 KiB combined redacted child diagnostics, 90 seconds per child,
120 seconds per case, and 30 minutes per scenario command. Exceeding any bound
is a failure with `coverage=partial`; it is never reported as a pass. The final
manifest records the last fully explored operation and the total observed
operation count.

## Welcome owner follow-on matrix

After `E2E-TXN-001` is green, the same scheduler covers these owner-local
transactions without changing membership, reservation, approval, or MLS state:

| Boundary | Complete states allowed after reopen | Stable scenario |
| --- | --- | --- |
| Lease housekeeping updates before commit | Exact prior state | `E2E-MSG-002` |
| Lease row selected but not updated | Exact prior state | `E2E-MSG-002` |
| Lease update before commit | Exact prior state | `E2E-MSG-002` |
| Lease commit engine window | Prior eligible state or one new leased generation; attempts increment at most once | `E2E-MSG-002` |
| Lease commit returned, result lost | Exact new lease; no replacement until supplied-time expiry | `E2E-MSG-002` |
| Adapter failed before acceptance | Leased, pending, or exhausted according to one committed result transition | `E2E-MSG-002` |
| Adapter accepted, process killed before local report | Original lease remains; after expiry, retry uses byte-identical Welcome and endpoint | `E2E-MSG-002` |
| Accepted-result commit window | Same-generation leased or delivered, never pending through the success path | `E2E-MSG-002` |
| Failed-result commit window | Same-generation leased, pending, or exhausted according to one transition | `E2E-MSG-002` |
| Stale result after re-lease | New generation unchanged; stale result rejected | `E2E-AUTH-001` |
| Last attempt killed then expires | Next acquisition terminalizes exhausted and emits no work | `E2E-RETENTION-001` |

Adapter acceptance plus local delivered-state commit is not atomic. A
byte-identical idempotent retry after lease expiry is duplicate-tolerant
recovery, not exactly-once delivery, recipient receipt, or recipient processing.

## Schema migration, restore, and destructive-lab separation

Schema versions 1 through 4 have distinct migration transactions. Migration
kill points must be numbered around each existing DDL/data-copy/version step
after those batches are refactored into observable statements. A fresh reopen
may expose only the exact source schema or exact target schema for that step.
Migration evidence belongs to `E2E-UPGRADE-001`; it must not be folded into the
join transaction pass count.

A stale-snapshot test copies only a gracefully closed disposable directory,
commits a newer state, restores the older copy, and records that the current
design accepts the old valid state. That is expected-gap evidence for
`E2E-RESTORE-001`, not a passing rollback-resistance result. Selecting a trusted
monotonic anchor or trust-reset protocol remains a prerequisite to changing
that verdict.

Finite-filesystem and device-mapper experiments are optional Linux-only
supplemental tasks. They require an isolated self-hosted runner and a separate
reviewed script that refuses unmarked paths, the host root volume, unresolved
devices, and pre-existing mounts. Silent dropped writes, corruption, VM reset,
and real power interruption remain deferred until a separate expected-state
oracle and destructive-lab safety review exist.

## Supervision, cleanup, and artifact safety

The controller must:

- create a unique absolute temporary directory containing an exact marker;
- reject symlinks and reparse-point escapes before copy, open, or cleanup;
- create each case from a gracefully closed baseline and include all observed
  SQLite sidecars in case ownership;
- pass keys and secret fixtures only through bounded same-account test channels
  with best-effort restrictive permissions and delete them after load;
- spawn direct children only, collect bounded output, use explicit barriers,
  terminate and reap every child, and start verification only after the writer
  is confirmed dead;
- never delete outside the exact marked case root and treat cleanup failure as
  a failed result;
- prove no child, open handle, live lease, mounted image, or marked directory
  remains before emitting `result=pass`; and
- use one supplied logical time and retained seed rather than wall-clock sleeps
  for lease and recovery decisions.

The public evidence output is a canonical bundle containing one bounded
`l2-evidence-v1` manifest per validated case. The bundle can be constructed
only from a sealed complete aggregate; the raw textual validator and metadata
constructors are private. Every record contains only:

- scenario/case ID, canonical case index/count, seed, checkpoint or VFS
  operation code and ordinal;
- expected complete-state class or closed allowed class set and the exact
  observed class (`I0`, `I1`, `J0`, or `J1`);
- normalized SQLite primary/extended result code when injected;
- commit/dirty metadata, lock digest, pinned toolchain, actual `rustc -Vv`
  release/commit/host, platform/architecture, the closed runner-image tuple,
  GitHub run/attempt/workflow/repository/event metadata, and SQLCipher/SQLite
  versions;
- configured byte/time/operation bounds and last fully explored ordinal;
- hashes of the test binary, that case's closed baseline and post-recovery
  encrypted artifact set, the canonical key-framed matrix, and the sealed
  internal aggregate observation; and
- assertion summary, integrity/schema/semantic/redaction results, child/handle/
  lease/directory cleanup results, and `coverage=complete|partial`.

All case records share the exact matrix digest and declare their canonical
index and total count. A missing, duplicated, reordered, contradictory, or
unknown internal claim fails before any public record is created. The evidence
record is bound to GitHub's immutable default `GITHUB_*`/`RUNNER_*` variables
and exact run identity; consumers still verify that run in GitHub rather than
treating an unsigned copied log fragment as independent attestation.

It omits raw paths, usernames, database keys, identity records, invitation
generations, bearer capabilities, approval records, request fingerprints, MLS
state, KeyPackages, Welcome bytes, endpoints, plaintext, raw SQL parameters,
and crash dumps. Known synthetic canaries for every forbidden fixture class
must be scanned across stdout, stderr, SQLite diagnostics, control frames,
manifests, and retained artifacts. Hashes of authority-bearing protocol values
remain omitted rather than becoming reusable confirmation or correlation
artifacts.

Task L2-5 does not yet emit that public manifest. Its checked tests retain only
`l2-io-observation-v1`: a bounded, closed-field, non-public diagnostic record
used in memory by the exhaustive-matrix constructors. It must say
`publication=prohibited`, cannot say `result=pass`, and cannot assert public
integrity, schema, retry, provenance, artifact-binding, or redaction results.
Task L2-8 owns promotion to `l2-evidence-v1` after it binds the observations to
the exact build/platform/artifact metadata above and scans the required
synthetic canaries, including captured pause-child stdout and stderr. Until
that promotion passes, L2-5 observations are test diagnostics rather than
portable or publishable security evidence.

## Supported-platform requirements

The required portable process-kill and named-VFS suites must pass the existing
explicit CI families before the corresponding L2 gate is called implemented:

- `ubuntu-24.04` x64;
- `macos-15` arm64; and
- `windows-2025` x64.

The controller uses Rust's portable child API and confirms termination with
`wait`; it does not require Unix signals, `/proc`, shell job control, or
platform-specific path syntax. Windows deletion failures are treated as useful
open-handle evidence, not retried until hidden. Platform-specific positive
tests are additional and cannot substitute for the common matrix. Hosted image
versions and OS/kernel details are evidence inputs; green hosted runs do not
prove all consumer hardware, filesystems, or OS versions.

Nightly is the default cadence for the complete ordinal sweep. A bounded smoke
subset may run on affected pull requests only after it is proven to detect an
intentionally defective adapter. Any atomicity violation, redaction failure,
forbidden output, cleanup failure, or budget overrun blocks the gate. CI must
not hide failures with blind retries.

## Wave-2 implementation tasks

Every task is small or medium, has one primary owner, and leaves unrelated
paths untouched. The lead owns workspace membership, lockfile, canonical docs,
coverage records, and CI reconciliation so parallel lanes do not edit shared
files concurrently.

All process controller, verifier, and crash-scenario integration tests live in
the `sessionctl` package. That package already depends on `storage-sqlcipher`
and can exercise the real adapter without reversing the dependency direction.
`storage-sqlcipher` never depends on the application package, and no crash
suite duplicates the controller or semantic oracle. Storage-owned tasks retain
only the cfg-gated hooks/open seam and ordinary in-process boundary tests; the
unsafe named-VFS implementation remains in its separate publish-disabled crate.

### Task L2-0: Freeze the fault protocol and checked build boundary

**Description:** Add the closed checkpoint enum, versioned bounded control
frames, oracle state codes, checked test-only build configuration, and the
private connection-opening seam that selects the fixed fault VFS only in that
build. Fault hooks and the named-VFS entry points are absent from ordinary
production builds. The production crate retains `#![forbid(unsafe_code)]`.

Use the workspace-declared custom configuration
`cfg(session_chat_storage_fault_testing)`, not a Cargo feature: the ordinary
`--all-features` gate must not compile the hooks. Register that exact cfg under
the workspace `unexpected_cfgs` lint, enable it only in the named L2 job's
environment, reject it with `compile_error!` when `debug_assertions` are off,
and record `fault_build=true` in L2 evidence. No runtime environment variable
or public command-line argument may activate hooks in an ordinary binary.

**Ownership:** `crates/storage-sqlcipher/src/fault_testing.rs` (new), the
minimal hook call sites plus private default-or-named connection open path in
`crates/storage-sqlcipher/src/lib.rs`, one dedicated protocol/build-boundary
test file, and compile-fail fixtures. Shared Cargo/check-cfg wiring is
lead-owned.

**Acceptance:**

- Every inviter/joiner checkpoint above is emitted only from its exact current
  statement boundary, with occurrence indices bounded below 64.
- Unknown versions/codes, oversized frames, duplicate/out-of-order barriers,
  and hooks in ordinary builds fail closed or are absent.
- Hook payloads cannot carry secret bytes and an intentionally defective
  checkpoint order is detected.
- Ordinary `create`/`open` still select the default VFS. Only the cfg-gated,
  doc-hidden fault entry points can select the one closed fault-VFS name, and an
  ordinary-build compile-fail fixture proves those entry points are absent.

**Verification:** focused storage protocol tests, `cargo fmt --all --check`, and
workspace Clippy with warnings denied.

**Dependencies:** none. **Estimated scope:** M (3-5 files).

### Task L2-1: Build the bounded process controller and verifier

**Description:** Add the single reusable hidden L2 writer/verifier role and
parent controller that creates marked case roots, exchanges the closed
protocol, kills/reaps the writer, and applies the full integrity/schema/semantic
oracle in a fresh process. Every later process-fault suite imports this one
cfg-gated `sessionctl` module; no storage-package test imports the application
or duplicates its supervisor/oracle.

**Ownership:** new `apps/sessionctl/src/l2_process.rs`, its cfg-gated doc-hidden
library export, new hidden binary entry, and `apps/sessionctl/tests/l2_process.rs`.
Do not edit the L1 module. The hidden binary must fail closed without the custom
cfg and cannot activate fault behavior through ordinary runtime input.

**Acceptance:**

- A RED test proves a deliberately mixed fixture and a secret-bearing child
  diagnostic fail the harness.
- Graceful control, kill, timeout, oversized output, missing acknowledgement,
  lingering handle, and directory-cleanup cases are bounded and deterministic.
- Non-target checkpoints advance only after an exact continue acknowledgement;
  a target checkpoint remains unacknowledged and cannot emit or execute the
  next boundary before the controller confirms termination.
- A passing manifest is emitted only after fresh-process verification and all
  cleanup checks pass.

**Verification:** focused `sessionctl` L2 tests plus the existing L1 process
tests to prove no regression.

**Dependencies:** L2-0 protocol frozen. **Estimated scope:** M (3-5 files).

### Task L2-2: Retain inviter crash/restart atomicity

**Description:** Drive every observed inviter checkpoint from a unique closed
baseline and classify the reopen result against `I0`/`I1`, including exact
retry after the post-commit-result-loss checkpoints.

**Ownership:** new `apps/sessionctl/tests/l2_crash_restart_inviter.rs` and
inviter-only fixtures/support under the `sessionctl` test tree. It imports the
L2-1 controller/oracle and exercises the real `storage-sqlcipher` dependency.

**Acceptance:**

- Every listed inviter checkpoint is covered; each pre-commit application kill
  is `I0`, and each post-commit-return kill is `I1`.
- Mixed-state and repeated-Add defective cases are detected.
- Exact retry changes no complete-state digest and emits no second Welcome
  work item.

**Verification:** `cargo test -p sessionctl --test l2_crash_restart_inviter
--all-features --locked --offline -- --test-threads=1`.

**Dependencies:** L2-0 and L2-1. **Estimated scope:** S (1-2 files).

### Task L2-3: Retain joiner crash/restart atomicity

**Description:** Drive the split group-write/KeyPackage-delete transaction at
every observed checkpoint and classify `J0`/`J1` after fresh reopen.

**Ownership:** new `apps/sessionctl/tests/l2_crash_restart_joiner.rs` and
joiner-only fixtures/support under the `sessionctl` test tree. It imports the
same L2-1 controller/oracle and exercises the real storage dependency.

**Acceptance:**

- Every listed joiner checkpoint is covered across both provider callbacks.
- No case exposes a group with a retained KeyPackage or a commit row without
  its exact group.
- Post-commit recovery and exact retry perform neither a second join nor a
  second deletion.

**Verification:** `cargo test -p sessionctl --test l2_crash_restart_joiner
--all-features --locked --offline -- --test-threads=1`.

**Dependencies:** L2-0 and L2-1. **Estimated scope:** S (1-2 files).

### Task L2-4: Isolate the named VFS fault adapter

**Description:** Implement the smallest publish-disabled VFS delegator that
classifies file roles, counts bounded operations, pauses at commit-window
operations, and injects actual `SQLITE_FULL`/extended `SQLITE_IOERR_*` codes.

**Ownership:** new `crates/storage-sqlcipher-fault-vfs/**` only. The storage
connection-selection seam already belongs to L2-0; this lane does not edit
`storage-sqlcipher`. Workspace membership and lockfile changes are lead-owned.

**Acceptance:**

- Unsafe/native code is isolated from `storage-sqlcipher`, documented at each
  boundary, and denied outside the minimal delegator.
- The adapter registers under the one closed name consumed by L2-0, with
  SQLite's make-default flag disabled. Tests record the default VFS before and
  after registration, prove an ordinary connection bypasses the delegator, and
  prove one explicitly named disposable connection reaches it.
- Defective tests prove wrong file-role classification, skipped ordinals,
  incorrect result codes, and an unexpected WAL/temp file are detected.

**Verification:** focused VFS crate tests on Linux, macOS, and Windows plus
Clippy/rustdoc for the new crate.

**Dependencies:** L2-0 protocol frozen; parallel-safe with L2-1. **Estimated
scope:** M (3-5 files).

### Task L2-5: Sweep full and I/O errors

**Description:** Arm L2-4 only after a closed baseline is established, sweep
one-shot and persistent failures through the inviter and joiner transactions,
then verify `I0|I1` and `J0|J1` after disabling the fault.

**Ownership:** new `apps/sessionctl/tests/l2_io_faults.rs` and I/O-only fixture
manifests. It imports the L2-1 controller/oracle and uses L2-0's cfg-only named
open entry point with the L2-4 delegator.

**Acceptance:**

- Every observed supported operation ordinal up to the bound is explored, and
  partial exploration cannot report pass.
- Persistent failure fails closed while armed; clean reopen never accepts a
  mixed state or silently removes a hot journal.
- Actual primary/extended codes and last explored ordinals appear in bounded,
  closed-field internal observations that explicitly prohibit publication.

**Verification:** `cargo test -p sessionctl --test l2_io_faults
--all-features --locked --offline -- --test-threads=1` on all three CI families.

**Dependencies:** L2-0, L2-1, and L2-4. **Estimated scope:** M (2-4 files).

**Retained implementation:** `apps/sessionctl/tests/l2_io_faults.rs` discovers
the exact clean inviter/joiner operation counts, sweeps every supported ordinal
in one-shot and persistent modes, and separately pauses/kills a direct child at
every observed journal write/sync/delete and main-file write/sync ordinal. Each
case uses a fresh closed baseline and the L2-1 fresh verifier. Closed aggregate
observations reject missing or duplicate cases before reporting complete matrix
coverage. These `l2-io-observation-v1` records are not the public
`l2-evidence-v1` manifest and carry no public redaction or provenance verdict.

### Task L2-6: Add durable Welcome owner crash cases

**Description:** Reuse the proven scheduler for lease acquisition, adapter
acceptance ambiguity, accepted/failed result transitions, stale generations,
and terminal attempt/expiry behavior.

**Ownership:** new `apps/sessionctl/tests/l2_outbox_crash_restart.rs` only; do
not edit the inviter/joiner crash files. It reuses the L2-1 controller/oracle.

**Acceptance:**

- Every follow-on matrix row classifies one permitted complete state and leaves
  membership/approval/reservation/MLS digests unchanged.
- Adapter-accepted/result-lost retry is byte-identical and does not claim
  exactly-once delivery.
- Stale/foreign results and last-attempt resurrection are detected.

**Verification:** focused outbox crash test plus existing `durable_outbox` and
coordinator tests.

**Dependencies:** L2-1, L2-2, and L2-5. **Estimated scope:** S (1-2 files).

### Task L2-7: Retain migration and stale-snapshot evidence

**Description:** Number observable schema v1-to-v4 migration steps, run
source-or-target-only crash classification, and retain a separate expected-gap
stale-snapshot case.

**Ownership:** new `apps/sessionctl/tests/l2_migration_restore.rs` plus
migration-only fixtures/support under the `sessionctl` test tree. Minimal
migration checkpoint refactoring in `storage-sqlcipher/src/lib.rs` is scheduled
only after L2-2/L2-3 and cannot overlap the L2-0 storage owner.

**Acceptance:**

- Every killed migration reopens as the exact source or target schema, never a
  mixed/repaired schema.
- Immutable fixtures remain unchanged and no migration invents identity/group
  scope.
- A valid stale restore is recorded as `expected_gap=rollback-anchor-absent`,
  never as a passing rollback-resistance gate.

**Verification:** focused migration/stale-snapshot commands, fixture digests,
and existing migration tests.

**Dependencies:** L2-2, L2-3, and L2-5. **Estimated scope:** M (3-5 files).

### Task L2-8: Integrate the three-OS nightly gate

**Description:** Reconcile workspace membership, commands, coverage, canonical
status/claim documents, and the existing explicit OS matrix after all retained
evidence is green.

**Ownership:** lead-owned Cargo/lockfile, CI, coverage, ADR, threat-model,
roadmap, audit brief, and execution-index files. No implementation lane edits
these paths concurrently.

**Acceptance:**

- Inviter and joiner process-kill plus named-VFS suites pass on all three
  required families with complete coverage manifests.
- An intentionally defective adapter is caught in the PR smoke subset.
- L2-5 internal observations are promoted to a canonical public per-case
  `l2-evidence-v1` bundle only after exact build/platform/artifact provenance is attached and
  synthetic canaries are absent from bounded stdout, stderr, diagnostics,
  control frames, the manifest, and retained encrypted artifacts.
- Canonical documents claim only application-process-kill and SQLite-visible
  fault evidence and retain every prohibition below.

**Verification:** focused scenario commands, complete workspace formatting,
Clippy, tests, rustdoc, retained Node tests, repository policy, dependency
policy where available, and an independent review.

**Dependencies:** L2-2, L2-3, and L2-5; L2-6/L2-7 may land as separately named
gates. **Estimated scope:** M (3-5 integration files per atomic commit).

**Retained implementation:** `apps/sessionctl/src/l2_process/evidence.rs`
keeps raw promotion private, rejects dirty or incomplete promotion, requires
exact bounded Git, actual compiler, GitHub run/workflow, closed runner tuple,
engine, test-binary, and encrypted-artifact provenance, and scans
stdout, stderr, diagnostics, control-frame material, the internal observation,
every public case manifest, and retained encrypted artifacts for the closed
synthetic canary and actual-case catalogs. Complete checkpoint, SQLite
return-code, and commit-window kill aggregates alone can emit canonical,
key-framed per-case `l2-evidence-v1` bundles. The dedicated CI matrix runs
the failure-sensitive smoke subset on pull requests and the complete suites on
non-PR runs for `ubuntu-24.04`, `macos-15`, and `windows-2025`. A portable
passing claim remains conditional on that required job being green for the
exact revision.

## Dispatch graph and checkpoints

```text
L2-0 fault protocol + exact adapter checkpoints
  |
  +--> L2-1 sessionctl controller/verifier
  |      +--> L2-2 sessionctl inviter crash suite --+
  |      +--> L2-3 sessionctl joiner crash suite ---+--> L2-8 E2E-TXN-001 integration
  |                                      |
  +--> L2-4 isolated named VFS ----------+--> L2-5 FULL/IOERR sweep --+
                                                                    |
                         L2-2 + L2-5 --> L2-6 outbox crash ----------+
                         L2-2 + L2-3 + L2-5 --> L2-7 migration/restore
```

Checkpoint A follows L2-0: human review freezes checkpoint ordering, the
test-only build boundary, and secret-free frame schema before parallel runtime
work. L2-1 and L2-4 then proceed in parallel with non-overlapping ownership.

Checkpoint B follows L2-1/L2-4: deliberately defective writer, verifier, VFS,
redaction, timeout, and cleanup cases must be RED before positive sweeps begin.
L2-2, L2-3, and L2-5 then proceed in parallel on separate test files.

Checkpoint C integrates `E2E-TXN-001` only after both process suites and the
portable I/O sweep are green on Linux, macOS, and Windows. Outbox, migration,
restore, and privileged Linux work retain separate scenario verdicts and may
not broaden that claim.

## Verification commands

Candidate commands become required only after their named targets exist:

The L2 fault commands run in a CI/job environment with
`RUSTFLAGS=--cfg session_chat_storage_fault_testing`; the workflow supplies the
environment identically on all three operating systems. The ordinary full
workspace commands run without that cfg and prove that the retained product
graph does not expose the fault hooks.

```sh
cargo test -p sessionctl --test l2_process --all-features --locked --offline -- --test-threads=1
cargo test -p sessionctl --test l2_crash_restart_inviter --all-features --locked --offline -- --test-threads=1
cargo test -p sessionctl --test l2_crash_restart_joiner --all-features --locked --offline -- --test-threads=1
cargo test -p sessionctl --test l2_io_faults --all-features --locked --offline -- --test-threads=1
cargo test -p sessionctl --test l2_outbox_crash_restart --all-features --locked --offline -- --test-threads=1
cargo test -p sessionctl --test l2_migration_restore --all-features --locked --offline -- --test-threads=1
cargo test -p storage-sqlcipher --all-features --locked --offline
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo test --workspace --all-features --locked --offline
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked --offline
node --test scripts/check-repository.test.mjs scripts/setup-codex-links.test.mjs
node --test spikes/sealed-invitation-provider/test/provider.test.mjs
node scripts/check-repository.mjs
cargo deny --all-features --locked check
```

Every unavailable command is reported exactly. A missing local `cargo-deny`
does not convert dependency policy into passing evidence; CI remains required.

## Claims that remain prohibited

Even after every task in this plan passes, do not claim:

- protection from OS crash, real power loss, lying flushes, filesystem,
  firmware, controller, or hardware faults;
- stale-snapshot detection, rollback resistance, or a trusted monotonic clock;
- exactly-once delivery, recipient receipt, recipient processing, or no remote
  duplicate after adapter-acceptance ambiguity;
- production durability, production storage, secure deletion, backup safety,
  restore safety, rekey safety, or old-secret erasure;
- platform-vault custody, hostile same-account process isolation, crash-dump or
  swap protection, or unlocked-endpoint protection;
- portability beyond the exact pinned dependency graph, hosted runner images,
  OS/architecture/filesystem combinations, and operations actually retained;
- WAL safety or authorization to change `journal_mode=DELETE` or
  `synchronous=FULL`;
- a durable human-approval/replay owner, deployable independent-process client,
  network transport, hosted realm, privacy, anonymity, or production readiness;
  or
- completion of L3-L6, real-network, container, platform-vault, rollback-anchor,
  release, or operated-service gates.

The strongest permitted conclusion is narrower: on the exact tested
SQLCipher/SQLite graph and platform matrix, after a bounded application-process
kill or injected SQLite-visible full/I/O error, fresh reopen exposed one
complete allowed transaction state, exact retry did not repeat the MLS
membership transition, the evidence remained redacted, and supervised cleanup
completed.
