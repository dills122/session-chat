# Implementation plan: profile-bound transport abstraction

Status: active staged implementation plan; ADR 0015 is accepted, the generalized
dispatch and Task 6 conformance slices are complete, Task 9's durable
owner-store plus capability-admission/MLS composition checkpoints are complete,
and the durable client-reload and independent-process L1 checkpoints are
complete before network work

Date: 2026-08-20

## Overview

Stabilize the existing `session-transport` local one-Welcome adapter and the
`session-inviter-transaction` outbox conformance model, then generalize them
into a stable core-facing envelope-delivery boundary with a deterministic
adverse-network control path and shared adapter conformance harness. Real
network adapters follow only after the Phase 1 protocol core can complete the
capability, approval, MLS, owner-local transaction, and outbox flow required by
ADRs 0004, 0008, 0009, 0012, and 0014.

This plan does not select a production transport. It creates the boundary and
evidence needed to compare transports without changing MLS, admission, or the
canonical envelope format.

The cross-system execution cadence, stable scenario IDs, retained evidence
bundle, and progression from offline two-client tests to process, storage,
network, packet-capture, and release gates are defined in
[`REAL_WORLD_E2E_TESTING.md`](REAL_WORLD_E2E_TESTING.md).
The remaining Phase 1 subset is sequenced by
[`PHASE1_PROTOCOL_CLOSEOUT.md`](PHASE1_PROTOCOL_CLOSEOUT.md); later real-network
experiments in this plan do not block the protocol laboratory.

## Existing baseline on `master`

- `session-protocol` owns bounded canonical `OpaqueEnvelope` bytes and the
  closed local Welcome deposit endpoint from ADR 0014.
- `session-transport` implements bounded local one-message deposit, receive,
  and acknowledgement with separate authorities and exact-retry behavior.
- `session-inviter-transaction` models atomic membership/outbox visibility,
  ambiguous commit recovery, bounded delivery leasing, and exact retry in
  memory.
- A narrow synchronous `EnvelopeTransport` trait and deterministic memory
  adapter exist for bounded conformance work. They are not the complete
  budget-aware polling, cursor, lifecycle, profile-binder, coordinator, network,
  or durable-storage boundary.

The plan extends this baseline. It does not recreate these crates or relabel
their current evidence as durable or production-ready.

## Architecture decisions carried into the plan

- The core-facing contract is envelope delivery, not raw sockets or a vendor
  SDK.
- Profile semantics and adapter implementation identity are separate.
- Mailbox authority uses the right-specific types from ADR 0010.
- Portable delivery is unordered and duplicate-capable; omission, delay,
  expiry, and outage are normal inputs, and bounded attempts do not guarantee
  eventual delivery.
- The owner-local transaction store owns durable outbox truth, idempotency keys,
  leases, and commit recovery.
- The coordinator executes leased work and owns retry policy, expiry checks,
  receive-side deduplication, cursors, and acknowledgement scheduling without a
  second outbox ledger.
- Adapters receive bounded operations and scoped network authority.
- Private profiles fail closed and require egress evidence.
- Memory transport remains the control path after real adapters are added.

## Dependency graph

```text
Existing local adapter + inviter transaction model
        |
        v
ADR 0015, transport contract, and baseline gap review
        |
        v
Common types, traits, authority tests, and error contract
        |
        v
Generalized memory control path + adverse-network scheduler
        |
        v
Shared conformance harness
        |
        +----------------------+
        |                      |
        v                      v
Profile binder/manifests   Coordinator + owner-store port
        |                      |
        +-----------+----------+
                    v
Existing outbox-model integration, then durable adapter evidence
        |
        +----------------------+----------------------+
        |                      |                      |
        v                      v                      v
Iroh Fast adapter       Tor/Arti spike        SimpleX SMP spike
                                                       |
                         +-----------------------------+
                         v
                 Katzenpost/Nym comparison
```

The external adapter spikes can run independently only after the common
contract and harness are stable.

## Active execution slice: durable headless composition

This slice begins only after the separately owned `sessionctl` orchestration
fault seams and memory/inviter schedule models merged to `master`. It reuses
those seams and does not reinterpret their pre-merge files.

| Work item | Delivery unit | Depends on | Status | Completion boundary |
| --- | --- | --- | --- | --- |
| `T9-SQL-OWNER` | Durable owner store | Task 8 | Complete | SQLCipher schema v2 is the sole Welcome ledger across migration, restart, leases, terminal states, and exact retry. |
| `T9-REAL-COMPOSITION` | Admission/MLS integration | `T9-SQL-OWNER` | Complete | Real capability admission holds a one-shot durability-pending MLS result until transaction-ID recovery proves commit or rollback, then delivery restarts without another Add. |
| `T9-SESSIONCTL` | Headless integration | merged orchestration fault seams | Complete | The existing Alice/Bob flow uses the real SQLCipher inviter transaction and reconstructed coordinator owner while preserving its coarse fault and output contracts. |
| `L1-PROCESS` | Independent-process runner | `T9-SESSIONCTL` | Complete | Separate client and untrusted-service processes exchange only public wire objects under bounded lifecycle control and emit a redacted evidence manifest. |

`T9-SESSIONCTL` persists and reloads Alice's exact client signing identity and
stored group through SQLCipher schema v4, failing closed on fresh, malformed,
missing, replacement, cross-group, or member-mismatched identity state.
`L1-PROCESS` now crosses graceful Alice process exit through a fresh reload
process while Bob and an untrusted forwarding service remain separate. Its
bounded filesystem IPC v1 carries only canonical protected-join,
LocalV1-deposit, and opaque-envelope objects; the bearer invitation and
disposable raw owner key stay on separate client-only test channels. ADR 0021
records the boundary. L1 itself provides no abrupt-kill, power-loss, rollback,
network-transport, or platform-key-custody evidence. The retained L2 suites now
cover bounded inviter/joiner application-kill recovery; Welcome-delivery kills,
power loss, rollback resistance, network transport, and platform key custody
remain open.

## Active execution slice: generalized dispatch boundary

This slice closes the remaining Task 3 dispatch decisions before extending the
memory control path. Research items are read-only inputs; they do not select a
dependency, provider protocol, or product profile by themselves.

| Work item | Delivery unit | Depends on | Status | Completion boundary |
| --- | --- | --- | --- | --- |
| `T3-DISPATCH` | Lead implementation | Tasks 1 and 2 | Complete | One mockable budget-aware deposit, poll, and acknowledgement boundary preserves right-specific method positions, requires provider-owned right-bound authority, uses explicit clock/cancellation inputs, and has compile/runtime contract tests. Generalized issuance remains outside this slice. |
| `R3-RUNTIME` | Research | None | Complete | Official-source comparison of runtime-neutral Rust dispatch, monotonic deadlines, and cancellation with a recommendation compatible with the pinned workspace. |
| `R3-MAILBOX` | Research | None | Complete | Protocol-source comparison of acknowledgement scope, cursor invalidation, rotation, and restart semantics, with security constraints separated from provider choices. |
| `R4-MEMORY-MAP` | Internal codebase exploration | None | Complete | Exact migration map from the narrow memory adapter to the generalized boundary, including test seams and shared-file conflict risks. |
| `T4-MEMORY` | Lead integration | `T3-DISPATCH`, `R4-MEMORY-MAP` | Complete | The deterministic memory adapter implements the accepted common boundary without weakening its existing fault and idempotency evidence. |

`T3-DISPATCH` acceptance is checked first with the smallest
`session-transport` compile/runtime tests, then with `cargo test -p
session-transport --all-features --locked --offline`. Integration work also
runs the `transport-memory` package tests. The complete workspace formatting,
lint, test, documentation, and repository-policy gates remain required before a
PR checkpoint.

## Active execution slice: adverse trace and shared conformance

This slice implements Tasks 5 and 6 without adding test-control behavior to the
production `session-transport` API. The canonical trace and reusable runner are
owned by a publish-disabled conformance crate; provider-specific fault state
remains in `transport-memory`.

| Work item | Delivery unit | Depends on | Status | Completion boundary |
| --- | --- | --- | --- | --- |
| `R5-TRACE` | Read-only research | Task 4 | Complete | Versioned trace ownership, vocabulary, bounds, redaction, determinism, and test seams are recorded from the accepted contracts and official Rust runtime sources. |
| `T5-TRACE` | Lead implementation | `R5-TRACE` | Complete | A strict canonical v1 trace parser rejects unknown/noncanonical/oversized input and round-trips one secret-free golden fixture byte-for-byte. |
| `T5-MEMORY-FAULTS` | Lead implementation | `T5-TRACE` | Complete | The memory provider supplies bounded outage, corruption, exact-byte stale-replay, acknowledgement-loss, release, and secret-free probe controls without weakening existing semantics. |
| `T6-HARNESS` | Lead implementation | `T5-MEMORY-FAULTS` | Complete | The bounded wake-aware runner replays retained traces twice against fresh memory adapters; common lifecycle, queue-saturation, and bounded virtual arbitrary-delay verdicts, exact retry identity, drop/quiescence, redaction, and deliberately defective bridges are covered. A publish-disabled deterministic FastV1 provider drives issuance, distinct rights, canonical deposit, cursor poll/resume, acknowledgement, rotation, exact retry, declaration mismatch, foreign authority, and stale predecessors through the shared boundaries. Its bounded owner model covers atomic page/cursor persistence, overlap deduplication, restart-safe acknowledgement recovery, cursorless successors, resynchronization, stale checkpoints, foreign bindings, and expiry. A closed matrix maps all 38 required lifecycle cases to retained evidence. |
| `T8-OWNER-PREREQS` | Lead implementation | `R7-COORD` | Complete | The inviter model issues scoped leases, terminalizes exhausted work, validates canonical LocalV1 delivery material and expiry scope, and rejects stale or foreign lease results. |
| `T8-COORDINATOR` | Lead implementation | `T8-OWNER-PREREQS` | Complete | The deposit-only port, one-attempt policy executor, LocalV1 resolver/adapter bridge, inviter-store integration, and cross-platform wake/cancel/deadline/drop supervisor are retained. |
| `T9-INMEMORY-INTEGRATION` | Lead implementation | `T8-COORDINATOR` | Complete | The atomic inviter outbox drives the real LocalV1 mailbox; acceptance, adapter failure, and ambiguous exact retry preserve one membership commit and one authoritative ledger. |
| `R7-COORD` | Read-only research | Tasks 5-6 contracts | Complete | Exact deposit-only coordinator/outbox ownership, recovery transitions, and five blocking contract defects are mapped for later Tasks 8-9. |
| `R7-CURSOR` | Read-only research | ADRs 0010/0015 | Complete | Generation-bound cursor, persist-before-acknowledge, mailbox rotation, restart, and stale-state requirements are recorded without selecting a provider. |

The retained v1 trace is strict LF-delimited lowercase ASCII, capped at 64 KiB,
512 bytes per line, 256 steps, 64 aliases per kind, and eight checkpoint
directives per operation. It stores only numeric aliases, relative time,
bounded sizes, normalized outcomes, and fault/control enums. It never stores
plaintext, ciphertext, raw identifiers, routes, capabilities, or provider
errors. Queue saturation is induced through bounded ordinary operations rather
than a state-forging action. Positive persisted cursor issuance, rotation,
restart, concurrency, network timing, and profile-specific privacy faults remain
outside this slice.

## Completed execution slice: durable Welcome owner store

This is the authoritative sequential backbone after the completed in-memory
Task 9 checkpoint. It evolves the existing SQLCipher inviter transaction rather
than wrapping the memory model or introducing coordinator persistence. The
`storage-sqlcipher` database remains the sole authority for membership,
invitation consumption, replay/approval result, exact Welcome work, attempts,
leases, and terminal delivery state.

Parallel work may own `apps/sessionctl`, new test-only property/model files for
the existing memory paths, and a SQLCipher fault-research document. This slice
does not edit those files before their changes merge.

| Work item | Delivery unit | Depends on | Status | Completion boundary |
| --- | --- | --- | --- | --- |
| `D9-SCHEMA-V2` | Lead storage contract | In-memory Task 9 checkpoint | Complete | A versioned SQLCipher schema and explicit v1 compatibility fixture retain one nonzero durable store identity, exact canonical Welcome/endpoint bytes, bounded attempt count, monotonic lease generation, opaque lease identity, lease expiry, and pending/leased/delivered/exhausted/expired states. Migration is one atomic transaction and unknown schemas fail closed. |
| `D9-RECOVERY-TESTS` | Lead storage evidence | `D9-SCHEMA-V2` design | Complete | Failing-first tests cover close/reopen coordination, stale re-lease, foreign-store leases, expiry, attempt exhaustion, ambiguous remote acceptance with byte-identical retry, and invisibility of rolled-back membership/outbox work. |
| `D9-OWNER-PORT` | Lead storage implementation | `D9-RECOVERY-TESTS` | Complete | `SqlCipherStorage` implements `WelcomeOutboxPort`; each lease, accepted result, and failed result uses one immediate SQL transaction and validates the exact live store/transaction/generation/lease identity. |
| `D9-DURABLE-COMPOSITION` | Lead integration | `D9-OWNER-PORT` | Complete | The real capability-admission and MLS Add path commits once through SQLCipher, reconstructs the stateless coordinator after close/reopen, and retries delivery without repeating MLS membership or reopening invitation state. |
| `D9-FAULT-EVIDENCE` | Lead verification | `D9-DURABLE-COMPOSITION` | Complete | Retained adapter-proportionate restart and storage-fault evidence passes targeted tests, production coverage ratchets, and the available full repository gates; local dependency-policy execution remains unavailable without the CI-provided `cargo-deny`, and stronger process-kill, disk/power, rollback, and production claims remain explicitly gated unless separately proven. |
| `D9-RESEARCH-RECONCILE` | Merged fault-research integration | companion fault packet | Complete | The per-row attempt ceiling persists; pre-reopen process-scoped leases fail closed; schema v2 is bound to `user_version`; migration is exclusive; and retained journal/synchronous configuration is read back. The portable child-kill/VFS suite, full structural fingerprint, immutable encrypted v1 artifact, and rollback anchor remain separate L2 gates. |

The initial schema-v2 state codes and migration are storage-internal, not wire
objects. Changing their observable recovery semantics requires compatibility
fixtures and negative tests. A lease is authoritative only when its persistent
store identity, transaction ID, generation, and opaque lease identity all match
the currently leased row. Reopen preserves the store identity; re-lease changes
both generation and lease identity so stale or foreign results fail closed.

## Phase A: contract adoption

### Task 1: Review and accept the transport decision

**Description:** Review ADR 0015 and the proposed version 1 contract against
ADRs 0001, 0003, 0010, 0012, and 0014. Map the proposed generalized semantics
against the existing local adapter and inviter-transaction model. Resolve only
questions that affect stabilization; leave real-network selection as research.

**Acceptance criteria:**

- [x] ADR 0015 is accepted, revised, or explicitly rejected with rationale.
- [x] Ownership among the owner-local store, coordinator, and adapter is
  unambiguous.
- [x] The first Rust API shape and acknowledgement-authority issuance model are
  recorded.

**Verification:**

- [x] Every normative transport statement has one authoritative home or a
  cross-reference.
- [x] `rg -n "EnvelopeTransport|EnvelopeDelivery|TransportProfileId" docs`
  reveals no contradictory interface or fallback semantics.

**Dependencies:** None

**Files likely touched:**

- `docs/adr/0015-bind-transport-adapters-to-versioned-profiles.md`
- `docs/specs/TRANSPORT_ABSTRACTION_V1.md`
- `docs/ARCHITECTURE_V2.md`

**Estimated scope:** Small

## Phase B: compile-time foundation

### Task 2: Freeze and map the existing local transport evidence

**Description:** Treat the existing `session-transport` local Welcome mailbox
and `session-inviter-transaction` model as the compatibility baseline. Record
which version 1 semantics they already prove, which are deliberately narrower,
and which require new implementation. Do not change runtime behavior in this
task.

**Acceptance criteria:**

- [x] Existing exact-retry, conflicting-second-deposit, expiry, capacity,
  right-separation, deletion, and redaction evidence is mapped to the proposal.
- [x] Gaps for general polling, cursors, batches, profiles, operation budgets,
  normalized errors, and adverse delivery are explicit.
- [x] The inviter transaction remains the single owner of Welcome-outbox truth
  and leases.

**Verification:**

- [x] `cargo test -p session-transport --all-features --locked --offline`
- [x] `cargo test -p session-inviter-transaction --all-features --locked --offline`
- [x] A retained gap table cites exact tests and distinguishes missing evidence
  from failed evidence.

**Dependencies:** Task 1

**Files likely touched:**

- `crates/session-transport/README.md`
- `crates/session-transport/src/lib.rs`
- `crates/session-transport/tests/local_welcome_mailbox.rs`
- `crates/session-inviter-transaction/README.md`
- `crates/session-inviter-transaction/tests/conformance.rs`
- `docs/evidence/transport-local-baseline.md`

**Estimated scope:** Medium

### Task 3: Extract the generalized contract and harden authority boundaries

**Description:** Add profile/adapter identifiers, canonical envelope view,
bounded operation types, receipts, batches, retry advice, and the core-facing
traits alongside the existing local API. Add negative and compile-time tests
showing that capabilities cannot be substituted and secret-bearing values
cannot enter ordinary debug/error output. Do not add network dependencies.

**Progress (updated 2026-09-03):** The bounded contract-values sub-increment is
implemented with closed profile IDs, validated adapter IDs, exact canonical
envelope ownership, operation budgets, bounded retry advice, context-free
failures, and a compile-fail `CanonicalEnvelope: Debug` check. A later Phase 1
increment added the narrow synchronous `EnvelopeTransport` trait with associated
right-specific types, and the separate `transport-memory` crate implements it.
The generalized issuance/lifecycle increment now fixes bounded four-right
authority sets, exact generation/cursor binding, compare-and-swap rotation,
explicit resynchronization, and the separate atomic receive-state owner port.
Task 3 implementation is complete; findings from all three independent-review
instances are remediated. Instance 3 was the configured maximum and returned
`Not ready` against its frozen pre-remediation target; human acceptance later
authorized proceeding and no fourth review started automatically. The
provider implementation and closed evidence matrix are now complete under Task
6/P1-5.

The local capability-evidence sub-increment extracts receive and
acknowledgement authority behind private fields and crate-only constructors,
retains the sender-facing canonical deposit endpoint, adds a compile-fail
wrong-right matrix, and seeds authority/ciphertext bytes into a coarse-error
redaction fixture. This proves the local adoption boundary only; generalized
capability issuance, rotation, receive-batch dispatch, and cursor state remain
open.

The bounded-operation sub-increment adds opaque cursors, poll count/byte/wait
limits, canonical deposit requests, bounded acknowledgement identifiers, and
identifier-minimal receipts. It enforces provider-neutral hard ceilings and the
caller's total byte budget before dispatch and keeps ciphertext/full identifiers
out of ordinary diagnostics. It deliberately does not stabilize dispatch,
async/clock mechanics, capabilities, or lifecycle operations. A follow-up
receive-batch sub-increment enforces request-specific item/byte ceilings and
local post-receive expiry without claiming incremental remote parsing or cursor
state semantics.

The dispatch sub-increment adds the static `EnvelopeDelivery` trait with
standard-library `Send` futures, right-specific provider-neutral outer wrappers
around associated provider material, and a
fallible clock/cancellation checkpoint. Tests cover generic dispatch,
pre-entry cancellation/deadline rejection, wall-clock failure, post-provider
cancellation, pending-future drop cleanup, and generalized wrong-right
compile failures, including aliased inner provider types. Capability
lifecycle/issuance and provider-wide redaction were subsequently closed by the
P1-4 increment. The wrappers prove only positional separation; each adapter
must independently prevent cross-right
derivation, validate exact scope, and review duplication policy per right.
Controlled deposit transfer remains allowed; receive and acknowledgement
authority should be non-cloneable by default. The memory adapter supplies that
provider-specific evidence. `RetryAdvice::Never` stops
the current operation budget but permits coordinator-owned exact-identity
reconciliation under a fresh budget after ambiguous completion.

The lifecycle sub-increment adds an issuance operation returning deposit,
receive, acknowledgement, and rotation rights for one exact generation. Full
cursor binding covers profile/configuration, continuity, generation, receive
scope, schema, provider epoch, and expiry. Rotation is idempotent and
compare-and-swap bound to an exact predecessor. The receive-state owner alone
atomically commits canonical envelopes/deduplication outcomes, exact
acknowledgement intents, and cursor advance; it reloads only the latest exact
checkpoint, including a cursorless successor revision, and can recover only
previously committed intents after restart; durable intent remains through
recovered-lease crash or ambiguous release until acceptance. Reusable poll requests and batches
carry exact binding, revision, position-kind, and cursor identity into commit,
and reject duplicate delivery IDs. Explicit resynchronization is an owner-CAS
transition persisted before polling from none. The owner-defined associated
commit handle is opaque to callers and rejects forged or rebound leasing;
explicit wall time gates commit, load, immediate lease, and recovery. Compile-fail and seeded-failure fixtures cover
all four authority positions. A closed lifecycle-case vocabulary defines the
provider evidence P1-5 must supply without selecting a network provider.
The same increment adds the non-secret reusable-provider declaration required
by the cursor-lifecycle research: cursor persistence/schema, generation policy,
rotation plus maximum routine drain, acknowledgement scope, and external owner
semantics are fixed before provider use. The declared nonlocal profile, cursor
schema, drain policy, and observed expiry are bound to issuance and rotation. LocalV1
declarations, issue requests, and cursor bindings fail closed because it is
cursorless and non-rotating; declarations do not enable profile binding.

**Acceptance criteria:**

- [x] Deposit cannot accept receive or acknowledgement authority; rotation
  remains outside the delivery interface.
- [x] A delivery ID or cursor cannot authorize acknowledgement.
- [x] Secret-bearing values have reviewed ownership, cloning, serialization,
  zeroization, and redaction behavior.
- [x] Deposit requests accept only canonical bounded envelope objects or validated
  views derived from `session-protocol` bytes.
- [x] Existing local callers remain covered while migration to the common trait
  is explicit and reviewable.

**Verification:**

- [x] Local compile-fail tests cover deposit, receive, acknowledgement, and
  delivery-ID substitution.
- [x] Generalized wrong-right tests cover the common trait.
- [x] The local rejection fixture contains none of the seeded authority or
  ciphertext bytes.
- [x] Generalized value tests cover cursor, poll, deposit-byte, acknowledgement-
  batch, and receipt bounds before dispatch.
- [x] Receive-batch tests cover request count/bytes and post-receive expiry.
- [x] Generalized adapter error/log fixtures cover every authority type.
- [x] `cargo test -p session-transport`

**Dependencies:** Task 2

**Files likely touched:**

- `crates/session-transport/src/lib.rs`
- `crates/session-transport/src/capability.rs`
- `crates/session-transport/src/error.rs`
- `crates/session-transport/src/profile.rs`
- `crates/session-transport/tests/types.rs`
- `crates/session-transport/tests/authority.rs`
- `crates/session-transport/tests/redaction.rs`

**Estimated scope:** Medium

## Checkpoint: contract foundation

- [x] ADR 0015 is accepted for implementation.
- [x] The crate builds without a network dependency.
- [x] Local authority-separation and seeded-redaction tests pass.
- [x] Existing local and deterministic-memory delivery state has retained test
  and review evidence.
- [x] Generalized authority, lifecycle, and provider-wide redaction tests pass.
- [x] Human acceptance confirmed proceeding after post-review remediation.
  Independent review instance 3 of 3 returned `Not ready` on its frozen target;
  no fourth review started automatically.

## Phase C: deterministic memory control path

### Task 4: Generalize the existing memory adapter into the control path

**Description:** Preserve the narrow local Welcome behavior while adding a
deterministic in-memory implementation of the common bounded deposit, poll, and
acknowledgement semantics.

**Progress (updated 2026-08-24):** The separate `transport-memory` crate now
implements both the narrow compatibility trait and the generalized
`EnvelopeDelivery` boundary with bounded explicit deliver, drop, duplicate,
hold/release reorder, exact-retry, expiry, authority, capacity, poll-page,
receipt, clock, and cancellation behavior. The profile explicitly rejects every
supplied cursor until persisted cursor state exists. Fixed hard ceilings bound
caller policy, live canonical bytes, scheduled copies, and lifetime. Task 4 is
complete for this cursorless Phase 1 memory profile; valid cursor persistence
and richer adverse scheduling remain Tasks 5 and 8 work.

**Acceptance criteria:**

- [x] Repeating identical destination/ID/bytes is idempotent.
- [x] Reusing an ID with different bytes conflicts without overwrite.
- [x] Queue count, byte, TTL, and poll-page limits are enforced before
  unbounded allocation.

**Verification:**

- [x] Unit tests cover full queues, expiration, rejected cursors, duplicate
  deposit, conflicting deposit, wrong rights, and repeated acknowledgement.
- [x] The existing local Welcome mailbox tests remain unchanged or gain only
  explicitly reviewed compatibility updates.
- [x] `cargo test -p session-transport`
- [x] `cargo test -p transport-memory`

**Dependencies:** Task 2 and the completed `T3-DISPATCH` subtask; remaining
Task 3 issuance/lifecycle work is not a prerequisite for this cursorless memory
control path.

**Files likely touched:**

- `crates/transport-memory/src/lib.rs`
- `crates/transport-memory/tests/deterministic_delivery.rs`
- `crates/session-transport/tests/local_welcome_mailbox.rs`

**Estimated scope:** Medium

### Task 5: Add the adverse-network schedule

**Description:** Add a deterministic controller that scripts delay, loss,
duplication, reordering, corruption, stale replay, queue saturation,
acknowledgement loss, cursor invalidation, and unavailability.

**Progress (updated 2026-08-25):** `transport-memory` retains the bounded
explicit action queue for delivery, loss, duplication, and hold/release
reordering and now adds persistent total unavailability, one-shot normalized
corrupt polling without dequeue, digest-checked exact-byte stale replay,
before/after-commit acknowledgement-result loss, and a secret-free bounded
snapshot. The publish-disabled `transport-conformance` crate owns a strict
64 KiB/256-step canonical adverse-trace v1 parser with closed tokens, numeric
aliases, bounded fixtures/checkpoints, hostile cases, redacted errors, and an
exact round-trip fixture. Its first normalized runner slice adds in-memory
fixture generation, virtual controls, bounded future driving, exact-byte alias
normalization, fresh-adapter double replay, and quiescence for a hold/release
memory trace plus fail-closed checkpoint cases. Cursor invalidation remains
fail-closed because the memory profile rejects every cursor. Full adverse-action
execution and deliberately defective adapters remain Task 6.

**Acceptance criteria:**

- [ ] Every fault is selected through deterministic test input rather than
  wall-clock races or nondeterministic randomness.
- [ ] Scheduled work is bounded and cancelable.
- [x] The trace format contains no secret capability bytes or plaintext.

**Verification:**

- [x] The first executable golden trace replays identically across fresh runs.
- [x] Memory-runner tests prove quiescence after cancellation and deadline.
- [x] `cargo test -p transport-conformance --test trace_v1`
- [x] `cargo test -p transport-memory --test adverse_schedule`

**Dependencies:** Task 4

**Files retained in this increment:**

- `crates/transport-conformance/src/trace.rs`
- `crates/transport-conformance/tests/trace_v1.rs`
- `crates/transport-conformance/tests/fixtures/adverse-trace-v1.txt`
- `crates/transport-memory/src/lib.rs`
- `crates/transport-memory/tests/adverse_schedule.rs`

**Estimated scope:** Medium

### Task 6: Build the reusable adapter conformance harness

**Description:** Extract contract tests that any adapter factory can run. The
memory adapter is the first implementation and supplies controllable failure
injection.

**Progress (updated 2026-08-25):** A versioned provider-specific bridge keeps
rights inside adapter implementations while the provider-neutral runner owns
deterministic fixture generation, operation budgets, scripted checkpoints,
bounded waitable-waker polling, alias normalization, expected-event comparison,
canonical reports, double replay, and final quiescence. The retained memory
fixture covers one complete hold/release delivery lifecycle and fail-closed
checkpoint outcomes. The runner accepts only LocalV1 and rejects unbound profile
labels. Exact retries reuse one mailbox/envelope-bound receipt alias, poll
normalization rejects foreign-mailbox or swapped-envelope pairs, and pending
futures may wake after polling returns within the one-second harness bound.
Bridge-level coverage proves delayed-wake drop cleanup reaches final quiescence,
while a non-waking future fails closed. Retry-delay reports preserve every valid
duration exactly in nanoseconds. A composed LocalV1 fixture now covers
duplication, stale replay, corruption, both acknowledgement-loss points, outage
recovery, cursor rejection, and expiry. Deliberately defective bridges prove
that changed retry receipts, cross-mailbox batches, ignored deadlines, leaked
drop work, and seeded provider failures fail closed. Factory freshness and
snapshot truth remain adapter obligations. A canonical queue-saturation fixture
now fills the eight-envelope mailbox, rejects the ninth deposit, drains and
acknowledges the accepted set, reaches quiescence, double-replays identically,
and catches an over-accepting bridge. A retained hold/advance/poll/release trace
now covers bounded arbitrary delay without wall-clock sleeps. The exhaustive
authority/resource matrix remains before Task 6 is complete. A deterministic
FastV1 provider now retains issuance, canonical deposit, cursor poll/resume,
acknowledgement, rotation, exact-retry, foreign-authority, stale-predecessor, and
declaration-substitution evidence; its companion owner model retains atomic cursor-page, deduplication,
acknowledgement-recovery, cursorless-successor, resynchronization, stale-state,
foreign-binding, and expiry evidence. The closed 38-row evidence matrix covers
the required lifecycle vocabulary. The retained LocalV1 cross-resource row
proves a foreign delivery ID is a no-op under another mailbox's valid
acknowledgement right and cannot consume the original mailbox's delivery.

**Acceptance criteria:**

- [x] The harness covers every common test in the transport specification.
- [x] Adapter-specific tests can add evidence without weakening common tests.
- [x] Failure output identifies normalized codes without printing secret data.

**Verification:**

- [x] The memory adapter passes the retained LocalV1 verdict fixtures.
- [x] A deliberately defective test adapter fails idempotency, redaction, and
  deadline tests for the expected reasons.
- [x] `cargo test -p transport-conformance`

**Dependencies:** Tasks 4 and 5

**Files likely touched:**

- `crates/transport-conformance/Cargo.toml`
- `crates/transport-conformance/src/lib.rs`
- `crates/transport-conformance/tests/memory.rs`
- `crates/transport-conformance/tests/defective.rs`

**Estimated scope:** Medium

## Phase D: policy binding and durable coordination

### Task 7: Implement manifests and profile binding

**Description:** Add closed version 1 profile requirements, adapter manifests,
binding validation, and non-secret binding records. Start with Local only; do
not enable Fast or Private profiles merely because their types exist.

**Progress (updated 2026-08-25):** The first slice implements one exact
LocalV1-only manifest and binding record. It rejects unknown manifest and
configuration versions, nonlocal profiles, broader byte/count limits, cursor
support, ambient egress, background work, adapter-managed retries, incomplete
mailbox operations, mismatched enforcement, and invalid record inputs. The API
binds one selected profile and accepts no fallback list. Network declarations,
brokers, authenticated negotiation, and every nonlocal profile remain open.

**Acceptance criteria:**

- [x] Unknown profile/manifest versions and contradictory requirements fail
  closed.
- [x] Adapter IDs never substitute for profile IDs.
- [x] No API accepts a generic fallback list.

**Verification:**

- [x] Tests reject ambient egress, excessive sizes, unsupported operations,
  broader retry behavior, and unknown versions.
- [x] Snapshot tests show binding records contain no routes or authority bytes.
- [x] `cargo test -p session-transport --test profile_binding`

**Dependencies:** Tasks 3 and 6

**Files likely touched:**

- `crates/session-transport/src/profile.rs`
- `crates/session-transport/src/manifest.rs`
- `crates/session-transport/src/binding.rs`
- `crates/session-transport/tests/profile_binding.rs`

**Estimated scope:** Medium

### Task 8: Implement coordinator policy and the owner-store port

**Description:** Add the initial LocalV1 deposit-only coordinator that applies
expiry, byte/attempt budgets, and cancellation around one adapter deposit.
Define an owner-store port through which it leases work and reports success or
bounded failure. Polling, cursor, and acknowledgement scheduling remain later
receiver-side work. The coordinator must not duplicate membership,
outbox, lease, attempt-count, or ambiguous-commit truth already owned by
`session-inviter-transaction` or a future durable implementation.

**Research gate (updated 2026-08-25):** Start with a LocalV1 deposit-only
coordinator. The owner store exclusively owns leases, attempts, retry
eligibility, terminal state, exact envelope, and encoded destination; a
profile/provider resolver returns only the typed deposit right. One owner lease
permits one adapter call with `max_attempts == 1`, and `Delivered` means adapter
acceptance only. Before implementation, fix inviter lease-token ABA, remove
exhausted work from eligible enumeration, canonically validate committed
envelope/endpoint/expiry relationships, define reconstructible LocalV1 deposit
material, and assign pending-future wake/drop supervision to the composition
root. Do not connect SQLCipher or claim durable restart in this slice.

**Prerequisite checkpoint (2026-08-25):**

- [x] Inviter lease-token ABA is removed by store-issued scoped lease identity.
- [x] Attempt-exhausted work is terminal and absent from eligible enumeration.
- [x] Committed envelope/endpoint bytes and their expiry relationship are
  canonically validated.
- [x] LocalV1 deposit material uses the reconstructible canonical
  `LocalWelcomeDepositEndpoint` schema.
- [x] The coordinator composition root supplies bounded wake/deadline/cancel
  supervision and drops unfinished adapter futures.

**Acceptance criteria:**

- [x] Duplicate delivery never emits two accepted core events.
- [x] Retry never exceeds attempts, bytes, deadline, or envelope expiration.
- [x] Adapter success/failure cannot reopen invitation or MLS membership state.
- [x] There is exactly one authoritative outbox/lease record for a Welcome.

**Verification:**

- [x] Each retained coordinator dispatch uses one attempt, bounded bytes, and a
  deadline subordinate to the owner lease.
- [x] The cross-platform blocking composition baseline wakes and drops pending
  work at that deadline; UI runtimes may provide an equivalent driver.

- [x] Model tests exhaust the retained bounded duplicate/reorder/loss schedules.
- [x] Tests distinguish deposit acceptance, receipt, acknowledgement, and
  application processing.
- [x] A deliberately stale or foreign lease cannot report delivery state.
- [x] `cargo test -p session-transport --test coordinator --all-features --locked --offline`
- [x] `cargo test -p session-transport --test supervisor --all-features --locked --offline`

**Dependencies:** Tasks 5, 6, and 7

**Files likely touched:**

- `crates/session-transport/src/coordinator.rs`
- `crates/session-transport/src/outbox_port.rs`
- `crates/session-transport/src/state.rs`
- `crates/session-transport/tests/coordinator.rs`
- `crates/session-transport/tests/retry_budget.rs`

**Estimated scope:** Medium

### Task 9: Integrate the coordinator with the transactional Welcome outbox

**Description:** First connect the coordinator to the existing
`session-inviter-transaction` conformance model and local Welcome adapter. Then
apply the same owner-store port to the retained SQLCipher laboratory
transaction required by ADRs 0008, 0014, and 0015. Membership commit and exact
encrypted Welcome work
remain atomic in that owner-local store, while delivery retry remains
idempotent and cannot repeat MLS Add or Commit.

**Acceptance criteria:**

- [x] A committed membership transition always has recoverable outbox work in
  the SQLCipher inviter transaction.
- [x] An uncommitted SQLCipher transition exposes no deliverable job.
- [x] SQLCipher restart recovery retries delivery without repeating MLS membership
  mutation or releasing the invitation.
- [x] Coordinator state can be discarded and reconstructed without losing or
  contradicting authoritative outbox state.

**Retained implementation checkpoints (2026-08-25 through 2026-08-28):**

- [x] The inviter transaction model implements the same sole-owner port used by
  the coordinator; no coordinator ledger is introduced.
- [x] Normal adapter acceptance marks only the exact lease delivered and leaves
  invitation consumption plus the committed MLS epoch unchanged.
- [x] Adapter failure returns only the exact outbox lease to pending.
- [x] A prior unrecorded adapter acceptance is retried with byte-identical
  envelope/endpoint identity, yields the same mailbox delivery, and does not
  repeat the atomic commit.
- [x] The SQLCipher adapter proves the owner-port properties across close/reopen
  and its retained pre/post-commit storage faults. Bounded join-writer
  application-kill and SQLite-visible fault evidence now exist; Welcome-delivery
  process-kill and real disk/power evidence remain separate gates.
- [x] The real capability-admission and MLS path defers in-memory invitation
  consumption while SQL durability is unresolved, recovers an ambiguous commit
  by transaction ID, finalizes once, reopens the owner store, and delivers the
  byte-identical Welcome without repeating MLS membership.

**Verification:**

- [x] Process-kill tests cover every baseline-observed inviter/joiner application
  checkpoint and SQLite commit-window pause; this is not power-loss evidence.
- [ ] Duplicate, lost, reordered, and delayed Welcome delivery remains safe.
- [x] The in-memory conformance model passes before a durable adapter is wired.
- [x] The exact targeted SQLCipher storage command is retained in test evidence.

**Dependencies:** Task 8, the existing inviter-transaction conformance model,
and the retained SQLCipher MLS/storage increment governed by ADRs 0008 and 0015

**Files likely touched:**

- `crates/session-core/src/join.rs`
- `crates/session-inviter-transaction/src/lib.rs`
- `crates/session-inviter-transaction/tests/conformance.rs`
- `crates/storage-sqlcipher/src/lib.rs`
- `crates/session-transport/src/outbox.rs`
- `crates/session-core/tests/join_recovery.rs`
- `crates/session-transport/tests/outbox_recovery.rs`

**Estimated scope:** Medium

## Checkpoint: Phase 1 transport control path

- [x] Memory transport remains deterministic and offline.
- [x] The complete Phase 1 headless flow passes through the common transport
  boundary.
- [ ] Process-crash recovery cannot repeat membership transitions; bounded
  duplicate/reordered memory schedules are retained.
- [x] The owner-local transaction store is the sole durable outbox and lease
  authority; coordinator restart does not create a second ledger.
- [x] `cargo fmt --all --check`
- [x] `cargo clippy --workspace --all-targets -- -D warnings`
- [x] `cargo test --workspace`
- [x] Review retained evidence before any real network adapter.

## Phase E: real-network experiments

### Task 10: Implement the Iroh Fast adapter

**Description:** Implement the first real adapter for the Fast profile, keeping
offline mailbox behavior separate where Iroh relays are stateless. Document
every discovery, relay, direct-peer, and DNS observer.

**Acceptance criteria:**

- [ ] Direct and relay paths carry byte-identical envelopes through the common
  contract.
- [ ] Direct-peer and relay metadata exposure is represented accurately in the
  profile and UI fixture.
- [ ] No adapter behavior is reused as an offline-mailbox claim.

**Verification:**

- [ ] Shared conformance suite passes.
- [ ] NAT, relay-only, route change, peer offline, and service outage tests pass.
- [ ] Packet captures match the Fast observer matrix.

**Dependencies:** Phase 1 checkpoint

**Files likely touched:**

- `crates/transport-iroh/Cargo.toml`
- `crates/transport-iroh/src/lib.rs`
- `crates/transport-iroh/tests/conformance.rs`
- `docs/evidence/transport-iroh-fast.md`

**Estimated scope:** Medium

### Task 11: Run the Tor/Arti Private Interactive spike

**Description:** Test an onion-hosted mailbox through Arti under an isolated
private-interactive egress policy. This is a spike, not product adoption.

**Acceptance criteria:**

- [ ] The client and mailbox expose no direct peer or clearnet service path.
- [ ] Onion-service identity, key lifecycle, bootstrap, suspension, and outage
  behavior are measured.
- [ ] Documentation retains Tor's end-to-end timing-correlation limitation.

**Verification:**

- [ ] Shared conformance suite passes or every failure is retained.
- [ ] Egress-denial tests block DNS, Iroh, identity, telemetry, update, preview,
  and crash endpoints.
- [ ] Packet captures and resource/latency measurements are retained.

**Dependencies:** Phase 1 checkpoint and network-isolation test support

**Files likely touched:**

- `spikes/transport-arti/README.md`
- `spikes/transport-arti/Cargo.toml`
- `spikes/transport-arti/src/main.rs`
- `spikes/transport-arti/tests/isolation.rs`
- `docs/evidence/transport-arti-spike.md`

**Estimated scope:** Medium

### Task 12: Run the SimpleX SMP queue spike

**Description:** Compare carrying Session Chat envelopes over SMP with an
independent Session Chat mailbox implementation that borrows only the queue
semantics. Do not adopt SimpleX chat encryption or membership.

**Acceptance criteria:**

- [ ] The spike measures envelope overhead, fixed-block behavior, queue
  rotation, offline delivery, two-router routing, and capability mapping.
- [ ] Integration and AGPL options are documented before any implementation is
  copied or embedded.
- [ ] The result recommends direct protocol use, prior-art-only use, or rejection.

**Verification:**

- [ ] Shared conformance cases are mapped and executed where the spike permits.
- [ ] Observer and authority matrices show no identity or MLS coupling.
- [ ] Exact protocol revision and implementation commit are retained.

**Dependencies:** Phase 1 checkpoint

**Files likely touched:**

- `spikes/transport-simplex/README.md`
- `spikes/transport-simplex/` experiment files
- `docs/evidence/transport-simplex-spike.md`

**Estimated scope:** Medium

### Task 13: Compare Katzenpost and Nym

**Description:** Run the same padded envelope workload, failure trace, observer
matrix, and measurement format through Katzenpost and Nym integration spikes.

**Acceptance criteria:**

- [ ] Both candidates are evaluated against identical logical delivery cases.
- [ ] Latency, variance, loss, retry work, polling, provider linkability,
  operator model, cover traffic, cost, and dependency burden are recorded.
- [ ] A local test network is not presented as real-world anonymity evidence.

**Verification:**

- [ ] Shared conformance mapping and adverse traces are retained.
- [ ] Packet captures confirm no fast/direct fallback.
- [ ] The comparison identifies evidence required for the next decision rather
  than selecting by feature list.

**Dependencies:** Phase 1 checkpoint and private-profile isolation support

**Files likely touched:**

- `spikes/transport-katzenpost/`
- `spikes/transport-nym/`
- `docs/evidence/transport-mixnet-comparison.md`

**Estimated scope:** Medium per independent spike

## Phase F: adjacent security work

These tasks share the privacy model but do not belong inside
`EnvelopeDelivery`:

- OHTTP first-contact directory lookup and observer-matrix tests;
- Privacy Pass one-use anonymous deposit stamps and quota tests;
- receive-bundle monitoring hooks for future KEYTRANS integration;
- desktop update rollback/freeze protection and release transparency; and
- OpenID4VP credential presentation in the admission layer.

Keeping them separate prevents the transport abstraction from becoming a
generic security-service interface.

## Risks and mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Trait is shaped around the first SDK | High | Stabilize memory semantics and conformance before real adapters |
| Adapter silently retries or opens background connections | High | Operation budgets, manifest declarations, scoped network broker or process isolation |
| Profile becomes a vague privacy score | High | Versioned closed constraints and observer matrices |
| Durable outbox and adapter state diverge | High | Transactional idempotency and crash-boundary tests |
| Capability appears in logs or errors | High | Non-debug secret types and seeded redaction tests |
| Strong adapter ordering leaks into core assumptions | Medium | Adverse memory schedule remains mandatory control path |
| Dynamic dispatch complicates Rust API prematurely | Medium | Resolve only after types and semantics compile generically |
| Too many candidate adapters delay Phase 1 | High | No real-network work before the Phase 1 checkpoint |
| Public mixnet exists but Session Chat has a tiny distinguishable traffic set | High | Measure application anonymity set and retain conservative claims |

## Open questions requiring maintainer review

- Should the first Rust API use generics, an actor boundary, or object-safe
  boxed futures?
- Does acknowledgement authority live per mailbox, per poll batch, or per
  delivery in the first provider protocol?
- Which durable component owns receive cursors and acknowledgement scheduling?
- Can an in-process network broker constrain Iroh and Arti sufficiently, or are
  separate adapter processes the preferred private-mode boundary?
- Where will future authenticated profile negotiation be bound without changing
  the existing Phase 1 invitation format?

These questions affect implementation shape, not the accepted security
boundaries. They should be resolved during Task 1 or the smallest task that can
produce direct evidence.
