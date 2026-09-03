# Implementation plan: Phase 1 protocol laboratory closeout

Status: proposed closeout plan; P1-0 documentation baseline complete,
implementation has not started

Date: 2026-09-02

## Objective

Finish the capability-only protocol foundation and retain enough executable
evidence to mark the Phase 1 laboratory complete without implying that a
user-facing or production-ready application exists.

Phase 1 is complete when two independent clients can establish, operate,
recover, and close a capability-admitted two-person session through the
complete Phase 1 protocol boundary under bounded deterministic hostile
conditions, without a GUI or real network service.

This plan sequences the remaining work. The canonical product, architecture,
threat-model, protocol specifications, and accepted ADRs remain authoritative.
If implementation requires a security or protocol contract to change, update
the shared contract first and record the consequential decision in an ADR and
the threat model in the same change.

## Completion boundary

Phase 1 completion requires all of the following:

- versioned invitation, protected-join, opaque-envelope, MLS, admission, and
  transport contracts remain bounded, canonical, and covered by positive and
  negative fixtures;
- one restartable inviter-local owner resolves invitation reservation, request
  replay, approval/result, MLS membership, invitation consumption, and Welcome
  outbox state without reconstructing or substituting the admitted KeyPackage;
- the joining client atomically persists the joined MLS state and consumes its
  exact one-time KeyPackage;
- the provider-neutral transport boundary has complete Phase 1 authority,
  lifecycle, cursor, redaction, retry, and adverse-delivery conformance;
- the headless composition crosses the common boundary for the operations it
  claims and the independent-process runner proves the canonical Phase 1
  scenarios; and
- the exact closeout revision passes the required repository, three-platform,
  dependency, coverage, and retained L2 evidence gates.

The following are not Phase 1 blockers:

- GitHub or credential admission;
- a hosted rendezvous service or real network adapter;
- a desktop shell, polished human-approval UI, or deep-link integration;
- production vault/key-protector selection, packaging, updates, or operated
  release infrastructure;
- physical power-loss, backup/restore, stale-snapshot rollback, or secure
  deletion evidence;
- multi-use invitations, large groups, attachments, recovery, or multi-device
  synchronization; and
- a cross-implementation MLS or production-security claim.

Those items keep their existing roadmap and release gates. Phase 1 retains the
current single-use, two-participant, capability-only scope and its explicit
simulated approval input.

## Application-bootstrap rule

Use `sessionctl`, `sessionctl-l1`, and `sessionctl-l2` as the Phase 1 reference
composition and evidence applications. Add another application entry point
only when an OS or process boundary cannot be proven through those headless
runners. Do not select a desktop framework or create a production service to
close a protocol-only gap.

The early fixture-driven UX-validation prototype may proceed independently,
but its findings are product evidence and cannot mark a protocol task complete.

## Retained baseline

| Area | Retained evidence | Closeout gap |
| --- | --- | --- |
| Wire and crypto | Canonical invitation/envelope encodings, strict Ed25519, fixed HPKE PSK contexts, exact KeyPackage binding, and hostile parsing tests | Preserve compatibility fixtures and claim limits while later tasks change composition |
| Admission and MLS | Capability verification, in-memory replay and invitation reservations, explicit approval, exact two-party Add/Welcome, messaging, update, and removal | Restartable durable replay/reservation/approval ownership before membership mutation |
| Durable storage | Atomic SQLCipher inviter/joiner commits, schema migration, identity/group reload, ambiguous-result recovery, and durable Welcome leases | The current database retains approved transaction shadows but cannot durably resolve the complete pre-commit replay/reservation/approval lifecycle |
| Transport | Right-specific types, bounded common dispatch, cursorless memory adapter, adverse trace parser, lifecycle/queue verdicts, and defective bridges | Provider-wide issuance/lifecycle conformance, arbitrary delay, exhaustive authority/resource verdicts, and common-boundary composition |
| Process evidence | Positive independent-process join, one exact-replay rejection, inviter/joiner kill sweeps, and SQLite-visible fault injection | Remaining `E2E-JOIN-002` cases and Welcome delivery lease/result process-kill recovery |
| Closeout | Canonical scenario catalog, redacted manifests, CI matrix, and coverage ratchets | One Phase 1 evidence matrix and exact-revision completion review |

## Dependency graph

```text
P1-1 durable recovery contract
  -> P1-2 durable authorization owner
     -> P1-3 durable admission composition
        -> P1-7 hostile first-contact process cases
        -> P1-8 Welcome delivery process-kill evidence

P1-4 transport lifecycle contract
  -> P1-5 conformance completion
     -> P1-6 common-boundary headless composition
        -> P1-7 hostile first-contact process cases

P1-7 + P1-8
  -> P1-9 closeout evidence matrix
     -> P1-10 exact-revision completion decision
```

The durable and transport contract tracks may proceed independently. Changes
within each track remain sequential because later work depends on the exact
contract and fixtures established by the preceding task.

## Phase 1 planning choices

- A process loss before the inviter-local membership transaction begins
  terminally abandons that request. The durable owner retains its replay record
  through expiry and releases only the matching invitation generation. It does
  not serialize or recreate the provider's live membership authority.
- Once the membership transaction may have begun, recovery uses the exact
  transaction ID and accepts only the complete old or complete committed state.
- Phase 1 adds a deterministic cursor-bearing lifecycle provider under the
  publish-disabled conformance crate. LocalV1 and the ordinary memory control
  profile remain cursorless and fail closed on supplied cursors.
- Every canonical `E2E-JOIN-002` input class crosses the process boundary once.
  Table-driven cases may share setup, but each requires a fresh authoritative
  state inspection and its own bounded evidence result.

These choices are proposed execution constraints. P1-1 and P1-4 record their
security consequences in the governing contracts before implementation.

## Task P1-0: Publish the closeout baseline

**Description:** Reconcile the current documentation, give Phase 1 one explicit
completion boundary, distinguish laboratory, pre-network, and production gates,
and repair planning metadata that could send later work in conflicting
directions.

**Acceptance criteria:**

- [x] The closeout plan is indexed from the documentation map and roadmap.
- [x] Active plans and the research backlog distinguish retained evidence from
      remaining Phase 1 work.
- [x] ADR identifiers and plan status summaries are unique and internally
      consistent.

**Verification:**

- [x] `node --test scripts/check-rust-coverage.test.mjs scripts/check-repository.test.mjs scripts/setup-codex-links.test.mjs spikes/sealed-invitation-provider/test/provider.test.mjs`
- [x] `node scripts/check-repository.mjs`
- [x] `git diff --check`

**Dependencies:** None

**Files likely touched:**

- `docs/README.md`
- `docs/ROADMAP_V2.md`
- `docs/RESEARCH_BACKLOG.md`
- `docs/plans/REAL_WORLD_E2E_TESTING.md`
- `docs/plans/TRANSPORT_ABSTRACTION_IMPLEMENTATION.md`
- `docs/adr/`

**Estimated scope:** Medium; documentation only

## Task P1-1: Freeze restartable authorization recovery

**Description:** Extend the accepted invitation/admission transaction contracts
with the exact durable pre-commit states and restart transitions. Specify what
is persisted after verification, while approval is pending, after rejection or
abandonment, and while membership commit outcome is unknown. Pre-commit process
loss follows the Phase 1 policy above: abandon the request, retain replay
history, and release only the exact live invitation reservation.

**Acceptance criteria:**

- [ ] The contract binds every durable state to the exact invitation
      generation, request ID and nonce, verifier context, KeyPackage reference,
      proof/request fingerprint, expiry, and one-shot transition authority
      without persisting a reconstructible membership authority.
- [ ] Restart, expiry, rejection, conflict, and ambiguous-result transitions
      preserve replay protection; pre-commit restart abandons safely and never
      reconstructs an admitted KeyPackage from identifiers or display metadata.
- [ ] The ADR and threat model record retention, bounds, rollback assumptions,
      and the boundary between durable authorization and simulated human input.

**Verification:**

- [ ] Repository documentation checks pass.
- [ ] Contract fixtures or model tests fail first for every newly specified
      transition before implementation begins.

**Dependencies:** P1-0

**Files likely touched:**

- `docs/specs/INVITER_JOIN_TRANSACTION_V1.md`
- `docs/specs/PROTECTED_CAPABILITY_JOIN_V1.md`
- `docs/IDENTITY_AND_ADMISSION.md`
- `docs/THREAT_MODEL.md`
- the governing ADR under `docs/adr/`

**Estimated scope:** Medium; contract-first documentation and fixtures

## Task P1-2: Implement the durable authorization owner

**Description:** Evolve `storage-sqlcipher` so the next compatible schema and
typed API own the P1-1 states before MLS mutation. Keep the SQLCipher store as
the sole owner rather than adding a second replay, approval, or invitation
ledger.

**Acceptance criteria:**

- [ ] The next schema version migrates accepted frozen fixtures atomically and
      unknown, malformed, stale, conflicting, or over-capacity records fail
      closed.
- [ ] Reserve, recover, reject/abandon, approve, consume, and replay-result
      operations enforce exact generation and one-shot ownership across
      close/reopen.
- [ ] Secret-bearing records remain bounded, encrypted at rest by the selected
      laboratory adapter, redacted from diagnostics, and zeroized where owned
      buffers make that possible.

**Verification:**

- [ ] `cargo test -p storage-sqlcipher --all-features --locked --offline`
- [ ] Targeted migration, close/reopen, conflict, capacity, expiry, and
      malformed-state tests pass.

**Dependencies:** P1-1

**Files likely touched:**

- `crates/storage-sqlcipher/src/lib.rs`
- `crates/storage-sqlcipher/tests/boundary_validation.rs`
- a focused durable-authorization test under `crates/storage-sqlcipher/tests/`
- the next frozen schema fixture under `crates/storage-sqlcipher/tests/fixtures/`
- `crates/storage-sqlcipher/README.md`

**Estimated scope:** Medium; split schema/API from composition if it exceeds one
focused review

## Task P1-3: Connect capability admission to durable recovery

**Description:** Replace the headless path's in-memory-only replay and
invitation authority handoff with the durable P1-2 owner while preserving the
provider's exact parsed KeyPackage and linear membership authority during the
live attempt. A restart before the transaction begins abandons that attempt as
P1-1 specifies; a recovered outcome-unknown commit finalizes once without a
second MLS Add.

**Acceptance criteria:**

- [ ] Fresh-process recovery before or after approval but before transaction
      staging abandons the request, retains its replay record, releases only the
      exact invitation reservation, and never authorizes a substituted
      KeyPackage.
- [ ] Rollback releases only the matching live reservation; a committed or
      outcome-unknown transaction remains consumed and exact retry is
      idempotent.
- [ ] `sessionctl` still completes `E2E-JOIN-001` with one membership commit,
      one Welcome job, and no provider proof or bearer material in evidence.

**Verification:**

- [ ] `cargo test -p admission-capability --all-features --locked --offline`
- [ ] `cargo test -p storage-sqlcipher --test capability_composition --locked --offline`
- [ ] `cargo test -p sessionctl --test phase_one --locked --offline`

**Dependencies:** P1-2

**Files likely touched:**

- `crates/admission-capability/src/lib.rs`
- `crates/admission-capability/tests/capability_approval.rs`
- `crates/storage-sqlcipher/tests/capability_composition.rs`
- `apps/sessionctl/src/lib.rs`
- `apps/sessionctl/tests/phase_one.rs`

**Estimated scope:** Medium; use a separate PR from the storage schema

## Checkpoint A: Durable authority

- [ ] P1-1 through P1-3 are complete and independently reviewed.
- [ ] A process restart cannot erase replay history, create a second live
      invitation reservation, or repeat MLS Add.
- [ ] The SQLCipher laboratory remains explicitly separate from a product vault
      or rollback-resistance claim.

## Task P1-4: Complete the provider-neutral transport lifecycle contract

**Description:** Close the remaining common-contract gap for scoped capability
issuance, mailbox lifecycle/rotation, generation-bound cursor handling, and
persist-before-acknowledge ordering. Keep LocalV1 and the Phase 1 memory profile
cursorless where specified, and define the deterministic cursor-bearing
conformance-provider requirements that will prove both positive lifecycle
behavior and fail-closed unsupported operations through the stable boundary.

**Acceptance criteria:**

- [ ] Deposit, receive, acknowledgement, and rotation authority issuance and
      lifecycle transitions are bounded, right-specific, generation-bound, and
      incapable of being authorized by identifiers or cursors.
- [ ] Cursor persistence/invalidity, acknowledgement ordering, rotation,
      restart, and explicit resynchronization semantics match the accepted
      transport research without selecting a network provider.
- [ ] Compile-time misuse and redaction tests prove the contract catches
      authority collapse, and a closed conformance-provider fixture contract
      defines every positive and stale-state behavior required by P1-5.

**Verification:**

- [ ] `cargo test -p session-transport --all-features --locked --offline`
- [ ] The transport specification, ADR, and contract tests agree on supported
      and deliberately unsupported Phase 1 operations.

**Dependencies:** P1-0

**Files likely touched:**

- `crates/session-transport/src/capability.rs`
- `crates/session-transport/src/contract.rs`
- `crates/session-transport/src/dispatch.rs`
- `crates/session-transport/tests/dispatch_contract.rs`
- `docs/specs/TRANSPORT_ABSTRACTION_V1.md`

**Estimated scope:** Medium; keep provider implementation out of this task

## Task P1-5: Finish the shared adverse-transport verdict suite

**Description:** Complete Task 6 of the transport implementation plan with
a deterministic cursor-bearing lifecycle provider, arbitrary-delay behavior,
and the exhaustive authority/resource matrix. Extend deliberately defective
bridges so every common verdict is known to detect the violation it names.

**Acceptance criteria:**

- [ ] The canonical trace vocabulary and runner cover bounded arbitrary delay
      without wall-clock sleeps or unbounded queues.
- [ ] The publish-disabled deterministic provider passes positive cursor,
      persist-before-acknowledge, rotation, restart, and resynchronization
      cases, while every right/resource substitution and stale generation has
      a normalized rejection verdict.
- [ ] Fresh-adapter double replay, quiescence, redaction, and defective-bridge
      detection remain deterministic and byte-identical.

**Verification:**

- [ ] `cargo test -p transport-memory --all-features --locked --offline`
- [ ] `cargo test -p transport-conformance --all-features --locked --offline`

**Dependencies:** P1-4

**Files likely touched:**

- `crates/transport-conformance/src/trace.rs`
- `crates/transport-conformance/src/trace/runner.rs`
- a focused deterministic lifecycle provider under `crates/transport-conformance/`
- `crates/transport-conformance/tests/memory.rs`
- focused fixtures under `crates/transport-conformance/tests/fixtures/`

**Estimated scope:** Medium; arbitrary delay and the authority matrix may land
as separate reviewable commits

## Task P1-6: Route the headless flow through the common transport boundary

**Description:** Use the generalized `EnvelopeDelivery` boundary for the
Phase 1 message operations assigned to it instead of relying on
memory-provider-specific calls in the composition root. Preserve the special
LocalV1 Welcome endpoint and its durable deposit-only coordinator where the
accepted profile requires it.

**Acceptance criteria:**

- [ ] `E2E-MSG-001`, `E2E-MSG-002`, `E2E-REMOVE-001`, and the Phase 1 portion
      of `E2E-AUTH-001` cross the common dispatch interface with explicit
      clocks, deadlines, cancellation, bounds, and right-specific authority.
- [ ] Replacing the conforming memory adapter with a deliberately defective
      adapter makes the appropriate scenario fail without changing MLS or
      admission code.
- [ ] The existing versioned `sessionctl` output and redaction contract remain
      stable unless a separately reviewed evidence-version change is required.

**Verification:**

- [ ] `cargo test -p sessionctl --test phase_one --locked --offline`
- [ ] Targeted adverse-delivery and orchestration-fault tests pass.
- [ ] `cargo test -p transport-conformance --all-features --locked --offline`

**Dependencies:** P1-5

**Files likely touched:**

- `apps/sessionctl/src/lib.rs`
- `apps/sessionctl/tests/phase_one.rs`
- `apps/sessionctl/tests/faults.rs`
- `crates/transport-memory/src/lib.rs`
- `crates/transport-conformance/tests/memory.rs`

**Estimated scope:** Medium; no network or GUI code

## Checkpoint B: Common transport boundary

- [ ] P1-4 through P1-6 are complete and independently reviewed.
- [ ] The memory adapter remains the deterministic control path.
- [ ] No real adapter, runtime, or product profile is selected implicitly.

## Task P1-7: Complete hostile independent-process first contact

**Description:** Expand `E2E-JOIN-002` beyond exact replay using the existing
bounded filesystem IPC runner. Exercise only cross-boundary cases that add
evidence beyond unit tests: malformed and expired requests, copied or
wrong-invitation inputs, wrong KeyPackage binding, wrong verifier context, and
unsafe duplication/reordering at the untrusted forwarder.

**Acceptance criteria:**

- [ ] Every canonical `E2E-JOIN-002` class fails before approval, MLS Add, or
      durable membership mutation and a fresh inspector proves the authoritative
      state is unchanged.
- [ ] The untrusted service receives only canonical public objects and cannot
      obtain bearer invitation, raw vault key, provider proof, or client-only
      authority.
- [ ] Each case has bounded process time, child cleanup, directory cleanup, and
      a fixed secret-free evidence record.

**Verification:**

- [ ] `cargo test -p sessionctl --test l1_process --locked --offline`
- [ ] The retained manifests pass forbidden-term and maximum-size checks.

**Dependencies:** P1-3 and P1-6

**Files likely touched:**

- `apps/sessionctl/src/l1_process.rs`
- `apps/sessionctl/tests/l1_process.rs`
- focused fixtures under `apps/sessionctl/tests/` if needed
- `apps/sessionctl/README.md`

**Estimated scope:** Medium; split cases if review size grows beyond five files

## Task P1-8: Retain Welcome-delivery process-kill recovery

**Description:** Extend the existing checked L2 controller to the durable
Welcome lease/result transitions already enumerated in the L2 plan. Kill the
coordinator around lease commit, adapter acceptance, accepted/failed result
commit, re-lease, and terminalization, then verify state in a fresh process.

**Acceptance criteria:**

- [ ] Every observed supported checkpoint recovers to one allowed complete
      state with one membership commit and byte-identical retry material.
- [ ] Ambiguous adapter acceptance, stale or foreign results, last-attempt
      expiry, and re-lease cannot resurrect work, consume another attempt, or
      mutate a newer generation.
- [ ] Raw case evidence remains non-public; the public aggregate retains only
      bounded secret-free completion evidence on Linux, macOS, and Windows.

**Verification:**

- [ ] Checked-cfg Welcome delivery suites pass with
      `RUSTFLAGS="--cfg session_chat_storage_fault_testing"` and one test thread.
- [ ] Existing `l2_public_evidence` and deliberately defective-evidence tests
      continue to pass.

**Dependencies:** P1-3

**Files likely touched:**

- `apps/sessionctl/src/l2_process.rs`
- `apps/sessionctl/src/l2_process/evidence.rs`
- a focused Welcome-delivery L2 test under `apps/sessionctl/tests/`
- `crates/storage-sqlcipher/src/fault_testing.rs`
- `docs/plans/L2_PROCESS_FAULT_TESTING.md`

**Estimated scope:** Medium; application-kill evidence only, not physical
power-loss or rollback evidence

## Task P1-9: Publish the Phase 1 evidence matrix

**Description:** Map every Phase 1 completion requirement and applicable
canonical scenario to its exact tests, retained evidence, supported platforms,
and claim limit. Resolve any uncovered cell with code/tests or explicitly move
it outside Phase 1 before requesting completion review.

**Acceptance criteria:**

- [ ] The matrix covers `E2E-JOIN-001`, `E2E-JOIN-002`, `E2E-TXN-001`,
      `E2E-MSG-001`, `E2E-MSG-002`, `E2E-REMOVE-001`, `E2E-AUTH-001`, and the
      Phase 1 portions of retention, upgrade, and abuse scenarios.
- [ ] Every passing claim links to executable evidence on the exact revision;
      missing physical/platform/product evidence remains visibly deferred.
- [ ] A fresh-context independent review finds no contradiction among the
      matrix, roadmap, architecture, threat model, ADRs, and active plans.

**Verification:**

- [ ] Repository documentation and link checks pass.
- [ ] `git diff --check`
- [ ] The independent review findings are resolved or explicitly accepted with
      rationale before completion is claimed.

**Dependencies:** P1-7 and P1-8

**Files likely touched:**

- a new Phase 1 record under `docs/evidence/`
- `docs/README.md`
- `docs/ROADMAP_V2.md`
- `docs/ARCHITECTURE_V2.md`
- `docs/THREAT_MODEL.md`

**Estimated scope:** Medium; evidence and documentation only

## Task P1-10: Make the completion decision on an exact revision

**Description:** Run the complete gate, obtain exact-revision portable CI
evidence, and only then change Phase 1 from `in progress` to `complete`. A
passing pull-request smoke is necessary but does not substitute for the full
non-PR three-platform L2 evidence run.

**Acceptance criteria:**

- [ ] The complete local gate passes, or any environment-only command is
      identified and verified by the corresponding required CI job.
- [ ] The merged candidate revision passes Rust, Node, coverage, dependency,
      and complete L2 evidence jobs on every required platform.
- [ ] A follow-up documentation checkpoint records the exact revision, marks
      this plan historical, and preserves every remaining product/network/
      platform limitation.

**Verification:**

- [ ] `node --test scripts/check-rust-coverage.test.mjs scripts/check-repository.test.mjs scripts/setup-codex-links.test.mjs spikes/sealed-invitation-provider/test/provider.test.mjs`
- [ ] `node scripts/check-repository.mjs`
- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings`
- [ ] `cargo test --workspace --all-features --locked --offline`
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked --offline`
- [ ] `cargo deny --all-features --locked check`, locally or through the required
      dependency-policy CI job
- [ ] The complete checked-cfg L2 suites from `.github/workflows/ci.yml` pass on
      Linux, macOS, and Windows for the exact completion revision.

**Dependencies:** P1-9

**Files likely touched:**

- `docs/evidence/`
- `docs/ROADMAP_V2.md`
- `docs/README.md`
- completed plans under `docs/plans/`

**Estimated scope:** Small; verification and completion metadata only

## Pull-request sequence

Keep each change reviewable and green:

1. **Documentation baseline:** P1-0 only.
2. **Durable recovery contract:** P1-1, with failing model/fixture tests where
   applicable.
3. **Durable authorization owner:** P1-2.
4. **Durable admission composition:** P1-3.
5. **Transport lifecycle contract:** P1-4.
6. **Transport conformance completion:** P1-5.
7. **Headless common-boundary composition:** P1-6.
8. **Hostile first contact:** P1-7.
9. **Welcome delivery process-kill evidence:** P1-8.
10. **Evidence and completion:** P1-9 followed by the exact-revision P1-10
    checkpoint.

Adjacent small tasks may share a PR only when they have the same owner and the
combined diff remains independently reviewable. Do not merge the durable and
transport tracks into one implementation PR.

## Risks and mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Durable display metadata accidentally becomes membership authority | Critical | Keep the concrete provider's exact KeyPackage and proof provenance linear; never reconstruct from `ApprovalContext` or identifiers |
| A second replay or outbox ledger creates split-brain recovery | High | Keep SQLCipher as the only durable owner and make every transition exact-generation and idempotency bound |
| Positive cursor/lifecycle work accidentally selects a network provider | Medium | Specify and test the common semantics with deterministic providers only |
| Process tests duplicate unit coverage without proving a new boundary | Medium | Add only cases that cross client/service/restart boundaries and require a fresh authoritative-state inspector |
| L2 evidence is mistaken for power-loss or rollback proof | High | Keep application-kill/SQLite-visible claims separate and retain physical-fault work outside Phase 1 |
| Phase 1 expands into a desktop or hosted product | High | Enforce the application-bootstrap rule and explicit non-goals above |

## Review gate

No implementation task begins until reviewers accept this closeout scope, the
P1-1 abandon-and-retain-replay recovery policy, and the P1-4 deterministic
cursor-provider boundary. Any requested expansion into product UI, real
networking, platform custody, or production durability returns to the roadmap
rather than silently expanding Phase 1.
