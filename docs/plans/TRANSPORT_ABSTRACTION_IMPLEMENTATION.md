# Implementation plan: profile-bound transport abstraction

Status: proposed stabilization plan; generalized transport API and network
adapter work must not begin until ADR 0015 and the version 1 contract are reviewed

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

## Existing baseline on `master`

- `session-protocol` owns bounded canonical `OpaqueEnvelope` bytes and the
  closed local Welcome deposit endpoint from ADR 0014.
- `session-transport` implements bounded local one-message deposit, receive,
  and acknowledgement with separate authorities and exact-retry behavior.
- `session-inviter-transaction` models atomic membership/outbox visibility,
  ambiguous commit recovery, bounded delivery leasing, and exact retry in
  memory.
- The local adapter has no common `EnvelopeDelivery` trait, profile binder,
  general queue/poll model, adverse-network scheduler, network path, or durable
  storage claim.

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

**Progress (2026-08-20):** The bounded contract-values sub-increment is
implemented with closed profile IDs, validated adapter IDs, exact canonical
envelope ownership, operation budgets, bounded retry advice, context-free
failures, and a compile-fail `CanonicalEnvelope: Debug` check. Capability types
and the delivery trait remain deliberately unimplemented, so Task 3 is not yet
complete.

**Acceptance criteria:**

- [ ] Deposit cannot accept receive, acknowledgement, or rotation authority.
- [ ] A delivery ID or cursor cannot authorize acknowledgement.
- [ ] Secret-bearing values have reviewed ownership, cloning, serialization,
  zeroization, and redaction behavior.
- [ ] The contract accepts only canonical bounded envelope objects or validated
  views derived from `session-protocol` bytes.
- [ ] Existing local callers remain covered while migration to the common trait
  is explicit and reviewable.

**Verification:**

- [ ] Compile-fail or type tests cover wrong-right calls.
- [ ] Error/log fixture tests contain none of the seeded secret bytes.
- [ ] `cargo test -p session-transport`

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

- [ ] ADR 0015 is accepted for implementation.
- [ ] The crate builds without a network dependency.
- [ ] Authority and redaction tests pass.
- [ ] Review before adding mutable delivery state.

## Phase C: deterministic memory control path

### Task 4: Generalize the existing memory adapter into the control path

**Description:** Preserve the narrow local Welcome behavior while adding a
deterministic in-memory implementation of the common bounded deposit, poll, and
acknowledgement semantics. Keep it in `session-transport` for the first
stabilization slice; extraction into `transport-memory` requires an explicit
review after the trait and ownership boundaries settle.

**Acceptance criteria:**

- [ ] Repeating identical destination/ID/bytes is idempotent.
- [ ] Reusing an ID with different bytes conflicts without overwrite.
- [ ] Queue count, byte, TTL, and poll-page limits are enforced before
  unbounded allocation.

**Verification:**

- [ ] Unit tests cover full queues, expiration, stale cursors, duplicate
  deposit, conflicting deposit, wrong rights, and repeated acknowledgement.
- [ ] The existing local Welcome mailbox tests remain unchanged or gain only
  explicitly reviewed compatibility updates.
- [ ] `cargo test -p session-transport`

**Dependencies:** Tasks 2 and 3

**Files likely touched:**

- `crates/session-transport/src/memory.rs`
- `crates/session-transport/tests/generalized_memory.rs`
- `crates/session-transport/tests/local_welcome_mailbox.rs`

**Estimated scope:** Medium

### Task 5: Add the adverse-network schedule

**Description:** Add a deterministic controller that scripts delay, loss,
duplication, reordering, corruption, stale replay, queue saturation,
acknowledgement loss, cursor invalidation, and unavailability.

**Acceptance criteria:**

- [ ] Every fault is selected through deterministic test input rather than
  wall-clock races or nondeterministic randomness.
- [ ] Scheduled work is bounded and cancelable.
- [ ] The trace format contains no secret capability bytes or plaintext.

**Verification:**

- [ ] Golden traces replay identically across repeated test runs.
- [ ] Tests prove no work remains after cancellation or deadline.
- [ ] `cargo test -p session-transport adverse`

**Dependencies:** Task 4

**Files likely touched:**

- `crates/session-transport/src/adverse.rs`
- `crates/session-transport/tests/adverse.rs`
- `crates/session-transport/tests/fixtures/trace-v1.txt`

**Estimated scope:** Medium

### Task 6: Build the reusable adapter conformance harness

**Description:** Extract contract tests that any adapter factory can run. The
memory adapter is the first implementation and supplies controllable failure
injection.

**Acceptance criteria:**

- [ ] The harness covers every common test in the transport specification.
- [ ] Adapter-specific tests can add evidence without weakening common tests.
- [ ] Failure output identifies normalized codes without printing secret data.

**Verification:**

- [ ] The memory adapter passes the harness.
- [ ] A deliberately defective test adapter fails idempotency, redaction, and
  deadline tests for the expected reasons.
- [ ] `cargo test -p transport-conformance`

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

**Acceptance criteria:**

- [ ] Unknown profile/manifest versions and contradictory requirements fail
  closed.
- [ ] Adapter IDs never substitute for profile IDs.
- [ ] No API accepts a generic fallback list.

**Verification:**

- [ ] Tests reject undeclared egress, excessive sizes, unsupported operations,
  broader retry behavior, and unknown versions.
- [ ] Snapshot tests show binding records contain no routes or authority bytes.
- [ ] `cargo test -p session-transport profile`

**Dependencies:** Tasks 3 and 6

**Files likely touched:**

- `crates/session-transport/src/profile.rs`
- `crates/session-transport/src/manifest.rs`
- `crates/session-transport/src/binding.rs`
- `crates/session-transport/tests/profile_binding.rs`

**Estimated scope:** Medium

### Task 8: Implement coordinator policy and the owner-store port

**Description:** Add the transport coordinator that applies expiry, dedup,
poll bounds, acknowledgement scheduling, retry budgets, and cancellation around
an adapter. Define an owner-store port through which it leases work and reports
success or bounded failure. The coordinator must not duplicate membership,
outbox, lease, attempt-count, or ambiguous-commit truth already owned by
`session-inviter-transaction` or a future durable implementation.

**Acceptance criteria:**

- [ ] Duplicate delivery never emits two accepted core events.
- [ ] Retry never exceeds attempts, bytes, deadline, or envelope expiration.
- [ ] Adapter success/failure cannot reopen invitation or MLS membership state.
- [ ] There is exactly one authoritative outbox/lease record for a Welcome.

**Verification:**

- [ ] Model or property tests exercise arbitrary duplicate/reorder/loss traces.
- [ ] Tests distinguish deposit acceptance, receipt, acknowledgement, and
  application processing.
- [ ] A deliberately stale or foreign lease cannot report delivery state.
- [ ] `cargo test -p session-transport coordinator`

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
apply the same owner-store port to the future durable transaction required by
ADRs 0008, 0012, and 0014. Membership commit and exact encrypted Welcome work
remain atomic in that owner-local store, while delivery retry remains
idempotent and cannot repeat MLS Add or Commit.

**Acceptance criteria:**

- [ ] A committed membership transition always has recoverable outbox work.
- [ ] An uncommitted transition exposes no deliverable job.
- [ ] Restart recovery retries delivery without repeating MLS membership
  mutation or releasing the invitation.
- [ ] Coordinator state can be discarded and reconstructed without losing or
  contradicting authoritative outbox state.

**Verification:**

- [ ] Crash tests cover every write boundary before and after commit.
- [ ] Duplicate, lost, reordered, and delayed Welcome delivery remains safe.
- [ ] The in-memory conformance model passes before a durable adapter is wired.
- [ ] Exact storage command from the selected adapter is retained in test
  evidence.

**Dependencies:** Task 8, the existing inviter-transaction conformance model,
and the future durable MLS/storage increment governed by ADRs 0008 and 0012

**Files likely touched:**

- `crates/session-core/src/join.rs`
- `crates/session-inviter-transaction/src/lib.rs`
- `crates/session-inviter-transaction/tests/conformance.rs`
- `crates/session-storage/src/transaction.rs`
- `crates/session-transport/src/outbox.rs`
- `crates/session-core/tests/join_recovery.rs`
- `crates/session-transport/tests/outbox_recovery.rs`

**Estimated scope:** Medium

## Checkpoint: Phase 1 transport control path

- [ ] Memory transport remains deterministic and offline.
- [ ] The complete Phase 1 headless flow passes through the common transport
  boundary.
- [ ] Duplicate/reordered delivery and crash recovery cannot repeat membership
  transitions.
- [ ] The owner-local transaction store is the sole durable outbox and lease
  authority; coordinator restart does not create a second ledger.
- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] Review retained evidence before any real network adapter.

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
