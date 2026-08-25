# Handoff: Phase 1 Transport Delivery Checkpoint

## Objective And Boundary

Continue the Phase 1 transport control path from the first complete in-memory
Welcome-delivery slice into durable owner-store recovery. The retained code now
binds transport profiles, leases inviter-owned Welcome work, executes one
deposit attempt through a narrow provider-neutral interface, and supervises
pending futures on a cross-platform standard-library baseline.

This checkpoint does **not** establish durable restart safety, a production
network transport, packet-level privacy, or a user-facing product flow. Preserve
the existing authority split: the owner-local transaction store owns membership,
outbox, lease, attempt, and terminal-state truth; the coordinator owns bounded
execution policy; the adapter owns only the right-specific transport operation.

## Canonical Sources

- `AGENTS.md`
- `docs/ARCHITECTURE_V2.md`
- `docs/TRANSPORTS.md`
- `docs/THREAT_MODEL.md`
- `docs/ROADMAP_V2.md`
- `docs/specs/TRANSPORT_ABSTRACTION_V1.md`
- `docs/specs/INVITER_JOIN_TRANSACTION_V1.md`
- `docs/plans/TRANSPORT_ABSTRACTION_IMPLEMENTATION.md`, especially Tasks 8-9
- `docs/plans/REAL_WORLD_E2E_TESTING.md`
- `docs/research/WELCOME_DELIVERY_COORDINATOR_2026-08-25.md`
- ADRs 0008, 0014, 0015, and 0018

This handoff is navigation and execution context, not a new protocol or product
source of truth. If it conflicts with the files above, the canonical files win.

## Current Repository State

- Worktree: the repository root associated with the branch below
- Branch: `codex/transport-dispatch-contract`
- Checkpoint before this handoff: `1ab6bee1db889fc9a3907c7a52b6828833bc74d7`
- Merge-base with the current local `origin/master` reference:
  `936e1078eaaeb6b4b35cd2874e1fed50074ec78a`
- The checkpoint was rebased cleanly onto that base after the unrelated project
  overview site merge. The delivered PR branch is eight commits ahead and zero
  behind, including this handoff and one dependency-policy pin fix.
- The branch had no configured upstream before PR delivery.
- The worktree was clean after the rebase and before this metadata refresh.

## Completed Work And Evidence

Retained commits, oldest first:

1. `5b905a90` — dispatch conformance foundation
2. `034b3453` — LocalV1 conformance and fail-closed profile binding
3. `3c38a228` — scoped monotonic delivery leases and owner-store hardening
4. `64526ca3` — deposit-only Welcome coordinator
5. `befc1432` — inviter outbox to LocalV1 mailbox integration
6. `1ab6bee1` — delayed-wake, deadline, cancellation, and drop supervision

The slice retains:

- strict bounded and deterministic transport traces, exact receipt/mailbox/
  envelope binding, defective-adapter cases, and secret-free reports;
- lossless `RetryAdvice::After` normalization and delayed legal wake support;
- canonical LocalV1 endpoint/profile binding that rejects unsupported profiles;
- store-scoped lease identity that rejects stale and foreign results, excludes
  exhausted work, and validates exact committed envelope/endpoint material;
- a narrow `EnvelopeDeposit` interface and one-attempt coordinator with no
  duplicate outbox ledger;
- in-memory end-to-end evidence for acceptance, adapter failure, and ambiguous
  exact retry without repeating MLS membership mutation; and
- a portable blocking supervisor built from Rust standard-library threads,
  synchronization, and wakers. It is a headless baseline, not a UI-runtime
  selection.

Targeted verification already observed at checkpoint `1ab6bee1`:

```sh
cargo fmt --all --check
git diff --check
cargo test -p session-transport -p session-inviter-transaction --all-features --locked --offline
cargo clippy -p session-transport -p session-inviter-transaction --all-targets --all-features --locked --offline -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc -p session-transport -p session-inviter-transaction --all-features --no-deps --locked --offline
node scripts/check-repository.mjs
node --test scripts/check-repository.test.mjs scripts/setup-codex-links.test.mjs
```

The affected Rust run covered 40 `session-transport` runtime/integration tests,
39 compile-fail doctests, and 10 inviter conformance/integration tests. The
transport-conformance suite was also green at the earlier conformance/profile
checkpoint. No instrumented line or branch percentage has been claimed.

Post-handoff full-workspace verification observed on 2026-08-25:

```sh
cargo fmt --all --check
git diff --check
cargo test --workspace --all-features --locked --offline
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked --offline
node scripts/check-repository.mjs
node --test scripts/check-repository.test.mjs scripts/setup-codex-links.test.mjs
```

All commands above passed. `cargo deny --all-features --locked check` was also
attempted, but this environment does not have the `cargo-deny` subcommand
installed; dependency-policy evidence must therefore come from CI or a prepared
development environment.

## Decisions And Rationale

- Do not add a thin SQLCipher shim around the in-memory lease model. The current
  SQLCipher schema is version 1 and its `inviter_joins.outbox_state` permits only
  pending state. It cannot truthfully represent store identity, lease generation,
  attempt count, lease expiry, delivered state, or exhausted state.
- Evolve the durable schema and its compatibility fixtures before implementing
  `WelcomeOutboxPort` for SQLCipher. Lease acquisition and result recording must
  remain transactions over the one authoritative inviter record.
- Keep the coordinator stateless with respect to authoritative delivery truth.
  It may be recreated after restart and must reacquire work from the owner store.
- Keep local app execution cross-platform from the first retained increment.
  Native event-loop or key-store implementations belong behind common contracts;
  Linux, macOS, and Windows must retain the same baseline workflow.

## Blockers And Limitations

- Durable SQLCipher lease/restart behavior is not implemented or tested.
- The SQLCipher schema needs a versioned migration and compatibility fixtures.
- No process-kill, disk-full, rollback, or restart fault evidence exists for the
  coordinator/outbox composition.
- `sessionctl` still exercises its older in-process direct Welcome path rather
  than this coordinator plus durable owner store.
- Arbitrary model/property-generated duplicate, reorder, loss, and delay traces
  remain open.
- No real network adapter, packet capture, metadata-observer evidence, or
  production privacy claim exists.
- Fresh Linux/macOS/Windows CI evidence is still required for the new supervisor.
- Local `cargo-deny` verification remains unobserved because the subcommand was
  not installed. The complete Rust test, lint, and documentation gates did pass.

## Immediate Next Actions

1. Design the version 2 SQLCipher inviter-outbox schema and migration. At
   minimum represent durable store identity, delivery state, attempt count,
   lease generation/identity, lease expiry, and terminal delivered/exhausted
   states while preserving the exact envelope and endpoint bytes.
2. Add failing compatibility and durable behavior tests before the adapter:
   reopen/restart recovery, stale lease after re-lease, foreign-store lease,
   attempt exhaustion, lease expiry, ambiguous prior adapter acceptance, and
   atomic invisibility of uncommitted membership/outbox work.
3. Implement `WelcomeOutboxPort` for SQLCipher using one transaction per lease
   or result transition. Do not introduce coordinator-owned persistence.
4. Add crash-boundary/process/disk evidence, then wire the real admission/MLS
   product path through the durable transaction and coordinator.
5. Move `sessionctl` to that same composition, add machine-readable redacted E2E
   output, property traces, coverage instrumentation, and three-platform CI.

The safe first coding action is to inspect
`crates/storage-sqlcipher/src/lib.rs` around schema creation and inviter
transaction queries, then write the schema compatibility fixtures and failing
lease tests without changing coordinator authority.

## Verification Commands

Run the smallest storage checks first, then the complete gate:

```sh
cargo test -p storage-sqlcipher --all-features --locked --offline
cargo test -p session-transport -p session-inviter-transaction -p storage-sqlcipher --all-features --locked --offline
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo test --workspace --all-features --locked --offline
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked --offline
cargo deny --all-features --locked check
node scripts/check-repository.mjs
node --test scripts/check-repository.test.mjs scripts/setup-codex-links.test.mjs
```

For durable claims, also retain the exact process/restart and storage-fault
commands in repository evidence rather than relying only on in-process tests.

## Delivery Metadata

- Date: 2026-08-25
- Repository: `dills122/session-chat`
- Worktree: the repository root associated with the branch below
- Branch: `codex/transport-dispatch-contract`
- Base/merge-base: `936e1078eaaeb6b4b35cd2874e1fed50074ec78a`
- Code checkpoint: `1ab6bee1db889fc9a3907c7a52b6828833bc74d7`
- PR: not recorded in this worktree
- Dirty files before handoff creation: none
- The handoff itself is the documentation-only commit immediately after the code
  checkpoint; repository history and CI remain authoritative.
