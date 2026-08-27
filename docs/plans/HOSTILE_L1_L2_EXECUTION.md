# Hostile L1 and L2 execution index

Status: wave 1 active

## Objective

Advance roadmap step 4 after the completed positive independent-process L1
runner. This wave retains the first hostile process-boundary cases, closes the
remaining reusable memory-adapter verdict gaps, and freezes the L2 abrupt-fault
contract before any crash-harness implementation. The canonical scenario and
layer requirements remain in
[`REAL_WORLD_E2E_TESTING.md`](REAL_WORLD_E2E_TESTING.md); this file records only
execution ownership and integration state.

Integration destination: `codex/l1-hostile-l2-wave1`, based on merged `master`
at `21e1d74`.

## Work items

| ID | Delivery unit | Dependencies | Owned paths | Status | Completion boundary |
| --- | --- | --- | --- | --- | --- |
| `W1-L1-HOSTILE` | Internal subagent | Positive `L1-PROCESS` | `apps/sessionctl/src/l1_process.rs`, `apps/sessionctl/tests/l1_process.rs`, new L1-only fixtures | Active | A bounded `E2E-JOIN-002` first-contact slice crosses the independent-process boundary and proves selected hostile input cannot mutate membership or produce secret-bearing evidence. |
| `W1-T6-COMPLETE` | Internal subagent | Retained adverse trace and memory runner | `crates/transport-conformance/**`, `crates/transport-memory/**` | Active | The next missing deterministic delay, queue-saturation, or authority/resource verdict slice is retained with a defective-adapter detection case and exact double-replay evidence. |
| `W1-L2-CONTRACT` | Internal subagent | ADR 0021 and retained SQLCipher recovery evidence | `docs/plans/L2_PROCESS_FAULT_TESTING.md` only | Active | A bounded contract enumerates process-kill/write-boundary cases, expected durable states, evidence/redaction rules, supported-platform constraints, and implementation slices without claiming power-loss or rollback resistance. |
| `W1-INTEGRATE` | Lead task | All active work items | This index plus canonical status documents after reconciliation | Pending | All child handoffs are reconciled, targeted and workspace gates pass, documentation matches retained behavior, and atomic commits are ready for review. |

## Verification

- `cargo test -p sessionctl --all-features --locked --offline`
- `cargo test -p transport-conformance --all-features --locked --offline`
- `cargo test -p transport-memory --all-features --locked --offline`
- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings`
- `cargo test --workspace --all-features --locked --offline`
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked --offline`
- retained Node and repository-policy commands from `AGENTS.md`

## Coordination rules

- Each writer owns only the paths listed above and must preserve concurrent
  edits elsewhere in the shared worktree.
- Writers do not commit. The lead reconciles and commits verified increments.
- Shared canonical plans, ADRs, coverage records, and repository indexes remain
  lead-owned until the implementation evidence is integrated.
- L2 runtime implementation does not begin in this wave; the contract is the
  dependency that enables safe parallel implementation in wave 2.
