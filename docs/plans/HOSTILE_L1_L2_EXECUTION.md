# Hostile L1 and L2 execution index

Status: completed historical wave-1 index; active L2 status moved to
`L2_PROCESS_FAULT_TESTING.md`

## Objective

Advance roadmap step 4 after the completed positive independent-process L1
runner. This wave retains the first hostile process-boundary cases, closes the
remaining reusable memory-adapter verdict gaps, and freezes the L2 abrupt-fault
contract before any crash-harness implementation. The canonical scenario and
layer requirements remain in
[`REAL_WORLD_E2E_TESTING.md`](REAL_WORLD_E2E_TESTING.md); this file records only
execution ownership and integration state.

Historical integration destination: `codex/l1-hostile-l2-wave1`, based on
merged `master` at `21e1d74`. The retained results subsequently landed on
`master`; this file no longer describes an active branch or review gate.

## Work items

| ID | Delivery unit | Dependencies | Owned paths | Status | Completion boundary |
| --- | --- | --- | --- | --- | --- |
| `W1-L1-HOSTILE` | Internal subagent | Positive `L1-PROCESS` | `apps/sessionctl/src/l1_process.rs`, `apps/sessionctl/tests/l1_process.rs`, new L1-only fixtures | Complete | Exact replay now crosses Bob, the untrusted service, and Alice as separate processes; Alice rejects the second protected request before approval, MLS Add, or transaction staging, and a fresh inspector proves no durable group exists. The rest of the hostile first-contact matrix remains open. |
| `W1-T6-COMPLETE` | Internal subagent | Retained adverse trace and memory runner | `crates/transport-conformance/**`, `crates/transport-memory/**` | Complete | A bounded queue-saturation fixture rejects the ninth envelope after eight accepted deposits, reaches quiescence, double-replays identically, and catches a deliberately over-accepting bridge. Arbitrary delay and the exhaustive authority/resource matrix remain open. |
| `W1-L2-CONTRACT` | Internal subagent | ADR 0021 and retained SQLCipher recovery evidence | `docs/plans/L2_PROCESS_FAULT_TESTING.md` only | Complete | The implementation-ready contract enumerates process-kill/write-boundary cases, complete-state oracles, evidence/redaction rules, supported-platform constraints, ownership-consumable `sessionctl` crash suites, and an explicitly owned cfg-only named-VFS open seam without claiming power-loss or rollback resistance. |
| `W1-INTEGRATE` | Lead task | All completed work items | This index plus canonical status documents after reconciliation | Complete | All child handoffs are reconciled, targeted and workspace gates pass, documentation matches retained behavior, and atomic commits are ready for review. |

## Retained increments

- `ecf68be` retains the exact-replay `E2E-JOIN-002` process slice.
- `599105f` retains the bounded queue-saturation transport verdict.
- `3df36cb` freezes the L2 process and storage fault-testing contract.

## Independent-review disposition

Review instance 1 of 1 returned `Not ready` with two P1 plan findings and no
executable finding. Both findings were accepted. The remediated contract:

- colocates the reusable controller/oracle and every process-fault integration
  suite under `sessionctl`, preserving the existing dependency direction; and
- assigns L2-0 the private, cfg-only default-or-named storage open seam and its
  ordinary-build exclusion tests, while L2-4 remains the isolated unsafe VFS
  owner.

The user authorized one additional fresh-context pass, making the revised
review limit instance 2 of 2. L2 runtime work did not begin until those
ownership seams were reconciled. The resulting retained implementation and
remaining gates are tracked in `L2_PROCESS_FAULT_TESTING.md`.

## Verification

- `cargo test -p sessionctl --all-features --locked --offline`
- `cargo test -p transport-conformance --all-features --locked --offline`
- `cargo test -p transport-memory --all-features --locked --offline`
- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings`
- `cargo test --workspace --all-features --locked --offline`
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked --offline`
- retained Node and repository-policy commands from `AGENTS.md`

All listed commands passed on 2026-08-26. The production coverage gate passed
at 92.99% lines, 88.56% regions, and 89.56% functions after focused hostile-role
failure tests preserved the existing ratchet. `cargo deny --version` reported
that `cargo-deny` is not installed locally, so dependency policy remains a CI
requirement rather than local passing evidence.

## Coordination rules

- Each writer owns only the paths listed above and must preserve concurrent
  edits elsewhere in the shared worktree.
- Writers may commit only their owned atomic increment. The lead independently
  reconciles every commit before integration.
- Shared canonical plans, ADRs, coverage records, and repository indexes remain
  lead-owned until the implementation evidence is integrated.
- L2 runtime implementation does not begin in this wave; the contract is the
  dependency that enables safe parallel implementation in wave 2.
