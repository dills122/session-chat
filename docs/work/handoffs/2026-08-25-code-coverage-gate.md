# Handoff: Production Rust Coverage Gate

## Objective And Boundary

Continue the independent code-coverage workstream after the first enforced
production baseline. The retained branch introduces source-based Rust coverage,
raises every security- and correctness-vital library component to at least 90%
line coverage, and makes the measured result part of `CI / Gate`.

Coverage is regression evidence, not a security or production-readiness claim.
Preserve the behavior-first standard: tests should exercise attacker-controlled
input, authorization boundaries, replay/expiry, rollback, and state transitions
rather than add lines solely to move a percentage.

## Canonical Sources

- `AGENTS.md`
- `docs/CODE_COVERAGE.md`
- `docs/SECURE_DEVELOPMENT.md`
- `docs/ROADMAP_V2.md`
- `docs/ARCHITECTURE_V2.md`
- `docs/IDENTITY_AND_ADMISSION.md`
- `docs/TRANSPORTS.md`
- `docs/THREAT_MODEL.md`
- the relevant protocol and storage ADRs
- `.github/workflows/ci.yml`
- `scripts/check-rust-coverage.mjs`

This handoff records navigation and observed evidence. The canonical contracts
above remain authoritative.

## Current Repository State

- Branch: `codex/coverage-vital-gate`
- Clean fetched base and merge-base:
  `0bce3a38c62356feef2a806f4eb9e7fd2c55073e`
- The starting detached HEAD exactly matched `origin/master`; no feature-branch
  commits were inherited.
- Coverage implementation checkpoint:
  `1be20b2c2c68bd74867105d69c6d90cdb2de891d`
- The branch is two commits ahead and zero behind the fetched `origin/master`
  before this handoff commit.
- The worktree was clean immediately before handoff creation.

## Completed Work And Evidence

Retained checkpoints, oldest first:

1. `bc9455d` — behavior-focused tests for invitation/message values, MLS pending
   transitions, SQLCipher input/read/staging boundaries, strict adverse traces,
   and deterministic memory-transport cleanup and capacity behavior.
2. `1be20b2` — production-only coverage checker, pinned toolchain/CI job,
   thresholds, baseline documentation, and roadmap/merge-gate updates.

The checker pins `cargo-llvm-cov` 0.9.0 and uses LLVM source-based coverage from
Rust 1.97.1. It discovers and runs every integration-test target with all
features against the locked offline dependency graph. This measures production
sources without allowing inline `#[cfg(test)]` helpers to count themselves.
The ordinary Rust CI job continues to run unit tests and compile-fail doctests
on Linux, macOS, and Windows.

The clean `origin/master` baseline was recomputed from an isolated archive with
the same measurement method:

- lines: 8034/8850 (90.78%)
- regions: 9950/11453 (86.88%)
- functions: 843/1010 (83.47%)

The retained result is:

- lines: 8163/8850 (92.24%), with a 92.23% ratchet
- regions: 10140/11453 (88.54%), with an 88.53% ratchet
- functions: 865/1010 (85.64%), with an 85.64% ratchet
- every vital library component: at least 90% lines
- `sessionctl`: measured and frozen at 292/373 (78.28%), not excluded or
  represented as meeting 90%

The only non-instrumented production-source allowance is the declaration-only
`crates/transport-conformance/src/lib.rs`. The checker rejects a missing source,
unassigned source, stale allowance, driver-version drift, test failure, or
threshold regression. CI uses a full-commit-pinned installation action and does
not upload source or coverage artifacts.

## Final Verification Observed

The following passed on 2026-08-25:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo test --workspace --all-features --locked --offline
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked --offline
node scripts/check-rust-coverage.mjs
node --test scripts/check-repository.test.mjs scripts/check-rust-coverage.test.mjs scripts/setup-codex-links.test.mjs spikes/sealed-invitation-provider/test/provider.test.mjs
node scripts/check-repository.mjs
npm ci --prefix site --offline
npm run check --prefix site
npm run build --prefix site
npm run dump:copy --prefix site
git diff --exit-code -- site/CONTENT_DUMP.md
git diff --check
```

`cargo deny --all-features --locked check` was attempted but could not run
because this environment does not have the `cargo-deny` subcommand installed.
CI retains the full-commit-pinned cargo-deny action, so dependency-policy
evidence must come from the PR checks or a prepared local environment.

## Decisions And Rationale

- Use integration-target production measurement. A naïve all-test report
  instruments inline test helpers and can inflate the file summary.
- Enforce workspace line, region, and function ratchets. Stable branch coverage
  is unavailable from the pinned stable Rust/LLVM stack, so regions are the
  retained control-flow proxy and explicit branch-oriented tests remain
  mandatory.
- Enforce 90% lines for every vital library component instead of relying only
  on a weighted workspace average.
- Keep `sessionctl` visible at its exact current result. Its remaining missed
  paths are mostly cross-crate error mappings that need narrow orchestration
  fault seams; denominator-only refactoring would be vanity coverage.
- Keep the job Linux-only for deterministic measurement while the existing
  three-platform Rust matrix remains authoritative for portability. Future
  platform-only sources require deliberate evidence and cannot be silently
  excluded.

## Remaining Work

- Introduce production-appropriate `sessionctl` fault seams and cover each
  orchestration failure milestone, raising its ratchet incrementally to 90%.
- Consider a stable branch or MC/DC gate only after the pinned toolchain can
  reproduce it reliably; do not adopt nightly coverage as required merge
  evidence without a separate compatibility decision.
- Raise component and workspace ratchets whenever retained behavior coverage
  improves.
- Add property/model/fuzz coverage independently where protocol parsers,
  persistence recovery, or state-machine complexity warrants it. Percentage
  gates do not replace those techniques.
- Confirm the new `CI / Rust production coverage` job on Linux and the unchanged
  three-platform Rust matrix in the prepared PR.

## Immediate Next Actions

1. Review the PR coverage job output and confirm every documented count is
   unchanged on the pinned Linux runner.
2. Require `CI / Gate` before merge and do not merge without explicit approval.
3. In the next `sessionctl` orchestration slice, write failing fault-injection
   tests first, preserve coarse public diagnostics, and raise only the explicit
   component ratchet after the behavior is retained.

## Delivery Metadata

- Date: 2026-08-25
- Repository: `dills122/session-chat`
- Branch: `codex/coverage-vital-gate`
- Base/merge-base: `0bce3a38c62356feef2a806f4eb9e7fd2c55073e`
- Code checkpoint: `1be20b2c2c68bd74867105d69c6d90cdb2de891d`
- PR: prepared after this handoff commit; repository and PR history are
  authoritative for its final URL and CI state
- Dirty files before handoff creation: none
