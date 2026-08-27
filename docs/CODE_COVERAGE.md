# Rust code-coverage policy and baseline

Status: required Phase 1 merge evidence

Code coverage is a regression detector and test-navigation aid. It does not by
itself prove a security invariant, protocol property, or production readiness.
The retained gate therefore combines hard measurement with behavior-focused
negative tests and the existing three-platform test, lint, rustdoc, and
dependency-policy jobs.

## Canonical command and toolchain

The repository uses Rust source-based coverage through `cargo-llvm-cov` 0.9.0
and the `llvm-tools-preview` component from the pinned Rust 1.97.1 toolchain.
CI installs the coverage driver through a full-commit-pinned action and does not
upload source, coverage profiles, or reports to a third party.

Run the exact local gate after fetching the locked dependency graph:

```sh
cargo fetch --locked
node scripts/check-rust-coverage.mjs
```

For a fresh development environment that does not already provide the driver:

```sh
cargo install cargo-llvm-cov --version 0.9.0 --locked
```

The checker verifies the installed driver version, discovers every Cargo
integration-test target, starts from clean coverage profiles, runs each target
with all features and the locked offline graph, exports LLVM JSON, validates
every production source assignment, applies the thresholds below, prints the
component table, and removes its temporary report.

## What is measured

The numerator and denominator cover Rust sources under `apps/*/src/**/*.rs` and
`crates/*/src/**/*.rs`. Integration targets are used for instrumentation so
inline `#[cfg(test)]` helpers in production files cannot inflate production
coverage by executing themselves. The normal Rust CI job still runs all unit,
integration, binary, and doctest targets on Linux, macOS, and Windows.

The policy makes these distinctions explicit:

- `apps/sessionctl/src/main.rs` is measured; binaries are not silently removed.
- Integration-test and compile-fail fixture sources are test evidence, not part
  of the production denominator.
- Stable Rust does not currently provide the branch and doctest coverage modes
  needed for reproducible enforcement here. The gate enforces lines plus stable
  LLVM region and function ratchets, while the ordinary Rust job separately
  enforces doctests.
- There is no generated Rust source in the workspace.
- `apps/sessionctl/src/l2_process.rs` and
  `crates/storage-sqlcipher/src/fault_testing.rs` are explicit
  non-instrumented allowances because they exist only under the registered
  checked fault-testing cfg and are absent from the ordinary production
  coverage build. Their checked-cfg test commands remain separate retained
  evidence.
- `crates/transport-conformance/src/lib.rs` is also an explicit
  non-instrumented allowance. It contains only the declaration `pub mod trace;`
  and therefore exports no instrumentable region. The checker requires every
  allowed file to exist and fails if an allowance becomes stale.
- Provider-invariant random failures, hard-to-reach production errors, and
  platform glue are not excluded. New production source that is absent from the
  report or not assigned to exactly one component fails the gate.

## Clean-master baseline and enforced result

Both columns below were produced on 2026-08-26 from the same integration-target
measurement method. The retained current result was regenerated from a clean
detached checkout so it does not depend on symbolic-versus-direct `HEAD` layout.
The baseline used a clean archive of
`origin/master` at `0bce3a38c62356feef2a806f4eb9e7fd2c55073e`; the current result includes
the coverage workstream, durable Welcome-delivery composition, exact
client-identity/group reload, the ADR 0021 independent-process L1 runner after
its cleanup and bounded-metadata hardening tests, the first hostile exact-replay
process case, and the bounded transport queue-saturation verdict.

| Production component | Clean master | Enforced result | Line gate |
| --- | ---: | ---: | ---: |
| `admission-capability` | 347/367 (94.55%) | 419/428 (97.90%) | 90% |
| `key-protector-passphrase` | 177/181 (97.79%) | 177/181 (97.79%) | 90% |
| `session-admission` | 43/46 (93.48%) | 43/46 (93.48%) | 90% |
| `session-core` | 334/376 (88.83%) | 343/376 (91.22%) | 90% |
| `session-crypto` | 50/63 (79.37%) | 63/63 (100.00%) | 90% |
| `session-crypto-hpke` | 229/232 (98.71%) | 229/232 (98.71%) | 90% |
| `session-crypto-mls` | 611/687 (88.94%) | 860/921 (93.38%) | 90% |
| `session-inviter-transaction` | 459/486 (94.44%) | 463/486 (95.27%) | 90% |
| `session-protocol` | 1176/1245 (94.46%) | 1176/1245 (94.46%) | 90% |
| `session-storage` | 501/521 (96.16%) | 501/521 (96.16%) | 90% |
| `session-transport` | 1032/1097 (94.07%) | 1035/1100 (94.09%) | 90% |
| `sessionctl` | 292/373 (78.28%) | 1861/2043 (91.09%) | 90% |
| `storage-sqlcipher` | 650/742 (87.60%) | 1279/1379 (92.75%) | 90% |
| `transport-conformance` | 1325/1514 (87.52%) | 1367/1514 (90.29%) | 90% |
| `transport-memory` | 808/920 (87.83%) | 836/920 (90.87%) | 90% |
| **Workspace** | **8034/8850 (90.78%)** | **10652/11455 (92.99%)** | **92.23% ratchet** |

The workspace also moved from 86.88% to 88.56% region coverage and from
83.47% to 89.56% function coverage. CI retains its existing stable floors at
92.23% lines, 88.53% regions, and 85.64% functions. The slight fractional
margin avoids making display rounding part of the contract.

## Vital initial scope

The first enforced scope maps directly to the current Phase 1 security and
correctness boundaries:

- canonical invitation, protected-join, and opaque-envelope parsing and
  serialization in `session-protocol`;
- invitation issuance, validation, reservation, release, expiry, reissue, and
  consumption in `session-core`;
- capability proof, replay reservation, explicit approval, and exact
  KeyPackage/credential/leaf-key ownership in `admission-capability`;
- bounded HPKE contexts and MLS Add, Welcome, update, removal, replay, expiry,
  storage, and inactive-state transitions;
- right-specific transport contracts, dispatch control, adverse scheduling,
  normalized conformance, and exact acknowledgement cleanup;
- inviter membership/Welcome-outbox atomicity and ambiguous-result recovery;
- sealed-vault lifecycle and exact-session unlock acceptance;
- SQLCipher inviter/joiner transaction, rollback, recovery, key-package
  deletion, read bounds, and single-owner staging boundaries; and
- the measurable `sessionctl` in-process and independent-process two-client
  orchestration paths.

The added tests target malformed and oversized attacker-controlled values,
zero and expired identifiers, illegal MLS prepare states, abandoned pending
epochs, storage read bounds, conflicting owner staging, bounded transport fault
queues, stale/held acknowledgement cleanup, and strict adverse-trace field and
reference validation. They do not introduce a new protocol or security claim.

## Ratchet and remaining work

The aggregate workspace already exceeds the 90% target, and every vital
library component now has a hard 90% line floor. Global line, region, and
function floors preserve the stronger observed result instead of permitting a
slide back to the minimum. A new production file, missing component, stale
allowance, tool-version drift, integration-test failure, or threshold regression
fails `CI / Rust production coverage` and therefore `CI / Gate`.

`sessionctl` now injects failures only at named cross-crate operation-result
boundaries. Its integration tests cover coarse redacted error mapping,
reservation and pending-Commit cleanup, proven SQL rollback, ambiguous
post-commit recovery, post-membership Welcome failure, a dropped application
delivery, and final orchestration quiescence. The normal binary uses the
no-fault plan and retains the successful durable two-client flow. The ADR 0021
binary additionally covers bounded canonical IPC, graceful Alice process exit,
exact durable reload, fixed coarse child summaries, and redacted evidence.

Stable branch coverage should replace or supplement the region proxy only when
the pinned Rust/LLVM toolchain provides reproducible cross-platform evidence.
Until then, reviews must continue to require explicit negative cases for
authorization, replay, expiry, rollback, malformed input, and state-transition
branches even when the numerical gate passes.
