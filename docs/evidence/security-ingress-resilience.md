# Security audit ingress-resilience tranche

Date: 2026-09-06 (local macOS verification)

Base: `abba6ea`, refreshed `origin/master` after the preceding audit batch.
Scope: findings 12, 9, 24, 8, 4 and 25 from the completed deep scan of
`23bf6eb`. The scan was treated as untrusted analysis; the current implementation,
direct callers and tests were independently traced before editing.

## Changes and retained evidence

| Finding | Current-source boundary and fix | Focused evidence |
| --- | --- | --- |
| 12: post-send desynchronization | `IrohFastDelivery::round_trip` now retains incomplete-exchange state before send; errors and dropped futures cannot reuse queued responses. Preflight rejection remains reusable. | `interrupted_exchanges_reject_later_same_operation_responses`: cancellation, deadline, wall-clock failure, insufficient response budget and future drop; a later different deposit cannot consume the original response. Existing preflight and malformed-response tests remain green. |
| 9: stray first peer | Both hosts retain the endpoint across rejected candidates under 32 attempts and one five-minute bound. Candidate handshake/stream opening and first frame each have a two-second bound. Alice opens the exact HPKE request before one-shot session ownership. | `network_host_rejects_strays_before_accepting_the_legitimate_joiner`: stalled peer, malformed frame, tampered HPKE and reordered first frame followed by the full legitimate MLS session. Both host candidate-exhaustion tests return failure and clean up. |
| 24: denied requests count as completion | The public Fast harness uses the authenticated serving method; every counted operation first passes exact mailbox/right authorization. Authorized idempotency conflict remains compatible. | `fast_host_rejects_unauthorized_runs_and_then_completes_the_common_case`: seven denied peers cannot complete the host; the subsequent legitimate seven-operation common case, including expected conflict, completes. |
| 8: Node parsing/retention | A shared closed envelope normalizer guards mailbox deposit and direct recipient opening. Fixed encoded widths precede decoding/crypto; only normalized fields are retained. Directory/attestor claims, signatures, proofs and map keys are bounded. | 22 Node tests pass, including missing/unknown/symbol/accessor/prototype fields, oversized/noncanonical crypto fields and signatures, unchanged queue capacity after rejection, direct recipient opening, and Unicode producer/verifier compatibility. |
| 4: umask | Unix directory creation uses mode 0700 atomically; existing 0600 files remain unchanged. Root validation rejects permissive directories. | `ipc_file_boundaries_under_permissive_umask` runs under umask 000 in a child process and checks directory/file modes. L1 integration fixtures now create contract-compliant private directories. |
| 25: special IPC files | Waiting channel, marker and provenance reads use the bounded regular-file opener. Unix adds nonblocking/no-follow opens and identity checks; Windows opens/rejects reparse points. | The watchdog-protected IPC regression rejects FIFO with no writer, FIFO held open at both ends, links to FIFO and regular files, directory and oversized inputs, and linked marker; missing-file timeout and delayed atomic publication remain valid. |

ADR 0027 records the decision and limits. ADRs 0021/0024, the threat model,
transport document and sealed-invitation protocol were updated in the same
change. Rust wire layouts, HPKE contexts, MLS authority and profile selection
remain unchanged. No fallback was added.

## Verification commands

Passed locally on macOS:

```sh
cargo fetch --locked
cargo check -p transport-iroh -p sessionctl --all-targets --all-features --locked --offline
cargo test -p transport-iroh --test conformance interrupted_exchanges --locked --offline
cargo test -p sessionctl --lib --locked --offline
cargo test -p sessionctl --test l1_process --locked --offline
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo test --workspace --all-features --locked --offline
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked --offline
cargo deny --all-features --locked check
node --test spikes/sealed-invitation-provider/test/provider.test.mjs
node --test scripts/check-repository.test.mjs scripts/setup-codex-links.test.mjs
node scripts/check-repository.mjs
git diff --check
```

The initial sandboxed loopback tests failed with `EndpointUnavailable` and the
initial dependency check could not lock the advisory cache. Both passed after
rerunning with the required local socket/cache permissions. The intermediate command
`cargo test -p transport-iroh -p sessionctl --lib --locked --offline` also caught
a missing test-only `File` import, which was corrected. The focused Clippy
command `cargo clippy -p transport-iroh -p sessionctl --all-targets --all-features
--locked --offline -- -D warnings` reported the type-complexity issue noted
below. The initial `cargo fmt --all --check` reported formatting differences;
`cargo fmt --all` resolved them without unrelated source changes. Intermediate tests
caught Node error-message and Unicode compatibility changes and old permissive
L1 fixtures; those were corrected and the relevant suites rerun. Clippy's
intermediate type-complexity failure was corrected. Dependency policy passed
with existing duplicate-dependency and unused-license-allowance warnings.

Production coverage passed: workspace lines 92.72%, regions 88.18%, functions
89.38%; every component exceeded its 90% line floor (sessionctl 90.91%,
transport-iroh 93.52%).

```sh
node scripts/check-rust-coverage.mjs
```

## Independent review and limits

A fresh read-only boundary investigator revalidated all six paths. A separate
fresh read-only candidate reviewer checked source-backed bypasses and
regressions. Its Unicode producer/verifier mismatch and remaining scalar
precheck findings were corrected and covered by the Node tests.

JavaScript has no bounded own-key enumeration API; introspection still scales
with an already materialized object's property count. Fixed fields are checked
first and full descriptor tables are no longer cloned. A future byte transport
must cap bytes before parsing JSON; arbitrary JavaScript proxies are not remote
wire data.

Windows inherits its existing ACL baseline; Unix mode evidence does not prove
Windows ACL privacy. Trusted parent directories, ordinary responsive filesystems
and no malicious same-account mutation remain assumptions. The Linux/Windows CI
matrix and external public/relay-only network tests were not run locally. No
production availability, anonymity, offline delivery or process-isolation claim
is made. Checked L2 storage-fault suites were not rerun: this patch does not
change their storage/VFS contracts or implementation.
