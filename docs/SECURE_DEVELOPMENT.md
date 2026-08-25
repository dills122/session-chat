# Secure development and merge gates

Status: repository policy for the Phase 1 protocol laboratory

The required CI workflow is intentionally small, deterministic, and always
triggered. It protects implemented behavior and claim-bearing documentation; it
does not certify future architecture or make a test build production-ready.

## Required `CI / Gate`

| Job | Enforced evidence |
| --- | --- |
| Rust | Exact toolchain and locked graph; all-target/all-feature Clippy and tests on pinned Linux, macOS, and Windows runners; formatting, doctests, and warning-free rustdoc on Linux |
| Retained Node tools | Exact Node patch and all dependency-free repository/provider tests |
| Repository policy | Local Markdown links, JSON parsing, evidence-manifest references/digests, absence of developer-local paths/placeholders, and immutable action references |
| Rust dependency policy | RustSec advisories/yanks, reviewed license allowlist, crates.io-only sources, and no wildcard requirements |
| Pull-request dependency review | Rejects newly introduced moderate-or-higher vulnerabilities in runtime or unknown scopes |
| Gate | Uses `always()` and verifies every intended job result, including an intentional dependency-review skip outside pull requests |

The workflow has no path filters: a documentation-only security-contract change
must produce the same stable required check as a code change. Every job has a
timeout. Pull-request jobs receive no secrets, checkout does not retain GitHub
credentials, workflow permissions are read-only, and every external action is
pinned to a full commit. The Rust matrix makes the common local-app foundation
an all-platform merge requirement; a matrix failure fails the aggregate Rust
job and therefore the final gate.

Run the equivalent local gate with:

```sh
cargo fetch --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo test --workspace --all-features --locked --offline
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked --offline
node --test scripts/setup-codex-links.test.mjs spikes/sealed-invitation-provider/test/provider.test.mjs
node --test scripts/check-repository.test.mjs
node scripts/check-repository.mjs
cargo deny --all-features --locked check
git diff --check
```

`cargo deny` requires the separately installed, reviewed tool. CI runs the
pinned cargo-deny action. Advisory retrieval and GitHub dependency review
require network access; the compilation and test phases fetch once and then run
offline.

## GitHub settings that complete the gate

Repository configuration must require the unique `CI / Gate` status on an
up-to-date branch. GitHub Actions should default to read-only tokens, must not
approve pull requests, and should require full-commit action references.
Secret scanning, push protection, Dependabot alerts and security updates,
private vulnerability reporting, and CodeQL default setup should be enabled.

One non-author approval, stale-approval dismissal, approval after the latest
reviewable push, and conversation resolution are intended for security or
protocol changes. Until a genuine second reviewer exists, the repository must
record independent review as a production-release blocker rather than pretend a
sole author provides it.

Repository settings are external state. CI files do not prove they are enabled;
capture the settings through GitHub when preparing an audit or release.

## Deliberately deferred gates

- Fuzzing, model/property tests, crash injection, Miri, and sanitizers become
  required when their parser, persistence, FFI, or state-machine surfaces land.
- Platform-native macOS, Windows, and Linux behavior tests begin with their
  adapters; the shared workspace build/lint/test matrix is already required.
- Image scanning begins with deployable OCI images.
- SBOMs, artifact attestations, signed reproducible updates, and protected
  release environments begin when a user-runnable artifact exists.
- Coverage percentages are diagnostic; they are not a substitute for explicit
  security invariants and negative tests.

No dependency or cryptographic update is auto-merged. Advisory exceptions need
an affected-path analysis, owner, expiry or removal condition, and review.

The [real-world E2E security test strategy](plans/REAL_WORLD_E2E_TESTING.md)
defines when deterministic two-client scenarios enter this required gate and
when heavier process, storage, network, packet-capture, platform, and release
lanes become mandatory. Those future lanes supplement this gate; they never
replace its always-on contract, unit, documentation, and dependency checks.
