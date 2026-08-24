# ADR 0018: Require cross-platform local-app baselines

Status: accepted

Date: 2026-08-20

## Context

Session Chat intends to ship a local desktop application rather than one
platform-specific client followed by later ports. Native credential stores,
prompt behavior, backup rules, packaging, and desktop integration differ across
macOS, Windows, and Linux. Implementing the strongest or easiest native path
first would let that platform's API shape core state and could make the other
clients weaker, incompatible, or permanently secondary.

## Decision

Treat macOS, Windows, and Linux as supported desktop operating-system families
from the first retained local-app increment. The desktop-shell ADR will select
exact minimum versions and architectures.

Every local-app capability must satisfy all of these conditions before it is
called implemented:

- one provider-neutral core contract and canonical persisted/protocol format;
- one common baseline workflow with equivalent security intent and failure
  behavior on all three operating-system families;
- build, lint, and conformance tests on pinned Linux, macOS, and Windows CI
  runners;
- no platform-specific API, identifier, serialized value, or conditional path
  in the core contract; and
- explicit capability reporting with fail-closed policy checks rather than
  assuming a platform name provides a security property.

Platform-native implementations may provide stronger optional modes after the
common baseline exists. Those modes remain adapters behind the same contract,
must not silently weaken or change the common format, and must be labeled by
measured properties rather than operating-system branding. A feature available
on only one supported family remains a spike, not a shipped local-app feature.

For the client vault, withdraw the macOS-first implementation order. The next
decision must select and test a portable baseline key-protection workflow on all
three families before native Keychain, Windows, or Secret Service adapters are
implemented. A passphrase-derived wrapping key using a reviewed Argon2id and
AEAD implementation is a candidate, not yet an adopted design.

The required Rust CI job becomes a Linux/macOS/Windows matrix immediately.
Formatting and rustdoc may run once on Linux; compilation, Clippy, and all tests
must pass on every matrix member.

## Consequences

- Portability failures surface while contracts and dependencies are still easy
  to change.
- A macOS-only positive result cannot establish client-vault readiness.
- The common baseline may be weaker or less convenient than the best native
  mode, so the UI must distinguish baseline and enhanced protection honestly.
- Platform-specific code remains possible, but it cannot determine core vault,
  MLS, storage, transport, or recovery behavior.
- CI cost increases by two Rust jobs; the security benefit is a required merge
  gate rather than an aspirational portability claim.

## Alternatives

### Implement one native client first and port later

Rejected because platform semantics would shape the contract before parity is
proved and would turn other supported clients into migrations.

### Use only the lowest common operating-system credential-store behavior

Rejected as the entire design because it would discard stronger optional
protections. The common baseline and optional factual capability profiles solve
different problems.

### Treat each platform as a separate product

Rejected because it would fragment persisted formats, security claims, tests,
and recovery behavior.
