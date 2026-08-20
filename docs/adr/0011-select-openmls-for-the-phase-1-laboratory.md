# ADR 0011: Select OpenMLS for the Phase 1 laboratory

Status: superseded by ADR 0012

Date: 2026-08-16

ADR 0012 supersedes the implementation and provider selection in this record.
This record remains the retained explanation of why OpenMLS 0.8.1 was evaluated
and rejected under the repository dependency policy.

## Context

Phase 1 needs a maintained RFC 9420 implementation for a two-person group,
KeyPackages, Add/Commit/Welcome, application messages, removal, and epoch
advancement. Implementing MLS primitives or the protocol locally is outside the
project's competence and security policy.

OpenMLS is a Rust RFC 9420 implementation with provider boundaries for
cryptography, randomness, and storage. Its current stable 0.8 line supports the
mandatory-to-implement X25519/AES-GCM/SHA-256/Ed25519 ciphersuite and the target
desktop platforms. Version 0.8.1 includes dependency updates made in response to
published `libcrux` and `hpke-rs` security advisories.

An SRLabs audit published in May 2026 reported eight OpenMLS findings. Upstream
states that seven, including the High-severity finding, were remediated in the
0.8.1/0.7.3 releases and that one Low-severity issue remained unresolved when
the audit notice was published. The unresolved issue's applicability to Session
Chat has not yet been established. This ADR accepts that uncertainty only for
the isolated laboratory: the integration slice must review the full report,
map every finding to the enabled feature set, and either document the remaining
risk or move to a fixed release before any networked, durable, or product claim.
The audit explicitly excluded cryptographic and storage providers from scope,
including the selected `openmls_rust_crypto` provider. It therefore supports
review of the OpenMLS protocol implementation only; Session Chat must separately
review provider dependencies and its storage adapter and cannot cite this audit
as evidence for either boundary.

OpenMLS persistence is not an application transaction manager. Group operations
write sensitive material through `StorageProvider`, and forward-secrecy deletion
depends on the provider irreversibly deleting old values. Session Chat also
needs atomicity across MLS state, invitation consumption, request replay state,
and outbound Welcome work.

## Decision

Use these exact dependencies for the first `session-crypto-mls` laboratory
increment:

```toml
openmls = "=0.8.1"
openmls_rust_crypto = "=0.5.1"
```

Use `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, the RFC 9420
mandatory-to-implement ciphersuite. Use fresh session-scoped BasicCredential
identity bytes and bind the credential and leaf signature key through ADR 0009.

Enable only the Rust crypto provider needed by the laboratory. Do not enable
draft extensions, JavaScript, fork-resolution, SQLite-provider convenience,
backtrace, test utilities in production targets, `content-debug`, or
`crypto-debug`. Dependency addition occurs in the dedicated MLS integration
slice, not in this architecture-only selection record.

The first increment uses isolated in-memory providers for deterministic
protocol tests. Before any durable or product claim, implement a Session Chat
storage adapter and prove:

- atomic commit of MLS state, invitation consumption, replay state, and queued
  Welcome delivery, including approval/result state and an outbox idempotency key;
- crash recovery before and after every write boundary;
- no committed membership without recoverable Welcome work and no visible
  Welcome job for uncommitted membership;
- retry that never repeats Add/Commit and delivery failure that never releases
  or reopens the invitation;
- monotonic epoch restoration and stale-snapshot rejection;
- irreversible deletion behavior consistent with forward secrecy;
- pending-Commit cleanup and idempotent duplicate processing; and
- storage-format migration and rollback behavior across dependency upgrades.

If OpenMLS cannot support those tests without unsafe cross-layer gaps, stop the
integration and revisit this ADR. Do not work around the limitation by treating
in-memory success as durable correctness.

## Applicability gate result

The [OpenMLS applicability map](../research/OPENMLS_0_8_1_APPLICABILITY.md)
records all eight published audit findings and the separately scoped provider
review. A disposable local implementation established that the exact API can
exercise the intended two-person flow and enforce the KeyPackage ownership
seam. It was not retained in the workspace.

The resolved `openmls_rust_crypto` graph introduces RustSec-advised HPKE and
libcrux packages. The affected functions in the compiled SHA-3 and secret
dependencies are not reachable from the selected X25519 suite. The advised
AES-GCM and ChaCha packages belong to an unused optional backend. Nevertheless,
the repository's advisory and GitHub dependency-review gates evaluate the added
locked packages and reject the graph. This ADR does not authorize weakening
those gates or adding broad advisory exceptions. Integration remains blocked
until a reviewed, API-compatible resolution passes them.

The acknowledged storage-desynchronization finding also remains applicable,
and the memory provider supplies no failure injection, rollback resistance,
secure deletion, or application transaction.

## Alternatives considered

### Implement MLS directly

Rejected. It would create a new cryptographic protocol implementation without
the review, interoperability, or maintenance base required by the threat model.

### Select an unreleased OpenMLS revision

Rejected. Phase 1 values reproducibility and reviewable upgrades over early API
access.

### Enable draft extensions immediately

Rejected. The two-person proof needs only RFC 9420 behavior. Draft surface area
would add interoperability and migration risk without validating the core flow.

## Upgrade and removal conditions

- Pin exact versions and review upstream changelogs and advisories before each upgrade.
- Keep committed interop, state-transition, and storage-rollback fixtures.
- Never enable secret-bearing debug features in shipped targets.
- Supersede this ADR if maintenance stops, required RFC behavior is missing, or
  persistence tests cannot meet Session Chat's atomicity contract.

## Sources reviewed

- [OpenMLS 0.8.1 signed release](https://github.com/openmls/openmls/releases/tag/openmls-v0.8.1)
- [OpenMLS 0.8.1 immutable changelog](https://github.com/openmls/openmls/blob/openmls-v0.8.1/CHANGELOG.md#081-2026-02-13)
- [OpenMLS 0.8.1 repository snapshot and supported ciphersuites](https://github.com/openmls/openmls/tree/openmls-v0.8.1)
- [`libcrux` advisory GHSA-435g-fcv3-8j26](https://github.com/cryspen/libcrux/security/advisories/GHSA-435g-fcv3-8j26)
- [`hpke-rs` advisory GHSA-g433-pq76-6cmf](https://github.com/cryspen/hpke-rs/security/advisories/GHSA-g433-pq76-6cmf)
- [OpenMLS KeyPackage documentation](https://book.openmls.tech/user_manual/create_key_package.html)
- [OpenMLS credential model](https://book.openmls.tech/user_manual/identity.html)
- [OpenMLS persistence requirements](https://book.openmls.tech/user_manual/persistence.html)
- [OpenMLS provider traits](https://book.openmls.tech/traits/traits.html)
- [May 2026 OpenMLS audit notice](https://blog.phnx.im/openmls-independent-security-audit/)
- [SRLabs OpenMLS security assurance report](https://blog.openmls.tech/SRL-OpenMLS_security_assurance_assessment.pdf)
