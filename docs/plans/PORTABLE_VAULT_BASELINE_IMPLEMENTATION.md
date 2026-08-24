# Implementation plan: portable vault-key baseline

Status: in progress; bounded non-production conformance adapter selected

Date: 2026-08-24

## Objective and completion boundary

Determine whether Session Chat can adopt one passphrase-derived key-protection
baseline with equivalent security intent and failure behavior on macOS,
Windows, and Linux. The leading candidate derives a key-encryption key with a
reviewed Argon2id implementation and uses a reviewed AEAD implementation to
wrap one random 32-byte session/database key.

This workstream is complete only when the decision evidence, versioned format,
provider-neutral contract, hostile-input tests, and three-OS CI evidence agree.
It does not add a desktop UI, recovery, native keychain integration, SQLCipher
product wiring, rollback resistance, device binding, fresh user presence, or a
production-storage claim.

## Decision question

Can the portable candidate be implemented with reviewed Rust dependencies,
bounded attacker-controlled work, an unambiguous authenticated format, coarse
fail-closed errors, and one shared conformance suite on the three supported OS
families without overstating what a human passphrase protects?

## Dependency graph and ownership

```text
PV-01 evidence refresh --------+
PV-02 repository boundary -----+--> PV-04 decision gate
PV-03 adversarial test model ---+          |
                                           v
                              PV-05 contract + red tests
                                           |
                                           v
                              PV-06 smallest implementation
                                           |
                                           v
                              PV-07 docs, review, full gates
```

The lead agent owns this execution index, the final decision, integration,
documentation reconciliation, and full-repository validation. Read-only lanes
may proceed in parallel, but no implementation begins until PV-04 records a
clear selected, rejected, or experiment-only outcome.

## Work items

### PV-01: cryptographic construction and dependency evidence

**Owner:** research lane

**Status:** completed

**Scope:** Compare current reviewed Argon2id and AEAD implementation options,
their exact dependency/features surface, RFC 9106 conformance, parameter and
resource controls, nonce/salt requirements, memory handling, and supported
Rust targets. Prefer standards, upstream documentation, audits, and repository
lockfile evidence.

**Acceptance:** The retained evidence separates documented facts, repository
observations, inferences, and unknowns; recommends exact versions/features or
rejects the candidate; and states what must be measured rather than copied
from a standard.

**Verification:** Links resolve to primary sources; exact candidate APIs and
dependency graph can be reproduced; no product assurance is inferred from a
crate name or algorithm alone.

### PV-02: repository integration boundary

**Owner:** repository-analysis lane

**Status:** completed

**Scope:** Map the smallest provider-neutral change across `session-storage`,
`storage-sqlcipher`, workspace dependencies, and existing conformance tests.
Preserve session-scoped lifecycle authority and keep the raw key outside the
copied database.

**Acceptance:** Recommend exact files and API ownership, identify dependency
direction and compatibility constraints, and explicitly defer product wiring
that is not needed for candidate evidence.

**Verification:** The proposal cites current types/tests and introduces no
platform identifier or native conditional path into the core contract.

### PV-03: adversarial format and conformance model

**Owner:** security-test lane

**Status:** completed

**Scope:** Define negative cases for wrong passphrases, modified headers,
ciphertext/tag tampering, nonce/salt substitution, unknown versions/suites,
truncation/trailing bytes, oversized inputs, excessive KDF work, identifier
substitution, replay/rollback limits, cancellation, secret redaction, and
zeroization boundaries.

**Acceptance:** Produce a severity-ranked threat-to-test matrix and identify
which properties are testable now versus dependent on UI, OS, persistence, or
external review.

**Verification:** Every attacker-controlled length and work factor has a
pre-work bound; authenticated context covers every security-relevant public
field; tests do not claim rollback resistance or secure deletion.

### PV-04: candidate decision gate

**Owner:** lead agent

**Status:** completed

**Dependencies:** PV-01, PV-02, PV-03

**Acceptance:** Update the retained decision packet and, if selected for a
bounded implementation, add an ADR that fixes the exact construction, format,
parameters or parameter policy, limitations, and stop conditions. Otherwise
record rejection or experiment-only status and stop before production code.

**Outcome:** Proceed with a bounded non-production conformance adapter using
exact RustCrypto `argon2` 0.5.3 and the already pinned AWS-LC 1.16.3
AES-256-GCM implementation. Version 1 accepts one fixed Argon2id v1.3
measurement profile (`m=65,536 KiB`, `t=3`, `p=4`), a 16-byte random salt, a
32-byte derived KEK, a 12-byte random nonce, and a random 32-byte wrapped key.
The profile is an RFC 9106 measurement starting point, not a final performance
or production parameter claim. The adapter remains outside the lifecycle and
SQLCipher product paths until cancellation, credential acquisition, key
handoff, persistence, rollback, and three-OS measurement gates are decided.

### PV-05: provider-neutral contract and failing tests

**Owner:** lead agent

**Status:** completed

**Dependencies:** PV-04 selected outcome

**Acceptance:** Add the smallest versioned wrapped-key value and portable
protector boundary needed by the decision. Write failing happy-path,
cross-context, malformed, resource-bound, and redaction tests before logic.

**Verification:** The red test fails for the intended missing behavior; the
contract contains no OS-specific type, generic serializer, or ambient secret.

**Evidence:** The initial laboratory skeleton returned only `Rejected`; four
of six integration tests failed on the missing provisioning, unsealing, and
tamper behavior. The contract now uses exact byte-owned values, a fixed
102-byte versioned record, a 1,024-byte passphrase limit, and no OS-specific
type or generic deserializer.

### PV-06: smallest portable implementation

**Owner:** lead agent

**Status:** completed

**Dependencies:** PV-05

**Acceptance:** Implement only enough reviewed Argon2id and AEAD behavior to
make the retained conformance tests pass. Key, passphrase, and intermediate
buffers avoid `Clone`, `Debug`, and `Display` and are zeroized where their
owners permit it. Public failures remain coarse.

**Verification:** Targeted test, Clippy, rustdoc, RFC/known-answer evidence,
and deterministic cross-platform fixtures pass offline from the lockfile.

**Evidence:** The implementation retains the RFC 9106 Argon2id known-answer
vector, one byte-exact portable wrapper fixture that also unwraps, and hostile
format/context/tamper tests. Targeted test and rustdoc checks pass locally;
final Clippy and whole-workspace evidence are recorded under PV-07.

### PV-07: reconciliation and checkpoint

**Owner:** lead agent

**Status:** in progress

**Dependencies:** PV-06

**Acceptance:** Reconcile the threat model, research backlog, architecture,
roadmap, crate documentation, and decision status. Conduct an independent diff
review before declaring the checkpoint ready.

**Verification:** Run repository policy checks, complete Rust format/Clippy/
test/rustdoc gates, dependency policy, and the Linux/macOS/Windows CI matrix.
Report any check that can only be completed by CI.

## Decision constraints carried forward

- The wrapped key is random provider output; a passphrase is never used as a
  database or session key directly.
- Argon2id raises offline-guessing cost but cannot create passphrase entropy.
- All KDF work factors and input sizes are validated before expensive work.
- Salt and AEAD nonce uniqueness are construction requirements, not parser
  hints.
- Every security-relevant public field is authenticated or fixed by the
  versioned contract.
- A copied wrapped-key object permits offline guessing and provides no device
  binding, user-presence, rollback, recovery, secure deletion, or endpoint
  compromise protection.
- The same canonical format and conformance fixtures must pass on Linux,
  macOS, and Windows before the baseline is called implemented.
