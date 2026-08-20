# OpenMLS 0.8.1 audit and provider applicability

Status: provider integration rejected; selection superseded by ADR 0012

Reviewed: 2026-08-17

ADR 0012 selects a different released MLS implementation for the isolated
laboratory. This map remains the retained evidence for rejecting the OpenMLS
0.8.1 provider graph and is not a current implementation plan.

## Scope and conclusion

ADR 0011 permitted exact OpenMLS 0.8.1 and `openmls_rust_crypto` 0.5.1 only for
an isolated, in-memory two-person laboratory. This review maps the eight
findings in the May 2026 SRLabs report to the exact signed OpenMLS tag at
commit `47dbedecad0c1fd8eb5368d582250ebfcc1e1ce6` and reviews the selected
provider boundary. It is a source and applicability review, not a new
cryptographic audit.

The OpenMLS protocol finding map supports continuing evaluation, but the
selected OpenMLS provider graph does not pass the repository dependency gate.
No OpenMLS crate or dependency is retained in the workspace; the separately
reviewed `mls-rs` laboratory selected by ADR 0012 is retained instead. The
published OpenMLS audit excluded cryptographic and storage providers, and its
acknowledged S1-3 storage finding directly reinforces Session Chat's durable
transaction stop condition.

## Evaluated dependency and feature boundary

The disposable evaluation used:

```toml
openmls = { version = "=0.8.1", default-features = false }
openmls_basic_credential = { version = "=0.5.0", default-features = false }
openmls_rust_crypto = { version = "=0.5.1", default-features = false }
openmls_traits = { version = "=0.5.0", default-features = false }
```

No OpenMLS draft, JavaScript, fork-resolution, SQLite, backtrace, test-utility,
`content-debug`, or `crypto-debug` feature was enabled. The evaluation adapter
accepted only `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, even though the
provider implements two additional classical ciphersuites.

The transient lock resolved `hpke-rs`, `hpke-rs-crypto`, and
`hpke-rs-rust-crypto` 0.6.1. It was removed with the evaluation crate and is not
the repository's current `Cargo.lock` boundary.

## Dependency-policy blocker

`cargo audit --no-fetch` rejected the evaluated lock with six vulnerabilities:

- `RUSTSEC-2026-0207` and `RUSTSEC-2026-0208` affect `libcrux-sha3` 0.0.8;
- `RUSTSEC-2026-0212` affects `libcrux-secrets` 0.0.5; and
- `RUSTSEC-2026-0209`, `RUSTSEC-2026-0211`, and `RUSTSEC-2026-0124` affect
  packages retained only through the unused optional libcrux HPKE backend.

The advised SHA-3 and secret packages occur in the compiled graph through
`hpke-rs` 0.6.1. Exact source tracing found the affected SHA-3 calls only in
X-Wing and ML-KEM branches, which the fixed X25519 suite cannot select; the
affected `libcrux-secrets` operations are therefore not reached by this
laboratory design. That narrows exploitability but does not make the repository
gate pass. `hpke-rs` 0.6.1 constrains `libcrux-sha3` to the affected 0.0.8 line,
and the repository has no advisory exceptions. GitHub dependency review also
rejects newly added runtime dependencies at moderate severity or higher.

No broad ignore is approved. Resume integration only with an audited,
API-compatible graph that passes both gates, or supersede ADR 0011 with a
reviewed provider choice. As reviewed, upstream issue 2126 remains open, says
the HPKE 0.6.x constraint prevents downstream updates to the patched libcrux
lines, and has no linked branch or pull request. OpenMLS 0.8.1 remains the
latest published release.

## Published finding map

| ID | Published status | Exact 0.8.1 evidence | Session Chat applicability and control |
| --- | --- | --- | --- |
| S3-7 — truncated or empty MAC accepted | High, mitigated | `equal_ct` rejects unequal lengths before constant-time byte comparison. | Applicable to membership and confirmation tags. A future laboratory must use this exact fixed line or a reviewed successor; malformed-message testing remains required before a product claim. |
| S2-5 — `GroupId` collision overwrites state | Medium, mitigated | `MlsGroupBuilder` loads the proposed ID and returns `GroupAlreadyExists` unless explicit replacement is requested. | A future laboratory must request random IDs and never call `replace_old_group`. Durable restore and namespace collision tests remain required. |
| S2-2 — past-epoch credential lookup after blank leaves | Medium, mitigated | Past-epoch lookup now maps retained `Member` values by `LeafNodeIndex`. | Phase 1 does not claim delayed past-epoch delivery. Reordered past-epoch tests remain required when retention is enabled. |
| S2-6 — joining client misses GroupContext extension support | Medium, mitigated | Welcome staging verifies that the added KeyPackage leaf supports every GroupContext extension; upstream retains a negative unknown-extension regression. | A future adapter should create only the ratchet-tree extension and reject unneeded KeyPackage and leaf extensions. Future extensions require an explicit policy and tests. |
| S1-4 — validation documentation/code mismatch | Low, mitigated | The 0.8.1 source contains the report's listed extension and PSK validation markers; upstream reports the finding mitigated. | This review did not independently prove every RFC validation. Interoperability fixtures, malformed-message tests, and later fuzzing remain gates. |
| S1-3 — group/storage desynchronization on provider error | Low, acknowledged | State-changing OpenMLS calls can mutate memory before an abstract provider reports a partial storage failure. No general rollback transaction was added. | Applicable and blocking outside any disposable memory laboratory. A Session Chat transaction adapter and crash tests are mandatory before networked or user-facing joins. |
| S0-1 — unbounded extension allocations | Informational, risk accepted upstream | OpenMLS permits large TLS vectors and places the application boundary ahead of parsing. | Applicable. A future adapter must bound serialized objects before parsing and reject unneeded extensions. Final limits require product and transport measurement. |
| S0-8 — overly strict proposal support check | Informational, mitigated | Proposal validation excludes leaves targeted by Remove proposals before computing the capability intersection. | A future two-person removal regression must retain this evidence. More complex concurrent proposal behavior remains outside Phase 1. |

The finding names, severities, and statuses come from Table 9 of the
[SRLabs report](https://blog.openmls.tech/SRL-OpenMLS_security_assurance_assessment.pdf).
The [audit notice](https://blog.phnx.im/openmls-independent-security-audit/)
states that seven fixes shipped in 0.8.1; the report identifies S1-3 as the
acknowledged remaining Low finding.

## Rust crypto and memory-provider review

The provider was outside the SRLabs audit. The exact source review established:

- `OpenMlsRustCrypto` combines `RustCrypto` with `MemoryStorage`; it is not a
  durable provider.
- Random bytes come from a locked ChaCha20 RNG seeded from operating-system
  entropy. BasicCredential Ed25519 signing keys are generated with `OsRng`.
- The selected suite uses X25519, HKDF-SHA-256, AES-128-GCM, and Ed25519 through
  the provider's RustCrypto/HPKE dependencies.
- The provider supports additional suites, so a future Session Chat adapter must
  enforce its suite allowlist before the verified KeyPackage can reach Add.
- Memory storage holds serialized secret state in a process-local `RwLock`
  map. It provides no encryption at rest, secure deletion, rollback resistance,
  crash recovery, or cross-layer transaction.
- The reviewed provider source contains no `unsafe` block, but this is not a
  transitive dependency audit or proof of memory erasure.
- The provider exposes detailed internal errors and its storage is publicly
  inspectable to a direct caller. A future wrapper must keep both private and
  map failures to coarse, non-secret-bearing errors.

This desk review is sufficient only to exercise the RFC flow. Before a
security-focused product claim, the crypto provider and complete locked
dependency graph need independent review, known-answer/interoperability tests,
platform RNG evidence, and a durable storage-adapter assessment.

## Disposable validation evidence

A local test-first evaluation, since removed from the workspace, exercised:

- bounded KeyPackage input before OpenMLS parsing;
- strict KeyPackage signature and Phase 1 suite/credential/extension policy;
- extraction of the canonical ciphersuite KeyPackage reference, exact
  BasicCredential identity, and leaf signature key;
- one-shot ownership of the verified KeyPackage through Add;
- one outstanding locally retained KeyPackage per laboratory client;
- an exact two-participant cap and unique session credential identity per leaf;
- Add, Commit, Welcome, two-way application encryption, duplicate rejection,
  member removal, epoch advancement, and removed-client inactivity; and
- rejection of an all-zero session identity and a modified KeyPackage.

The final disposable suite had eight passing tests with fresh randomized keys,
deterministic assertions, no network, no filesystem persistence, and no
external service. This observation established API feasibility and exposed two
missing application invariants—an exact two-participant cap and unique session
credential identities—which were added before the evaluation was removed. It
is not retained, reproducible repository evidence and does not support an
implemented-feature claim.

## Remaining stop conditions

Do not enable a networked or user-facing join path until all of the following
exist:

1. the selected provider graph passes repository advisory and dependency-review
   policy without a broad exception;
2. a linear `VerifiedAdmission` owns this exact verified KeyPackage and the
   complete ADR 0009 binding;
3. one recoverable transaction owns MLS state, invitation consumption, request
   replay, approval/result state, and an encrypted Welcome outbox idempotency key;
4. storage failure is injected before and after every write boundary;
5. monotonic epoch restore, stale snapshot rejection, irreversible old-secret
   deletion, pending-Commit recovery, and schema migration are tested;
6. malformed, reordered, lost, and replayed Commit/Welcome fixtures are retained;
7. an independent provider/dependency review and MLS interoperability fixtures
   pass; and
8. final envelope and extension bounds are measured against the selected
   transport and product limits.

## Primary sources

- [OpenMLS 0.8.1 signed release](https://github.com/openmls/openmls/releases/tag/openmls-v0.8.1)
- [OpenMLS issue 2126: patched libcrux dependency request](https://github.com/openmls/openmls/issues/2126)
- [OpenMLS 0.8.1 tagged source](https://github.com/openmls/openmls/tree/openmls-v0.8.1)
- [OpenMLS 0.8.1 dependency manifest](https://github.com/openmls/openmls/blob/openmls-v0.8.1/Cargo.toml)
- [`openmls_rust_crypto` 0.5.1 manifest](https://github.com/openmls/openmls/blob/openmls-v0.8.1/openmls_rust_crypto/Cargo.toml)
- [OpenMLS KeyPackage validation documentation](https://docs.rs/openmls/0.8.1/openmls/key_packages/key_package_in/struct.KeyPackageIn.html)
- [OpenMLS group creation documentation](https://book.openmls.tech/user_manual/create_group.html)
- [OpenMLS member-add documentation](https://book.openmls.tech/user_manual/add_members.html)
- [OpenMLS Welcome documentation](https://book.openmls.tech/user_manual/join_from_welcome.html)
- [OpenMLS member-removal documentation](https://book.openmls.tech/user_manual/remove_members.html)
- [OpenMLS audit notice](https://blog.phnx.im/openmls-independent-security-audit/)
- [SRLabs OpenMLS security assurance report](https://blog.openmls.tech/SRL-OpenMLS_security_assurance_assessment.pdf)
- [RustSec advisories for `libcrux-sha3`](https://rustsec.org/packages/libcrux-sha3.html)
- [`RUSTSEC-2026-0212` for `libcrux-secrets`](https://rustsec.org/advisories/RUSTSEC-2026-0212.html)
- [RustSec advisories for `libcrux-aesgcm`](https://rustsec.org/packages/libcrux-aesgcm.html)
- [`RUSTSEC-2026-0124` for `libcrux-chacha20poly1305`](https://rustsec.org/advisories/RUSTSEC-2026-0124.html)
