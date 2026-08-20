# ADR 0012: Select mls-rs for the Phase 1 laboratory

Status: accepted for isolated evaluation; implementation unstarted

Date: 2026-08-19

## Context

ADR 0011 selected OpenMLS 0.8.1 for an isolated Phase 1 evaluation. Its exact
Rust crypto provider graph failed the repository advisory policy, so no MLS
dependency or runtime was retained. Phase 1 still needs an RFC 9420
implementation for KeyPackage validation, Add/Commit/Welcome, application
messages, removal, and epoch advancement. Implementing MLS or a cryptographic
provider locally remains prohibited.

The [MLS implementation comparison](../research/MLS_IMPLEMENTATION_COMPARISON.md)
evaluated released OpenMLS and `mls-rs` graphs. `mls-rs` 0.56.0 with its AWS-LC
provider 0.25.0 resolved without a known RustSec advisory in the selected graph,
compiled on the pinned toolchain, and passed a disposable two-party ownership
and storage-boundary experiment. Upstream labels the AWS-LC and OpenSSL
providers stable and the RustCrypto provider experimental. Upstream also states
that `mls-rs` has not received a full independent third-party security audit.

The selected `aws-lc-rs` and `aws-lc-sys` dependencies use ISC, and
`aws-lc-sys` includes MIT-0, in addition to licenses already allowed by the
repository. Both identifiers are OSI-approved permissive licenses. The
repository allowlist now names them explicitly; this is a reviewed
license-policy expansion, not an advisory or source exception and not legal advice.

## Decision

Use these exact dependencies for the first isolated `session-crypto-mls`
laboratory increment:

```toml
mls-rs = { version = "=0.56.0", default-features = false, features = [
  "external_client",
  "out_of_order",
  "prior_epoch",
  "std",
  "tree_index",
] }
mls-rs-crypto-awslc = { version = "=0.25.0", default-features = false, features = ["non-fips"] }
```

Use `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, represented by
`CipherSuite::CURVE25519_AES128`. Do not enable the `mls-rs` X.509, PSK, custom
proposal, SQLite, SQLCipher, post-quantum, FIPS, serde, benchmark, fuzz/test
utility, or other optional surfaces until a specific retained requirement and
review justifies them. The AWS-LC provider still resolves its X.509 helper crate
unconditionally; it is part of the locked review boundary even though Session
Chat will not expose X.509 credentials. The non-FIPS provider selection makes
no FIPS claim.

Dependency addition occurs only in the dedicated laboratory implementation
slice. That slice must keep the MLS library behind a Session Chat adapter and:

- bound serialized KeyPackage, Welcome, Commit, and application objects before parsing;
- validate the KeyPackage with the configured identity, lifetime, version, and
  ciphersuite policy before admission;
- return a private, non-`Clone` linear admission value that owns the exact
  retained `MlsMessage`, its canonical KeyPackage reference, credential
  identity, and leaf signature key;
- consume that owned message directly into `CommitBuilder::add_member` and
  verify the resulting Welcome targets the same reference;
- cap Phase 1 groups at exactly two distinct session-scoped credential identities;
- keep cryptographic/provider errors private and expose only coarse application errors; and
- retain malformed, substituted, replayed, reordered, expired, removal, and
  epoch-transition tests without a network or GUI.

`mls-rs` separates commit construction, pending-commit application, and the
explicit `Group::write_to_storage` call. This is useful but does not itself
provide Session Chat's transaction. Its repository writes group state and epoch
records together, while a joining client's KeyPackage deletion is a subsequent
call through a separate repository trait. A future adapter must prove one
recoverable application transaction across MLS state, KeyPackage deletion,
invitation consumption, replay state, approval/result state, and the encrypted
Welcome outbox. The isolated laboratory may not claim durability, rollback
resistance, forward-secret deletion, or atomic delivery.

## Consequences and limits

- The isolated MLS lifecycle is unblocked from the known OpenMLS dependency issue.
- AWS-LC introduces native C and assembly build inputs. CI must build the exact
  graph on each supported native target before a client-platform claim.
- The selected graph is advisory-clean only as observed on 2026-08-19; every
  dependency update must repeat locked advisory, license, source, and API review.
- The locked graph retains duplicate `syn` versions and build-target
  `getrandom` versions under the repository's warning policy; review them again
  when the dependencies enter the workspace rather than treating the graph as minimal.
- AWS-LC's broader testing and partial formal-verification evidence does not
  transfer into a claim that the `mls-rs` protocol or provider adapter is audited.
- No networked, durable, user-facing, production-security, or interoperability
  claim follows from this decision or the disposable experiment.
- A full independent review of the exact protocol/provider boundary remains a
  release gate. The missing third-party `mls-rs` audit must be stated to external reviewers.

## Alternatives considered

### Keep OpenMLS 0.8.1

Rejected for this increment. Its selected provider graph still fails the
repository advisory policy. ADR 0011 and its applicability map retain the exact evidence.

### Use the mls-rs OpenSSL provider

Retained as a fallback. Its screened graph passed the current advisory, license,
and source policy and compiled on the review host, but it adds system/native
OpenSSL discovery and packaging variation. AWS-LC has the better documented
native client platform matrix for the intended desktop and mobile direction.

### Use the mls-rs RustCrypto provider

Rejected for the first laboratory even though its screened graph passed the
current dependency policy. Upstream labels that provider experimental.

### Implement a custom OpenMLS provider or MLS stack

Rejected. Both would move cryptographic protocol work into Session Chat without
the expertise, audit base, interoperability evidence, or maintenance capacity
required by the threat model.

## Upgrade and removal conditions

- Pin exact versions and feature flags in the workspace and retain `Cargo.lock`.
- Stop on any advisory, unknown source, unreviewed license, unsupported target,
  KeyPackage substitution seam, parser-bound failure, or storage behavior that
  cannot meet the cross-layer transaction.
- Remove or supersede this selection if upstream maintenance stops, the required
  ciphersuite or RFC behavior regresses, or a better-audited implementation passes
  the same evidence packet.
- Do not upgrade across a storage format or MLS behavior change without fixtures,
  migration tests, rollback tests, and an ADR update.

## Primary sources and retained evidence

- [`mls-rs` 0.56.0 tagged source](https://github.com/awslabs/mls-rs/tree/0.56.0)
- [`mls-rs` security notice and provider status](https://github.com/awslabs/mls-rs/tree/0.56.0#security-notice)
- [`mls-rs` 0.56.0 manifest](https://github.com/awslabs/mls-rs/blob/0.56.0/mls-rs/Cargo.toml)
- [`mls-rs` KeyPackage and reference implementation](https://github.com/awslabs/mls-rs/blob/0.56.0/mls-rs/src/key_package/mod.rs)
- [`mls-rs` external KeyPackage validation](https://github.com/awslabs/mls-rs/blob/0.56.0/mls-rs/src/external_client.rs)
- [`mls-rs` commit output and Add API](https://github.com/awslabs/mls-rs/blob/0.56.0/mls-rs/src/group/commit.rs)
- [`mls-rs` group-state storage trait](https://github.com/awslabs/mls-rs/blob/0.56.0/mls-rs-core/src/group/group_state.rs)
- [AWS-LC supported platforms and safety mechanisms](https://github.com/aws/aws-lc#platform-support)
- [SPDX license list](https://spdx.org/licenses/)
- [MLS implementation comparison](../research/MLS_IMPLEMENTATION_COMPARISON.md)
