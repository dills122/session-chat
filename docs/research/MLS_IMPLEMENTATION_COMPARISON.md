# MLS implementation and provider comparison

Status: decision complete; isolated implementation retained

Reviewed: 2026-08-19

Decision owner: Session Chat maintainers through ADR 0012

## Decision question and scope

Which released MLS implementation and cryptographic provider can support the
bounded Phase 1 laboratory without weakening repository dependency policy or the
ADR 0009 KeyPackage-ownership and future durable-transaction invariants?

This packet evaluated released crates and disposable local experiments only. It
did not authorize production dependencies, a networked join path, custom
cryptography, advisory exceptions, or a product-security claim. Primary sources,
exact published crate contents, and the repository's own policy were preferred.

Success required:

1. an exact locked graph with no RustSec vulnerability or disallowed source;
2. reviewed licensing without a package-specific exception;
3. the mandatory RFC 9420 ciphersuite and native target support;
4. an API seam that can retain one exact validated KeyPackage through Add and Welcome;
5. an explicit persistence boundary that does not force Welcome publication
   before the application can stage its transaction; and
6. bounded, locally reproduced evidence with limitations stated.

The stop condition was a decision-ready comparison and governing ADR. No
candidate would be accepted for production based on this packet.

## Executive conclusion

Select exact `mls-rs` 0.56.0 with `mls-rs-crypto-awslc` 0.25.0 and the reduced
feature set in ADR 0012 for the isolated Phase 1 laboratory. The selected
72-package experimental graph passed cargo-deny 0.20.2 advisories, bans,
licenses, and sources after ISC and MIT-0 were explicitly added to the reviewed
repository license allowlist. No advisory was ignored.

The ownership/storage experiment passed on macOS aarch64 with Rust 1.97.1. It
showed that a private non-`Clone` wrapper can retain the exact message whose
clone was validated, consume the retained message into Add, match the Welcome
to its canonical KeyPackage reference, exchange an encrypted application
message, and observe zero group-state writes until explicit persistence.

This is sufficient to start the isolated laboratory. It is not sufficient for
a durable or user-facing join path. `mls-rs` explicitly reports that it has not
received a full independent third-party security audit, and its separate group
state and KeyPackage repository calls still require a crash-injected
cross-layer transaction design.

## Candidate comparison

| Candidate | Exact screened boundary | Dependency result | API/platform result | Decision |
| --- | --- | --- | --- | --- |
| OpenMLS | `openmls` 0.8.1 + `openmls_rust_crypto` 0.5.1 | Fails: the current graph still contains RustSec-advised libcrux packages and an unmaintained transitive crate; the retained applicability map records the broader lock result | Prior disposable lifecycle was feasible; persistence had an acknowledged desynchronization risk | Do not integrate this release |
| `mls-rs` + AWS-LC | `mls-rs` 0.56.0 + `mls-rs-crypto-awslc` 0.25.0; reduced Phase 1 features | Passes after explicit ISC/MIT-0 allowlist review; no advisory or source exception; 72 packages | Ownership/storage experiment passes; upstream labels provider stable; AWS-LC actively tests intended native desktop/mobile classes | Select for isolated laboratory |
| `mls-rs` + OpenSSL | `mls-rs` 0.56.0 + `mls-rs-crypto-openssl` 0.21.0 with default `mls-rs` screening features | Passes current policy; 77 packages | Builds on review host and upstream labels provider stable; system/native OpenSSL packaging remains target-dependent | Retain as fallback |
| `mls-rs` + RustCrypto | `mls-rs` 0.56.0 + `mls-rs-crypto-rustcrypto` 0.22.1 with default `mls-rs` screening features | Passes current policy; 118 packages | Builds on review host, but upstream labels provider experimental | Reject for first laboratory |
| Cisco `mlspp` | Not dependency-resolved | Not evaluated | C++/FFI adds memory-safety, packaging, and toolchain boundaries | Not competitive for this Rust slice |

Package counts include the disposable root. OpenSSL and RustCrypto counts are
screening observations, not selected minimal graphs. A clean advisory scan means
only that the consulted database had no matching advisory for the resolved
graph at that time.

## Documented facts

- The published `mls-rs` 0.56.0 crate records source commit
  `8f1b43f447a792ff9307f1c2c7f54da63914870e`, which matches upstream tag
  `0.56.0`, and declares Rust 1.82.0 or newer.
- Upstream describes AWS-LC and OpenSSL as stable providers, RustCrypto as
  experimental, RFC 9420 conformance and interoperability tests as present,
  and a full third-party security audit as absent.
- `ExternalClient::validate_key_package` validates version, ciphersuite,
  signature, identity, lifetime, and KeyPackage properties and returns the
  parsed KeyPackage.
- `MlsMessage` exposes the KeyPackage and canonical reference; Add accepts an
  owned `MlsMessage`; Welcome exposes recipient KeyPackage references.
- Commit construction returns Welcome output before pending-commit application,
  and group state is not persisted until `Group::write_to_storage` is invoked.
- `GroupStateStorage::write` batches current group state and epoch inserts and
  updates and asks implementations to make that call atomic.
- Joining-client persistence writes group state and then deletes the consumed
  KeyPackage through a separate repository call. Those calls are not an
  application transaction by themselves.
- AWS-LC documents active native CI coverage for macOS aarch64/x86-64, Windows
  x86-64, Linux aarch64/x86-64 and other CPUs, Android aarch64, and iOS aarch64.
  Its WASM support is experimental and is not selected.
- ISC and MIT-0 are named SPDX licenses and OSI approved. Their inclusion in
  the allowlist is a policy fact, not legal advice about a future distribution.

## Reproduced observations

Environment:

- macOS aarch64;
- `rustc 1.97.1 (8bab26f4f 2026-07-14)`;
- `cargo 1.97.1 (c980f4866 2026-06-30)`; and
- temporary `cargo-deny 0.20.2` installed outside the repository.

Selected disposable manifest:

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

The lock resolved `aws-lc-rs` 1.16.3 and `aws-lc-sys` 0.40.0. The following
commands passed against the disposable graph:

```sh
cargo +1.97.1 test --locked --offline
cargo-deny --manifest-path <temporary>/Cargo.toml \
  --config <repository>/deny.toml --all-features --locked check
```

The disposable experiment covered exact validated-message equality, canonical
reference matching, Add, Welcome targeting, application encryption/decryption,
and explicit storage timing. Its temporary source and lock are intentionally
not repository artifacts. The retained `session-crypto-mls` crate and tests now
reproduce and extend that evidence with bounded parsing, path update, removal,
replay, reordering, delayed Commit, abandoned pending Commit, and hostile
third-member cases. These observations support only the isolated in-memory
laboratory claim.

The selected graph still contains `mls-rs-identity-x509` because the AWS-LC
provider depends on it unconditionally, even though the `mls-rs` X.509 feature
is disabled and the laboratory will not expose X.509 credentials. Cargo-deny
also warned about duplicate `syn` and build-target `getrandom` versions under
the repository's warning policy. These are retained review surfaces, not
advisory failures and not evidence that the graph is globally minimal.

The default-feature screening graphs for AWS-LC, OpenSSL, and RustCrypto all
compiled under the pinned toolchain and were advisory-clean. Before the
allowlist update, AWS-LC failed only on ISC and MIT-0. The OpenMLS screening
still failed on `RUSTSEC-2026-0207`, `RUSTSEC-2026-0208`,
`RUSTSEC-2026-0212`, and an unmaintained `proc-macro-error2`; the older retained
OpenMLS lock review also records advised optional packages that GitHub
dependency review would see when added.

## Inferences

- `mls-rs` gives Session Chat a stronger prospective transaction seam than the
  previously evaluated OpenMLS release because message output, in-memory state
  application, and persistence are explicit stages. A shared transaction-aware
  storage adapter appears feasible.
- Exact KeyPackage ownership is implementable without exposing a second
  caller-supplied KeyPackage at the membership API. The adapter must validate a
  clone internally, retain the equality-checked original in a private linear
  wrapper, and consume only that original into Add.
- AWS-LC is preferable to OpenSSL for the first native-client-oriented
  laboratory because its upstream platform matrix is clearer and does not rely
  on discovery of an independently installed OpenSSL. This does not make its
  build or cryptography risk-free.

## Unknowns and next gates

- No independent audit currently establishes the security of the exact
  `mls-rs` protocol/provider composition.
- The experiment did not run cross-implementation MLS interoperability vectors.
- A durable adapter has not proved atomic group state, KeyPackage deletion,
  invitation consumption, replay state, approval result, and Welcome outbox.
- Crash recovery, stale snapshot rejection, old-secret deletion, schema
  migration, and backup semantics remain untested.
- Linux, Windows, iOS, and Android builds were not reproduced by Session Chat.
- Parser bounds and hostile MLS object tests are retained for the adapter's
  KeyPackage, Welcome, Commit/application wire, and application plaintext
  boundaries; fuzzing and cross-implementation parser evidence remain open.
- The laboratory accepts explicit clock values for KeyPackage and Commit tests;
  production clock sourcing and exact RNG failure handling remain open.

The next implementation gate is admission-to-MLS orchestration plus the durable
transaction/storage call trace and cross-implementation fixtures. No networked
or durable join path may precede that evidence.

## Primary source index

- [`mls-rs` 0.56.0 tagged source and security notice](https://github.com/awslabs/mls-rs/tree/0.56.0)
- [`mls-rs` 0.56.0 manifest](https://github.com/awslabs/mls-rs/blob/0.56.0/mls-rs/Cargo.toml)
- [`mls-rs` KeyPackage implementation](https://github.com/awslabs/mls-rs/blob/0.56.0/mls-rs/src/key_package/mod.rs)
- [`mls-rs` external validation](https://github.com/awslabs/mls-rs/blob/0.56.0/mls-rs/src/external_client.rs)
- [`mls-rs` commit and Welcome output](https://github.com/awslabs/mls-rs/blob/0.56.0/mls-rs/src/group/commit.rs)
- [`mls-rs` group-state repository](https://github.com/awslabs/mls-rs/blob/0.56.0/mls-rs/src/group/state_repo.rs)
- [`mls-rs-core` storage trait](https://github.com/awslabs/mls-rs/blob/0.56.0/mls-rs-core/src/group/group_state.rs)
- [AWS-LC platform and safety documentation](https://github.com/aws/aws-lc)
- [SPDX license list](https://spdx.org/licenses/)
- [OpenMLS issue 2126](https://github.com/openmls/openmls/issues/2126)
- [OpenMLS applicability map](OPENMLS_0_8_1_APPLICABILITY.md)
