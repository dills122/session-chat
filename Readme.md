# Session Chat

[![CI](https://github.com/dills122/session-chat/actions/workflows/ci.yml/badge.svg)](https://github.com/dills122/session-chat/actions/workflows/ci.yml)

Session Chat is a protocol-first project for disposable, end-to-end encrypted
conversations with pluggable admission and delivery. The project is currently a
headless research and implementation laboratory, not a deployable chat product.

The design principle is: **publish the door, not the key**.

## Current implementation

The Rust workspace currently contains:

- `session-protocol`, with a bounded opaque envelope, canonical v1/v2
  domain-separated Ed25519 capability invitations, and bounded canonical
  protected-join outer, inner, AAD, and local deposit-endpoint value types
- `session-core`, with configurable expiration checks and a bounded inviter-owned
  availability, reservation, release, and post-membership consumption lifecycle
- `session-crypto-hpke`, with provider-neutral one-shot RFC 9180 PSK join
  protection, an AWS-LC implementation, an RFC known-answer vector, and an
  independent-provider interoperability test
- `session-crypto-mls`, with an isolated in-memory two-party MLS 1.0 adapter for
  bounded KeyPackage validation, Add/Welcome, messages, path updates, and removal

The signing key authenticates the invitation bytes, not a GitHub identity or
person. The capability invitation is a secret bearer object and must not be
posted publicly or placed in a transport envelope. The MLS adapter is not wired
to invitations or admission and has no durable storage or network path.
The protected-join adapter proves possession of the invitation capability for
one exact typed HPKE context; it does not approve admission, track replay,
validate the KeyPackage, or mutate invitation/MLS state. Admission approval,
cross-layer atomic persistence, mailbox behavior, networking, and a user
interface remain unimplemented. The core
transition names encode caller preconditions; they do not prove admission or
MLS membership has occurred.

ADR 0014 defines the exact local-only invitation-v2, HPKE capability-join, and
one-Welcome response contract. Its canonical protocol value types are now
implemented and tested, and its one-shot HPKE operation now has RFC and
cross-provider evidence. Its admission, mailbox, and orchestration behavior
remains an accepted design boundary rather than runtime evidence or a
network/production claim.

```sh
cargo fetch --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo test --workspace --all-features --locked --offline
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked --offline
cargo deny --all-features --locked check
```

The retained JavaScript research and repository tooling have no third-party
runtime dependencies:

```sh
node --test scripts/check-repository.test.mjs scripts/setup-codex-links.test.mjs
node --test spikes/sealed-invitation-provider/test/provider.test.mjs
node scripts/check-repository.mjs
```

## Repository map

- `crates/` contains retained Rust protocol code.
- `docs/` contains the product definition, architecture, threat model, roadmap,
  research, ADRs, and legacy evidence.
- `spikes/` contains disposable feasibility experiments; production crates must
  not depend on them.
- `scripts/` contains tested repository setup tooling.

Start with [the v2 document index](docs/README.md). Security claims are bounded
by the evidence recorded there and in the tests. The
[secure-development policy](docs/SECURE_DEVELOPMENT.md) explains the required
merge gate and the repository settings that must back it.

## Legacy v1

The retired Angular/NestJS prototype is preserved by the `legacy-v1` tag rather
than duplicated in the active source tree. See the
[legacy archive index](docs/legacy-v1/README.md) for recovery commands, behavior,
and security lessons.

## License

[MIT](LICENSE)
