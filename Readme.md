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
  v1/v2 availability, reservation, release, and post-membership consumption lifecycle
- `session-admission`, with an object-safe, provider-neutral approval context
  that exposes no proof, bearer capability, parsed KeyPackage, or membership authority
- `session-crypto-hpke`, with provider-neutral one-shot RFC 9180 PSK join
  protection, an AWS-LC implementation, an RFC known-answer vector, and an
  independent-provider interoperability test, plus provider-owned creation of
  every random invitation-v2 field
- `admission-capability`, with HPKE-proof provenance, exact provider-validated
  KeyPackage ownership, bounded in-memory request-ID/nonce replay reservation,
  exact v2 invitation binding, the shared non-authorizing approval seam, and
  ownership-preserving invitation/MLS prepare/apply coordination
- `session-crypto-mls`, with an isolated in-memory two-party MLS 1.0 adapter for
  bounded KeyPackage validation, Add/Welcome, messages, path updates, and removal
- `session-transport`, with provider-generated, right-specific local Welcome
  mailboxes, one-envelope idempotency, expiry, and bounded in-memory state
- `session-inviter-transaction`, with a bounded fault-injectable conformance
  model for atomic invitation/replay/approval/MLS-snapshot/Welcome-outbox state

The signing key authenticates the invitation bytes, not a GitHub identity or
person. The capability invitation is a secret bearer object and must not be
posted publicly or placed in a transport envelope. The MLS adapter has no
durable storage or network path; the capability adapter coordinates it only
through the in-memory approval-gated path described below.
The protected-join and capability-admission adapters prove possession for one
exact typed HPKE context, preserve the exact signed-invitation instance,
independently validate and own the exact KeyPackage, and reserve replay values
within bounded in-memory state. The approval-gated path binds that value to the
local v2 invitation reservation before MLS preparation. Explicit rejection,
expiry, pre-commit failure, or abandonment releases both reservations; a
successful in-memory Add consumes invitation state. This sequencing is not a
durable transaction. A separate conformance model now proves the required
atomic visibility, ambiguous-commit recovery, and resumable Welcome-outbox
semantics over bounded memory records. A durable adapter, real cross-layer
persistence, durable or network mailbox behavior, human UI approval, and a user
interface remain unimplemented. The in-memory approved-join result now carries
only the exact authenticated deposit endpoint beside its MLS outputs, and a
retained test delivers the encrypted Welcome through the local adapter. This
sequential path is not evidence for a durable outbox or network profile.

ADR 0014 defines the exact local-only invitation-v2, HPKE capability-join, and
one-Welcome response contract. Its canonical protocol value types are now
implemented and tested, its one-shot HPKE operation has RFC and cross-provider
evidence, and its capability-admission boundary now retains explicit simulated
approval plus in-memory invitation/MLS/Welcome-delivery coordination. Human
approval UX, durable atomic replay/membership/outbox state, and network behavior
remain accepted design boundaries rather than runtime or production claims.

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
