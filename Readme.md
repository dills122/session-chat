# Session Chat

[![Rust Protocol](https://github.com/dills122/session-chat/actions/workflows/rust.action.yml/badge.svg)](https://github.com/dills122/session-chat/actions/workflows/rust.action.yml)
[![Retained Tools](https://github.com/dills122/session-chat/actions/workflows/node-tools.action.yml/badge.svg)](https://github.com/dills122/session-chat/actions/workflows/node-tools.action.yml)

Session Chat is a protocol-first project for disposable, end-to-end encrypted
conversations with pluggable admission and delivery. The project is currently a
headless research and implementation laboratory, not a deployable chat product.

The design principle is: **publish the door, not the key**.

## Current implementation

The Rust workspace currently contains:

- `session-protocol`, with a bounded opaque envelope and a canonical,
  domain-separated Ed25519 signed capability invitation
- `session-core`, with configurable expiration checks and bounded in-memory
  one-time invitation consumption

The signing key authenticates the invitation bytes, not a GitHub identity or
person. The capability invitation is a secret bearer object and must not be
posted publicly or placed in a transport envelope. Encrypted joins, capability
proofs, admission approval, MLS, durable persistence, networking, and a user
interface remain unimplemented.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

The retained JavaScript research and repository tooling have no third-party
runtime dependencies:

```sh
node --test scripts/setup-codex-links.test.mjs
node --test spikes/sealed-invitation-provider/test/provider.test.mjs
```

## Repository map

- `crates/` contains retained Rust protocol code.
- `docs/` contains the product definition, architecture, threat model, roadmap,
  research, ADRs, and legacy evidence.
- `spikes/` contains disposable feasibility experiments; production crates must
  not depend on them.
- `scripts/` contains tested repository setup tooling.

Start with [the v2 document index](docs/README.md). Security claims are bounded
by the evidence recorded there and in the tests.

## Legacy v1

The retired Angular/NestJS prototype is preserved by the `legacy-v1` tag rather
than duplicated in the active source tree. See the
[legacy archive index](docs/legacy-v1/README.md) for recovery commands, behavior,
and security lessons.

## License

[MIT](LICENSE)
