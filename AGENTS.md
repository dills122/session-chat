# AGENTS

AI coding guidance for Session Chat.

## Purpose

This repository builds Session Chat 2.0: disposable, end-to-end encrypted
conversations with pluggable admission and transport.

Optimize for:

- client-owned session keys and fail-closed security behavior
- independence between identity/admission, rendezvous, transport, and MLS state
- small, testable vertical slices on a protocol-first foundation
- explicit protocol contracts, threat-model updates, and retained test evidence

The v2 documents are a design baseline, not a claim that the current protocol
laboratory already provides the described security properties.

## Start Here

Read these documents before changing v2 behavior:

1. `docs/README.md`
2. `docs/PRODUCT_V2.md`
3. `docs/ARCHITECTURE_V2.md`
4. `docs/IDENTITY_AND_ADMISSION.md`
5. `docs/TRANSPORTS.md`
6. `docs/THREAT_MODEL.md`
7. `docs/ROADMAP_V2.md`
8. the relevant record under `docs/adr/`

Use `docs/RESEARCH_BACKLOG.md` for unresolved questions. Do not silently turn a
research item into a security or product claim.

## Architecture Boundaries

Current areas:

- `crates/session-protocol`: versioned wire objects and canonical serialization
- `crates/session-core`: bounded inviter-owned invitation lifecycle state; descriptor
  validation is read-only and consumption follows successful membership
- `crates/session-crypto-hpke`: provider-neutral one-shot capability join
  protection with a pinned AWS-LC implementation and fixed typed contexts
- `crates/admission-capability`: automated capability-proof verification, exact
  KeyPackage ownership, bounded replay reservation, explicit simulated approval,
  and in-memory invitation/MLS coordination
- `crates/session-crypto-mls`: isolated in-memory two-party MLS adapter with
  bounded exact KeyPackage ownership and explicit prepare/apply transitions
- `spikes/`: disposable feasibility code; production packages must not depend on it
- `docs/`: canonical v2 product, architecture, threat-model, protocol, ADR, and legacy-evidence baseline
- `scripts/`: tested repository and AI Central setup tooling

Planned v2 areas:

- later `session-core` increments: durable join, membership, and session state machines
- later `session-crypto-mls` increments: admission orchestration and protected
  transactional state persistence
- later admission increments: human approval UX and durable atomic
  replay/result, invitation, membership, and Welcome-outbox state
- `crates/session-transport` plus adapters: opaque envelope delivery
- `apps/sessionctl`: headless protocol and conformance client

When a change spans areas, update the shared contract first and preserve the
dependency direction described in `docs/ARCHITECTURE_V2.md`.

## Security Guardrails

- Treat invitations, deep links, envelopes, provider assertions, mailbox objects,
  persistence, and network input as attacker-controlled.
- Never put plaintext, group keys, bearer capabilities, raw provider tokens, or
  stable external identity fields into transport envelopes or logs.
- Admission proves authorization for one exact MLS KeyPackage, credential
  identity, and leaf signature key; it does not replace MLS membership or grant
  transport authority.
- Private transport fails closed. Do not add an automatic fast/direct fallback.
- Bind proofs to the invitation, challenge, verifier audience, proposed member
  key, and expiration as applicable.
- Bound storage, parsing, retries, queues, decompression, and unauthenticated work.
- Use reviewed cryptographic libraries and protocols. Do not implement custom
  cryptographic primitives.
- Record consequential security or protocol changes in an ADR and update the
  threat model in the same change.

## Contract-First Files

Treat these as normative design contracts until code-level schemas replace them:

- `docs/ARCHITECTURE_V2.md`
- `docs/IDENTITY_AND_ADMISSION.md`
- `docs/TRANSPORTS.md`
- `docs/THREAT_MODEL.md`
- `docs/spikes/SEALED_INVITATION_PROVIDER_PROTOCOL.md`
- `docs/adr/`

Keep serialized formats versioned and canonical. A format or state-machine change
requires compatibility fixtures and negative tests before it is considered done.

## Scope Control

- Do not restore or incrementally reinterpret retired JWT, Socket.IO, Redis, or
  deterministic invitation-hash state as v2 cryptographic state. Use the
  `legacy-v1` tag only for historical inspection.
- Keep Phase 1 to two participants, capability admission, in-memory transport,
  and a headless client.
- Defer GitHub admission, SSI/credentials, production rendezvous, Tauri UI,
  mixnets, large groups, attachments, and recovery until their roadmap phases.
- Preserve existing user changes and avoid unrelated package or formatting churn.
- Do not claim a mode or property is secure, anonymous, private, ephemeral, or
  production-ready beyond the evidence actually retained in the repository.

## Repository Conventions

- The default branch is `master`; use `codex/<topic>` feature branches for retained
  behavior, contract, test, or documentation work. Do not commit directly to
  `master`.
- Follow the pinned Rust toolchain and workspace lints. Retained Node scripts use
  ESM and built-in modules so they can be tested without an npm install.
- Prefer deterministic, offline unit and integration tests for protocol work.
- Add malformed, expired, replayed, duplicated, reordered, unauthorized, and
  persistence-rollback cases at every untrusted boundary where they apply.
- Update docs whenever setup, commands, contracts, wire behavior, or security
  claims change.

## Useful Commands

Retained Node tooling and invitation-provider spike:

```sh
node --test scripts/check-repository.test.mjs scripts/setup-codex-links.test.mjs
node --test spikes/sealed-invitation-provider/test/provider.test.mjs
node scripts/check-repository.mjs
```

Rust v2 workspace:

```sh
cargo fetch --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo test --workspace --all-features --locked --offline
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked --offline
cargo deny --all-features --locked check
```

Run the smallest relevant checks first, then the complete gate for the changed
area. Report exact commands and any check that could not run.

## AI Central Context

Selected steering is committed, while reviewed skills are linked locally from
the pinned AI Central checkout. Repository-specific instructions remain real,
trackable files. This file is authoritative when generic linked guidance
conflicts with Session Chat's security boundaries. Recreate the ignored local
skill links with `node scripts/setup-codex-links.mjs`.

See `.codex/AI_CENTRAL.md` for the installed revision, selection,
repository-visible link policy, verification, and refresh command.
