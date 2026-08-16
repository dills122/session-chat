# AGENTS

AI coding guidance for Session Chat.

## Purpose

This repository preserves a legacy Angular/NestJS chat prototype while building
Session Chat 2.0: disposable, end-to-end encrypted conversations with pluggable
admission and transport.

Optimize for:

- client-owned session keys and fail-closed security behavior
- independence between identity/admission, rendezvous, transport, and MLS state
- small, testable vertical slices instead of a destructive rewrite
- explicit protocol contracts, threat-model updates, and retained test evidence

The v2 documents are a design baseline, not a claim that the legacy application
already provides the described security properties.

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

- `apps/chat-frontend/`: legacy Angular UI
- `apps/chat-backend/`: legacy NestJS, Socket.IO, JWT, and Redis backend
- `libs/shared-sdk/`: legacy shared TypeScript contracts
- `spikes/`: disposable feasibility code; production packages must not depend on it
- `docs/`: canonical v2 product, architecture, threat-model, protocol, and ADR baseline

Planned v2 areas:

- `crates/session-protocol`: versioned wire objects and canonical serialization
- `crates/session-core`: invitation, join, membership, and session state machines
- `crates/session-crypto-mls`: MLS integration and protected state persistence
- `crates/session-admission` plus adapters: admission policy and verified key binding
- `crates/session-transport` plus adapters: opaque envelope delivery
- `apps/sessionctl`: headless protocol and conformance client

When a change spans areas, update the shared contract first and preserve the
dependency direction described in `docs/ARCHITECTURE_V2.md`.

## Security Guardrails

- Treat invitations, deep links, envelopes, provider assertions, mailbox objects,
  persistence, and network input as attacker-controlled.
- Never put plaintext, group keys, bearer capabilities, raw provider tokens, or
  stable external identity fields into transport envelopes or logs.
- Admission proves authorization to propose a session-scoped member key; it does
  not replace MLS membership or grant transport authority.
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

- Build v2 alongside the legacy prototype until the first encrypted end-to-end
  protocol milestone passes; do not incrementally reinterpret legacy JWT or
  Socket.IO state as v2 cryptographic state.
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
- Follow existing Rush, TypeScript, Angular, NestJS, Prettier, and ESLint config
  in legacy areas.
- Prefer deterministic, offline unit and integration tests for protocol work.
- Add malformed, expired, replayed, duplicated, reordered, unauthorized, and
  persistence-rollback cases at every untrusted boundary where they apply.
- Update docs whenever setup, commands, contracts, wire behavior, or security
  claims change.

## Useful Commands

Legacy workspace:

```sh
node common/scripts/install-run-rush.js update
node common/scripts/install-run-rush.js lint
node common/scripts/install-run-rush.js build
node common/scripts/install-run-rush.js test:ci
```

Current invitation-provider spike:

```sh
node --test spikes/sealed-invitation-provider/test/provider.test.mjs
```

Once the Rust v2 workspace exists, its minimum handoff gate is expected to include:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
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
