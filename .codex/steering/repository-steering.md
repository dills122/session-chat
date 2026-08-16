# Repository Scope And Priorities

This repository builds Session Chat 2.0, a disposable end-to-end encrypted chat
protocol and client, while preserving the current Angular/NestJS application as
a legacy prototype.

Primary deliverables:

- a versioned, transport-independent protocol core with MLS group security
- pluggable admission for capabilities, GitHub assertions, and later credentials
- opaque fast, mailbox, and private transport adapters with explicit guarantees

Core priorities:

- client-owned keys, forward secrecy, and post-removal security
- strict separation of session security, admission, rendezvous, and transport
- stable typed and serialized contracts between modules
- deterministic verification and honest, evidence-bounded security claims

## Active Boundaries

- `docs/` owns the v2 product, architecture, threat-model, roadmap, and decision baseline.
- `spikes/` owns disposable feasibility experiments and is not a production dependency.
- `apps/chat-frontend/`, `apps/chat-backend/`, and `libs/shared-sdk/` own the legacy prototype.
- Future `crates/` packages own the Rust protocol core and adapters; future
  `apps/sessionctl/` owns the headless conformance client.

## Safe Refactor Boundaries

Do not refactor these without explicit instruction and an updated ADR where the
security model changes:

- invitation, admission-proof, envelope, or MLS state semantics
- client key ownership, member removal, epoch, or persistence guarantees
- the separation between external identity, session-scoped member keys, and transport
- private-mode fail-closed behavior or metadata claims
- legacy public routes, storage behavior, or workspace project names

Safe default changes:

- feature-scoped protocol-laboratory improvements
- fail-closed parsing, validation, and replay protection
- focused positive, negative, adversarial, and persistence tests
- documentation corrections that do not silently broaden a security claim
