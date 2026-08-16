# Repository Scope And Priorities

This repository builds Session Chat 2.0, a disposable end-to-end encrypted chat
protocol and client. The retired web prototype is available only through the
`legacy-v1` tag and `docs/legacy-v1/` evidence.

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
- `crates/session-protocol/` owns the current Rust wire-format implementation.
- Future `crates/` packages own the remaining Rust protocol core and adapters; future
  `apps/sessionctl/` owns the headless conformance client.

## Safe Refactor Boundaries

Do not refactor these without explicit instruction and an updated ADR where the
security model changes:

- invitation, admission-proof, envelope, or MLS state semantics
- client key ownership, member removal, epoch, or persistence guarantees
- the separation between external identity, session-scoped member keys, and transport
- private-mode fail-closed behavior or metadata claims
- the decision to keep retired v1 contracts out of active protocol code

Safe default changes:

- feature-scoped protocol-laboratory improvements
- fail-closed parsing, validation, and replay protection
- focused positive, negative, adversarial, and persistence tests
- documentation corrections that do not silently broaden a security claim
