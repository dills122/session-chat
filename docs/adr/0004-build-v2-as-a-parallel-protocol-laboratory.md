# ADR 0004: Build v2 as a parallel capability-first protocol laboratory

Status: accepted for Phase 1 scope; source-tree coexistence superseded by ADR 0006

Date: 2026-08-16

## Context

The v2 design now separates session security, admission, rendezvous, and
transport; defines a threat model; describes GitHub, capability, and credential
admission; and has a concrete sealed invitation-provider spike. The remaining
unknowns are important, but they no longer prevent testing the central product
claim: two people can establish an end-to-end encrypted disposable session
without making GitHub, a mailbox service, a GUI, or a production network part of
the security core.

Continuing broad research would defer the highest-value evidence. Beginning with
a cleanup or in-place rewrite of the Angular/NestJS prototype would also couple
the new protocol to legacy JWT, Socket.IO, Redis, and wire assumptions before the
new state machine has proved itself.

## Decision

Begin Phase 1 implementation. Preserve the legacy application and build a new
Rust protocol laboratory alongside it. Do not perform a destructive cleanup or
move legacy code until the first encrypted end-to-end milestone passes.

ADR 0006 later superseded the coexistence and cleanup timing in this paragraph.
The capability-only, two-person, in-memory, headless scope and acceptance
evidence below remain in force.

The first slice is deliberately capability-only, two-person, in-memory, and
headless. It has no external service dependency.

Before implementation changes begin:

1. Land the design documents and invitation-provider spike as a reviewable baseline.
2. Mark the final unchanged legacy baseline with a `legacy-v1` tag or equivalent.
3. Do v2 work on a feature branch rather than directly on `master`.

These are preparation steps for the implementation change; this ADR does not by
itself create a commit, tag, or branch.

## Initial workspace

The target shape is:

```text
crates/
├── session-protocol
├── session-core
├── session-crypto-mls
├── session-admission
├── admission-capability
├── session-transport
└── transport-memory
apps/
└── sessionctl
```

Responsibilities:

- `session-protocol` owns versioned wire objects, limits, and canonical serialization.
- `session-core` owns invitation, join, approval, membership, and session state machines.
- `session-crypto-mls` adapts the selected MLS implementation and protected persistence.
- `session-admission` defines proof verification and session-key binding contracts.
- `admission-capability` implements single-use secret-capability admission.
- `session-transport` defines delivery of opaque envelopes only.
- `transport-memory` provides deterministic loss, duplication, reordering, and replay tests.
- `sessionctl` drives complete flows without a GUI or network service.

Crates may be introduced incrementally if each commit remains runnable and the
ownership boundaries above are not collapsed for convenience.

## First complete flow

The first milestone must demonstrate one complete story:

1. Alice creates a bounded, expiring, single-use capability invitation.
2. Bob opens it, creates a fresh session-scoped member key, and sends an encrypted
   join request whose proof is bound to that invitation and key.
3. Alice validates the request and explicitly approves Bob.
4. Alice creates or advances the MLS group and sends Bob an MLS Welcome.
5. Alice and Bob exchange encrypted application messages over the memory transport.
6. Alice removes Bob and advances the epoch.
7. Bob cannot decrypt messages from the new epoch.

## Milestone acceptance evidence

The slice is not complete until automated tests show all of the following:

- A copied public invitation does not disclose or derive a session/group key.
- Invalid, expired, consumed, and replayed invitations fail closed.
- A join proof cannot be rebound to another invitation or proposed member key.
- Transport code sees opaque, bounded envelopes rather than plaintext messages.
- Two independent clients converge on the expected MLS group and epoch state.
- Captured envelopes contain no plaintext, raw bearer capability, or group key material.
- Duplicate and reordered delivery is safe and deterministic.
- A newly admitted member cannot decrypt application messages from an earlier epoch.
- A removed member cannot decrypt application messages from a later epoch.
- State can be serialized and restored without accepting stale-state rollback.
- Logs and errors contain no plaintext, secret capability, or key material.

Where feasible, parsers and state machines should add property tests or fuzz
targets in addition to example-based tests.

## Research allowed inside the slice

Research is bounded to decisions that directly unblock the milestone:

1. Select a reviewed MLS implementation, crypto provider, ciphersuite, and persistence
   strategy. Avoid unreleased APIs, experimental extensions, and sensitive debug output.
2. Select deterministic canonical encodings for invitations and protocol envelopes,
   with explicit versioning and rejection of ambiguous or non-canonical inputs.
3. Select a maintained RFC 9180 HPKE implementation for pre-membership objects;
   do not build a custom HPKE construction.

Record each consequential selection in an ADR with exact dependency versions,
feature flags, trust assumptions, and removal or upgrade conditions. Other
research stays in `docs/RESEARCH_BACKLOG.md` unless the milestone exposes a real
blocker.

## Excluded from Phase 1

Do not add these to the first slice:

- GitHub identity or an identity bridge
- SSI, DIDs, verifiable credentials, wallets, or OpenID4VP
- the sealed invitation provider as a deployed dependency
- Iroh, relay infrastructure, or Docker deployment
- Katzenpost or any production mixnet
- Tauri or the Angular v2 interface
- attachments, large groups, multi-device state, or recovery

The interfaces must permit these later, but speculative implementations would
weaken the value of the first proof.

## Integration order after the milestone

After the capability/memory slice passes, add one independent variable at a time:

1. GitHub admission through the same admission interface
2. sealed first-contact mailbox and invitation-provider integration
3. fast direct/relay transport
4. desktop UI around the proven core
5. private mixnet transport with fail-closed behavior
6. credential/SSI admission at an interoperable presentation boundary

Each step must retain capability admission and deterministic memory-transport
tests as the control path.

## Consequences

- Useful implementation work starts now while research remains evidence-driven.
- The legacy prototype stays available for UX and migration reference without
  becoming the v2 security foundation.
- The first milestone will look smaller than the intended product, but it tests
  the hardest invariants with the fewest moving parts.
- Some temporary duplication is accepted until the Rust core has earned a
  migration boundary.
- Cleanup becomes justified after the protocol core can complete the encrypted
  two-person flow and its negative tests pass, not before.
