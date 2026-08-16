# Session Chat 2.0 design documents

Status: Phase 1 protocol laboratory in progress

These documents describe the proposed Session Chat 2.0 pivot. They are a
working design baseline, not a claim that the current application implements
the described security properties.

The central product idea is:

> Publish the door, not the key.

Session Chat should provide disposable, end-to-end encrypted conversations
between people who can be admitted using an external identity, a portable
credential, a secret capability, or manual approval. Identity and network
privacy are independent choices: a GitHub-verified conversation can travel
over a mixnet, while an anonymous conversation can use no external identity at
all.

## Document map

- [Product definition](PRODUCT_V2.md) defines the product promise, primary
  workflows, user-visible modes, and non-goals.
- [Architecture](ARCHITECTURE_V2.md) separates session security, admission,
  rendezvous, and transport.
- [Identity and admission](IDENTITY_AND_ADMISSION.md) covers GitHub, verifiable
  credentials, SSI/DIDs, capability admission, and session-scoped identities.
- [Transports](TRANSPORTS.md) covers fast delivery, mixnets, offline mailboxes,
  reliability, and privacy downgrade rules.
- [Threat model](THREAT_MODEL.md) defines assets, trust boundaries, attackers,
  invariants, and severity calibration.
- [Roadmap](ROADMAP_V2.md) proposes an incremental implementation and validation
  sequence.
- [Phase 1 build decision](adr/0004-build-v2-as-a-parallel-protocol-laboratory.md)
  commits the next slice to a capability-first Rust protocol laboratory.
- [V1 retirement decision](adr/0006-retire-v1-from-the-default-branch.md)
  removes the old runtime while preserving its exact tagged snapshot and lessons.
- [Legacy v1 archive index](legacy-v1/README.md) records recovery commands,
  behavior, security lessons, and project-history evidence.
- [Research backlog](RESEARCH_BACKLOG.md) records unresolved questions without
  prematurely turning them into architecture decisions.
- [Reference ledger](REFERENCES.md) records the standards and projects that
  informed the current baseline, including their status when reviewed.
- [Sealed invitation provider spike](spikes/SEALED_INVITATION_PROVIDER.md)
  explores first-contact delivery without an external messaging platform.
- [Sealed invitation provider protocol](spikes/SEALED_INVITATION_PROVIDER_PROTOCOL.md)
  develops the spike into roles, objects, lifecycles, abuse policies, and
  deployment profiles.
- [Architecture decision records](adr/) record the foundational decisions that
  other documents rely on.

## Decision labels

The documents use the following labels:

- **Decision**: the current design baseline. Changing it should update an ADR.
- **Proposed**: preferred direction, but not yet validated enough for an ADR.
- **Research**: deliberately unresolved.
- **Deferred**: potentially useful, but outside the first product slice.

## Current repository versus v2

The current Angular, NestJS, Socket.IO, JWT, and Redis application is the legacy
prototype. It is useful as product and UX history, but it is not the security
foundation for v2. In the current wire format, the message body and bearer token
are sent together, and the backend validates server-managed membership before
rebroadcasting the same message object. The v2 design instead requires clients
to own session keys and the infrastructure to handle opaque encrypted
envelopes.

Nothing in these documents should be read as retroactively describing the
legacy application as end-to-end encrypted.

## Current implementation

The final unchanged legacy baseline is preserved by the `legacy-v1` tag. Phase
1 has begun with `crates/session-protocol`, which currently implements only the
bounded, versioned, deterministic-CBOR opaque envelope defined by ADR 0005.
Invitation signing, HPKE, admission, MLS, persistence, and transport adapters
remain unimplemented and must not be inferred from that foundation.

## Reference standards and projects

- [RFC 9420: Messaging Layer Security](https://www.rfc-editor.org/rfc/rfc9420)
- [RFC 9750: MLS Architecture](https://www.rfc-editor.org/rfc/rfc9750)
- [RFC 9180: Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180)
- [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [W3C Decentralized Identifiers 1.0](https://www.w3.org/TR/did-core/)
- [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [Katzenpost specifications](https://katzenpost.network/docs/specs/)
- [Iroh documentation](https://docs.iroh.computer/)

References indicate relevant standards and prior art. They do not commit the
project to a particular library, credential format, DID method, network, or
service operator.
