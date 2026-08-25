# ADR 0015: Bind transport adapters to versioned profiles

Status: accepted; local baseline mapped, generalized implementation in progress

Date: 2026-08-20

## Context

ADR 0001 separates opaque delivery from session security and admission. ADR
0010 separates deposit, receive, acknowledgement, and rotation authority. The
existing illustrative `EnvelopeTransport` and concrete local one-Welcome
adapter are sufficient to show those boundaries, but they do not yet say who
owns generalized retries, how adapter capabilities are evaluated, how profile
downgrade is prevented, or how direct, onion, mixnet, asynchronous queue, and
disruption-tolerant transports fit one contract.

Current research identifies credible but non-equivalent candidates including
Iroh, Tor/Arti, SimpleX SMP, Katzenpost, Nym, Veilid, and Reticulum. Treating
their adapter names as privacy modes would couple product claims to local
implementations. Allowing adapters to select fallbacks would also let a private
session expose peer or relationship metadata when its intended network fails.

## Decision

Define a stable, versioned envelope-delivery contract in `session-transport`.
The protocol core sees canonical bounded envelope bytes and right-specific
mailbox capabilities only.

Separate these concepts:

- `TransportProfileId` names a reviewed semantic and egress contract;
- `AdapterId` names a local implementation;
- the owner-local transaction store remains the authoritative owner of durable
  outbox records, idempotency keys, leases, and commit recovery;
- the delivery coordinator executes leased work and owns adapter-independent
  expiry checks, deduplication, polling, acknowledgement scheduling, and total
  retry policy through that store's transition contract;
- a profile binder validates and records the adapter/configuration selected for
  one locally authorized profile before I/O; and
- an adapter performs bounded delivery operations using only the network and
  mailbox authority explicitly supplied to it.

The portable delivery baseline is unordered and duplicate-capable. The
coordinator makes bounded attempts while work remains eligible, but loss,
omission, arbitrary delay, expiry, and unavailability mean there is no eventual
delivery guarantee. Protocol state machines must remain correct under that
baseline even when an adapter provides stronger behavior.

Adapters cannot select or negotiate a different profile. There is no generic
fallback list. A multipath or composite strategy is permitted only as a
separately named, versioned profile whose paths all satisfy the profile contract
and whose correlation and failure behavior are tested.

Production adapters must receive network access through either a
profile-scoped network broker or a separately isolated process/OS egress
boundary. Adapter capability declarations are not proof of privacy; private
profiles require packet-capture and egress-denial evidence.

The detailed proposed contract is
[`docs/specs/TRANSPORT_ABSTRACTION_V1.md`](../specs/TRANSPORT_ABSTRACTION_V1.md).

## Alternatives considered

### One trait implemented directly by every network library

Rejected. It leaves retry, fallback, error, cursor, and background-network
behavior adapter-specific and gives the protocol core no stable place to enforce
budgets or profile policy.

### Use adapter names as transport profiles

Rejected. An implementation name does not define a deployment, observer model,
operator set, egress policy, or product guarantee. Multiple adapters may satisfy
one profile, and one adapter may support multiple configurations with different
exposure.

### Capability flags and runtime permission enums

Rejected for mailbox authority under ADR 0010. Deposit, receive,
acknowledgement, and rotation remain distinct types. Adapter manifests may
declare supported operations, but they do not replace authority-bearing values.

### Automatic ordered fallback

Rejected. It violates ADR 0003 and can reveal metadata precisely when a private
network is disrupted. Explicit user-approved profile change remains a separate
security decision.

### Expose path and mailbox subtraits to the protocol core

Rejected. Some candidates combine routing and queues while others require a
separate store-and-forward service. The adapter may compose internal path and
mailbox pieces, but the core needs one envelope-delivery contract.

## Consequences

- The existing local one-Welcome adapter is retained as evidence; a generalized
  memory adapter and conformance harness precede production adapters.
- The coordinator becomes security-sensitive code, but it must not create a
  second durable outbox ledger beside the owner-local transaction store.
- Profile policy is explicit, versioned, testable, and independent of vendor
  or protocol names.
- Private-mode enforcement requires network/process isolation in addition to
  Rust types.
- Adapter errors and observations use a stable redacted schema.
- Stronger adapter ordering or delivery guarantees remain optimizations and
  cannot become hidden core dependencies.
- Adding a candidate transport requires a manifest, threat-model mapping,
  conformance evidence, packet-capture expectations where applicable, and a
  profile decision; implementing a trait alone is insufficient.

## Adoption gate

The accepted decision permits incremental internal generalization of the
existing local-only `session-transport` API. The retained additive increments
now include bounded profile, adapter, canonical-envelope, operation, cursor,
poll, deposit-request, acknowledgement-batch, and identifier-minimal receipt
values beside the local API. Version 1 fixes hard ceilings of 256 cursor bytes,
64 envelopes and 4 MiB of canonical bytes per poll, 60 seconds of requested
poll wait, and 64 delivery identifiers per acknowledgement operation. A deposit
request also rejects canonical bytes larger than its total operation byte
budget before dispatch.

These values do not publish a complete multi-adapter request dispatcher,
receive-batch contract, generalized capability representation, or mailbox
lifecycle interface. Capability representation and dispatch must be proven
against the local adapter before that interface is stabilized. Network adapters
remain gated on the memory control path and conformance harness.

The owner-local transaction store remains authoritative for Welcome-outbox
truth and leases. Acknowledgement issuance stays provider-specific while its
right remains statically distinct. Initial profile IDs use the closed reserved
version 1 set; authenticated wire negotiation requires a later protocol schema.
Network-broker and process-isolation choices remain deferred until a network
adapter spike can produce direct evidence.

## Sources reviewed

- [Retained technology landscape](../research/TRANSPORT_SECURITY_LANDSCAPE_2026-08-20.md)
- [RFC 9458: Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458)
- [Tor onion-service overview](https://community.torproject.org/onion-services/overview/)
- [SimpleX Messaging Protocol](https://github.com/simplex-chat/simplexmq/blob/stable/protocol/simplex-messaging.md)
- [Katzenpost specifications](https://katzenpost.network/docs/specs/)
- [Nym network overview](https://nym.com/network)
