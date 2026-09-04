# ADR 0024: Use Iroh for the Fast online link

Status: accepted; implementation pending

Date: 2026-09-04

## Context

The retained two-terminal proof now establishes the complete Phase 1 flow over
bounded local filesystem IPC. The next increment needs to carry those same
canonical public wire objects between computers without redefining admission,
MLS membership, or durable owner state. The accepted Fast profile permits a
direct or relay path and explicitly makes no anonymity claim.

Iroh 1.1.0 provides authenticated peer-to-peer QUIC connections addressed by
an endpoint public key. Its documented connection setup can use direct socket
addresses, a relay, or both. The default N0 preset also uses address lookup and
relay services, which add observers that must be disclosed. Iroh relays are
connectivity infrastructure, not offline mailboxes.

Sources:

- <https://docs.rs/iroh/1.1.0/iroh/#connection-establishment>
- <https://docs.rs/iroh/1.1.0/iroh/#encryption>
- <https://docs.rs/iroh/1.1.0/iroh/#relay-servers>
- <https://docs.rs/iroh/1.1.0/iroh/endpoint/struct.RecvStream.html#method.read_to_end>
- <https://docs.rs/iroh/1.1.0/iroh/endpoint/struct.Builder.html#method.alpns>

## Decision

Use pinned `iroh` 1.1.0 for the first FastV1 online link. Pin the Tokio runtime
used by the headless proof separately. Disable Iroh default features and enable
only the AWS-LC TLS provider plus port mapping for this public Fast experiment.

The first increment is a bounded, ordered online link for the existing
versioned Session Chat IPC frames:

- use one Session Chat-specific ALPN;
- authenticate the expected remote Iroh endpoint ID before accepting protocol
  data;
- prefix every frame with a fixed-width length and reject zero or oversized
  frames before allocation;
- bound connection establishment, frame reads, and frame writes with caller
  deadlines;
- retain the existing canonical protocol decoders after network receipt;
- keep the endpoint key ephemeral for the headless proof; and
- expose the N0 preset only through an explicit Fast network command.

This online link does not implement offline mailbox storage, cursor
persistence, mailbox rotation, or durable delivery acknowledgement. It must not
be registered as satisfying the complete reusable `EnvelopeDelivery` mailbox
contract until those operations and their right-specific authority schemas are
implemented and pass the shared conformance suite.

The local direct-only test configuration disables relays and address lookup.
The cross-computer command uses Iroh's N0 preset and clearly reports the
Fast-profile metadata caveat. It never serves a Private profile and has no
automatic profile fallback.

## Security and privacy consequences

- Direct peers can learn each other's network addresses.
- Iroh relays can observe endpoint IDs, network addresses, timing, and volume,
  but not the QUIC plaintext.
- Address-lookup and DNS infrastructure can observe endpoint publication and
  lookup metadata.
- Session Chat wire objects remain protected by their existing HPKE, MLS, and
  signature boundaries; Iroh endpoint authentication does not authorize
  admission or MLS membership.
- A malicious peer, relay, or network can still drop, delay, duplicate, replay,
  reorder across reconnections, or refuse traffic. Existing protocol checks
  remain authoritative.
- Ephemeral endpoint keys make this a demonstration path, not durable peer
  identity, recovery, or rollback-resistant endpoint state.

## Alternatives considered

### Ad hoc TCP framing

Rejected. It would require a new authenticated transport construction and NAT
strategy before delivering useful cross-computer evidence.

### Treat the Iroh relay as an offline mailbox

Rejected. The documented relay forwards encrypted connectivity traffic and
does not provide Session Chat's durable deposit, poll, acknowledgement, cursor,
or rotation semantics.

### Put Iroh endpoint identity into MLS credentials

Rejected. Network routing and session membership remain independent. Endpoint
authentication cannot replace admission or MLS authorization.

## Follow-up gates

- The bounded link and same-host direct-only integration test pass on Linux,
  macOS, and Windows.
- A two-computer Fast proof carries the exact protected join, Welcome, message,
  update, removal, and post-removal frames.
- Observer evidence and packet captures are retained before making a stronger
  Fast transport claim.
- A later mailbox adapter defines right-specific network authority and passes
  the complete `EnvelopeDelivery` conformance suite before claiming offline
  delivery.
