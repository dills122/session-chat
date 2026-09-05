# ADR 0024: Use Iroh for the Fast online link

Status: accepted; bounded link, headless composition, and first connected
delivery-adapter slice implemented; Task 10 external-network evidence open

Date: 2026-09-04

Last reviewed: 2026-09-05

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
- <https://docs.rs/iroh/1.1.0/iroh/endpoint/struct.RecvStream.html#method.read_exact>
- <https://docs.rs/iroh/1.1.0/iroh/endpoint/struct.Builder.html#method.alpns>

## Decision

Use pinned `iroh` 1.1.0 for the first FastV1 online link. Pin the Tokio runtime
used by the headless proof separately. Disable Iroh default features and enable
only the AWS-LC TLS provider plus port mapping for this public Fast experiment.

The first increment is a bounded, ordered online link for the existing
versioned Session Chat IPC frames:

- use one Session Chat-specific ALPN;
- authenticate the expected host endpoint ID on connect; the accepting side
  obtains the authenticated remote endpoint ID but still relies on the normal
  Session Chat admission proof before membership;
- accept only the lowercase hexadecimal endpoint-ID text emitted by the host;
- prefix every frame with a fixed-width length and reject zero or oversized
  frames before allocation, with a crate-wide 256 KiB maximum caller bound and
  fallible allocation inside that ceiling;
- reject zero or greater-than-five-minute operation bounds, derive one checked
  absolute deadline per operation, and share it across connection setup, frame
  reads/writes, and graceful shutdown;
- report graceful shutdown only after the peer acknowledges all outbound bytes
  and cleanly finishes its inbound stream; peer reset and connection failure
  are not receipts;
- poison the ordered link after any failed, timed-out, or cancelled frame
  operation, so a partial prefix or payload cannot desynchronize later reuse;
- retain the existing canonical protocol decoders after network receipt;
- create the durable bearer invitation before accepting a peer, require the
  operator to transfer it over a separate authenticated confidential channel,
  and begin the Iroh stream with the HPKE-protected join request rather than
  sending the invitation to the first connector;
- allow a separately bounded five-minute operator handoff before the host's
  initial protected-join wait expires, and accept only bounded regular
  invitation files rather than blocking-capable special filesystem objects;
- keep the endpoint key ephemeral for the headless proof; and
- expose the N0 preset only through an explicit Fast network command.

The first Task 10 increment registers a connected `EnvelopeDelivery` adapter on
top of this link. It implements deposit, poll, and acknowledgement with
separate operation capabilities, versioned canonical CBOR frames, a volatile
bounded service, and a mailbox-scoped authenticated cursor. Its manifest binds
only to FastV1 and records ambient network egress, declared background work,
in-process execution, coordinator-owned retry, and exact envelope, batch,
count, and cursor limits. The shared connected-delivery case runs against both
the memory adapter and the direct-loopback Iroh adapter.

This connected adapter does not implement offline mailbox storage, durable
cursor or acknowledgement persistence, mailbox lifecycle rotation,
reconnection, or service-loss recovery. Those omissions remain explicit even
though the online operation schemas now satisfy the first common-contract
slice.

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
- An unauthorised first connector can deny service to this one-connection
  experiment, but it cannot retrieve the bearer invitation from the host or
  construct a valid protected join without independently obtaining that file.
- Deadlines, peer mismatch, noncanonical endpoint text, oversized remote frame
  declarations, and reset-before-receipt fail closed with payload-free errors.
- Ephemeral endpoint keys make this a demonstration path, not durable peer
  identity, recovery, or rollback-resistant endpoint state.

## Dependency-policy review

The pinned Iroh graph is checked only for the three supported application CI
targets: x86_64 Linux GNU, Apple Silicon macOS, and x86_64 Windows MSVC. This
excludes WebAssembly-only dependencies from the retained local-app claim rather
than granting their licenses repository-wide.

Four exact transitive crates require narrow license exceptions in `deny.toml`:
`attohttpc 0.30.1` under MPL-2.0, `foldhash 0.2.0` under Zlib, `spez 0.1.2`
under BSD-2-Clause, and `webpki-roots 1.0.9` under CDLA-Permissive-2.0. The
exceptions are version-specific and do not authorize those licenses for
unrelated dependencies. The MPL dependency is
consumed unmodified, while the CDLA dependencies contain the public root data
used by the TLS graph; this review is a repository policy decision, not legal
advice.

At Task 10 start on 2026-09-05, the pinned dependency graph and all four exact
license exceptions were re-reviewed and remained unchanged.

`paste 1.0.15` is reported by RUSTSEC-2024-0436 as unmaintained and has no safe
upgrade. It remains a transitive macro dependency of Iroh's Linux network
watcher, not cryptographic or protocol authority. The repository retains one
named advisory exception owned by `@dills122`. The Task 10 review extended no
scope: the exception remains limited to this exact transitive crate and must be
removed or reviewed again by 2026-12-04.

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
- The connected adapter's right-specific authority and shared direct-loopback
  delivery case remain green on Linux, macOS, and Windows before Task 10
  advances.
- A durable mailbox service and lifecycle composition require their own
  retained conformance evidence before any offline-delivery claim.
- Remove or explicitly re-review the `paste 1.0.15` advisory exception by
  2026-12-04 and re-review all Iroh-specific license exceptions whenever the
  pinned graph changes.
