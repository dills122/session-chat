# Iroh Fast adapter evidence

Status: Task 10 in progress; two-computer common-adapter harness ready for external runs

Date: 2026-09-05

## Claim boundary

The retained implementation is an online, connected FastV1 adapter. It carries
canonical opaque envelopes through the common `EnvelopeDelivery` deposit,
poll, and acknowledgement contract over one authenticated Iroh stream. Its
mailbox service is volatile and in-process. This evidence does not establish
offline delivery, durable service state, anonymity, lifecycle rotation,
reconnection, or production readiness.

## Implemented controls

- Independent random deposit, receive, and acknowledgement capabilities are
  scoped to one authenticated server endpoint, mailbox, operation, and expiry.
- The service retains domain-separated capability digests and a separate
  per-mailbox cursor key. Raw capabilities remain in right-specific client
  types that omit ordinary diagnostics and zeroize on drop.
- Version 1 canonical CBOR request and response frames reject malformed,
  trailing, noncanonical, wrong-version, wrong-operation, and oversized input.
- A 256 KiB link frame ceiling is exact for the adapter. Per-operation caller
  deadlines, application-frame network-byte budgets, and a single attempt are
  enforced without internal retry.
- Mailbox lifetime, live-mailbox count, logical envelope count, retained bytes,
  poll count and bytes, acknowledgement count, cursor size, and requests per
  connection are bounded.
- Exact canonical deposit retry returns the same delivery identifier. Reusing
  an envelope identifier with different bytes fails with an idempotency
  conflict. Exact acknowledgement retry succeeds without restoring content.
- The 40-byte opaque cursor contains a position authenticated by a
  mailbox-specific HMAC-SHA256 key and grants no receive right by itself.
- The FastV1 binder accepts only the adapter's exact limits and operations and
  records `InProcessAmbientNetwork` enforcement. No Private or offline property
  is inferred from the manifest.
- A stable FastV1 UI fixture describes direct-peer, relay, address-lookup, DNS,
  NAT, online-only, and non-anonymous behavior. It makes no offline claim.
- Public auto and relay-only endpoint modes expose only an address-free selected
  path class and open path-family booleans. Relay-only mode removes direct IP
  transports and fails if an open direct path or non-relay selected path is
  observed.
- The operator handoff is canonical version-two CBOR bounded to 256 bytes. It
  binds the requested `auto` or `relay-only` path policy, contains all three
  short-lived test capabilities, uses zeroizing buffers,
  publishes atomically without replacing an existing path, and rejects
  malformed, expired, excessive, trailing, noncanonical, and aliased
  special-file input. A joiner mode mismatch is rejected before public network
  work, and cleanup leaves a replacement pathname untouched.
- Both public roles render the complete stable FastV1 disclosure before endpoint
  creation. Tests that construct public N0 endpoints are ignored operator checks.

## FastV1 observer matrix

This matrix is conservative: an observer that participates during connection
setup remains listed even when Iroh later migrates application traffic to a
direct path.

| Observer | Direct selected | Relay selected | Excluded by the Session Chat boundary |
| --- | --- | --- | --- |
| Remote Fast peer/mailbox service | Authenticated endpoint ID, peer network address, timing, volume, mailbox capabilities presented to that service, and opaque envelope bytes | Authenticated endpoint ID, timing, volume, mailbox capabilities presented to that service, and opaque envelope bytes; discovery may still expose advertised or probed peer addresses even while a relay carries application traffic | MLS plaintext and group keys |
| N0 relay | Endpoint ID, client network address, online/control traffic, and any earlier relayed traffic with timing and volume | Both connection endpoints, their network addresses, timing, volume, and encrypted QUIC traffic | QUIC plaintext, mailbox capabilities, opaque-envelope framing, MLS plaintext, and group keys |
| N0 Pkarr publisher/resolver | Publisher or requester network address, endpoint-derived publication or lookup key, published route data, and timing | Same, including published relay route data | MLS plaintext, group keys, and mailbox capabilities |
| DNS resolver | N0/`iroh.link` lookup names, requester network address under the resolver's transport policy, and timing | Same | QUIC plaintext, MLS plaintext, group keys, and mailbox capabilities |
| NAT discovery service or local gateway port mapper | Public mapping, client network address, and timing; the gateway also sees the requested local mapping | Relay-only mode removes IP application transports; capture evidence must still determine whether the configured stack emitted discovery or mapping control traffic | Application plaintext, group keys, and mailbox capabilities |
| Local network or transit observer | Source/destination network addresses, timing, and volume of direct, relay, lookup, and DNS traffic visible at that position | Source/destination network addresses, timing, and volume of relay, lookup, and DNS traffic visible at that position | Encrypted application content, subject to endpoint compromise rather than passive observation |
| Out-of-band handoff service | Account/contact metadata, attachment timing and size, and any content its own encryption boundary exposes | Same | This channel is outside Iroh and outside the Session Chat transport claim |

The path snapshot proves only Iroh's address family and selected path at one
instant. It does not prove what every external observer retained, that an
earlier path was unused, anonymity, or non-collusion.

## Packet-capture reconciliation contract

Raw captures contain network identifiers and remain outside the repository.
For each external run, retain a redacted report with the exact revision,
platform, Iroh version, requested mode, initial and final path classes, capture
tool/version, interface category, start/end UTC, packet and byte totals grouped
by peer/relay/lookup/DNS role, and the SHA-256 digest of the restricted raw
capture. Never retain raw capabilities, plaintext, group keys, stable external
identity, or unrestricted local addresses in the report.

An auto/direct result must show encrypted peer-path traffic and may also show
relay, lookup, DNS, NAT-discovery, and port-mapping traffic. A relay-only result
must show relay/lookup/DNS traffic and no direct peer application path. Packet
payloads must not contain the seeded canonical envelope ciphertext bytes or any
test plaintext as a visible application record. A capture cannot establish
content security by visual inspection alone; the protocol and crypto tests
remain authoritative.

## Retained automated evidence

`transport-conformance::run_connected_delivery_conformance_v1` is one shared
case used by both `transport-memory` and `transport-iroh`. It covers:

1. first canonical deposit;
2. byte-identical retry with the same receipt;
3. same-ID/different-bytes conflict rejection;
4. poll with byte-identical canonical envelope output;
5. exact-set acknowledgement;
6. idempotent acknowledgement retry; and
7. final poll with no acknowledged content.

The direct-loopback Iroh case additionally checks authenticated endpoint setup
and clean bidirectional shutdown. Link unit and integration tests retain local
and remote frame-bound rejection, partial-I/O poisoning, reset rejection,
canonical endpoint parsing, authenticated-peer mismatch, and bounded timeouts.
Connected adverse-path cases retain queue saturation, authenticated cursor
pagination, unknown-mailbox and foreign-acknowledgement rejection, exact
remote-status mapping, local authority/lifetime/budget preflight, and semantic
link poisoning for malformed, truncated, trailing, and noncanonical requests
and responses. The production coverage gate records 93.61% line coverage for
`transport-iroh` and workspace totals of 92.72% lines, 88.00% regions, and
89.31% functions for this increment.

`sessionctl-fast-adapter` now composes that shared case as explicit host and
join commands suitable for two computers. The retained local test proves the
harness completes over a classified direct loopback path. External public N0
runs remain required before recording direct or relay two-computer evidence.

A historical operator-driven single-computer public N0 check on implementation
revision `79e6605566f709fd27053ffee4b52956c800e799` exercised the predecessor v1
handoff in both modes. The auto run connected initially through a relay and
migrated to a direct path; the relay-only run selected a relay at both
observations and reported no open direct path. Both retained byte identity and
completed cleanly. This result remains route-feasibility evidence only. It does
not validate the current path-bound v2 handoff or satisfy the two-computer, NAT,
or packet-capture evidence gates.

Deterministic loopback cases also retain a bounded peer-offline connection
failure and a service outage after request receipt. The latter maps to retryable
`Unavailable`, poisons the ordered adapter, and prevents reuse after ambiguous
partial work.

GitHub CI on predecessor implementation revision
`ba83404c27e485af38dbf7141dca8e7a2f93fcc9` passed the Rust and L2 evidence
jobs on Linux x64, macOS arm64, and Windows x64, along with production
coverage, dependency policy and review, repository policy, retained Node tools,
the project site, CodeQL, and the aggregate gate. Exact-revision CI for the v2
handoff and review fixes must be recorded after this increment is published.

Commands for this increment:

```sh
cargo clippy -p transport-conformance -p transport-iroh --all-targets --locked --offline -- -D warnings
cargo test -p transport-conformance --all-targets --locked --offline
cargo test -p transport-iroh --all-targets --locked --offline -- --test-threads=1
cargo test -p sessionctl --test fast_adapter_network --locked --offline
cargo test -p sessionctl --lib fast_adapter::tests --locked --offline
node scripts/check-rust-coverage.mjs
```

The Iroh tests require local loopback socket access. Public N0 endpoint
construction and reachability cases remain ignored unless an operator
explicitly runs them with network access.

## Open Task 10 evidence

- real two-computer direct and relay runs through the prepared common-adapter
  harness;
- a new public N0 operator run of the path-bound v2 handoff in both modes;
- real NAT evidence and two-computer repetition of the retained relay-only,
  route-change, peer-offline, and service-outage cases;
- packet captures reconciled with the Fast observer matrix;
- durable mailbox-service and client receive-state integration if offline
  delivery is later selected; and
- mailbox lifecycle issuance/rotation and reconnection composition.
