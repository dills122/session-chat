# Iroh Fast adapter evidence

Status: Task 10 in progress; connected direct-loopback slice retained

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
and responses. The production coverage gate records 93.96% line coverage for
`transport-iroh` and workspace totals of 92.79% lines, 88.01% regions, and
89.13% functions for this revision.

GitHub CI on implementation revision
`ba83404c27e485af38dbf7141dca8e7a2f93fcc9` passed the Rust and L2 evidence
jobs on Linux x64, macOS arm64, and Windows x64, along with production
coverage, dependency policy and review, repository policy, retained Node tools,
the project site, CodeQL, and the aggregate gate.

Commands for this increment:

```sh
cargo clippy -p transport-conformance -p transport-iroh --all-targets --locked --offline -- -D warnings
cargo test -p transport-conformance --all-targets --locked --offline
cargo test -p transport-iroh --all-targets --locked --offline -- --test-threads=1
node scripts/check-rust-coverage.mjs
```

The Iroh tests require local loopback socket access. The public N0 reachability
case remains ignored unless an operator explicitly runs it with network access.

## Open Task 10 evidence

- a real two-computer run through the common adapter contract;
- direct and relay path classification with byte-identical envelope evidence;
- NAT, forced relay-only, route-change, peer-offline, and service-outage cases;
- packet captures reconciled with the Fast observer matrix;
- durable mailbox-service and client receive-state integration if offline
  delivery is later selected; and
- mailbox lifecycle issuance/rotation and reconnection composition.
