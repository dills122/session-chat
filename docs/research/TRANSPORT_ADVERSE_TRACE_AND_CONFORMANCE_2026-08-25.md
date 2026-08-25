# Transport adverse trace and conformance research

Status: accepted implementation input; trace parser and memory fault controls
implemented, normalized runner and reusable suite still open

Date: 2026-08-25

## Decision

Own deterministic adverse traces, virtual controls, normalization, and reusable
adapter tests in the publish-disabled `transport-conformance` crate. Keep
provider-specific fault state in `transport-memory`. Do not add test controls to
the production `session-transport` contract.

The retained v1 format is strict LF-delimited lowercase ASCII with the header:

```text
session-chat.transport.adverse-trace/v1
```

It is capped at 64 KiB, 512 bytes per line, 256 steps, 64 aliases per kind, and
eight checkpoint directives per operation. It has closed record, action,
control, failure, retry, and expected-event tokens. Numeric aliases stand in for
mailboxes, envelopes, deliveries, and cursors. Envelope fixtures contain only a
logical-ID alias, content variant, ciphertext length, and relative expiry; no
fixture bytes enter the trace.

The parser rejects unknown versions/records, CRLF and other noncanonical forms,
numeric overflow or nonminimal numbers, duplicate and forward-referenced
aliases, noncontiguous steps, oversized fixtures, and excessive work before
retention. Its errors expose only a category and optional line number.

## Required action vocabulary

- open a bounded mailbox;
- arm deliver, drop, hold, or duplicate deposit behavior;
- release held work or inject an exact stale replay;
- arm one corrupt poll;
- set persistent availability;
- lose one acknowledgement result before or after commit;
- advance virtual monotonic and wall clocks; and
- perform bounded deposit, poll, and exact-set acknowledgement with a scripted
  checkpoint sequence and explicit drive mode.

Queue saturation is induced through ordinary bounded operations. It is not a
state-forging action. Positive cursor issuance, mailbox rotation, restart,
concurrency, profile-specific route churn, packet capture, and stochastic
schedules remain outside v1.

## Determinism and cancellation

Each future runner must start with a fresh adapter and one fresh local
`Instant`, reconstruct only checked relative offsets, map randomized provider
values to local aliases, consume every one-shot fault exactly once, and reject
non-quiescent completion. A golden trace must run twice against fresh adapters
and emit byte-identical normalized event output.

Rust futures are inert until polled, and a future that returns `Pending` must
arrange a wake rather than relying on a tight loop. `Instant` is monotonic but
opaque and unsuitable for persistence. Dropping an owned future stops its local
progress but cannot roll back detached or remote work. These constraints follow
the official [`Future`](https://doc.rust-lang.org/1.97.1/std/future/trait.Future.html),
[`Instant`](https://doc.rust-lang.org/1.97.1/std/time/struct.Instant.html), and
[Rust async cancellation guidance](https://rust-lang.github.io/async-book/part-guide/more-async-await.html#cancellation).

## Redaction boundary

Trace input/output, errors, snapshots, and assertion summaries may contain only
schema/profile enums, numeric aliases, bounded counts and sizes, relative time,
and normalized outcomes. They never contain plaintext, ciphertext, canonical
envelope bytes, raw identifiers, routes, addresses, capabilities, provider
errors, admission evidence, or stable identities.

The memory provider's stale-replay control accepts test-supplied opaque bytes
only after their domain-separated digest matches an existing logical delivery.
The separate replay queue is bounded and counted but never restores
acknowledged provider state. Before/after-commit acknowledgement loss remains
distinguishable only through the secret-free conformance snapshot.

## Remaining implementation

1. Expose a generic adapter factory and adverse-control seam to the harness.
2. Add a virtual `DispatchControl`, counting waker, and explicit drop driver.
3. Generate test-only envelope/cursor bytes from aliases in memory.
4. Normalize randomized receipts and batches back to aliases.
5. Run every golden trace twice and require quiescence and identical output.
6. Add deliberately defective idempotency, redaction, and deadline/drop
   adapters to prove the suite detects violations.

The implemented parser and provider controls are evidence inputs, not yet a
conformance verdict for any adapter.
