# Transport adverse trace and conformance research

Status: accepted implementation input; trace parser, memory fault controls, and
first normalized double-replay memory runner implemented; reusable suite open

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

## Retained runner increment

The first runner slice now exposes a versioned adapter bridge that keeps rights
behind numeric mailbox aliases. The provider-neutral harness owns checked
fixture generation, virtual checkpoint observations, bounded wake-aware future
driving, exact canonical-byte normalization, expected-event comparison,
canonical report bytes, two fresh-adapter replays, and a secret-free final
adapter-reported quiescence check. The runner accepts only LocalV1 until a
reviewed profile binder exists. One retained memory trace covers hold/release
through exact-set acknowledgement, while focused traces cover cancellation,
deadline, wall-clock failure, unbound-profile rejection, and non-quiescent
rejection. The factory contract requires independent instances; the type system
cannot prove absence of shared provider state.

Exact retries must reuse the same alias, mailbox, envelope, and raw provider
receipt; a raw receipt cannot be introduced under another alias. Poll
normalization binds that receipt to its deposited mailbox and exact deposited
envelope instead of independently matching global alias maps. `poll-once-drop`
accepts only the terminal `future-dropped` expectation. The driver waits at
most one second for a wake after a pending poll, so legal delayed wakes are not
mistaken for missing wake registration while non-waking work remains bounded.
An adapter-bridge test proves that delayed-wake drop cleanup releases active
work before final quiescence. Retry-delay normalization uses exact bounded
nanoseconds rather than truncating valid fractional seconds.

The composed LocalV1 verdict fixture covers duplicate delivery, stale replay,
one-shot corrupt polling, before/after-commit acknowledgement loss, persistent
outage recovery, invalid cursors, and expiry. Paired conforming/defective bridge
tests prove detection of changed retry receipts, cross-mailbox poll results,
ignored deadline checkpoints, and active work retained after future drop. A
seeded provider context remains structurally unable to cross the closed bridge
error and snapshot types into runner diagnostics.

## Remaining implementation

1. Complete arbitrary-delay, queue-saturation, and exhaustive
   authority/resource-bound verdict coverage.
2. Add profile-specific verdict suites only after their reviewed binding
   contracts exist.

The implemented parser and provider controls are evidence inputs, not yet a
conformance verdict for any adapter.
