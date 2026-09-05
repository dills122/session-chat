# Session Chat transport conformance

`transport-conformance` is a publish-disabled, offline test-support crate for
the provider-neutral transport contract. It is not linked into a client or
network service and grants no transport authority.

The first retained increment defines a strict canonical adverse-trace v1
format. The parser accepts only LF-delimited lowercase ASCII with closed record
and action tokens, numeric aliases instead of provider identifiers, relative
time, bounded fixture sizes, scripted checkpoints, and normalized expected
events. It rejects unknown versions and records, noncanonical encodings,
duplicate or forward-referenced aliases, oversized files and lines, more than
256 steps, and more than eight checkpoints per operation. Parser errors expose
only a category and line number and never echo the rejected input.

The trace never stores plaintext, ciphertext, canonical envelope bytes, raw
mailbox/delivery/envelope/cursor identifiers, routes, capabilities, provider
errors, admission data, or stable identities. Envelope and cursor fixtures are
described by bounded numeric aliases and sizes. The runner generates their
test-only bytes in memory and compares received canonical bytes exactly before
normalizing randomized provider values back to aliases.

The first runner increment adds a provider-specific bridge that retains all
rights behind mailbox aliases, checked virtual clocks, a bounded waitable-waker
driver, canonical normalized reports, end-state quiescence, and two fresh
memory-adapter replays. Its runner test suite covers hold/release, deposit, poll,
acknowledgement, cancellation, deadline, wall-clock failure, exact-retry receipt
identity, mailbox/envelope-bound poll normalization, exact canonical bytes, and
adapter-reported leftover-work rejection. The driver allows a wake
to arrive for up to one second after a pending poll, including before a
`poll-once-drop` future is dropped; a non-waking future fails closed. Exact retry
delays use bounded `after-ns:<nanoseconds>` tokens so every valid transport
duration remains distinguishable. This first runner accepts only `LocalV1`; it
cannot mint evidence for an unbound Fast or Private profile.

The composed LocalV1 verdict fixture additionally covers duplicate delivery,
stale replay, one-shot corruption, before/after-commit acknowledgement loss,
outage recovery, invalid cursors, and expiry. Deliberately defective bridges
prove detection of changed exact-retry receipts, cross-mailbox receive batches,
ignored deadline checkpoints, leaked drop work, and seeded provider failures.
One bounded queue-saturation fixture fills the memory profile's eight-envelope
mailbox, normalizes the rejected ninth envelope as `queue-full`, drains and
acknowledges the accepted set, replays identically on two fresh adapters, and
rejects a deliberately over-accepting bridge. A separate retained trace holds
delivery across multiple bounded virtual-clock advances, proves it remains
invisible before release, and completes without wall-clock sleeps. The
exhaustive authority/resource matrix, remaining lifecycle cases, and
profile-specific evidence remain open.
Passing the parser or this first memory trace does not establish complete
adapter conformance, network privacy, durability, or production readiness.

The crate also contains a deterministic FastV1 provider for contract testing.
It issues four distinct opaque rights for a fresh generation, performs
compare-and-swap routine or compromise rotation, reproduces an exact rotation
retry, and rejects foreign rights, competing stale predecessors, and declaration
substitution. Through the shared dispatch boundary it performs bounded canonical
deposit, cursor-bearing poll, exact acknowledgement, cursor rejection, and
idempotency-conflict handling. Its predictable authority bytes and lack of
network I/O make it conformance support only, never a selectable product adapter.

Its companion in-memory receive-state owner atomically retains exact canonical
pages, cursor progress, duplicate outcomes, and acknowledgement intent. Restart
tests recover cursor and acknowledgement work, preserve ambiguous release,
terminalize acceptance, persist cursorless successors and explicit
resynchronization, and reject stale checkpoints, foreign bindings, and expired
operations. This is a bounded conformance model, not durable product storage.
The LocalV1 resource matrix also proves that a delivery ID presented under a
different mailbox's valid acknowledgement right is an identifier-free no-op:
it cannot consume the original mailbox's retained delivery, which remains
available to its own right.
The closed evidence matrix maps all required lifecycle cases to the retained
provider, owner, common-contract, or compile-fail test that exercises them.

## Verification

```sh
cargo test -p transport-conformance --all-features --locked --offline
cargo clippy -p transport-conformance --all-targets --all-features --locked --offline -- -D warnings
```
