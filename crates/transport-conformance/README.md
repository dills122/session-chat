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
Exhaustive common-case coverage and profile-specific evidence remain open.
Passing the parser or this first memory trace does not establish complete
adapter conformance, network privacy, durability, or production readiness.

## Verification

```sh
cargo test -p transport-conformance --all-features --locked --offline
cargo clippy -p transport-conformance --all-targets --all-features --locked --offline -- -D warnings
```
