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
described by bounded numeric aliases and sizes; a later runner will generate
their test-only bytes in memory.

The normalized runner, adapter factory seam, virtual control, alias normalizer,
memory integration, deliberately defective adapters, and double-replay evidence
remain the next increment. Passing this parser does not establish adapter
conformance, network privacy, durability, or production readiness.

## Verification

```sh
cargo test -p transport-conformance --all-features --locked --offline
cargo clippy -p transport-conformance --all-targets --all-features --locked --offline -- -D warnings
```
