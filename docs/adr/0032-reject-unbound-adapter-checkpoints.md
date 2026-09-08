# ADR 0032: Reject checkpoint-bound polls on adapters without lifecycle binding

- Status: Accepted
- Date: 2026-09-07

## Context

`ReceiveCheckpointV1::poll_request` carries a complete non-authorizing
`ReceivePollBindingV1`. `ReceiveBatch::new` preserves that value so the durable
owner can prove that a returned page belongs to its exact checkpoint.

The current `transport-memory` and `transport-iroh` receive capabilities do not
bind a `CursorBindingV1`. Accepting a checkpoint-bound request would therefore
let valid mailbox-A authority return mailbox-A ciphertext in a batch labeled
with checkpoint B. Owner validation would prove only that the batch copied the
request, not that the provider matched the source mailbox.

## Decision

- Memory and Iroh reject every poll whose request contains a receive-checkpoint
  binding with `AuthorityScopeMismatch` before reading mailbox data or sending
  an Iroh request.
- Existing explicitly unbound experimental polling remains supported.
- These adapters must not claim durable reusable-mailbox lifecycle support.
- Future bound polling requires provider-issued receive authority tied to the
  complete `CursorBindingV1` or a domain-separated fingerprint of its canonical
  representation. Iroh must authenticate that binding in its wire request and
  validate it server-side.

## Consequences

Checkpoint-derived polling now fails closed on both experimental adapters.
This prevents foreign-checkpoint relabeling without introducing a partial
client-only binding check. Adding bound Iroh polling later is a versioned wire
and handoff-contract change requiring compatibility fixtures and negative tests.
