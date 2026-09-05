# ADR 0025: Close Phase 1 recovery and conformance evidence

Status: accepted; implementation and exact-revision completion gate in progress

Date: 2026-09-05

## Context

The Phase 1 closeout requires independent-process Welcome recovery and a
reviewed evidence matrix. Review of the existing deterministic lifecycle model
also found that checkpoint provenance, acknowledgement authority, and cumulative
receive retention were weaker than the accepted ADR 0015 contract.

## Decision

Keep this increment inside the protocol laboratory. Observe the real SQLCipher
Welcome owner at housekeeping, selection, lease update, commit, accepted-result,
and failed-result boundaries using checked-build, secret-free barriers. Kill a
supervised child while it is blocked at each clean-baseline checkpoint. Separately
derive the SQLite commit-window pause ordinals from a clean named-VFS trace and
kill a direct child at every supported journal write/sync/delete and main-file
write/sync ordinal for each Welcome workload.

A fresh process must open the production store and compare every immutable
membership, reservation, approval, identity, MLS, and delivery-material field
against the closed encrypted baseline. Only the five lease/result fields may
change, and only by the complete transition allowed at that checkpoint. The
coordinator uses a deterministic acceptance/failure adapter that compares the
actual envelope and endpoint byte-for-byte; acceptance does not prove recipient
receipt or processing. Lost acceptance is retried only after the owner lease
expires. Attempts, generation, terminal state, foreign/open-scope authority,
and unchanged membership remain part of the oracle.

Use the existing L2 provenance/redaction promotion gate. Raw fixtures and case
observations remain non-public; only complete sealed sweeps may produce bounded
`l2-evidence-v1` records bound to the compiler, Git revision, runner, GitHub run,
test executable, and encrypted artifacts. Application control uses the closed
24-byte `WLK1` fixture. The ordinary binary has no activation path.

Correct the deterministic lifecycle reference implementation to meet ADR 0015:

- Expose read-only request checkpoint binding so an external provider can compare
  it with authenticated receive authority before constructing a batch.
- Use model cursor schema 2: exactly 40 bytes consisting of continuity ID (16),
  generation (8), provider-state epoch (8), and delivery sequence (8), with
  integers in big-endian order. Reject legacy eight-byte cursor values and
  foreign generation scope. Cursor bytes contain no receive capability.
- Bind immediate commit evidence to its owner instance and each acknowledgement
  lease to a distinct opaque live identity. Restart invalidates live handles;
  recovery and terminal acceptance invalidate immediate commit authority.
- Reject foreign/unknown IDs and mixed acknowledgement sets in the reusable
  deterministic provider before mutation; retain exact repeated acknowledgements.
  The existing LocalV1 memory profile retains its documented unknown-ID no-op.
- Bound the receive owner to 64 retained unique deliveries and 4 MiB of canonical
  bytes. Capacity rejection changes neither checkpoint nor acknowledgement
  intent, and never evicts live deduplication history. Exact duplicates may still
  pass at capacity.

The new cursor encoding belongs only to the publish-disabled model. It selects
no network adapter and migrates no product state. Existing laboratory cursor
schema 1 is rejected rather than silently reinterpreted.

## Consequences and limits

The [Phase 1 evidence matrix](../evidence/phase1-closeout.md) is the claim index.
Phase 1 remains in progress until a merged immutable revision passes the full
three-platform non-PR gate and a later metadata-only checkpoint cites it.

This evidence is application-kill and SQLite-visible laboratory evidence. It
proves neither physical power-loss safety, stale-snapshot rollback resistance,
secure deletion, platform key custody, a production receive owner, nor a network
profile. Iroh feasibility remains separate from the reusable Fast adapter.
