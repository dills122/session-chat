# ADR 0031: Separate transient and durable MLS Add results

Status: accepted

Date: 2026-09-08

## Context

The MLS adapter returned the same client, group, and applied-Add types for
process-local tests and durable compositions. After a durable Add advanced the
group, callers could invoke the ordinary provider write without the exact
`CommittedAdditionStorageBinding`. The applied result also exposed Welcome and
Commit bytes before the atomic invitation, replay, approval, MLS, and outbox
transaction succeeded. Current product compositions used the bound path, but
the safe public API permitted an incorrect durable integration.

## Decision

Carry a sealed `TransientStorage` or `DurableStorage` marker through MLS clients,
groups, and prepared Adds.

- Process-local provider tests use the explicitly named
  `create_transient_client_with_storage` and
  `write_transient_state_to_storage` APIs.
- Applying an Add to a durable group records an exact state-revision persistence
  obligation. Ordinary durable writes reject while that obligation exists.
- Raw provider writes remain private to the MLS adapter.
- A durable `CommittedAddition` exposes no Welcome or Commit transport output.
  Its one-shot bound stage-and-write operation is the only path that can clear
  the obligation.
- Successful bound persistence returns `PersistedAddition`, which then exposes
  the exact Welcome and Commit. Failure returns no transport-capable result and
  leaves the durable group blocked until authoritative reload or recovery.
- Capability-admission durability-pending values expose only binding metadata
  and the deposit endpoint. Durable storage construction of the exact Welcome
  outbox record occurs only after the exact provider storage write is active;
  the earlier staging callback carries envelope metadata but cannot read the
  Welcome ciphertext.

No wire format or SQL schema changes.

## Consequences and limits

Compile-time mode separation prevents a durable group from calling transient
write or output APIs. Runtime state-revision checks still reject stale or
intervening group transitions. The configured durable storage provider remains
trusted same-process code; it can obtain the encrypted Welcome only inside the
originating, digest-matched provider write. Application staging callbacks
cannot inspect it. This closes the accidental public bypass; it does not
provide rollback resistance, secure deletion, platform key custody, or
production readiness.

Retained tests cover direct durable-write rejection, staging failure, exact
binding, post-persistence output release, explicit transient storage, durable
authorization recovery, SQLCipher migration evidence, and fault-enabled L2
compilation.
