# Welcome delivery coordinator research

Status: implementation map; spec corrections required before coordinator code

Date: 2026-08-25

## Recommendation

Implement a future LocalV1 deposit-only `WelcomeDeliveryCoordinator` in
`session-transport`. It must not poll, acknowledge, own persistence, or create a
second retry/lease ledger.

Two seams are sufficient:

- `WelcomeOutboxStore` leases the next exact eligible owner job and exclusively
  owns attempts, lease expiry, retry eligibility, terminal state, envelope, and
  encoded destination.
- `DepositEndpointResolver<D>` validates stored profile/adapter/mailbox/
  operation/expiry scope and returns only a typed deposit right. It owns no
  durable state and cannot mint receive or acknowledgement authority.

The coordinator makes one adapter call per owner lease with adapter attempts
set to one. A retry receives a fresh owner lease and operation budget but uses
byte-identical canonical envelope and destination identity. `Delivered` means
only that the adapter accepted deposit, never recipient receipt or application
processing.

## Required corrections first

1. The inviter model currently accepts caller-selected lease IDs and can reuse
   an expired ID, allowing a stale lease-token ABA. The store must issue unique
   tokens or durably reject reuse.
2. Attempt-exhausted jobs remain in pending enumeration and could be hot-looped.
   Eligibility must exclude or explicitly terminalize them.
3. Committed Welcome and endpoint bytes are only length-checked. Commit must
   validate canonical envelope and endpoint/profile scope plus
   `outbox_expiry <= envelope_expiry <= endpoint_expiry`.
4. The generalized memory deposit material cannot be reconstructed from stored
   bytes. LocalV1 should reuse the existing canonical transferable Welcome
   endpoint schema rather than inventing a second format.
5. `DispatchControl` observes clocks/cancellation but does not supply wakeups.
   The composition root must explicitly supervise deadline/cancellation and
   drop the returned future; no active-preemption claim is allowed.
6. The plan must reference governing ADR 0008 and the actual SQLCipher inviter
   schema rather than nonexistent transaction files or a duplicate ADR.

## Owner transitions

- Atomic membership commit creates one pending outbox item.
- Leasing increments the owner attempt exactly once and issues a unique token.
- Known pre-provider cancellation releases the exact lease to pending.
- Ambiguous post-provider failure releases it or lets the lease expire; exact
  identity is retried without repeating MLS.
- Adapter acceptance completes only the exact live lease.
- A crash after remote acceptance leaves the lease to expire and exact retry
  reconciles idempotently.
- Expired or exhausted work remains retained terminal state and is never leased.
- Stale, foreign, reused, or expired lease results cannot mutate current work.

No new ADR is required if this preserves ADRs 0008 and 0015. A new decision is
required only for coordinator persistence, dynamic adapters, a second endpoint
schema, or non-Local authenticated profile selection. SQLCipher integration and
durable restart claims remain later work.
