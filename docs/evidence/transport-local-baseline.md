# Local transport baseline evidence

Date: 2026-08-20

Repository baseline: `8b2860453d997de73806659a69c023de7abb04cb`

Status: retained implementation map for Tasks 1 and 2 of the transport
stabilization plan; missing evidence is not failed evidence

## Scope

This map freezes the behavior already implemented by `session-protocol`,
`session-transport`, and `session-inviter-transaction` before the generalized
transport contract is added. It prevents later work from silently weakening
the local Welcome profile or claiming that the existing in-memory models are
durable, networked, anonymous, or production-ready.

## Implemented evidence

| Contract area | Current evidence | Boundary |
| --- | --- | --- |
| Canonical envelope | `OpaqueEnvelope` enforces deterministic CBOR and 64 KiB outer/60 KiB ciphertext bounds | The transport API accepts the protocol object and re-encodes it for idempotency; there is no reusable canonical-byte view |
| Deposit authority | `LocalWelcomeDepositEndpoint` carries only local instance, mailbox, deposit capability, profile, and expiry | Local ADR 0014 schema only; no generic route escape hatch |
| Receive authority | `LocalWelcomeReceiveCapability` is a distinct non-`Clone`, non-`Debug`, non-`Display` type | Single local mailbox only; no cursor or batch semantics |
| Acknowledgement authority | `LocalWelcomeAcknowledgementCapability` is separate from receive and `DeliveryId` | Mailbox-scoped local right; no provider-neutral issuance model |
| Secret handling | Raw capability secrets are zeroized when owned and only domain-separated commitments are retained | No generalized diagnostic event schema exists |
| Deposit idempotency | Exact envelope ID and canonical bytes return the original `DeliveryId` before and after acknowledgement | A changed or different second envelope is coarsely rejected because the mailbox holds one logical Welcome |
| Acknowledgement idempotency | Repeating acknowledgement with the exact right and delivery succeeds without resurrecting ciphertext | No multi-delivery acknowledgement batch exists |
| Bounds and expiry | Mailbox count, lifetime, envelope lifetime, encoded size, and one-message depth are bounded before mutation | No general byte budget, poll page, cursor, or wait budget exists |
| Owner-local transaction | The inviter model atomically exposes invitation consumption, replay retention, approval, MLS snapshot, and Welcome outbox state | In-memory conformance model only; no disk durability, rollback protection, or live transport integration |
| Outbox leasing | Pending work, bounded lease attempts, lease expiry, exact completion, and ambiguous commit recovery are modeled | The transport coordinator and owner-store port do not exist |

## Explicit gaps for the generalized contract

The baseline does not yet provide:

- closed `TransportProfileId` values separate from local `AdapterId` values;
- a reusable `CanonicalEnvelope` view over exact protocol bytes;
- bounded operation budgets, retry advice, or stable normalized failure codes;
- a common deposit, poll, and acknowledgement trait;
- provider-neutral capability representation or issuance rules;
- general queues, pagination, cursors, poll waits, or acknowledgement batches;
- adapter manifests, profile binding, or scoped network authority;
- a deterministic adverse-network scheduler or shared adapter conformance harness;
- coordinator integration with the existing inviter outbox model; or
- durable or network transport evidence.

## Retained tests

`crates/session-transport/tests/local_welcome_mailbox.rs` proves:

- distinct deposit, receive, and acknowledgement rights;
- exact retry before and after acknowledgement;
- rejection without replacement for a competing envelope;
- rejection of foreign and expired authority; and
- mailbox and envelope bounds before storage mutation.

`crates/session-inviter-transaction/tests/conformance.rs` proves:

- all pre-commit faults leave only the original reservation;
- a lost commit response recovers one complete commit;
- conflicting retry and stale generations fail closed;
- delivery failure and expired leases preserve committed membership; and
- transaction capacity and delivery-attempt limits fail closed.

## Next implementation gate

Add only the bounded, non-network contract values first: closed profile IDs,
validated adapter IDs, a canonical envelope owner, operation budgets, and
normalized redacted failures. Preserve the local adapter API during that
increment. Stabilize capability representation and dispatch only after those
values compile and their negative tests pass.
