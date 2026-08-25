# Spec: inviter join transaction v1

Status: implementation contract; fault-injectable in-memory conformance model,
SQLCipher durable Welcome owner, and real capability-admission/MLS composition
implemented

## Objective

Define the single inviter-local commit required by ADR 0008 and ADR 0012. One
successful commit makes the following facts visible together:

- the exact invitation generation is consumed;
- the exact join request is retained as replay state;
- the approval result is retained;
- the inviter's advanced MLS group snapshot is retained; and
- the encrypted Welcome and its deposit-only destination are pending in an
  outbox under one idempotency key.

Network delivery is never part of this transaction. A delivery or
acknowledgement failure cannot release the invitation, erase replay state, or
roll back the MLS epoch.

The first implementation is a deterministic, bounded, fault-injectable memory
model. The `storage-sqlcipher` laboratory passes the durable Welcome-owner
subset across close/reopen and schema migration. A retained real
capability-admission/MLS integration holds a one-shot durability-pending result
until recovery resolves the SQL outcome. These adapters do not establish
rollback resistance, production readiness, or durable-client integration.

## Assumptions

1. Capability verification, exact KeyPackage ownership, automated policy, and
   any human approval complete before this transaction begins.
2. The MLS provider has prepared and applied exactly one Add, and supplies the
   complete post-Add snapshot required to reload that group without repeating
   the Add.
3. The Welcome is already MLS-encrypted. Its bytes and deposit-only endpoint
   are nevertheless sensitive metadata and must not enter logs.
4. Invitation identifiers and request identifiers are not sufficient to name a
   reservation. The exact invitation record signature is the generation token
   that prevents stale-reservation ABA after expiry and reissue.
5. The database and vault-key strategy remain an open implementation choice.
   Adding a durable adapter requires a separate evidence-backed dependency and
   at-rest protection decision.

## Owned record

Each commit is selected by a provider-generated, nonzero 16-byte transaction
identifier. The committed record owns these bounded values:

| Value | Bound or invariant |
| --- | --- |
| Transaction ID | exactly 16 nonzero bytes |
| Invitation ID | exactly 16 nonzero bytes |
| Invitation generation | exact 64-byte signed-record signature |
| Join request ID | exactly 16 nonzero bytes |
| Request fingerprint | exact 32-byte digest over the canonical protected request |
| Group ID | non-empty, at most 255 bytes |
| Epochs | `epoch_after == epoch_before + 1` |
| Approval record | non-empty, at most 4 KiB |
| MLS group snapshot | non-empty, at most 2 MiB |
| Welcome envelope | non-empty, at most 64 KiB |
| Deposit endpoint | non-empty, at most 4 KiB |
| Outbox expiry | later than commit time |

The model and future adapters use exact byte equality for idempotent recovery.
Reusing a transaction ID with any different field is rejected. Reusing an
invitation generation or join request under a different transaction is also
rejected.

## State transitions

Before commit, the exact invitation generation is `Reserved` by the exact join
request. Commit has only two externally recoverable outcomes:

```text
Reserved
  | atomic commit
  v
Consumed + ReplayRetained + Approved + MlsAdvanced + OutboxPending
```

- A known failure before commit leaves the original reservation unchanged and
  creates no replay, approval, MLS, or outbox record.
- A success returns `Committed`.
- An identical retry returns `AlreadyCommitted` without applying MLS again.
- A crash or lost response after commit is recovered by transaction ID and
  returns the already-committed record.
- A conflicting retry fails closed.

The in-memory conformance model injects failures at every staging boundary and
immediately after the atomic state swap. A durable adapter must additionally
run process-crash and storage-fault tests against the real engine.

## Outbox transitions

The committed Welcome starts `Pending`. A worker may lease it for one bounded
delivery attempt and then report either outcome:

- failure or an expired lease returns the same item to `Pending`;
- success marks it `Delivered`; and
- duplicate success for the same transaction is idempotent.

The durable SQLCipher adapter additionally retains `AttemptsExhausted` and
`Expired` terminal states so restart enumeration cannot resurrect work after
its configured attempt or lifetime bound. Its version-2 row persists the
attempt count, monotonically renewed lease generation, opaque lease identity,
and lease expiry. A result must match the exact persistent store identity plus
transaction/generation/lease tuple.

Leasing, retrying, expiring, or completing delivery never mutates invitation,
replay, approval, or MLS state. Delivery uses the transaction ID as the stable
local idempotency key. The remote transport still enforces its own exact
envelope idempotency contract.

## Recovery API

Recovery accepts only the exact transaction ID and returns a secret-free view:

- whether the atomic commit exists;
- the committed epoch;
- whether the outbox is pending, leased, delivered, exhausted, or expired; and
- the current delivery-attempt count.

The full stored record is borrowed only by the delivery integration. It does
not implement `Debug`, `Display`, or serialization through a generic object
graph.

## Security and resource rules

- Validate all lengths, nonzero identifiers, epoch arithmetic, and expiry
  before allocating or changing state.
- Bound committed records, outstanding transactions, delivery attempts, and
  lease duration.
- Never evict a committed membership or pending outbox item to make room.
- Never log or include the MLS snapshot, Welcome, destination capability,
  invitation generation, approval evidence, or request fingerprint in errors.
- Do not accept generic maps, extensions, accessors, symbols, or recursively
  cloned values at this boundary. Inputs are concrete byte strings and scalar
  fields only.
- A copied durable store must not reveal secrets without an unsealed
  client-vault key. Database encryption alone does not provide rollback
  resistance; that remains a separate platform/storage requirement.

## Required evidence

The conformance suite must prove:

1. every injected pre-commit failure leaves only the original reservation;
2. an injected post-commit lost response recovers one complete commit;
3. identical retry is idempotent and conflicting retry is rejected;
4. stale invitation generations and duplicate request IDs cannot commit;
5. delivery failure and lease expiry preserve the committed membership and
   pending Welcome;
6. delivery success changes only outbox state;
7. all byte, capacity, attempt, time, and arithmetic bounds fail closed; and
8. secret-bearing records have no accidental `Debug` or generic serialization
   surface.

## Deferred durable adapter gate

Before claiming durability, select and record the storage engine, transaction
mode, vault-key lifecycle, file permissions, secure-delete limitations, backup
behavior, corruption handling, rollback detection, migration policy, and MLS
provider storage integration. The adapter must prove that the MLS snapshot and
all Session Chat rows share one real atomic commit. If the selected MLS storage
hook cannot participate in that commit, it is unsuitable for this boundary.
