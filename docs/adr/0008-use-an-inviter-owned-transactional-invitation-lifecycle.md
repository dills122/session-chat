# ADR 0008: Use an inviter-owned transactional invitation lifecycle

Status: accepted for the Phase 1 state-machine contract

Date: 2026-08-16

## Context

A signed invitation authenticates its own descriptor. Signature and time
validation do not prove that the local client issued it, that a joiner proved
the required capability or identity, that the inviter approved the request, or
that MLS membership changed successfully.

The first `InvitationRegistry::accept` API combined descriptor validation with
one-time consumption. That ordering allowed an invalid or premature request to
burn an invitation and allowed arbitrary valid self-signed descriptors to
occupy inviter replay state.

## Decision

Invitation descriptor validation is read-only and retryable. Only the inviter's
local issuance path creates lifecycle state.

A single-use invitation follows this state machine:

```text
local issue
    |
    v
Available --validated admission request--> Reserved(join_request_id)
    ^                                           |
    |                                           | reject or pre-commit failure
    +-------------------------------------------+
                                                |
                                                | approval + durable MLS Commit
                                                v
                                            Consumed
```

Expiration or explicit revocation terminates `Available` or `Reserved` state.
Expiration is checked again at every transition. A reservation belongs to one
nonzero join-request identifier and one exact locally issued descriptor
instance; another request or a stale token from an expired/reissued invitation
cannot replace, release, or consume it.

The admission state machine may reserve only after all automated checks pass:

- invitation signature, time, mode, and local descriptor binding;
- join-request replay identifier and expiration;
- capability or external admission proof;
- the KeyPackage and admission-to-KeyPackage binding from ADR 0009; and
- configured resource and protocol-version policy.

Manual approval occurs while reserved. Rejection or a failure before the MLS
state transaction releases the reservation. Successful approval atomically
persists the MLS Add/Commit transition, `Consumed` invitation state, request
replay state, approval/result state, and the encrypted Welcome with its durable
outbox job and idempotency key. Network
delivery happens after that transaction and is independently retryable. A crash
after commit resumes the outbox; once the MLS epoch advances, delivery failure
must not release the invitation.

Any known failure before the transaction releases the reservation. An ambiguous
transaction result must be recovered from durable state: retry must not repeat
the MLS Add/Commit, a committed result must retain `Consumed` and resume only
outbox work, and only a proven uncommitted result may return to `Available`.

The in-memory Phase 1 implementation models these transitions but cannot make a
durability, process-concurrency, or rollback-resistance claim. Its explicit
`reserve_after_admission` and `consume_after_membership` method names record the
caller preconditions until the complete join state machine owns them.

## Alternatives considered

### Consume when a descriptor is opened

Rejected. Opening proves only descriptor validity and permits trivial invitation
denial of service.

### Consume after proof validation but before approval

Rejected. A valid but rejected request would permanently burn a single-use
invitation, and a crash could strand it without membership.

### Consume after Welcome acknowledgement

Rejected. The MLS membership transition has already occurred before delivery;
acknowledgement loss must be handled by idempotent retry rather than re-admission.

## Consequences

- Descriptor parsing cannot mutate inviter-owned replay state.
- Locally issued state, not arbitrary self-signed input, consumes registry capacity.
- Persistent storage must transact invitation and MLS state together.
- Reservations need timeout/recovery rules and idempotent request identifiers.
- Multi-use invitations require a later explicit counter/policy extension rather
  than reinterpreting the single-use state machine.
