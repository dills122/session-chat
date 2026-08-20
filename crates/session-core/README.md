# session-core

`session-core` owns invitation, join, approval, membership, and session state
machines for the Session Chat 2.0 protocol laboratory. Only the first
inviter-owned invitation-lifecycle increment exists today; admission proof,
MLS orchestration, persistence, and transport state remain unimplemented in
this crate.

## Capability invitation lifecycle

`InvitationRegistry` separates these operations:

1. `issue` signs an invitation and creates bounded inviter-owned `Available` state.
2. `validate_descriptor` authenticates attacker-controlled bytes and applies
   configured time policy without mutation.
3. `reserve_after_admission` reserves the matching locally issued invitation
   for one nonzero join-request ID and binds the opaque reservation authority to
   that exact signed descriptor instance.
4. `release` returns a rejected or pre-commit failure to `Available`.
5. `consume_after_membership` moves the matching reservation to `Consumed`.

The explicit transition names encode caller preconditions. The current crate
does not yet verify capability possession, bind an MLS KeyPackage, record human
approval, or perform an MLS transition. Those operations must move behind one
complete state-machine API as their slices land.

Remote self-signed descriptors can be validated but cannot create registry
state or consume its capacity. A stored invitation is matched by its expiration,
inviter verifying key, and Ed25519 signature, which binds the complete canonical
descriptor. Reservation authority carries that record commitment so expiry and
same-ID reissuance cannot create an ABA transition.

The current registry is deliberately single-process and in-memory. `&mut self`
makes one transition indivisible within this state machine, but this is not a
claim of durable or cross-process atomicity. Persistent implementations must
commit MLS state, request replay state, invitation consumption, and queued
Welcome delivery with approval/result state and an outbox idempotency key in one
recoverable transaction under ADR 0008.

Issued and validated objects contain a bearer capability and therefore do not
implement `Debug` or `Clone`. They must not enter logs or transport metadata.
Encoded invitation bytes are caller-owned bearer-secret buffers.

## Verification

```sh
cargo test -p session-core --test invitation_registry
cargo clippy -p session-core --all-targets -- -D warnings
```
