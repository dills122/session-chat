# session-core

`session-core` owns invitation, join, approval, membership, and session state
machines for the Session Chat 2.0 protocol laboratory. The inviter-owned
lifecycle supports both the original v1 descriptor and provider-generated v2
protected-join descriptor. Admission proof, approval/MLS orchestration,
persistence, and transport state remain outside this crate.

## Capability invitation lifecycle

`InvitationRegistry` separates these operations:

1. `issue` signs a v1 invitation; `issue_v2` accepts only the complete
   provider-generated wrapper. Both create bounded inviter-owned `Available` state.
2. `validate_descriptor` and `validate_descriptor_v2` authenticate
   attacker-controlled bytes and apply configured time policy without mutation.
3. The version-specific `reserve*_after_admission` methods reserve the matching
   locally issued invitation for one nonzero join-request ID and bind the opaque
   authority to that exact signed descriptor instance and schema.
4. `release` returns a rejected or pre-commit failure to `Available`.
5. `consume_after_membership` moves the matching reservation to `Consumed`.

The explicit transition names encode caller preconditions. The current crate
does not yet verify capability possession, bind an MLS KeyPackage, record human
approval, or perform an MLS transition. Those operations must move behind one
complete state-machine API as their slices land.

Remote self-signed descriptors can be validated but cannot create registry
state or consume its capacity. V1 and v2 share one bound. A stored invitation is
matched by schema, expiration, inviter verifying key, and Ed25519 signature,
which binds the complete canonical descriptor. Reservation authority carries
that record commitment so expiry, cross-version confusion, and same-ID
reissuance cannot create an ABA transition.

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
cargo test -p session-core --all-features --locked --offline
cargo clippy -p session-core --all-targets --all-features --locked --offline -- -D warnings
```
