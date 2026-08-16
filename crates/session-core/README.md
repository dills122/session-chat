# session-core

`session-core` owns invitation, join, approval, membership, and session state
machines for the Session Chat 2.0 protocol laboratory. Only the first
invitation-acceptance increment exists today; join, admission, MLS, persistence,
and transport state remain unimplemented.

## Capability invitation registry

`InvitationRegistry` accepts attacker-controlled invitation bytes in this
order:

1. canonical parsing and strict signature verification in `session-protocol`
2. configured future-skew, expiration, and maximum-lifetime checks
3. live invitation-ID replay lookup
4. bounded-capacity check
5. expired-entry pruning and insertion as one successful mutable operation

Every rejected input leaves the registry unchanged. Expiration is exclusive:
an invitation with `expires_at == now` is expired. Replay entries remain only
until the signed invitation expires and are pruned on the next successful
acceptance.

The current registry is deliberately single-process and in-memory. `&mut self`
makes one acceptance indivisible within this state machine, but this is not a
claim of durable or cross-process atomicity. Persistent transactional replay
state and rollback protection remain a later Phase 1 slice.

Accepted objects still contain a bearer capability and therefore do not
implement `Debug`. They must not enter logs or transport envelopes.

## Verification

```sh
cargo test -p session-core --test invitation_registry
cargo clippy -p session-core --all-targets -- -D warnings
```
