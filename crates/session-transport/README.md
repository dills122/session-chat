# Session Chat transport

`session-transport` implements ADR 0010's first right-specific delivery adapter:
a bounded, single-process local Welcome mailbox for Phase 1 protocol tests.

It also contains the first additive ADR 0015 contract values. The closed
`TransportProfileId` set fails on unknown versions; `AdapterId` accepts only a
bounded local diagnostic grammar; `CanonicalEnvelope` owns one exact validated
protocol encoding without ordinary debug or clone output; and
`OperationBudget`, `RetryAdvice`, and `TransportFailure` expose finite work and
context-free failure semantics. No generalized delivery trait, profile binder,
coordinator, or network adapter exists yet.

`LocalMemoryWelcomeTransport` creates fresh mailbox identifiers and independent
deposit, receive, and acknowledgement authorities with AWS-LC's CSPRNG. Only
the existing `LocalWelcomeDepositEndpoint` is sender-facing. Joiner-retained
receive and acknowledgement types do not implement `Clone`, `Debug`, or
`Display`, and temporary secret copies are zeroized. The adapter stores only
domain-separated SHA-256 capability commitments.

Each mailbox accepts at most one bounded `OpaqueEnvelope`. The same envelope ID
and canonical bytes are an idempotent retry. Any changed or different second
envelope is rejected without replacement. Acknowledgement deletes the retained
ciphertext but keeps a bounded envelope commitment so later exact retries return
the original `DeliveryId` without resurrecting the delivery. The delivery ID is
untrusted and never authorizes acknowledgement by itself.

Mailbox count, lifetime, envelope lifetime, protocol byte size, and retained
queue depth are bounded. Authority, mailbox, expiry, collision, and full-mailbox
failures use coarse secret-free errors.

This is not a network transport, durable mailbox, crash-safe outbox, anonymous
profile, or production privacy claim. The local Phase 1 profile deliberately
has no rotation operation.

## Verification

```sh
cargo test -p session-transport --all-features --locked --offline
cargo clippy -p session-transport --all-targets --all-features --locked --offline -- -D warnings
```
