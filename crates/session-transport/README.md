# Session Chat transport

`session-transport` implements ADR 0010's first right-specific delivery adapter:
a bounded, single-process local Welcome mailbox for Phase 1 protocol tests.

It also contains the first additive ADR 0015 contract values. The closed
`TransportProfileId` set fails on unknown versions; `AdapterId` accepts only a
bounded local diagnostic grammar; `CanonicalEnvelope` owns one exact validated
protocol encoding without ordinary debug or clone output; and
`OperationBudget`, `RetryAdvice`, and `TransportFailure` expose finite work and
context-free failure semantics. The next additive values bound opaque cursors,
poll count/bytes/wait, acknowledgement batches, and deposit bytes against one
operation budget. Request and receipt types omit ordinary diagnostics when they
own ciphertext or full identifiers. `ReceiveBatch` validates item count,
aggregate canonical bytes, and local post-receive expiry against its exact poll
request before the result crosses the contract. The narrow provider-neutral
`EnvelopeTransport` compatibility trait and the generalized `EnvelopeDelivery`
dispatch trait both keep deposit, receive, and acknowledgement operations
distinct instead of erasing them into generic credentials. The generalized
trait adds provider-neutral outer right wrappers, so an already-issued wrapper
cannot directly occupy another operation position even if inner provider types
alias. This positional check is not an issuance proof: each adapter must still
ensure one right cannot derive another, validate exact scope, and review
cloning/serialization policy per right. Transferable deposit endpoints remain
allowed; receive and acknowledgement authority should be non-cloneable by
default. It returns runtime-neutral
standard-library futures and receives explicit monotonic-deadline,
fallible-wall-clock, and cooperative-cancellation observations. Reviewed
adapters are selected at composition time; neither trait loads code or grants
ambient authority. No lifecycle boundary, profile binder, coordinator, or
network adapter exists yet.

`RetryAdvice::Never` ends attempts under the current operation budget. If a
deposit may already have committed, a coordinator may reconcile only the exact
same idempotency identity under a fresh budget while owner-local state still
marks that operation eligible; it must not create a competing operation.

`LocalMemoryWelcomeTransport` creates fresh mailbox identifiers and independent
deposit, receive, and acknowledgement authorities with AWS-LC's CSPRNG. Only
the existing `LocalWelcomeDepositEndpoint` is sender-facing. Joiner-retained
receive and acknowledgement types do not implement `Clone`, `Debug`, or
`Display`, and temporary secret copies are zeroized. The adapter stores only
domain-separated SHA-256 capability commitments. The local capability types
now live behind private fields and crate-only constructors in `capability.rs`;
compile-fail tests reject cross-right substitution, while a seeded diagnostic
fixture proves coarse errors omit both authority and ciphertext bytes.

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
