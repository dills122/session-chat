# Session Chat deterministic memory transport

`transport-memory` is the fault-controlled opaque-envelope adapter for Phase 1
headless and conformance tests.

It implements `session_transport::EnvelopeTransport` with separate deposit,
receive, and acknowledgement capability types. Authority secrets are generated
by AWS-LC, zeroized on drop, and retained by the adapter only as
domain-separated SHA-256 commitments. The deterministic label applies to the
test-controlled delivery outcomes, not to secret generation.

The adapter supports bounded `Deliver`, `Drop`, `Hold`, and `Duplicate` actions.
Held deliveries can be released by insertion index to model reordering. Exact
deposit retries retain one logical `DeliveryId`, changed bytes under the same
envelope ID are rejected, and per-mailbox accepted-envelope and per-envelope
attempt limits bound retained commitments and fault work. Acknowledgement
deletes the retained envelope and every scheduled copy while preserving the
bounded digest needed for exact-retry recognition until mailbox expiry.

`OpaqueEnvelope` is a structural byte container. This adapter neither encrypts
its contents nor proves that callers supplied ciphertext. It is single-process,
non-durable, non-networked, and provides no anonymity, traffic-analysis, crash,
or rollback guarantee. Its public fault controls are a test harness and must
not be exposed as a production transport API.

## Verification

```sh
cargo test -p transport-memory --all-features --locked --offline
cargo clippy -p transport-memory --all-targets --all-features --locked --offline -- -D warnings
```
