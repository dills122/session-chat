# session-inviter-transaction

This crate is the bounded, deterministic conformance model for ADR 0008's
inviter-local join transaction. It proves that invitation consumption, replay
retention, approval state, one advanced MLS snapshot, and one encrypted Welcome
outbox item have only an all-or-nothing visible outcome.

It also models exact retry recovery and bounded outbox leasing. A lost commit
response recovers by transaction ID without repeating MLS Add. Delivery
failure, lease expiry, and retry never undo membership or invitation
consumption.

This crate is not a database and provides no disk durability, process-crash
recovery, at-rest encryption, vault integration, rollback resistance, or
network delivery. A storage adapter may claim ADR 0008 conformance only after it
passes the same behavioral contract with real storage faults and proves that
the MLS provider snapshot participates in the same atomic commit.

Secret-bearing commit records, delivery leases, and delivery payloads do not
implement `Debug`, `Display`, or generic serialization. All input surfaces are
concrete bounded byte strings and scalar fields.

## Verification

```sh
cargo test -p session-inviter-transaction --all-features --locked --offline
cargo clippy -p session-inviter-transaction --all-targets --all-features --locked --offline -- -D warnings
```
