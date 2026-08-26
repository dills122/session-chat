# sessionctl

`sessionctl` is the headless Phase 1 composition and conformance client. One
run creates fresh Alice and Bob clients, issues a secret-capability
invitation, protects and verifies the exact join request, records an explicit
simulated approval, applies the MLS Add, and persists Alice's exact post-Add
snapshot, invitation consumption, approval/replay result, and encrypted Welcome
outbox atomically in a disposable SQLCipher database. A retained fault case
recovers an ambiguous commit result by transaction ID. The normal flow
reconstructs a coordinator owner from the database and delivers the Welcome through the
right-specific local mailbox, exchanges two MLS application messages over the
deterministic memory transport, applies a path update, removes Bob, and confirms
Bob rejects a later message.

```sh
cargo run -p sessionctl --locked --offline
```

Output contains only coarse public milestones. Capability material,
invitation identifiers, KeyPackages, credentials, ciphertext, and plaintext
are not printed.

`cargo run -p sessionctl --locked --offline -- --evidence-v1` emits a bounded,
versioned `key=value` scenario result for `E2E-JOIN-001`. The record declares
its actual `single-process-sqlcipher-local-v1` topology and contains no paths,
identifiers, authority, ciphertext, plaintext, or credential material. It is a
machine-readable scenario result, not the future complete independent-process
evidence manifest.

The library also exposes a narrow `PhaseOneFaultPlan` conformance seam. It can
stop the same flow only at named operation-result boundaries and observes only
coarse cleanup states; it receives no protocol bytes, identifiers, authority,
plaintext, or provider error values. The default binary injects no faults.

This executable still composes both logical clients and the LocalV1 adapter in
one process. Alice's live MLS signing identity is not reloaded after process
restart; only the coordinator owner is reconstructed from SQLCipher. The binary
does not provide a network service, full durable-client recovery, rollback
protection, a sealed client vault, human approval UX, anonymity, or a production
client.
