# sessionctl

`sessionctl` is the headless Phase 1 composition and conformance client. One
run creates fresh in-memory Alice and Bob clients, issues a secret-capability
invitation, protects and verifies the exact join request, records an explicit
simulated approval, applies the MLS Add, delivers the encrypted Welcome through
the right-specific local mailbox, exchanges two MLS application messages over
the deterministic memory transport, applies a path update, removes Bob, and
confirms Bob rejects a later message.

```sh
cargo run -p sessionctl --locked --offline
```

Output contains only coarse public milestones. Capability material,
invitation identifiers, KeyPackages, credentials, ciphertext, and plaintext
are not printed.

The library also exposes a narrow `PhaseOneFaultPlan` conformance seam. It can
stop the same flow only at named operation-result boundaries and observes only
coarse cleanup states; it receives no protocol bytes, identifiers, authority,
plaintext, or provider error values. The default binary injects no faults.

This executable composes single-process adapters. It does not provide a
network service, durable state, crash recovery, rollback protection, a sealed
client vault, human approval UX, anonymity, or a production client.
