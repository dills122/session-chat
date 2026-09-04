# sessionctl

`sessionctl` is the headless Phase 1 composition and conformance client. One
run creates fresh Alice and Bob clients, durably retains a secret-capability
invitation before publication, protects and verifies the exact join request,
records an explicit simulated approval through the restartable authorization
owner, applies the MLS Add, and persists Alice's exact post-Add snapshot,
invitation consumption, approval/replay result, and encrypted Welcome outbox
atomically in a disposable SQLCipher database. Retained fault cases prove exact
rollback release and recover an ambiguous commit by authorization-attempt and
transaction IDs. The normal flow
closes Alice's initial MLS client, reloads her exact credential, signer, and
group from the database, reconstructs the coordinator owner, and delivers the Welcome through the
right-specific local mailbox. Application messages, the path update, removal,
and the post-removal rejection check cross the provider-neutral
`EnvelopeDelivery` boundary using bounded operations and distinct deposit,
receive, and acknowledgement rights over the deterministic memory adapter.

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

The in-process LocalV1 message path deliberately uses immediate cursorless
polls and does not claim durable receive-checkpoint persistence. Cursor-bound
restart and persist-before-acknowledgement behavior remains isolated in the
transport conformance models until a selected network adapter supplies those
semantics.

The independent-process runner uses the same durable authorization owner and
recovers a lost pre-approval provider value as abandoned while retaining replay
and reloading the exact invitation opening context.

This executable still composes both logical clients and the LocalV1 adapter in
one process. Alice's exact identity and group now cross a real SQLCipher
close/reopen boundary, but no operating-system process exits and Bob remains
live in memory. The binary does not provide a network service,
independent-process client recovery, rollback
protection, a sealed client vault, human approval UX, anonymity, or a production
client.
