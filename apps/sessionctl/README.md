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

To run the same scripted protocol proof from two terminals on one computer,
choose a new absolute run-directory path. Start the host first:

```sh
cargo run -p sessionctl --bin sessionctl-pair --locked --offline -- host /tmp/session-chat-pair
```

Then run the joining client in a second terminal:

```sh
cargo run -p sessionctl --bin sessionctl-pair --locked --offline -- join /tmp/session-chat-pair
```

The host owns a bounded local forwarder and removes only its marked fresh run
directory after both commands report `status=complete`. This is a scripted
two-process protocol demonstration over local filesystem IPC, not yet an
interactive chat UI or network transport.

For the scripted proof across two computers, both machines must run this same
revision and have internet access to Iroh's public N0 address-lookup/relay
services. On the first computer, choose a new local state directory and run:

```sh
cargo run -p sessionctl --bin sessionctl-net --locked -- host /tmp/session-chat-network-host
```

The host prints a public `endpoint=` value, then creates the bearer invitation
at `/tmp/session-chat-network-host/direct/invitation.v2` and reports
`invitation=ready`. Transfer that invitation file to the second computer over
an authenticated, confidential channel independent of Iroh. The endpoint ID is
public; the invitation file is admission authority and must remain secret.
Choose a different new local state directory on the second computer and run:

```sh
cargo run -p sessionctl --bin sessionctl-net --locked -- join HOST_ENDPOINT_ID /tmp/session-chat-invitation.v2 /tmp/session-chat-network-join
```

Both commands report `status=complete` after the separately transferred
invitation authorizes a protected join, Welcome, two MLS application messages,
path update, removal, and post-removal rejection over the authenticated Iroh
link. The first network frame is the HPKE-protected join request; the host never
sends the bearer invitation to a connector. Each computer keeps its own
temporary SQLCipher/local capability state and removes only its marked state
directory on success. The join command does not delete the separately
transferred source file; remove it according to the transfer system's handling
policy after the proof completes.

This command explicitly selects the FastV1 experiment. A direct peer can learn
the other peer's address; N0 relay, address-lookup, and DNS infrastructure can
observe endpoint, address, timing, size, and lookup metadata. The command is
online-only, accepts one connection, uses ephemeral Iroh endpoint keys, and
provides no offline mailbox, reconnection, anonymity, production deployment,
or interactive free-form chat claim.

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
