# Sealed invitation provider spike

This dependency-free Node.js spike tests one narrow architectural question:

> Can Session Chat operate an optional first-contact provider that discovers a
> recipient's receive bundle and queues an invitation without receiving the
> invitation plaintext?

The spike separates two roles:

- `AddressAttestor` independently binds address control to the complete receive
  bundle.
- `InvitationDirectory` maps an authorized lookup key to a signed, rotating
  receive bundle.
- `InvitationMailboxService` stores fixed-size encrypted envelopes under a
  random mailbox identifier and uses distinct read and acknowledgement
  capabilities.

The directory sees the lookup key but does not receive invitation traffic. The
mailbox sees random mailbox identifiers and ciphertext but has no identity
field. They are separate classes because production should support separate
services and, ideally, separate operators.

## Run

Requires Node.js 22 or newer and no installed packages:

```bash
npm test
```

## What the tests demonstrate

- End-to-end invitation sealing to a recipient receive key
- No invitation plaintext in either service's stored view
- No directory identity in the mailbox record
- Address-attestor binding independent of the directory
- Signed directory records bound to the lookup key
- Chained receive-bundle rotation and rollback rejection
- In-process rejection of concurrently authorized competing successors
- Snapshotted async authorization inputs and bounded proof structures
- Closed receive-bundle schemas with every stored field authenticated
- Rejection of unknown, oversized, deep, and cyclic bundle extras before authorization
- Read-capability enforcement
- Ciphertext tamper detection
- Envelope and mailbox expiration
- Retry deduplication and right-separated acknowledgement authority
- Bounded, canonical acknowledgement identifier lists
- Fixed envelope size and bounded queues
- Rejection of unauthorized directory registration

## What this is not

This is not production cryptography or a deployable network service.

The crypto module composes Node's X25519, HKDF-SHA-256, and AES-256-GCM to
exercise the intended data boundaries. Production must use a reviewed RFC 9180
HPKE implementation and published protocol test vectors rather than promote
this spike construction into a wire protocol.

The address attestor signs the address-to-bundle binding, but its injected
address-control check uses a deliberate placeholder string. A real attestor
must verify GitHub control, a trusted credential, or control of an existing
receive key. The in-memory attestor and directory signing keys are also
ephemeral and have no production rotation or trust-distribution design.

The spike does not implement:

- HTTP, authentication, durable persistence, or multi-process/database transactions
- Oblivious HTTP, a mixnet, or private information retrieval
- Privacy Pass or another anonymous abuse-control mechanism
- Directory transparency or equivocation detection
- Sender authentication or MLS admission
- Push notifications
- Key recovery or multi-device synchronization

The full recommendation and privacy analysis are in
[`docs/spikes/SEALED_INVITATION_PROVIDER.md`](../../docs/spikes/SEALED_INVITATION_PROVIDER.md).
The expanded lifecycle and protocol design is in
[`SEALED_INVITATION_PROVIDER_PROTOCOL.md`](../../docs/spikes/SEALED_INVITATION_PROVIDER_PROTOCOL.md).
