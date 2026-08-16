# Session Chat 2.0 architecture

Status: proposed

## Architectural principle

**Decision:** Session security, admission, rendezvous, and transport are
independent layers.

```text
Out-of-band invitation
        |
        v
+---------------------------+
| Session protocol core     |
| invitation state machine  |
| MLS group state           |
| replay/expiry rules       |
+---------------------------+
      |             |
      v             v
+-------------+  +------------------+
| Admission   |  | Envelope delivery|
| GitHub      |  | direct/relay     |
| credential  |  | mixnet           |
| capability  |  | test/local       |
| manual      |  +------------------+
+-------------+           |
      |                   v
      |          +------------------+
      +--------->| Opaque rendezvous|
                 | and mailboxes    |
                 +------------------+
```

Identity providers do not send chat messages. Transports do not evaluate
identity claims. Rendezvous services do not decide MLS membership. Only an
admitted client holds session keys.

## Core components

### Client

The client owns:

- Device root material protected by the operating system where possible
- Fresh session- or invitation-scoped signing keys
- MLS credentials, KeyPackages, group state, and epoch secrets
- Invitation creation and verification
- Admission proof creation and verification
- Encrypted local session state
- Message ordering, retry, replay, and expiration logic
- User-visible descriptions of verified evidence and privacy guarantees

The proposed shell is Angular inside Tauri, with Rust responsible for protocol,
cryptography, storage, and networking. The browser UI is not the authority for
keys or membership decisions.

### Identity bridge

The optional identity bridge converts an external authorization event into a
short-lived attestation bound to:

- The stable provider-side subject identifier
- A fresh Session Chat public key
- The invitation identifier and challenge
- The intended verifier or realm
- Issue and expiration times

It must not receive chat plaintext, MLS group secrets, or recipient history.
Raw provider tokens must not leave the bridge and must not enter logs.

The bridge is unnecessary for secret-capability admission. Credential
presentations may be verified entirely on the client when the chosen format and
status mechanism allow it.

### Optional first-contact directory and post office

The Session Post Office closes the gap between knowing a recipient's external
address and delivering the first invitation. It has two independently
deployable roles:

- An invitation directory maps a verified address or unguessable receive code
  to a signed, rotating receive bundle.
- A sealed invitation mailbox accepts fixed-size ciphertext under the random
  mailbox identifier in that bundle.

The directory learns the target lookup but must not receive invitation traffic.
The mailbox learns a random mailbox and delivery metadata but must not receive
the external identity, read capability, or invitation plaintext. Private
profiles access these roles through OHTTP, the mixnet, or another explicitly
evaluated privacy layer.

For verified addresses, the identity bridge or credential verifier signs an
attestation over the complete receive bundle. Senders validate that attestation
independently of the directory. The directory signature authenticates its
response and freshness but is not the sole identity-to-key trust anchor.

The post office is not an MLS Delivery Service, admission authority, permanent
user directory, or generic pre-admission messenger. The detailed proposal and
validated simulator are in the
[sealed invitation provider spike](spikes/SEALED_INVITATION_PROVIDER.md).

### Rendezvous and mailbox service

The service stores opaque, expiring envelopes addressed by unguessable mailbox
capabilities. It assists with:

- Encrypted join requests
- Admission responses and MLS Welcome delivery
- Offline application messages where supported
- TTL enforcement
- Deduplication hints and bounded object sizes

It must not receive message plaintext, admission plaintext, OAuth tokens,
device private keys, MLS epoch secrets, or a canonical plaintext participant
list.

### Delivery transport

Transports move already encrypted envelopes. Initial adapters are expected to
include:

- Local/in-memory transport for deterministic tests
- Fast direct delivery with encrypted relay fallback
- Katzenpost-backed delivery for a high-privacy experiment

Transport selection is a session profile property. A high-privacy session must
fail closed rather than silently use a fast direct path.

### Realm administration

A self-hosted realm configures:

- Enabled identity/admission methods
- Trusted identity and credential issuers
- Allowed credential types and claims
- Maximum expiration and participant limits
- Enabled transports and fallback rules
- Attachment and retention policies
- Service endpoints and operator keys

The realm operator may observe service-level operational metadata according to
the chosen transport, but should not possess message keys or plaintext.

## Protocol objects

Every persisted or transmitted object should declare enough version and suite
information to reject ambiguity:

- Protocol and serialization version
- Object type
- Invitation encryption suite
- Signature suite
- MLS protocol version and ciphersuite
- Credential/admission proof type
- Transport profile where relevant
- Creation and expiration times
- Replay identifier

Canonical binary encoding is preferred for signed protocol objects. JSON can
remain a diagnostic representation, but ad hoc JSON serialization must not be
the signature boundary.

### Invitation descriptor

An invitation descriptor can contain:

- Random invitation identifier
- Expiration and admission mode
- Join challenge
- Invitation encryption public key
- Opaque rendezvous descriptors
- Supported protocol versions and transports
- Inviter's session-scoped public credential
- Signature

It must not contain an MLS group secret, message key, OAuth token, unrestricted
membership token, or private capability unless the invitation mode explicitly
requires the link itself to remain secret.

### Encrypted join request

The join request contains:

- Admission proof or capability proof
- Proposed session-scoped member key
- MLS KeyPackage
- Supported versions and transports
- Response mailbox capability
- Fresh nonce and expiration

The entire request is encrypted to the invitation key before entering a
rendezvous service or transport.

### Admission and MLS join

After approval:

1. The inviter validates the admission proof, invitation binding, expiry,
   replay identifier, and MLS KeyPackage.
2. The inviter constructs an MLS Add and Commit.
3. The group advances to a new epoch.
4. An encrypted Welcome is delivered to the joiner's response mailbox.
5. The invitation is consumed, rotated, or retained according to its explicit
   multi-use policy.

MLS protects group content and membership transitions; the invitation protocol
only protects the pre-membership exchange.

## Interfaces

Illustrative boundaries:

```rust
trait AdmissionVerifier {
    async fn verify(
        &self,
        proof: AdmissionProof,
        context: AdmissionContext,
    ) -> Result<VerifiedAdmission>;
}

trait EnvelopeTransport {
    async fn send(
        &self,
        mailbox: MailboxId,
        envelope: OpaqueEnvelope,
    ) -> Result<DeliveryId>;

    async fn receive(
        &self,
        mailbox: MailboxId,
        cursor: Option<Cursor>,
    ) -> Result<Vec<ReceivedEnvelope>>;

    async fn acknowledge(&self, delivery: DeliveryId) -> Result<()>;
}
```

Invitation publication is intentionally outside `EnvelopeTransport`. An invite
may be posted to GitHub, copied privately, rendered as a QR code, or exchanged
through another system.

## Proposed repository layout

```text
session-chat/
|-- apps/
|   |-- desktop/                 # Angular + Tauri client
|   |-- landing/                 # public invite landing page
|   `-- sessionctl/              # headless protocol/debug client
|-- crates/
|   |-- session-core/            # state machines and invariants
|   |-- session-protocol/        # canonical wire formats
|   |-- session-crypto-mls/      # MLS integration
|   |-- session-admission/       # admission traits and policies
|   |-- admission-github/
|   |-- admission-credential/
|   |-- admission-capability/
|   |-- session-storage/
|   |-- session-transport/
|   |-- transport-iroh/
|   `-- transport-katzenpost/
|-- services/
|   |-- identity-bridge/
|   |-- invitation-directory/   # optional rotating receive-bundle lookup
|   |-- invitation-mailbox/     # optional sealed first-contact envelopes
|   |-- rendezvous/
|   `-- admin/
|-- deploy/
`-- docs/
```

The retired application is preserved by the `legacy-v1` tag and documented
under `docs/legacy-v1/`; it is intentionally absent from the active layout.
Restoring it as a compatibility layer would risk turning server-authoritative
Socket.IO rooms into accidental cryptographic protocol state.

## Architecture invariants

1. Infrastructure never receives application plaintext or MLS group secrets.
2. Admission evidence is bound to the invitation and proposed session key.
3. Copying a targeted public invite does not grant membership.
4. A session-scoped key is not silently reused as a global identity.
5. Transport selection does not change the session protocol or message format.
6. Identity selection does not change MLS or delivery semantics.
7. Expired or consumed protocol objects fail closed.
8. Private mode never silently downgrades to a less private transport.
9. Anonymous mode makes no external identity-provider requests.
10. Logs, telemetry, and crash reports exclude secrets, plaintext, raw tokens,
    admission proofs, and stable identifiers unless explicitly justified.
