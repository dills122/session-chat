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

The desktop shell remains a research decision. Tauri with Rust responsible for
protocol, cryptography, storage, and networking is the leading boundary, but no
web UI framework is selected. Whatever shell is chosen, UI code is not the
authority for keys or membership decisions. ADR 0018 additionally prohibits a
native API from shaping the core contract: one baseline local workflow and
format must build and pass conformance on macOS, Windows, and Linux before the
capability is considered implemented. Stronger native behavior is optional and
reported through factual adapter capabilities.

### Identity bridge

The optional identity bridge converts an external authorization event into a
short-lived attestation bound to:

- The stable provider-side subject identifier
- The canonical MLS KeyPackage reference, session-scoped credential identity,
  leaf signature key, MLS version and ciphersuite, and join-request identifier
  defined by ADR 0009
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

The proposed detailed boundary separates a stable, versioned profile from a
local adapter implementation. The owner-local transaction store remains the
authority for durable outbox records and leases. A delivery coordinator
executes leased work and owns adapter-independent expiry checks, deduplication,
retry policy, polling, and acknowledgement scheduling without creating a
second outbox ledger. A profile binder supplies one adapter with only the
network and mailbox authority allowed by the selected profile; adapters cannot
select fallbacks or broaden egress. See the
[transport abstraction specification](specs/TRANSPORT_ABSTRACTION_V1.md) and
[accepted ADR 0015](adr/0015-bind-transport-adapters-to-versioned-profiles.md).

### Realm administration

A self-hosted realm configures:

- Enabled identity/admission methods
- Trusted identity and credential issuers
- Allowed credential types and claims
- Maximum expiration and participant limits
- Enabled transport profiles and explicit profile-change policy
- Attachment and retention policies
- Service endpoints and operator keys

The realm operator may observe service-level operational metadata according to
the chosen transport, but should not possess message keys or plaintext.

## Protocol objects

### Current Phase 1 evidence

The active Rust laboratory now contains thirteen narrow pieces of this architecture:

- `session-protocol` encodes and strictly verifies deterministic signed
  secret-capability invitation v1/v2 layouts and owns ADR 0014's bounded
  canonical protected outer/inner, exact AAD, and local deposit-endpoint value
  types, in addition to the opaque envelope from ADR 0005.
- `session-core` creates bounded inviter-owned invitation-v1/v2 state, accepts
  v2 local issuance only from the provider-generated wrapper, validates remote
  descriptors without mutation, and models explicit reservation, release, and
  post-membership consumption in memory.
- `session-admission` defines the object-safe, provider-neutral approval
  observation and decision contract. Its context is display-only and carries no
  proof, bearer capability, parsed KeyPackage, reservation, or membership authority.
- `session-crypto` defines the provider-neutral, object-safe message-session
  contract for bounded protected bytes, redacted events, and coarse errors.
- `session-crypto-hpke` defines the separate provider-neutral one-shot join
  protection boundary. Its AWS-LC implementation owns fresh invitation X25519
  key generation and exact typed PSK-mode seal/open contexts.
- `admission-capability` accepts only HPKE-opened requests, independently
  validates and owns the exact provider KeyPackage, compares the ADR 0009 tuple,
  retains bounded in-memory request-ID/nonce replay reservations, binds the
  exact HPKE-opened invitation signature to local v2 state, consumes an explicit
  simulated approval decision through the shared seam, and permits only that
  provider-owned approved one-shot value to enter MLS prepare/apply.
- `session-crypto-mls` isolates the pinned `mls-rs`/AWS-LC provider behind
  bounded KeyPackage, Welcome, and message inputs and models an in-memory
  two-member Add, path-update, message, and removal lifecycle. It is the only
  current implementation of the provider-neutral message contract.
- `session-transport` creates bounded local one-Welcome mailboxes with distinct
  deposit, receive, and acknowledgement authorities, exact-retry idempotency,
  expiry, and no ambient credentials. Its additive generalized values provide
  closed profile IDs, bounded local adapter IDs, exact canonical-envelope
  ownership, finite operation budgets, bounded retry advice, and context-free
  failures. It also defines the provider-neutral right-specific opaque-envelope
  transport trait; no profile binder, coordinator, or network adapter exists.
- `transport-memory` implements that trait with bounded deterministic drop,
  hold/release, duplication, reordering, retry, and acknowledgement controls
  for headless tests. It is not a network transport.
- `session-inviter-transaction` is a bounded, fault-injectable conformance model
  for all-or-nothing invitation/replay/approval/MLS-snapshot/Welcome-outbox
  visibility, exact retry recovery, and delivery leasing. It is not storage.
- `session-storage` is a deterministic in-memory conformance model for the
  session-scoped sealed-vault lifecycle and bounded canonical opaque receipt.
  It is not encrypted or durable storage and has no production key protector.
- `storage-sqlcipher` is a file-backed encrypted durability-laboratory adapter
  for the real inviter and joiner MLS persistence calls. It is not connected to
  a platform key protector and provides no rollback or production claim.
- `sessionctl` composes the current local pieces into one headless Alice/Bob
  flow: capability join, simulated approval, Welcome delivery, bidirectional
  application messages, path update, removal, and post-removal rejection. It
  is not a durable, hosted, or networked client.

The invitation registry, replay verifier, and MLS adapter remain separate
in-process state machines. The capability adapter now coordinates them through
an approval-gated one-shot API: rejection and pre-commit failure release both
reservations, abandonment also clears the MLS pending Commit, and successful
in-memory Add consumes the invitation before returning its outputs. This is
sequential in-memory coordination, not one persistent, cross-process,
crash-atomic, or rollback-resistant transaction. Human approval UX, durable
membership/replay integration, and durable Welcome outbox processing do not
exist in that product path. The separate memory conformance model and SQLCipher
laboratory exercise atomic visibility and ambiguous-result recovery without
connecting to the sequential join path. The in-memory committed join result
now carries the
exact authenticated deposit-only endpoint beside its MLS Welcome, and retained
integration evidence delivers that Welcome through the local mailbox. No
network transport exists. The headless composition retains an executable
happy-path acceptance test across these boundaries, but does not make their
sequential in-memory mutations atomic or persistent.

ADR 0014 accepts the local-only contract: a signed capability invitation v2,
RFC 9180 PSK-protected join request, the invitation-scoped Ed25519 key as
intended verifier, and a closed local one-Welcome deposit endpoint. The
canonical value types, AAD derivation, and one-shot HPKE operation exist in
code. Hosted verifier and network route meaning remain outside that schema.

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

For the local capability profile, ADR 0014 and the
[protected capability join specification](specs/PROTECTED_CAPABILITY_JOIN_V1.md)
define a closed encrypted request containing:

- Admission proof or capability proof
- Join-request replay identifier
- MLS KeyPackage and its ciphersuite KeyPackage reference
- Session-scoped credential identity and leaf signature key extracted from that KeyPackage
- Supported versions and transports
- Response deposit endpoint carrying deposit authority only; it conveys no
  receive, acknowledgement, or rotation authority
- Fresh nonce and expiration

The request uses RFC 9180 PSK mode with the secret invitation capability and an
invitation-scoped X25519 recipient key. The exact signed invitation, visible
outer header, HPKE contexts, inner request, KeyPackage tuple, verifier, protocol
selection, and local response descriptor are cross-checked before mutation.
The current adapter can encrypt the complete request. No rendezvous service or
transport is connected, so repository evidence does not yet establish that all
future transmitted requests pass through this boundary.

The accepted Phase 1 response endpoint has no URL, hostname, generic route,
realm, receive, acknowledgement, or rotation field. Those require later
transport-specific schemas rather than an extension to the local profile.

### Admission and MLS join

After approval:

1. The inviter validates the admission proof, invitation binding, expiry,
   replay identifier, and exact admission-to-KeyPackage binding from ADR 0009.
2. The inviter reserves the locally issued invitation for that request.
3. The inviter records explicit approval or releases the reservation on rejection.
4. The inviter consumes the opaque one-shot `VerifiedAdmission` to construct an
   MLS Add and Commit with its owned, exact verified KeyPackage.
5. MLS epoch/group state, request replay state, invitation consumption,
   approval/result state, and the exact encrypted Welcome plus a durable outbox
   job with an idempotency key commit atomically.
6. The group advances to a new epoch.
7. The committed outbox delivers the Welcome idempotently to a separately
   authorized response endpoint; delivery failure does not undo membership and
   a restart resumes the outbox job.

A verified rejection or failure before the transaction releases the invitation
reservation. Once commit begins, an ambiguous result is recovered from durable
state rather than guessed: a committed result proceeds only through idempotent
outbox retry, while an uncommitted result may safely release. Retry never
repeats the MLS Add/Commit, and delivery failure never reopens the invitation.

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

trait EnvelopeDelivery {
    async fn deposit(
        &self,
        destination: &DepositEndpoint,
        envelope: &CanonicalEnvelope,
        budget: OperationBudget,
    ) -> Result<DepositReceipt, TransportFailure>;

    async fn poll(
        &self,
        authority: &ReceiveCapability,
        request: PollRequest,
    ) -> Result<ReceiveBatch, TransportFailure>;

    async fn acknowledge(
        &self,
        authority: &AcknowledgementCapability,
        deliveries: BoundedDeliveryIds,
        budget: OperationBudget,
    ) -> Result<AcknowledgementReceipt, TransportFailure>;
}
```

`VerifiedAdmission` is privately constructible, opaque, non-`Clone`, and
one-shot. It contains the full `AdmissionContext` and the exact parsed, verified KeyPackage. The
membership state machine consumes it directly; the verifier interface does not
return a detachable reference that can be reused with another request or
reconstructed KeyPackage, and the membership API accepts no separately supplied
KeyPackage or invitation/request context.

`DepositEndpoint`, `ReceiveCapability`, `AcknowledgementCapability`, and
`RotationCapability` are distinct authority-bearing types under ADR 0010.
Secret-bearing variants do not implement `Debug` or enter transport metadata.
`CanonicalEnvelope` is one validated view of the exact deterministic bytes
owned by `session-protocol`; adapters do not create alternative envelope
representations. The portable baseline is unordered and duplicate-capable; the
coordinator makes bounded attempts without promising eventual delivery, and the
protocol core remains correct under loss, omission, arbitrary delay, expiry,
and unavailability.

Invitation publication is intentionally outside `EnvelopeDelivery`. An invite
may be posted to GitHub, copied privately, rendered as a QR code, or exchanged
through another system.

## Proposed repository layout

```text
session-chat/
|-- apps/
|   |-- desktop/                 # selected desktop shell around Rust core
|   |-- landing/                 # public invite landing page
|   `-- sessionctl/              # headless protocol/debug client
|-- crates/
|   |-- session-core/            # state machines and invariants
|   |-- session-protocol/        # canonical wire formats
|   |-- session-crypto/          # provider-neutral message-session contract
|   |-- session-crypto-mls/      # MLS integration
|   |-- session-admission/       # admission traits and policies
|   |-- admission-github/
|   |-- admission-credential/
|   |-- admission-capability/
|   |-- session-storage/
|   |-- session-transport/
|   |-- transport-memory/
|   |-- transport-conformance/
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
2. Admission evidence is bound to the invitation and the exact MLS KeyPackage,
   credential identity, and leaf signature key proposed for membership.
3. Copying a targeted public invite does not grant membership.
4. A session-scoped key is not silently reused as a global identity.
5. Transport selection does not change the session protocol or message format.
6. Identity selection does not change MLS or delivery semantics.
7. Expired or consumed protocol objects fail closed.
8. Private mode never silently downgrades to a less private transport.
9. Anonymous mode makes no external identity-provider requests.
10. Logs, telemetry, and crash reports exclude secrets, plaintext, raw tokens,
    admission proofs, and stable identifiers unless explicitly justified.
11. Descriptor validation is read-only; single-use consumption occurs only with
    the successful membership transaction.
12. Deposit, receive, acknowledgement, and rotation rights are not interchangeable.
13. A cryptographic backend is selected from a reviewed allowlist for a new
    session; an active session never silently changes backend or storage format.
14. A transport adapter cannot select a different profile, fallback path, or
    broader network authority than the locally authorized profile binding.
