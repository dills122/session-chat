# Phase 1 response-deposit and verifier-context research packet

Status: research complete; endpoint value and separate local mailbox behavior
subsequently adopted and implemented under ADR 0014

Reviewed: 2026-08-20

Decision record: ADR 0014 and `docs/specs/PROTECTED_CAPABILITY_JOIN_V1.md`

## Decision question and scope

What exact verifier context and response-deposit descriptor should the first
capability-authorized join request carry so that an inviter can return one MLS
Welcome without receiving broader mailbox authority or solving production realm
discovery prematurely?

This packet closes two inputs left open by the HPKE join-request research. It
proposes a local-memory-only Phase 1 profile, assigns the inner request's field
positions, and defines the authority and retry lifecycle that a later transport
slice should test. This packet itself is research; ADR 0014 later adopts the
local wire contract, and `session-transport` now implements its local mailbox
state machine. The committed approved-join result subsequently connected the
authenticated deposit endpoint to the exact MLS Welcome in memory. That path
does not add a network endpoint, define a hosted realm, or make the coordination
durable or crash-atomic.

The scope is deliberately smaller than a general `DepositEndpoint`. The first
schema can express only a single-purpose local Welcome mailbox. A network,
private-realm, mixnet, or public-rendezvous endpoint requires a new
transport-specific descriptor and its own threat analysis.

## Executive conclusion

Propose two exact Phase 1 values:

1. The intended verifier is the invitation-scoped 32-byte Ed25519 verifying key
   already authenticated by the signed invitation. It identifies the exact
   verifier key for this invitation generation; it is not a user identity,
   realm identity, DNS identity, or durable trust root.
2. The response descriptor is a closed deterministic-CBOR
   `LocalWelcomeDepositEndpointV1` containing a local transport instance ID,
   mailbox ID, high-entropy deposit capability, and expiration. It contains no
   receive, acknowledgement, or rotation authority and no URL, hostname,
   headers, generic route bytes, or extension map.

The joining client creates the local Welcome mailbox before it constructs the
join request. It sends only the deposit endpoint inside the HPKE-protected
request and retains separately typed receive and acknowledgement capabilities.
The mailbox accepts one logical Welcome envelope. An exact retransmission of
the same envelope ID and bytes is idempotent; a different second envelope is
rejected. This supports the inviter's accepted atomic outbox contract without
making remote acknowledgement a membership precondition.

Bearer capability lessons from OAuth are used only as security analogies. The
proposed endpoint is not an OAuth token, authorization server, or HTTP
authentication scheme. Session Chat should borrow the least-authority,
audience, short-lifetime, and no-URL-leakage properties without adopting OAuth
syntax or semantics.

ADR 0014 accepts this recommendation for the local Phase 1 contract. Adoption
is not implementation: exact fixtures, a CSPRNG-owned mailbox-creation API, and
retained negative and state-machine evidence remain required.

## Method and source index

Primary standards were used for the relevant general security properties, then
reconciled with the repository's accepted contracts.

- [RFC 6750: OAuth 2.0 Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750.html),
  for the threat model of a secret usable by any possessor, short lifetime,
  audience restriction, transport protection, and URL/log leakage. This is
  analogous guidance only.
- [RFC 8707: Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707.html),
  for restricting authority to one exact resource or audience. This is
  analogous guidance only.
- [RFC 4086: Randomness Requirements for Security](https://www.rfc-editor.org/rfc/rfc4086.html),
  for adversary-resistant unpredictability and the distinction between apparent
  randomness and cryptographic entropy.
- [RFC 8949: Concise Binary Object Representation](https://www.rfc-editor.org/rfc/rfc8949.html),
  for deterministic encoding requirements.
- Repository contracts: ADR 0005, ADR 0008, ADR 0009, ADR 0010, ADR 0012,
  architecture, identity/admission, transports, threat model, and the HPKE
  join-request research packet.

Standards and repository facts in this packet were checked on 2026-08-20.

## Facts, observations, and inferences

### Standards facts

- A bearer token is usable by any party that possesses it, so disclosure in
  storage or transit transfers its authority. RFC 6750 therefore requires
  protection in storage and transport and recommends audience-restricted,
  short-lived tokens.
- RFC 6750 warns against putting bearer tokens in page URLs because URLs can
  enter browser history, logs, and other observable locations.
- RFC 8707 describes audience restriction as a way to prevent a token issued
  for one resource from being used at another. Its OAuth syntax is not needed
  here, but the confused-deputy defense applies to capability design.
- RFC 4086 requires secret values to be hard for an adversary to guess. A
  statistically random-looking value can still be predictable; entropy
  provenance must come from a reviewed cryptographic generator rather than a
  format or statistical test.
- RFC 8949 deterministic encoding requires applications to define their map or
  array constraints and preferred encodings. Deterministic CBOR does not itself
  define application field meaning or reject application-level unknowns.

### Repository observations

- ADR 0010 already requires distinct `DepositEndpoint`, `ReceiveCapability`,
  `AcknowledgementCapability`, and `RotationCapability` types. A transport
  profile selects behavior; it does not grant ambient mailbox authority.
- Architecture requires the join request to carry deposit authority only. It
  explicitly excludes receive, acknowledgement, and rotation authority.
- `DeliveryId` is untrusted and cannot authorize acknowledgement by itself.
- The accepted inviter transaction commits the exact encrypted Welcome and a
  durable idempotent outbox job with membership, invitation consumption, replay,
  and result state. Delivery happens after commit, resumes after restart, and
  cannot reopen the invitation.
- The current protocol laboratory has no transport crate, no admission
  orchestrator, no durable outbox, and no connected HPKE join path.
- The current `OpaqueEnvelope` parser pre-bounds a complete object at 64 KiB
  and its uninterpreted ciphertext at 60 KiB.
- Phase 1 is scoped to local/in-memory transport. Hosted realm packaging and
  network rendezvous are later roadmap work.
- The current MLS adapter enforces a maximum 16 KiB serialized KeyPackage,
  32-byte session credential identity, 32-byte Ed25519 leaf signature key, and
  32-byte canonical KeyPackage reference for ciphersuite 1.
- The invitation-scoped Ed25519 verifying key already authenticates the exact
  signed capability descriptor. The HPKE packet also proposes binding that key
  into `info`.
- The portable realm descriptor is a separate proposal, not an adopted schema
  or implemented trust root.

### Design inferences

- Phase 1 does not need a hosted realm identifier to satisfy ADR 0009's
  intended-verifier binding. Binding the exact invitation-scoped verifier key
  is narrower and already rooted in the invitation that the inviter issued.
- A local transport descriptor should not contain a generic URL or route field.
  Such a field would accidentally create network parsing, SSRF, proxy, redirect,
  canonical-host, and realm-trust questions in an otherwise local slice.
- A transport instance ID is needed in addition to a mailbox ID. It prevents a
  capability serialized for one local transport instance from being accepted
  by another instance or adapter that happens to reuse a mailbox identifier.
- The deposit capability must be bound by lookup and policy to the exact
  transport instance, mailbox, purpose, and expiration. It is not a general
  local write token.
- Queue depth one logical envelope is sufficient for the response mailbox. The
  inviter already has an idempotent outbox obligation, so the mailbox needs
  exact-retry equivalence rather than an unbounded queue.
- A proof-of-possession or key-bound deposit token adds a separate signing-key
  lifecycle without reducing Phase 1's local threat surface enough to justify
  it. A high-entropy, single-purpose, short-lived bearer capability is the
  smaller first design. Network profiles can revisit sender-constrained
  authorization under a new schema.

## Options considered

| Option | Benefit | Cost or risk | Result |
| --- | --- | --- | --- |
| Invitation-scoped verifier key | Exact, already signed, no extra discovery or stable identity | Valid only for that invitation generation; says nothing about who owns the key | Propose for Phase 1 capability mode |
| Hosted realm ID and root context | Can support stable operator discovery and verifier policy | Realm descriptor, rotation, rollback, migration, and custody are only proposals | Defer to a new hosted profile |
| DNS name or URL as verifier | Familiar routing syntax | Conflates routing with trust; creates redirects, canonicalization, migration, and correlation concerns | Reject |
| Local single-Welcome bearer deposit capability | Small, right-specific, testable, no ambient credential | Any possessor can deposit until expiry or first use | Propose with high entropy, encryption, scope, and one-use policy |
| Key-bound or DPoP-style deposit | Sender compromise does not transfer authority without its key | Adds a key, signature scheme, proof replay rules, and lifecycle to a local-only slice | Defer to evidence from a network profile |
| Generic route object or extension map | One schema could carry many transports | Unknown fields become authority and parser surface; version meaning drifts | Reject for version 1 |
| Reuse receive capability for deposit | Fewer values | Violates ADR 0010 and lets the inviter read or delete responses | Reject |

## Proposed verifier context

`CapabilityInvitationVerifierV1` is exactly the 32-byte Ed25519 verifying key
from `SignedCapabilityInvitationV2`. No wrapper object is needed in the wire
request because the capability admission schema and proof version define its
meaning.

Validation requires exact equality among:

- the key authenticated by the signed invitation;
- the verifier key bound into the HPKE `info` value;
- the verifier key in the decrypted inner request; and
- the key selected by the local invitation record for that exact invitation
  generation.

The key must not be interpreted as:

- an inviter's global account or device identity;
- a realm's offline root or service key;
- a DNS/TLS identity;
- proof of durable continuity across invitation reissue; or
- authorization to admit any KeyPackage other than the exact bound request.

Reissuing the same invitation ID after expiry or revocation requires a fresh
invitation signature key, HPKE key pair, challenge, and key ID. A stale request
therefore fails the generation bindings even before reservation.

A future credential, GitHub, or hosted-realm proof may require a structured
verifier context. That change must use a new admission-proof or request schema
version rather than overloading these 32 bytes.

## Proposed local response descriptor

`LocalWelcomeDepositEndpointV1` is a fixed seven-item deterministic-CBOR array:

| Position | Field | Proposed constraint |
| ---: | --- | --- |
| 0 | Endpoint schema version | unsigned integer `1` |
| 1 | Object type | new allowlisted local-Welcome-deposit type |
| 2 | Transport profile | unsigned integer `1` for local memory |
| 3 | Transport instance ID | exactly 16 random bytes; non-zero |
| 4 | Mailbox ID | exactly 16 random bytes; non-zero |
| 5 | Deposit capability | exactly 32 CSPRNG bytes; non-zero; secret-bearing |
| 6 | Expiration | unsigned 64-bit Unix seconds |

The descriptor is valid only when its expiration is no later than the enclosing
join request's expiration and within the local application's configured maximum
lifetime and clock-skew policy.

The schema is closed. It has no:

- receive, acknowledgement, deletion, rotation, or administrative authority;
- hostname, URL, IP address, port, proxy, redirect, or arbitrary route bytes;
- realm ID, user ID, stable external identity, or global device ID;
- HTTP header, cookie, generic metadata, or provider credential;
- extension map, unknown field, tag, float, indefinite-length item, or trailing
  data; or
- mechanism for selecting another transport or weakening the privacy profile.

The complete endpoint is confidential bearer authority. It exists in plaintext
only in owned client memory and the zeroizing join-request plaintext builder,
then appears only inside the HPKE ciphertext and the inviter's future protected
outbox state. Its bytes must not implement `Debug` or `Display`, enter logs,
metrics, errors, transport metadata, URLs, clipboard data, or crash reports.

The endpoint's serialized value should be moved into the request builder. A
retry resends the same bounded protected request bytes; it does not repeatedly
reconstruct or clone the plaintext capability.

## Proposed canonical inner join request

With the local response descriptor defined, `CapabilityJoinRequestV1` can be a
fixed 21-item deterministic-CBOR array:

| Position | Field | Proposed constraint |
| ---: | --- | --- |
| 0 | Join-request schema version | unsigned integer `1` |
| 1 | Object type | new allowlisted capability-join-request type |
| 2 | Admission-proof version | unsigned integer `1` for capability HPKE-PSK possession |
| 3 | Invitation ID | exactly 16 bytes |
| 4 | Join challenge | exactly 32 bytes |
| 5 | Invitation encryption key ID | exactly 16 bytes |
| 6 | Intended verifier | exact 32-byte invitation Ed25519 verifying key |
| 7 | Join-request ID | exactly 16 random bytes; non-zero |
| 8 | Issue time | unsigned 64-bit Unix seconds |
| 9 | Expiration | unsigned 64-bit Unix seconds; later than issue time |
| 10 | Request nonce | exactly 32 CSPRNG bytes; non-zero |
| 11 | MLS protocol version | unsigned integer `1` for MLS 1.0 |
| 12 | MLS ciphersuite | unsigned integer `1` |
| 13 | KeyPackage reference | exactly 32 bytes under ciphersuite 1 |
| 14 | Canonical KeyPackage | non-empty exact TLS object; at most 16 KiB |
| 15 | Credential type | unsigned integer `1` for BasicCredential |
| 16 | Credential identity | exactly 32 non-zero session-scoped bytes |
| 17 | Leaf signature key | exactly 32 bytes for Ed25519 under ciphersuite 1 |
| 18 | Application protocol version | unsigned integer `1` |
| 19 | Transport profile | unsigned integer `1` for local memory |
| 20 | Response deposit endpoint | exact nested `LocalWelcomeDepositEndpointV1` array |

ADR 0014's normative specification assigns the object and enum code points.
This research packet retains the analysis; the specification, not this packet,
is the wire contract.

The local response descriptor's transport profile must equal position 19. The
request's invitation, challenge, encryption key ID, verifier, and profile must
equal the corresponding signed or HPKE-bound values. The request expiration
must be within the invitation validity interval, and the endpoint expiration
must be no later than the request expiration.

After canonical parsing, admission validates the exact KeyPackage and compares
positions 11 through 17 with values extracted from that exact provider-validated
object. It then constructs the private non-`Clone` `VerifiedAdmission` consumed
directly by MLS Add. No detachable KeyPackage reference or reconstructed
KeyPackage may cross that seam.

Successful HPKE PSK opening proves possession of the high-entropy invitation
capability for this exact context. It does not prove human identity, approve the
request, reserve or consume the invitation, create MLS membership, or grant any
transport right beyond the nested one-purpose deposit capability.

## Proposed memory-transport boundary

The first adapter should model the accepted rights even though it has no
network:

```text
create_welcome_mailbox(now, expires_at)
  -> (LocalWelcomeDepositEndpoint, ReceiveCapability,
      AcknowledgementCapability)

send_welcome(endpoint, envelope_id, exact_opaque_envelope)
  -> DeliveryId

receive_welcome(receive_capability)
  -> zero or one ReceivedEnvelope

acknowledge_welcome(ack_capability, delivery_id)
  -> acknowledged
```

`RotationCapability` is not issued because the local one-use mailbox is never
rotated. A future reusable or network mailbox must add rotation explicitly; it
must not recover it from ambient state.

The adapter stores rights in separate internal records or derives independent
random values. It must not use one byte string with role flags. Each operation
validates the exact transport instance, mailbox, right, purpose, and expiration
before reading, copying, cloning, provider work, or state mutation.

### Deposit and idempotency lifecycle

The mailbox starts `Empty` and has these logical transitions:

```text
Empty
  exact valid first deposit -> Occupied(envelope_id, digest, exact bytes)

Occupied
  same envelope_id + same digest + same bytes -> Occupied (idempotent success)
  any different envelope -> unchanged rejection

Occupied
  authorized acknowledgement of delivered envelope -> Acknowledged

Any nonterminal state
  expiration -> Expired
```

The digest is an internal lookup optimization, not equality authority. Exact
bounded bytes and envelope ID must also compare so a digest collision cannot
replace the stored Welcome. The adapter must not recursively inspect the opaque
envelope payload.

The queue holds at most one logical envelope and one bounded exact copy. A
wrong, expired, malformed, cross-instance, cross-mailbox, or wrong-right
request returns a coarse error and leaves state unchanged. An expired endpoint
cannot be revived by a retry. The first adapter reuses the current 64 KiB
complete `OpaqueEnvelope` and 60 KiB ciphertext limits, and the envelope expiry
must be no later than the mailbox endpoint expiry.

The inviter's future outbox persists the exact protected Welcome envelope,
endpoint, envelope ID, and idempotency state in the inviter-local transaction.
After commit, it retries only those exact bytes. It never repeats MLS Add or
Commit and never releases the consumed invitation because delivery or
acknowledgement failed.

The joiner receives with its separate receive capability, validates and applies
the Welcome under the joining-client transaction described by ADR 0012, and
uses its acknowledgement capability for deletion/status handling. A malformed
or unusable Welcome can be acknowledged to stop redelivery only after the
client has retained enough coarse local result state to avoid ambiguity. Remote
acknowledgement is not evidence that inviter membership committed correctly.

## Required retained evidence before adoption

### Encoding and parser boundary

- retain canonical fixtures for the endpoint and complete 21-item request;
- round-trip through independent deterministic-CBOR implementations;
- reject maps, extra/missing/reordered array items, unknown object/profile/type
  values, tags, floats, indefinite lengths, non-preferred integers, trailing
  bytes, wrong fixed lengths, all-zero reserved identifiers, invalid time
  ordering, and nested profile or expiry mismatches;
- pre-bound the protected object, plaintext, nested descriptor, KeyPackage, and
  envelope before allocation, recursive parsing, cloning, or provider calls;
  and
- prove unknown/accessor-backed/symbol-keyed object data cannot enter a native
  authorization or serialization boundary if a JavaScript shell is later added.

### Capability and lifecycle behavior

- obtain all IDs and capabilities from an injected reviewed CSPRNG in
  production paths, with deterministic sources available only to tests;
- prove deposit cannot receive, acknowledge, delete, rotate, administer, or
  address another mailbox/instance;
- prove receive and acknowledgement capabilities cannot deposit or exercise
  each other's rights;
- prove exact retransmission succeeds without storing a second copy and a
  different second envelope cannot replace the first;
- reject wrong right, instance, mailbox, purpose, expiration, envelope ID, or
  byte content without mutation;
- prove the one-envelope and byte limits under concurrency and competing
  deposits; and
- prove capability bytes never appear in formatting, errors, logs, metrics,
  traces, URLs, test snapshots, or crash diagnostics.

### Join and outbox integration

- compare every signed/outer/HPKE/inner duplicate before reservation;
- reject replay and stale-generation requests, including same invitation ID
  and same request ID after expiry/reissue;
- consume the exact provider-validated KeyPackage only through a one-shot
  admission value;
- retain crash-point tests for the inviter-local membership/invitation/replay/
  result/Welcome-outbox transaction and prove restart retries only the exact
  committed envelope;
- retain separate joiner-local atomicity tests for joined group state and
  one-time KeyPackage deletion; and
- prove delivery and acknowledgement failures neither reopen an invitation nor
  roll back committed membership.

## Confidence, limitations, and unresolved work

Confidence is high that the proposed local descriptor preserves ADR 0010's
right separation and is small enough for a bounded Phase 1 transport slice.
Confidence is high that the invitation-scoped verifier key is the narrowest
context that satisfies capability admission without inventing hosted trust.

Confidence is medium in the exact lifecycle until concurrency, crash, and
outbox integration tests exist. The proposed 16-byte identifiers and 32-byte
capabilities also depend on a real CSPRNG-owned creation API; current repeated-
byte fixtures are not production evidence.

This packet provides no network confidentiality, source-address privacy,
host-compromise resistance, realm continuity, DNS trust, endpoint migration,
durable rollback protection, or production-readiness guarantee. The later local
implementation establishes only in-memory admission, delivery API, and
state-machine semantics.

Still unresolved for later profiles:

- the exact hosted realm descriptor, offline-root custody, generation and
  rollback semantics, and verifier-key rotation;
- network endpoint discovery, authentication, TLS and proxy policy, SSRF and
  redirect resistance, and metadata leakage;
- anonymous deposit abuse control and resource accounting;
- whether a network deposit right should remain bearer-only or become
  sender-constrained; and
- transport-specific replacement, revocation, draining, and migration.

## Adopted decision and next gate

ADR 0014 accepts the local Phase 1 protected request, assigns code points in the
normative specification, updates the threat model, and keeps hosted transport
out of scope. The next implementation slice should contain only:

1. protocol value types and canonical parsing for the local endpoint and inner
   request;
2. a right-specific in-memory one-Welcome mailbox with exact idempotency;
3. CSPRNG-owned creation with deterministic test injection; and
4. hostile-boundary tests without connecting admission, MLS membership,
   durability, or a network.

That slice should stop if it needs a URL, ambient credential, generic extension
map, hosted realm interpretation, or authority broader than one Welcome
deposit.
