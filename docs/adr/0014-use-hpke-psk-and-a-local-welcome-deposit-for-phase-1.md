# ADR 0014: Use HPKE PSK and a local Welcome deposit for Phase 1

Status: accepted; canonical protocol value types implemented, HPKE and stateful
integration unimplemented

Date: 2026-08-20

## Context

The Phase 1 laboratory has an authenticated secret-capability invitation, an
inviter-owned reservation lifecycle, exact MLS KeyPackage validation, and an
isolated two-party MLS lifecycle. It does not yet protect a join request before
the joiner is an MLS member, prove capability possession over the ADR 0009
binding, or return a Welcome through a right-specific transport.

ADR 0010 requires deposit, receive, acknowledgement, and rotation authority to
remain separate. ADR 0008 requires the inviter's future durable membership
transaction to commit the exact encrypted Welcome and an idempotent outbox job,
then deliver after commit without reopening the invitation. A Phase 1 response
descriptor must fit those contracts without prematurely defining hosted realm
identity, arbitrary network routes, or production rendezvous.

The supporting
[HPKE research](../research/HPKE_JOIN_REQUEST_PROFILE.md) reproduced PSK seal,
open, negative context checks, and bidirectional interoperability for the
selected suite. The
[response-deposit research](../research/PHASE1_RESPONSE_DEPOSIT_AND_VERIFIER_CONTEXT.md)
compared verifier and authority designs and proposed a closed local one-Welcome
mailbox.

## Decision

Adopt the exact local-only contract in
[`PROTECTED_CAPABILITY_JOIN_V1.md`](../specs/PROTECTED_CAPABILITY_JOIN_V1.md).
This is a protocol decision. The fixed canonical value types and AAD derivation
are now retained in `session-protocol`; that parser evidence is not an HPKE,
admission, transport, or production-security claim.

### Invitation and HPKE profile

- Introduce `SignedCapabilityInvitationV2`; never reinterpret accepted version
  1 bytes. Version 1 cannot trigger a plaintext, Base-mode, or compatibility
  fallback.
- Use RFC 9180 PSK mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and
  AES-128-GCM. The invitation's secret capability is the PSK.
- Production invitation creation must obtain the 32-byte capability and all
  other secret/random fields from a reviewed cryptographic generator. Length
  and nonzero checks do not prove entropy.
- Use one invitation-scoped X25519 recipient key pair, independent from the
  Ed25519 invitation signature key and capability. Reissue after expiry or
  revocation requires a fresh challenge, capability, encryption key ID, HPKE
  key pair, and signature key even if an invitation ID is deliberately reused.
- The adapter constructs the exact `psk_id`, `info`, and AAD from typed values.
  Callers cannot supply arbitrary HPKE mode, suite, domain, `info`, or AAD.
- The first implementation may reuse the already selected
  `mls-rs-crypto-awslc` provider behind a private one-shot join-protection
  boundary. Provider types and cloneable provider secrets do not cross that
  boundary. No new cryptographic primitive is implemented locally.

### Admission and verifier binding

Successful PSK-mode opening proves possession of the high-entropy capability
for the exact HPKE context. The inner request does not repeat the raw
capability, add a capability hash, or add a custom application HMAC.

For capability admission version 1, the intended verifier is the exact 32-byte
invitation-scoped Ed25519 verifying key authenticated by the signed invitation.
It is not a user, device, DNS, TLS, or realm identity and does not establish
continuity across invitations.

The inviter must compare every value duplicated among the signed invitation,
HPKE outer header, HPKE contexts, and inner request before reservation or other
state mutation. It then validates the exact canonical KeyPackage and complete
ADR 0009 tuple. HPKE success alone does not approve a request, reserve or
consume an invitation, or create MLS membership.

### Local Welcome deposit

The Phase 1 response descriptor is only
`LocalWelcomeDepositEndpointV1`. It carries a local transport instance ID,
mailbox ID, high-entropy deposit capability, transport profile, and expiration.
It carries no receive, acknowledgement, deletion, rotation, administration, URL,
hostname, arbitrary route, realm, header, metadata, or extension authority.

The joiner creates the mailbox and receives three separately typed values:

- a deposit endpoint moved into the protected join request;
- a receive capability retained locally; and
- an acknowledgement capability retained locally.

The local mailbox accepts one logical bounded `OpaqueEnvelope`. An exact retry
with the same envelope ID and bytes is idempotent. A different second envelope
cannot replace it. `DeliveryId` remains an untrusted identifier and cannot
authorize acknowledgement without the matching acknowledgement capability.
The local one-use mailbox has no rotation operation.

### Parsing and state ordering

All four schemas are fixed-length deterministic-CBOR arrays with explicit
versions and allowlisted object types. Maps, tags, floats, indefinite lengths,
generic extensions, trailing bytes, unsupported code points, invalid fixed
lengths, and non-preferred encodings are rejected. Complete input and each
variable field are bounded before allocation, recursive parsing, copying, or
cryptographic provider work.

Protected-request handling remains read-only through authentication, canonical
inner parsing, exact cross-context comparison, replay checks, and KeyPackage
validation. Invitation reservation occurs only after that admission boundary.
The later MLS Add, inviter-local durable transaction, Welcome outbox, and
joiner-local joined-state/KeyPackage-deletion transaction remain governed by
ADRs 0008, 0009, and 0012. This ADR does not make those steps atomic.

## Consequences and limits

- The next slice can implement exact protocol value types and a deterministic
  in-memory transport without a network, GUI, persistence layer, approval
  flow, or connected MLS membership transition.
- Hosted realm, public rendezvous, direct, relay, mixnet, and private-network
  endpoints require new transport-specific schemas. Version 1 has no generic
  route escape hatch.
- Credential, GitHub, manual, and hosted-realm proofs may need different
  verifier contexts and admission-proof versions. They must not overload the
  capability verifier bytes.
- The bearer deposit capability is appropriate only for this high-entropy,
  encrypted, short-lived, single-purpose local profile. Sender-constrained
  network authorization remains a future research question.
- A committed membership transition is not rolled back because Welcome deposit,
  receipt, or acknowledgement fails. Exact outbox retry is the recovery path.
- There is still no integrated join, durable replay protection, outbox,
  deployable client, network service, hosted trust, forward-secret deletion, or
  production-security claim.

## Alternatives considered

### HPKE Base mode plus a custom capability proof

Rejected. PSK mode already binds high-entropy shared-secret possession into the
standard key schedule. A separate HMAC or transmitted capability creates a
second proof construction and more secret copies.

### HPKE Auth or AuthPSK sender identity

Rejected for capability mode. A sender KEM identity adds lifecycle and
correlation without improving anonymous bearer-capability admission.

### Realm ID, DNS name, or URL as the Phase 1 verifier

Rejected. Local capability admission can bind the already authenticated
invitation key. Hosted identity, discovery, rotation, rollback, and migration
are separate decisions.

### Generic deposit route or extension map

Rejected. It would make unknown fields part of the authority and parsing
surface and silently import network, redirect, and SSRF behavior into the local
slice.

### Reuse receive authority for deposit or acknowledge by delivery ID

Rejected by ADR 0010. Either choice grants more authority than the operation
requires and makes leakage or confused-deputy failures harder to detect.

### Key-bound deposit capability for local memory

Deferred. It adds another key, signature, replay model, and lifecycle before a
network threat demonstrates the need. A future network profile can decide this
under a new schema.

## Upgrade and removal conditions

- Any field-layout, code-point, HPKE-domain, fixed-length, or canonicalization
  change requires a new schema version and compatibility/negative fixtures.
- Do not enable invitation v2 until capability, identifier, nonce, HPKE key,
  and signing-key creation are owned by a reviewed CSPRNG/provider API.
- Do not connect the contract to MLS membership until the one-shot admission
  ownership and before-mutation rejection matrix pass.
- Do not enable a network or user-facing join until the inviter-local durable
  transaction, exact Welcome outbox retry, joining-client transaction, crash,
  rollback, and replay evidence pass.
- Supersede this ADR before adding a generic route, hosted verifier meaning,
  another HPKE mode/suite, or authority broader than one local Welcome deposit.
