# ADR 0014: Use HPKE PSK and a local Welcome deposit for Phase 1

Status: accepted; canonical protocol values, one-shot HPKE, bounded in-memory
automated capability admission, and a separate local mailbox implemented;
integrated stateful flow unimplemented

Date: 2026-08-20

## Context

The Phase 1 laboratory has an authenticated secret-capability invitation, an
inviter-owned reservation lifecycle, exact MLS KeyPackage validation, an
isolated two-party MLS lifecycle, the selected one-shot protected join
operation, and an automated capability verifier owning the exact ADR 0009 value
with bounded in-memory replay reservation. The verifier now retains the exact
HPKE-opened invitation signature, binds that value to provider-generated local
v2 state, consumes an explicit simulated approval decision, and permits only
the approved one-shot value to enter MLS preparation. The laboratory does not
yet commit durable cross-layer state or connect the approved Welcome to the
separate right-specific local transport.

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
are retained in `session-protocol`. `session-crypto-hpke` now implements the
provider-neutral one-shot operation with the pinned AWS-LC provider; that
cryptographic evidence is not admission, replay, transport, or
production-security evidence.

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
- The public operation is one-shot. Internally, sealing creates the reviewed
  provider context first so the generated encapsulated key can be included in
  the exact AAD, seals once, and drops the context. Opening mirrors that order.
- The first implementation reuses the already selected
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

### Implemented evidence

`session-crypto-hpke` retains the official RFC 9180 PSK known-answer vector,
opens an AWS-LC-produced request with an independent dev-only HPKE
implementation, and rejects wrong keys, changed signed context, mismatched
inner bindings, and tampered encapsulation/ciphertext/AAD fields through one
coarse public error. Its fresh invitation X25519 key generation is provider
owned. The same provider boundary now generates and signs the complete
invitation-v2 context: invitation ID, challenge, bearer capability, encryption
key ID, Ed25519 signing seed, and HPKE keypair. Callers supply only issue and
expiration times.

`admission-capability` accepts only the private successful-open wrapper,
independently validates the exact KeyPackage through the MLS provider, compares
the canonical reference, credential identity, and leaf signature key, and owns
the parsed provider value. Its bounded in-memory replay reservation binds both
request ID and nonce to the invitation generation and uses a monotonic
reservation ID to prevent stale-release ABA. The same non-reconstructed provider
object and exact invitation signature move through local v2 reservation,
explicit simulated approval, and MLS preparation. Rejected, expired, failed, or
abandoned work releases invitation and replay state without changing membership;
successful in-memory Add consumes the invitation before returning its outputs.
This is not human UI approval, a durable membership transaction, durable replay
protection, or a Welcome outbox.

`session-transport` separately implements the local one-Welcome mailbox. It
generates independent deposit, receive, and acknowledgement authorities,
stores only domain-separated authority commitments, bounds mailbox count and
lifetime, and retains exact-retry and rejection evidence. It deliberately has
no rotation operation. This adapter is not yet connected to the approved join
result and is not durability, networking, anonymity, or production evidence.

## Consequences and limits

- The next slice can connect the approval-gated ownership chain to the existing
  right-specific in-memory transport without claiming persistence or a
  networked product.
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
- There is still no durable approved invitation-to-admission transaction,
  durable replay protection, outbox,
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
- Inviter-owned lifecycle state may accept invitation v2 only through the
  provider-generated wrapper; it must not add a caller-constructed claims path.
- Do not connect the contract to MLS membership until the one-shot admission
  ownership and before-mutation rejection matrix pass.
- Do not enable a network or user-facing join until the inviter-local durable
  transaction, exact Welcome outbox retry, joining-client transaction, crash,
  rollback, and replay evidence pass.
- Supersede this ADR before adding a generic route, hosted verifier meaning,
  another HPKE mode/suite, or authority broader than one local Welcome deposit.
