# Spec: Protected capability join v1

Status: accepted contract under ADR 0014; canonical protocol value types
implemented, cryptographic and stateful behavior unimplemented

## Objective

Define the first encrypted capability-authorized join request and its local
one-Welcome response mailbox. The contract lets a future headless Phase 1
client prove possession of one high-entropy invitation capability, bind that
proof to the exact ADR 0009 KeyPackage tuple, and give the inviter only the
authority required to deposit the resulting Welcome.

The retained protocol crate implements the four canonical value types, strict
decoders, exact fixtures, and outer AAD derivation. This specification does not
implement HPKE operations, capability verification, approval, invitation
reservation, MLS membership, mailbox behavior, durable state, outbox
processing, hosted realm trust, a network transport, or a deployable client.

## Assumptions

1. The invitation is secret because it carries a bearer capability used as an
   HPKE PSK. It is not a publicly postable targeted invitation.
2. Production creation obtains every secret and random identifier from a
   reviewed CSPRNG/provider. Deterministic injection is test-only.
3. The intended verifier for this capability proof is the exact
   invitation-scoped Ed25519 key, not a global identity or realm trust root.
4. The response mailbox is an in-process deterministic adapter. A network or
   hosted route uses a different descriptor schema.
5. Every received byte and timestamp is attacker-controlled. Authentication,
   canonical parsing, comparison, replay, and policy checks are read-only.
6. ADRs 0008, 0009, 0010, 0012, and 0014 remain authoritative for state,
   ownership, authority, MLS, and provider behavior.

## Tech stack

- Rust 1.97.1, edition 2024, with `unsafe` forbidden by the participating crates
- `minicbor` 2.3.0 and ADR 0005's restricted deterministic-CBOR profile
- `ed25519-dalek` 3.0.0 for strict invitation signatures
- the pinned `mls-rs-crypto-awslc` 0.25.0 provider boundary for the proposed
  first HPKE adapter, without exposing provider types
- the existing exact `thiserror` and `zeroize` workspace dependencies for
  coarse errors and owned-secret cleanup

## Cryptographic profile

`InvitationEncryptionSuite = 1` means exactly:

| Component | IANA identifier | Algorithm |
| --- | ---: | --- |
| KEM | `0x0020` | DHKEM(X25519, HKDF-SHA256) |
| KDF | `0x0001` | HKDF-SHA256 |
| AEAD | `0x0001` | AES-128-GCM |
| Mode | `0x01` | PSK |

The 32-byte `SecretCapability` from the invitation is the PSK. The invitation
creator must establish that it contains 256 bits from a reviewed cryptographic
generator. A decoder can prove only fixed length and the reserved nonzero rule.

The HPKE recipient X25519 key pair is fresh per invitation generation and
independent from the Ed25519 invitation key and capability. Private provider
types remain behind a non-`Clone`, non-`Debug`, zeroizing Session Chat wrapper.

### PSK identifier

Both sides construct:

```text
ASCII("session-chat/invitation-capability-psk/v1") || 0x00 ||
invitation_id[16] || join_challenge[32] || invitation_key_id[16]
```

The PSK identifier is non-empty and never contains the capability or its hash.

### HPKE info

Both sides construct:

```text
ASCII("session-chat/join-request-hpke/v1") || 0x00 ||
invitation_schema_u16_be || invitation_encryption_suite_u16_be ||
join_request_schema_u16_be || application_protocol_u16_be ||
transport_profile_u16_be ||
invitation_id[16] || join_challenge[32] || invitation_key_id[16] ||
recipient_public_key[32] || inviter_ed25519_verifying_key[32]
```

These are fixed raw byte constructions, not CBOR. Callers never provide a
free-form domain, `psk_id`, `info`, AAD, mode, or suite.

## Code-point registry

| Registry | Value | Meaning |
| --- | ---: | --- |
| Wire object type | `1` | `OpaqueEnvelope` (existing) |
| Wire object type | `2` | `SignedCapabilityInvitation` (existing type, versioned layout) |
| Wire object type | `3` | `ProtectedJoinRequestV1` |
| Nested object type | `4` | `CapabilityJoinRequestV1` |
| Nested object type | `5` | `LocalWelcomeDepositEndpointV1` |
| Signature suite | `1` | Ed25519 strict verification |
| Invitation encryption suite | `1` | RFC 9180 profile above |
| Admission mode | `1` | Secret capability |
| Invitation use policy | `1` | Single use |
| Admission-proof version | `1` | HPKE PSK capability possession |
| Credential type | `1` | MLS BasicCredential |
| MLS protocol version | `1` | MLS 1.0 |
| MLS ciphersuite | `1` | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` |
| Application protocol version | `1` | Phase 1 Session Chat application selection; no message-body schema is implied |
| Transport profile | `1` | Local memory |

Unknown values fail closed. These code points do not authorize another mode,
suite, transport, or compatibility fallback.

## Restricted encoding profile

All schemas below use ADR 0005's deterministic-CBOR profile:

- fixed-length arrays and definite-length byte strings;
- shortest preferred integer encodings;
- no maps, tags, floats, text fields, indefinite-length items, or generic
  extensions;
- exact field count, field type, and fixed-byte length;
- no trailing data; and
- decode, re-encode, and byte-for-byte equality before acceptance.

The complete protected outer object is limited to 32 KiB before CBOR parsing.
The HPKE ciphertext is non-empty and limited such that the complete encoded
object remains within that bound. The decrypted canonical inner request is
limited to 24 KiB before CBOR parsing. The nested KeyPackage is non-empty and
limited to 16 KiB before TLS parsing. Fixed-size checks happen before copying
into arrays or invoking cryptographic providers.

## Signed capability invitation v2

`SignedCapabilityInvitationV2` is a fixed 18-item array:

| Position | Field | Constraint |
| ---: | --- | --- |
| 0 | Invitation schema version | unsigned integer `2` |
| 1 | Object type | unsigned integer `2` |
| 2 | Signature suite | unsigned integer `1` |
| 3 | Invitation encryption suite | unsigned integer `1` |
| 4 | Join-request schema | unsigned integer `1` |
| 5 | Application protocol version | unsigned integer `1` |
| 6 | Transport profile | unsigned integer `1` for local memory |
| 7 | Invitation ID | exactly 16 nonzero bytes |
| 8 | Issued at | unsigned 64-bit Unix seconds |
| 9 | Expires at | unsigned 64-bit Unix seconds; later than issue time |
| 10 | Admission mode | unsigned integer `1` |
| 11 | Use policy | unsigned integer `1` |
| 12 | Join challenge | exactly 32 nonzero bytes |
| 13 | Secret capability/HPKE PSK | exactly 32 nonzero CSPRNG bytes |
| 14 | Inviter verifying key | exactly 32-byte valid Ed25519 public key |
| 15 | Invitation encryption key ID | exactly 16 nonzero CSPRNG bytes |
| 16 | HPKE recipient public key | exactly 32 nonzero bytes; provider-generated at local creation |
| 17 | Signature | exactly 64-byte Ed25519 signature |

The complete invitation remains limited to 512 bytes before parsing.

The signature input is:

```text
ASCII("session-chat/signed-invitation/v2") || 0x00 ||
canonical_cbor(array positions 0 through 16)
```

Verification uses strict Ed25519 verification. Version 1 and version 2 use
different signature domains and layouts. Reissue after expiry or revocation
requires a fresh challenge, capability, signature key, encryption key ID, and
HPKE key pair even if the caller deliberately reuses the invitation ID.

## Protected join-request outer object

`ProtectedJoinRequestV1` is a fixed seven-item array:

| Position | Field | Constraint |
| ---: | --- | --- |
| 0 | Protected-request schema version | unsigned integer `1` |
| 1 | Object type | unsigned integer `3` |
| 2 | Invitation encryption suite | unsigned integer `1` |
| 3 | Invitation ID | exactly 16 nonzero bytes |
| 4 | Invitation encryption key ID | exactly 16 nonzero bytes |
| 5 | HPKE encapsulated value | exactly 32 bytes; selected provider must reject an invalid KEM value |
| 6 | HPKE ciphertext and tag | non-empty; complete object at most 32 KiB |

AAD is exactly the canonical deterministic-CBOR encoding of a six-item array
containing positions 0 through 5. Position 6 is excluded from its own AAD.

Before HPKE open, the inviter parses the bounded outer object and locates one
exact local invitation generation by invitation ID and encryption key ID. It
does not reserve, consume, create replay state, or expose provider diagnostics
on failure.

The local Phase 1 invitation contains no request-delivery URL or route. A test
harness or later headless composition root passes the exact protected bytes to
the inviter's local handler. Adding rendezvous or network routing requires a
new signed invitation and transport descriptor version.

## Canonical inner capability request

The HPKE plaintext is a fixed 21-item `CapabilityJoinRequestV1` array:

| Position | Field | Constraint |
| ---: | --- | --- |
| 0 | Join-request schema version | unsigned integer `1` |
| 1 | Object type | unsigned integer `4` |
| 2 | Admission-proof version | unsigned integer `1` |
| 3 | Invitation ID | exactly 16 nonzero bytes |
| 4 | Join challenge | exactly 32 nonzero bytes |
| 5 | Invitation encryption key ID | exactly 16 nonzero bytes |
| 6 | Intended verifier | exact 32-byte invitation Ed25519 verifying key |
| 7 | Join-request ID | exactly 16 nonzero CSPRNG bytes |
| 8 | Issue time | unsigned 64-bit Unix seconds |
| 9 | Expiration | unsigned 64-bit Unix seconds; later than issue time |
| 10 | Request nonce | exactly 32 nonzero CSPRNG bytes |
| 11 | MLS protocol version | unsigned integer `1` |
| 12 | MLS ciphersuite | unsigned integer `1` |
| 13 | KeyPackage reference | exactly 32 bytes under ciphersuite 1 |
| 14 | Canonical KeyPackage | non-empty exact TLS object; at most 16 KiB |
| 15 | Credential type | unsigned integer `1` |
| 16 | Credential identity | exactly 32 nonzero session-scoped bytes |
| 17 | Leaf signature key | exactly 32-byte valid, non-weak Ed25519 key |
| 18 | Application protocol version | unsigned integer `1` |
| 19 | Transport profile | unsigned integer `1` for local memory |
| 20 | Response deposit endpoint | exact nested seven-item endpoint array |

Request issue and expiration must fall within the invitation's accepted
validity interval and configured skew/lifetime policy. Every field duplicated
from the signed invitation, outer object, or HPKE contexts compares exactly.

After canonical parsing, the inviter validates the exact KeyPackage through the
selected provider and compares positions 11 through 17 with values extracted
from that same owned provider-validated object. Only then may admission produce
the private non-`Clone` value consumed directly by MLS Add.

Successful HPKE open is only the capability-possession proof for this context.
It does not approve the request, mutate invitation state, or establish
membership.

## Local Welcome deposit endpoint

Position 20 contains a fixed seven-item
`LocalWelcomeDepositEndpointV1` array:

| Position | Field | Constraint |
| ---: | --- | --- |
| 0 | Endpoint schema version | unsigned integer `1` |
| 1 | Object type | unsigned integer `5` |
| 2 | Transport profile | unsigned integer `1` |
| 3 | Transport instance ID | exactly 16 nonzero CSPRNG bytes |
| 4 | Mailbox ID | exactly 16 nonzero CSPRNG bytes |
| 5 | Deposit capability | exactly 32 nonzero CSPRNG bytes |
| 6 | Expiration | unsigned 64-bit Unix seconds |

The endpoint expiration is no later than the inner request expiration and is
within configured local lifetime/skew policy. Its transport profile equals
inner position 19 and signed invitation position 6.

This endpoint contains deposit authority only. It has no receive,
acknowledgement, deletion, rotation, administration, URL, hostname, IP address,
port, proxy, redirect, arbitrary route, realm, identity, HTTP field, generic
metadata, or extension.

The secret-bearing endpoint is moved into the request builder. Receive and
acknowledgement capabilities are separately generated, typed, and retained by
the joiner. No secret-bearing authority type implements `Clone`, `Debug`, or
`Display` or enters errors, logs, metrics, traces, URLs, clipboard data, or
crash reports.

## Local mailbox lifecycle

The first transport exposes the conceptual operations:

```text
create_welcome_mailbox(now, expires_at)
  -> (LocalWelcomeDepositEndpoint, ReceiveCapability,
      AcknowledgementCapability)

send_welcome(endpoint, exact_opaque_envelope)
  -> DeliveryId

receive_welcome(receive_capability)
  -> zero or one ReceivedEnvelope

acknowledge_welcome(acknowledgement_capability, delivery_id)
  -> acknowledged
```

The adapter models separate random authority values rather than one secret plus
permission flags. Every operation validates the exact transport instance,
mailbox, right, purpose, and expiration before reading, copying, provider work,
or mutation. `DeliveryId` is untrusted and is never sufficient authority.

The state machine is:

```text
Empty
  exact valid first deposit -> Occupied(envelope_id, digest, exact bytes)

Occupied
  same envelope_id + same digest + same bytes -> Occupied (idempotent success)
  any different envelope -> Occupied (coarse rejection, unchanged)

Occupied
  matching acknowledgement capability + delivery ID -> Acknowledged

Empty or Occupied
  expiration -> Expired
```

The digest is only an internal lookup optimization. Exact bounded bytes and the
envelope ID remain equality authority. The adapter does not recursively inspect
the opaque ciphertext.

The queue holds at most one logical envelope and one exact copy. It reuses the
current `OpaqueEnvelope` limits: 64 KiB complete canonical object and 60 KiB
ciphertext. The envelope expiration is no later than the endpoint expiration.
An expired endpoint cannot be revived by retry.

The local profile issues no `RotationCapability`. A future reusable or network
mailbox introduces rotation explicitly under a new schema.

## Processing order

The inviter performs, without mutation through step 7:

1. pre-bound and canonically parse the protected outer object;
2. locate the exact locally issued invitation generation;
3. enforce invitation, version, suite, and time policy;
4. construct typed HPKE contexts and open with one coarse failure result;
5. pre-bound and canonically parse the zeroizing plaintext and nested endpoint;
6. compare every outer, signed, HPKE, and inner binding exactly;
7. enforce replay policy and validate the exact KeyPackage/ADR 0009 tuple;
8. produce the one-shot admission value and only then reserve the invitation;
9. after approval, consume that value directly into MLS Add; and
10. later commit and deliver under the separate ADR 0008/0012 transaction and
    outbox contracts.

Unknown, malformed, expired, replayed, stale-generation, wrong-suite,
wrong-context, or authentication-failed input leaves invitation, replay,
admission, MLS, mailbox, and outbox state unchanged.

## Project structure for the first implementation increment

```text
crates/session-protocol/       # canonical invitation v2, outer, inner, endpoint types
crates/session-protocol/tests/ # exact fixtures and hostile decoding matrix
docs/specs/                    # this normative contract
docs/adr/                      # ADR 0014 decision rationale
```

The right-specific memory transport is a subsequent increment under
`crates/session-transport`; HPKE provider adaptation, admission orchestration,
MLS wiring, durability, and `sessionctl` remain later slices.

## Code style

Public wire types keep fields private, own their bounded canonical bytes where
necessary, and expose typed accessors. Parsing returns coarse structural errors
without secret content:

```rust
let protected = ProtectedJoinRequest::decode_canonical(attacker_bytes)?;
let invitation = registry.lookup_generation(
    protected.invitation_id(),
    protected.invitation_key_id(),
)?;
let request = protector.open_and_decode(invitation, protected)?;
```

Secret-bearing types do not implement `Clone`, `Debug`, or `Display`. Public
APIs accept typed versions and profiles rather than caller-provided numeric or
cryptographic context bytes. No panic, wall-clock read, ambient credential,
network call, or provider diagnostic is allowed on attacker-controlled decode
paths.

## Testing strategy

### Encoding fixtures

- retain exact canonical bytes and decoded accessors for all four schemas;
- independently reproduce the RFC 9180 PSK known-answer vector for the selected
  suite and retain an AWS-LC/independent-provider interoperability fixture;
- prove version 1 invitation fixtures remain byte-identical and cannot be
  decoded as version 2; and
- prove outer AAD, `psk_id`, and `info` change when any bound field changes.

### Hostile parsing

- reject every missing, extra, reordered, mistyped, wrong-length, zero-reserved,
  unknown, unsupported, trailing, non-preferred, indefinite, over-limit, or
  cross-schema field before state mutation;
- reject maps, tags, floats, text substitutions, generic extensions, invalid
  Ed25519/X25519 keys, empty ciphertext, and malformed/trailing KeyPackages;
- pre-bound complete and nested data before recursive parsing, allocation,
  copying, or authorization; and
- if a JavaScript boundary is later added, reject oversized, deep, cyclic,
  accessor-backed, symbol-keyed, or unknown data before native cloning or
  authorization.

### Cryptographic and admission binding

- reject wrong PSK, PSK ID, recipient key, `info`, AAD, suite, invitation
  generation, verifier, challenge, request ID, nonce, time, protocol, transport,
  KeyPackage/reference, credential, and leaf key;
- reject stale requests across expiry/reissue even when invitation and request
  IDs recur;
- collapse provider failures to a coarse error and prove secret/provider
  diagnostics never escape; and
- prove every rejection through KeyPackage validation leaves all state
  unchanged.

### Mailbox authority and state

- prove each capability can exercise only its named right;
- reject another instance, mailbox, right, purpose, expiry, envelope ID, or
  bytes without mutation;
- prove exact retransmission is idempotent and a different second envelope
  cannot replace the first;
- prove the one-envelope and byte limits under competing deposits; and
- prove delivery or acknowledgement failure cannot reopen a consumed
  invitation or roll back committed membership when later integration exists.

## Commands

First protocol increment:

```sh
cargo test -p session-protocol --test protected_capability_join
cargo test -p session-protocol --all-features --locked --offline
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo test --workspace --all-features --locked --offline
```

Documentation-only decision increment:

```sh
node scripts/check-repository.mjs
node --test scripts/check-repository.test.mjs scripts/setup-codex-links.test.mjs
git diff --check
```

## Boundaries

- Always: pre-bound attacker data; use exact canonical encodings; keep all
  secrets and plaintext out of diagnostics; use reviewed crypto providers;
  compare every binding before mutation; keep authority right-specific; retain
  compatibility and negative fixtures.
- Ask first: add persistence, connect admission to MLS, add a network endpoint,
  add another admission method, suite, provider, transport, or verifier
  context, or expose the schema through a UI/deep link.
- Never: reinterpret invitation v1, downgrade or fall back, accept generic route
  data, derive one key from another, add custom cryptographic primitives, grant
  receive/acknowledgement/rotation through the deposit endpoint, use ambient
  credentials, or claim durability/production security from an in-memory test.

## Success criteria

1. Every schema has one exact fixture and rejects all non-canonical variants.
2. Invitation v1 behavior and bytes remain unchanged.
3. HPKE contexts and the inner request bind the complete accepted tuple.
4. Wrong or stale context fails before any lifecycle or provider-owned state
   mutation.
5. The exact validated KeyPackage remains linearly owned through admission and
   MLS Add in the later integration.
6. Deposit, receive, and acknowledgement authority cannot substitute for one
   another.
7. One exact Welcome may be retried idempotently; another cannot replace it.
8. No capability, private key, plaintext, or provider detail reaches formatting
   or telemetry.
9. All repository gates pass with the exact lockfile.

## Deferred questions

- Hosted realm verifier and response endpoint schemas
- Network authentication, discovery, proxy, redirect, and SSRF policy
- Anonymous deposit abuse control and resource accounting
- Sender-constrained network deposit authorization
- Durable invitation/admission/MLS/outbox and joiner transactions
- Approval UX and headless orchestration
- Credential, GitHub, manual, and targeted public invitation schemas
