# HPKE and capability join-request research packet

Status: research complete; framing adopted and implemented under ADR 0014;
HPKE operation unimplemented

Reviewed: 2026-08-19

Decision record: ADR 0014 and `docs/specs/PROTECTED_CAPABILITY_JOIN_V1.md`

## Decision question and scope

Which HPKE mode, ciphersuite, provider boundary, and version-binding rules should
protect the first capability-authorized join request before the requester is an
MLS member?

This packet is deliberately narrower than a complete network join protocol. It
compares released Rust implementations, reproduces a one-shot PSK flow, and
drafts the cryptographic wrapper and admission binding. This packet itself is
research; ADR 0014 later adopts the local contract. Neither document adds a
dependency, implements admission, defines a production rendezvous descriptor,
or claims that a networked join path exists.

The protocol crate now retains invitation v2 with an HPKE recipient public key,
while preserving invitation-v1 bytes and signature domain unchanged. The core
and MLS adapter remain separate in-memory state machines and expose no encrypted
join-request operation. The provider-neutral HPKE operation remains the next
implementation boundary.

## Executive conclusion

Propose RFC 9180 PSK mode with the following exact algorithm triple for the
first laboratory profile:

- KEM `0x0020`: DHKEM(X25519, HKDF-SHA256);
- KDF `0x0001`: HKDF-SHA256; and
- AEAD `0x0001`: AES-128-GCM.

Use the invitation's 32-byte secret capability as the HPKE PSK, but only after
the invitation creator obtains it from a reviewed cryptographic random-number
generator. The current `SecretCapability` constructor checks length and rejects
the reserved all-zero value; it does not establish the RFC requirement that the
PSK contain at least 32 bytes of entropy.

For the first adapter, reuse the already pinned `mls-rs-crypto-awslc` 0.25.0
`CipherSuiteProvider` behind a narrow, provider-neutral, one-shot
join-protection interface. Its current graph already contains
`mls-rs-crypto-hpke` 0.21.0 and AWS-LC, and its public API exposes PSK seal and
open. Do not add standalone `hpke` 0.14.0 merely to implement the same suite.
Retain that pure-Rust crate as an interoperability oracle and possible future
alternative, subject to a fresh dependency review.

Do not use HPKE Auth or AuthPSK mode for capability invitations. A sender KEM
identity is unnecessary for bearer-capability admission, adds another key
lifecycle, and becomes a correlation surface if reused. Do not use Base mode
plus a custom HMAC. PSK mode already standardizes proof of high-entropy shared-
secret possession in the HPKE key schedule.

ADR 0014 accepts this recommendation for the local Phase 1 contract. The
normative specification assigns the exact schemas and code points. Adoption is
not implementation: retained fixtures, a CSPRNG-owned invitation-creation API,
and the negative evidence listed below remain required.

## Method and source index

Primary standards and upstream project materials were preferred. Published
crate sources and temporary exact-version Cargo graphs were inspected in
addition to repository code.

- [RFC 9180: Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180.html),
  especially sections 5.1.2, 7, 9.5, 9.7, 10, and appendix A.1.2.
- [`mls-rs` 0.56.0 source and security notice](https://github.com/awslabs/mls-rs/tree/0.56.0).
- [`mls-rs-core` 0.27.0 HPKE provider contract](https://docs.rs/mls-rs-core/0.27.0/mls_rs_core/crypto/trait.CipherSuiteProvider.html).
- [`mls-rs-crypto-awslc` 0.25.0](https://docs.rs/mls-rs-crypto-awslc/0.25.0/mls_rs_crypto_awslc/).
- [`hpke` 0.14.0](https://docs.rs/crate/hpke/0.14.0), including its exact
  feature and known-answer-test documentation.
- [`hpke-rs` 0.6.1](https://docs.rs/crate/hpke-rs/0.6.1) and its published
  libcrux provider graph.
- [RustSec advisories for `hpke-rs`](https://rustsec.org/packages/hpke-rs.html)
  and the exact advised libcrux packages resolved by the disposable graph.
- Current repository contracts: ADR 0005, ADR 0007, ADR 0008, ADR 0009, ADR
  0010, ADR 0012, the signed invitation specification, architecture, threat
  model, and dependency policy.

All web/project facts in this packet were checked on 2026-08-19. Advisory and
release status can change and must be refreshed when the recommendation is
adopted.

## Standards facts

- RFC 9180 PSK mode binds a `psk` and non-empty `psk_id` into the HPKE key
  schedule. It authenticates that the sender possessed the PSK.
- The RFC requires a PSK with at least 32 bytes of entropy and warns that the
  construction is unsuitable for a low-entropy password. An observable
  successful/failed decryption path can become a dictionary oracle for a weak
  PSK.
- HPKE defines no application wire format. An embedding must unambiguously
  encode at least the encapsulated value, ciphertext, order when multiple
  ciphertexts exist, and non-implicit context such as recipient-key selection.
- HPKE does not provide general replay protection, application downgrade
  prevention, a rendezvous protocol, or a durable one-time-consumption state
  machine. Session Chat must provide those properties around HPKE.
- HPKE ciphertexts are not forward secret with respect to compromise of the
  recipient's long-lived secrets. Invitation-key lifetime and deletion remain
  application responsibilities.
- RFC 9180 includes PSK known-answer vectors for the proposed X25519,
  HKDF-SHA256, AES-128-GCM suite.

## Repository observations

- The version 1 `SignedCapabilityInvitation` signs a 32-byte join challenge, a
  32-byte bearer capability, and an invitation-scoped Ed25519 verifying key. It
  does not contain an HPKE recipient key, HPKE suite, key identifier, or
  encrypted join-request schema identifier.
- `SecretCapability::new` accepts any non-zero 32-byte array. Callers currently
  own entropy provenance; fixtures intentionally use deterministic repeated
  bytes. No production capability-generation function exists.
- ADR 0009 requires admission to bind the invitation and challenge, join
  request, canonical MLS KeyPackage reference, MLS version and ciphersuite,
  credential identity and leaf signature key, intended verifier, validity
  interval, and admission-proof version.
- The current exact workspace graph already contains `mls-rs-crypto-hpke`
  0.21.0 through `mls-rs-crypto-awslc` 0.25.0. Its selected MLS ciphersuite 1
  uses the same HPKE algorithm triple proposed here.
- `mls-rs-core` exposes one-shot `hpke_seal_psk` and `hpke_open_psk`; the
  AWS-LC provider implements both. Its upstream secret-key representation is
  cloneable, so a Session Chat adapter must keep it behind a private,
  non-`Clone` wrapper rather than leaking the provider type.
- The repository's present dependency policy allows Apache-2.0 and MIT but not
  MPL-2.0. No policy exception should be inferred from this comparison.

## Disposable reproduced evidence

The experiments were run outside the repository on macOS aarch64 with the
locally pinned Rust toolchain. Temporary source and locks are intentionally not
retained as product code.

### Existing AWS-LC provider

An exact disposable graph using only `mls-rs-core` 0.27.0 and
`mls-rs-crypto-awslc` 0.25.0 generated an X25519 key pair and completed one-shot
PSK seal/open with the proposed suite. Open failed when any of the following was
changed:

- the 32-byte PSK;
- the PSK identifier;
- the `info` protocol context; or
- the authenticated outer-header bytes.

`cargo audit --no-fetch` scanned the resulting 51-package graph against 1,169
locally cached advisories and returned no vulnerability. That is a dated
database observation, not a security audit.

### Standalone `hpke` alternative

Exact `hpke` 0.14.0 compiled and completed the same PSK flow with default
features disabled and only `aes`, `alloc`, `getrandom`, and `x25519` enabled.
The disposable graph contained 41 packages including its root and was clean
against the same local advisory snapshot.

A combined experiment generated the recipient key with the AWS-LC provider and
proved interoperability in both directions:

1. AWS-LC PSK seal, `hpke` 0.14.0 open; and
2. `hpke` 0.14.0 PSK seal, AWS-LC open.

The experiment used the exact proposed algorithms, PSK, PSK identifier, `info`,
and AAD. This establishes API and representation feasibility, not a retained
cross-provider fixture or a complete independent implementation audit.

### `hpke-rs`/libcrux alternative

Exact `hpke-rs` 0.6.1 with its libcrux and `std` features resolved 130 packages
including the disposable root. `cargo audit --no-fetch` reported six
vulnerabilities in the resolved graph:

- `RUSTSEC-2026-0207` and `RUSTSEC-2026-0208` in `libcrux-sha3`;
- `RUSTSEC-2026-0209` and `RUSTSEC-2026-0211` in `libcrux-aesgcm`;
- `RUSTSEC-2026-0124` in `libcrux-chacha20poly1305`; and
- `RUSTSEC-2026-0212` in `libcrux-secrets`.

The same graph reported two unmaintained warnings, and the directly evaluated
crates use MPL-2.0 outside the current allowlist. This exact provider graph is
not eligible for adoption. No advisory or license exception is proposed.

## Option comparison

| Option | Security construction | Dependency/provider result | Decision |
| --- | --- | --- | --- |
| AWS-LC PSK mode through the pinned `mls-rs` provider | Standard PSK mode; exact proposed suite; one-shot API | Already in the selected graph; disposable negative and interoperability checks pass; upstream `mls-rs` still lacks a full independent third-party audit | Propose for the first laboratory adapter |
| Standalone `hpke` 0.14.0 PSK mode | Standard PSK mode; exact proposed suite; compile-time suite selection and RFC vectors | Reduced graph passes the dated advisory check and interoperates, but adds a second cryptographic implementation and duplicate primitives | Retain as oracle/fallback, not a new runtime dependency now |
| `hpke-rs` 0.6.1 with libcrux | Standard PSK mode and provider abstraction | Exact graph has six current vulnerabilities, unmaintained warnings, and an unapproved license | Reject this released graph |
| HPKE Base mode with capability in plaintext | Recipient encryption only; bearer capability is retransmitted inside ciphertext | Technically feasible but needlessly copies the bearer secret and does not authenticate possession in the HPKE key schedule | Reject |
| HPKE Base mode plus application HMAC | Separate custom composition for possession proof | Adds a second proof construction, domains, keys, and verification ordering when PSK mode already exists | Reject |
| HPKE Auth or AuthPSK | Static sender KEM key authenticates a key holder | Adds sender-key lifecycle and a correlation surface inconsistent with anonymous capability admission | Reject for capability mode |

## Proposed provider-neutral boundary

The public application/core API should not expose provider HPKE types or accept
arbitrary `info`, AAD, mode, or suite bytes. A narrow internal contract should
own the profile:

```text
InvitationJoinProtector
  generate_invitation_key() -> (non-clone secret, public key)
  seal_capability_request(verified invitation context, bounded canonical plaintext)
      -> bounded protected join request
  open_capability_request(owned invitation secret, verified invitation context,
                          bounded protected join request)
      -> zeroizing canonical plaintext or one coarse rejection
```

Required properties:

- one-shot HPKE only; no reusable application-visible HPKE contexts;
- exactly one allowlisted suite in the first implementation;
- secret key and capability types are non-`Clone`, non-`Debug`, and zeroized on
  drop to the extent Rust ownership can provide;
- the adapter, not callers, constructs `info`, `psk_id`, and AAD from typed
  context;
- all input-size and fixed-field checks happen before provider calls or cloning;
- provider errors collapse to a coarse rejection before crossing the adapter;
- no runtime-loaded plugin, network-fetched provider, silent suite fallback, or
  active-invitation provider swap; and
- provider selection remains independent from the provider-neutral established
  message-session interface in ADR 0013.

## Researched cryptographic profile

These byte constructions were the draft inputs to ADR 0014. The normative
layouts and code points now live in
[`PROTECTED_CAPABILITY_JOIN_V1.md`](../specs/PROTECTED_CAPABILITY_JOIN_V1.md);
this packet remains the supporting research record.

### Invitation versioning

Introduce `SignedCapabilityInvitationV2`; never reinterpret accepted version 1
bytes. Version 2 adds signed fields for:

- invitation encryption suite;
- join-request schema version;
- application protocol version;
- local transport profile;
- random 16-byte invitation-encryption key identifier; and
- exact 32-byte X25519 recipient public key.

The HPKE key pair is invitation-scoped, generated independently from the
invitation signing key and capability, and never derived from either. Reissuing
an expired/revoked invitation—even with the same invitation ID—requires a fresh
challenge, capability, signature key, key pair, and key identifier. Version 1
invitations remain usable only by the current laboratory behavior; they must not
trigger an unencrypted network-join fallback.

### PSK identifier

The PSK identifier is implicit and constructed exactly as:

```text
ASCII("session-chat/invitation-capability-psk/v1") || 0x00 ||
invitation_id[16] || join_challenge[32] || invitation_key_id[16]
```

It contains no capability bytes or capability hash. Both sides derive it from
the strictly verified signed invitation. The fixed-length suffix makes the
construction unambiguous.

### HPKE `info`

The HPKE `info` value is implicit and constructed exactly as:

```text
ASCII("session-chat/join-request-hpke/v1") || 0x00 ||
invitation_schema_u16_be || invitation_encryption_suite_u16_be ||
join_request_schema_u16_be || application_protocol_u16_be ||
transport_profile_u16_be ||
invitation_id[16] || join_challenge[32] || invitation_key_id[16] ||
recipient_public_key[32] || inviter_ed25519_verifying_key[32]
```

This binds the HPKE operation to the selected invitation, request, application,
and transport profiles, exact signed invitation generation, recipient key, and
intended invitation-scoped verifier. Integer encodings here are fixed-width
network byte order; this construction is not a CBOR object.

### Protected outer object

`ProtectedJoinRequestV1` is a fixed seven-item deterministic-CBOR array under
the accepted specification:

| Position | Field | Draft constraint |
| ---: | --- | --- |
| 0 | Wire schema version | unsigned integer `1` |
| 1 | Object type | unsigned integer `3` |
| 2 | Invitation encryption suite | unsigned integer `1` |
| 3 | Invitation ID | exactly 16 bytes |
| 4 | Invitation key ID | exactly 16 bytes |
| 5 | HPKE encapsulated value | exactly 32 bytes for X25519 |
| 6 | HPKE ciphertext and tag | non-empty; bounded before allocation/copy |

AAD is the exact canonical deterministic-CBOR encoding of positions 0 through
5 as a six-item array. The ciphertext field is excluded from its own AAD. The
encapsulated value is already part of HPKE's KEM computation; including it in
the application AAD also binds the complete visible header representation.

The proposed maximum canonical inner plaintext is 24 KiB and the proposed
maximum complete protected object is 32 KiB. These limits accommodate the
existing 16 KiB KeyPackage boundary while staying below the repository's 64
KiB generic wire-object cap. They must be validated against the final response
descriptor before adoption.

### Canonical inner capability request

The decrypted plaintext is a separate fixed-layout
`CapabilityJoinRequestV1`. The companion
[response-deposit and verifier-context packet](PHASE1_RESPONSE_DEPOSIT_AND_VERIFIER_CONTEXT.md)
proposes a closed 21-item array and assigns its numeric field positions. It
uses the invitation-scoped 32-byte Ed25519 key as the capability verifier and a
fixed `LocalWelcomeDepositEndpointV1` containing only local transport-instance,
mailbox, deposit-capability, and expiration values. The nested endpoint has no
receive, acknowledgement, rotation, URL, hostname, arbitrary route, or generic
extension field.

The proposed inner request carries the complete ADR 0009 tuple: request and
proof versions; invitation, challenge, encryption key ID, and verifier; fresh
request ID and nonce; validity; MLS version and ciphersuite; exact canonical
KeyPackage and reference; its exact credential identity and leaf signature
key; application and transport selections; and the right-specific local
response descriptor. ADR 0014's normative specification assigns the object and
enum code points; neither packet is runtime evidence.

For capability mode, successful PSK-mode opening is the possession proof. Do
not add or transmit a separate raw capability, capability hash, or application
HMAC. The authenticated inner fields provide the complete ADR 0009 admission
context. Admission still has to parse and validate the exact KeyPackage, compare
every duplicated/extracted field, enforce policy and replay state, and produce
the one-shot `VerifiedAdmission`; HPKE success alone does not grant membership.

Every selected value repeated across the signed invitation, HPKE outer header,
HPKE context, and inner request must compare exactly. Unknown, unsupported, or
mismatched versions/suites fail before invitation reservation or other state
mutation. There is no downgrade to invitation version 1, Base mode, or
plaintext.

## Key lifecycle and state ordering

The invitation encryption private key belongs to the inviter's invitation
record and future client vault. It should be unavailable while the vault is
sealed and deleted after the invitation is consumed, expires, or is revoked,
subject to the durable replay/acknowledgement design.

The first safe ordering remains:

1. pre-bound and parse the protected outer object;
2. locate an exact locally issued invitation generation by invitation ID and
   encryption key ID;
3. enforce invitation/version/time policy without mutation;
4. open HPKE with one coarse failure result;
5. pre-bound and canonically parse the zeroizing plaintext;
6. enforce exact outer/signed/inner equality and replay checks;
7. validate the exact MLS KeyPackage and full ADR 0009 binding;
8. reserve only after capability/admission verification;
9. consume the resulting non-clone `VerifiedAdmission` directly into MLS Add;
   and
10. later persist inviter state and publish Welcome under the transaction and
    outbox rules already required by ADR 0008 and ADR 0012.

HPKE does not make steps 6 through 10 atomic and does not replace the existing
stale-generation reservation token defense.

## Required retained evidence before adoption

### Standards and interoperability

- reproduce the RFC 9180 appendix A.1.2 PSK vectors for the exact suite;
- retain a deterministic cross-provider fixture that AWS-LC and an independent
  implementation both seal/open; and
- record exact dependency locks, licenses, advisories, upstream revisions, and
  target-platform builds.

### Entropy and secret ownership

- add an invitation-creation API that obtains capability, invitation ID,
  challenge, key ID, HPKE key pair, nonce, and signing key material from a
  reviewed CSPRNG/provider;
- keep deterministic injection only for fixtures/tests; do not use statistical
  tests as proof of entropy;
- prove secret-bearing types cannot be cloned or formatted through public APIs;
  and
- test zeroization/drop behavior where observable without claiming allocator,
  OS, backup, or hardware erasure.

### Hostile boundary and state-machine cases

- reject wrong PSK, recipient key, PSK ID, `info`, AAD, suite, object type,
  schema version, invitation generation, and every duplicated binding field;
- reject malformed/all-zero X25519 public keys and encapsulated values as the
  provider requires, trailing data, non-deterministic CBOR, empty ciphertext,
  and every over-limit input before recursive parsing or allocation;
- reject expired/future requests, replayed request IDs/nonces, another
  invitation/challenge/verifier, and stale requests after same-ID reissue;
- prove all authentication/decryption failures are externally coarse and leave
  lifecycle, admission, MLS, replay, and outbox state unchanged;
- prove no capability, private key, plaintext, KeyPackage private material, or
  provider diagnostic reaches logs/errors; and
- retain crash/rollback evidence before any durable or networked claim.

## Confidence and limitations

Confidence is high that RFC 9180 PSK mode is the correct standardized
construction for high-entropy bearer-capability possession and that the pinned
AWS-LC provider can implement the proposed suite. The direct API, negative
context checks, dated advisory scan, and two-provider interoperability exercise
support that conclusion.

Confidence is medium in the complete proposed wire profile. The companion
packet now makes the Phase 1 local response descriptor and invitation-key
verifier context exact, but neither schema is adopted or implemented. Hosted
realm/verifier identity, durable key deletion, and the cross-layer transaction
remain unspecified or unimplemented. Upstream `mls-rs` has not received a full
independent third-party security audit, and this research did not audit AWS-LC
or either HPKE implementation.

No post-quantum, production-readiness, metadata-hiding, forward-secrecy,
anonymous-rendezvous, durable replay, or host-compromise guarantee follows from
this packet.

## Adopted decision and next gate

ADR 0014 accepts the mode, suite, provider seam, binding constructions, and
local schemas. The next implementation slice remains local and bounded:

1. implement the exact version 2 invitation, version 1 protected-request,
   21-item inner request, and typed local response-descriptor schemas;
2. add provider-neutral join-protection types with an AWS-LC implementation;
3. add CSPRNG-owned invitation creation and retained RFC/cross-provider
   fixtures; and
4. connect decryption to read-only validation only, leaving durable admission,
   reservation, MLS membership, Welcome outbox publication, and network
   transport for subsequent explicit slices.

Keep hosted realm and network endpoint schemas separate. Stop if the local slice
requires a URL, ambient credential, generic extension map, or authority broader
than one Welcome deposit.
