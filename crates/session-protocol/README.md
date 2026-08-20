# session-protocol

`session-protocol` owns the bounded, versioned wire objects for the Session Chat
2.0 protocol laboratory. It performs serialization, structural validation, and
strict verification of the signed invitation schemas. It also owns the bounded
canonical value types for ADR 0014's protected outer request, decrypted inner
request, exact outer AAD, and local deposit endpoint. It does not decide
admission, consume invitations, deliver objects, perform HPKE, or operate MLS.

## Version 1 opaque envelope

The deterministic CBOR object is a five-item array:

| Position | Field | Version 1 constraint |
| ---: | --- | --- |
| 0 | Protocol version | Unsigned integer `1` |
| 1 | Wire object type | Unsigned integer `1` (`OpaqueEnvelope`) |
| 2 | Envelope ID | Exactly 16 bytes |
| 3 | Expiration | Unsigned Unix time in seconds |
| 4 | Ciphertext | Definite byte string, at most 60 KiB |

The complete encoded object is limited to 64 KiB. The envelope deliberately
contains no identity, admission method, or inner message-type field. The
transport receives ciphertext and the minimum delivery metadata only.

Decoding enforces the restricted deterministic-CBOR profile from ADR 0005. It
rejects unknown versions and object types, indefinite lengths, wrong field
counts or types, non-shortest encodings, trailing bytes, and size-limit
violations.

## Version 1 signed capability invitation

The Phase 1 invitation is a fixed 12-item deterministic-CBOR array containing:

- version, object type, Ed25519 suite, capability admission mode, and single-use policy
- a 16-byte invitation ID
- issue and expiration times
- a 32-byte join challenge and 32-byte secret bearer capability
- a 32-byte invitation-scoped Ed25519 verifying key
- a 64-byte signature

The exact schema and fixture requirements are in
[`docs/specs/SIGNED_INVITATION_V1.md`](../../docs/specs/SIGNED_INVITATION_V1.md).
Signatures cover the fixed `session-chat/signed-invitation/v1` application
domain and canonical unsigned fields. Verification uses
`ed25519-dalek::VerifyingKey::verify_strict`.

The descriptor intentionally contains a secret capability. It is not publicly
postable, must not enter logs or opaque transport envelopes, and does not prove
the inviter's GitHub identity or personhood. The signing key only authenticates
the descriptor against mutation; channel authenticity and admission remain
separate concerns under ADR 0007.

## Protected capability join protocol values

Invitation v2 adds the fixed HPKE suite, protected-request schema, application
selection, local transport profile, invitation encryption key ID, and recipient
public key under its own signature domain. The protected outer request is
limited to 32 KiB, its canonical AAD covers the six non-ciphertext fields, the
decrypted inner request is limited to 24 KiB, and its KeyPackage field is
limited to 16 KiB. The nested local response endpoint carries deposit authority
only and is limited to 128 bytes.

Every new schema is a fixed deterministic-CBOR array. Decoders reject unknown
code points, wrong counts/types/lengths, reserved zero values, non-preferred and
indefinite encodings, trailing bytes, invalid or weak Ed25519 leaf keys, and
complete inputs above their limits. Exact fixtures preserve invitation-v1
compatibility and lock all four new layouts.

These are parsing and framing guarantees. Ciphertext is not created or opened
by this crate, and successful parsing is not capability possession, admission,
approval, MLS membership, mailbox delivery, or durable state.

## Verification

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
