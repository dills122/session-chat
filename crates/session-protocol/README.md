# session-protocol

`session-protocol` owns the bounded, versioned wire objects for the Session Chat
2.0 protocol laboratory. It performs serialization, structural validation, and
strict verification of the signed invitation schema. It does not decide
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

## Verification

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
