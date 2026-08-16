# session-protocol

`session-protocol` owns the bounded, versioned wire objects for the Session Chat
2.0 protocol laboratory. It performs serialization and structural validation;
it does not perform admission, transport, signature, HPKE, or MLS operations.

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

## Verification

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
