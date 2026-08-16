# ADR 0005: Use deterministic CBOR for v2 wire objects

Status: accepted for the Phase 1 protocol laboratory

Date: 2026-08-16

## Context

Session Chat signs, persists, and transports attacker-controlled protocol
objects. Those objects need one stable byte representation so signatures,
fixtures, replay identifiers, and cross-implementation tests do not depend on
serializer behavior or accept equivalent but differently encoded inputs.

The first implementation increment only needs the opaque transport envelope.
Invitation signatures, HPKE suites, and MLS objects remain separate P0
decisions. Choosing their algorithms is outside this ADR.

## Decision

Version 1 wire objects use the core deterministic encoding requirements from
[RFC 8949 section 4.2.1](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1).
The Rust implementation begins with `minicbor` 2.3.0 and its type-directed
encoder and decoder.

Session Chat further restricts the version 1 profile:

- top-level protocol objects are fixed-length arrays with positions defined by
  the object schema
- arrays and byte strings always use definite lengths
- integers use their shortest preferred representation
- maps, tags, floating-point values, indefinite-length items, and generic
  extension fields are not present in version 1 schemas
- protocol version and object type are explicit and allowlisted
- decoders reject trailing bytes, incorrect field counts or types, oversized
  input, and oversized variable-length fields
- accepted bytes are decoded, re-encoded, and compared byte-for-byte so a
  non-deterministic representation is rejected

Future signatures and content-derived identifiers cover these validated
deterministic bytes. Diagnostic JSON, if added, is never a signature boundary.

The dependency is pinned exactly for the first protocol milestone. Upgrades
must retain the committed wire fixtures and negative tests.

## Alternatives considered

### Postcard

Postcard has a stable and compact wire format, but its specification explicitly
does not enforce canonicalization and treats schema evolution as an application
concern. A decode-and-re-encode check could narrow it, but standardized CBOR is
a better cross-language contract for the intended protocol.

### Ad hoc JSON

JSON is useful for diagnostics but has too many representation choices to use
as the signed wire boundary without an additional canonicalization standard and
more text-processing surface.

### Unrestricted CBOR

RFC 8949 allows multiple representations for the same data model value. Using
CBOR without a deterministic application profile would leave signed objects
malleable at the serialization layer.

## Consequences

- Wire bytes are compact, standardized, and independently implementable.
- Fixed array positions make version 1 schemas simple but require a new version
  for incompatible layout changes.
- Re-encoding every decoded object adds bounded work. Input-size checks happen
  before decoding so an attacker cannot make that work unbounded.
- The first crate can prove transport opacity and parser limits without
  prematurely selecting signature, HPKE, or MLS algorithms.
- A future implementation in another language must reproduce the committed
  fixtures exactly and enforce the same restricted profile.

## Sources reviewed

- [RFC 8949: Concise Binary Object Representation](https://www.rfc-editor.org/rfc/rfc8949.html)
- [`minicbor` 2.3.0 documentation](https://docs.rs/minicbor/2.3.0/minicbor/)
- [Postcard wire-format canonicalization behavior](https://postcard.jamesmunns.com/wire-format#canonicalization)
