# ADR 0009: Bind admission to the MLS KeyPackage actually added

Status: accepted for the Phase 1 admission contract

Date: 2026-08-16

## Context

The original design bound admission evidence to a generic "proposed session
member public key" while carrying an MLS KeyPackage separately. Independently
validating those objects does not prove that the identity or capability evidence
authorizes the MLS leaf that will join. An attacker could present evidence for
key A and substitute a valid KeyPackage controlled by key B.

MLS `BasicCredential` also does not itself define the semantic binding between
its identity bytes and its signature key. Session Chat must define and verify
that application-level authentication binding.

## Decision

For the initial MLS profile, "session member key" means the signature public key
authenticated by the leaf node in the exact KeyPackage being proposed. Every
admission proof and normalized `VerifiedAdmission` binds all of:

```text
invitation ID
invitation challenge
join request ID
canonical MLS KeyPackage reference
MLS protocol version and ciphersuite
credential type and session-scoped credential identity
leaf signature public key
intended verifier or realm
issue time and expiration time
admission-proof protocol version
```

The KeyPackage reference is the RFC 9420 ciphersuite hash reference over
the canonical TLS-serialized KeyPackage. Session Chat does not invent a second
KeyPackage hash format.

`VerifiedAdmission` has private constructors and is an opaque, non-cloneable,
one-shot value. It owns the
complete binding tuple above and the exact parsed, cryptographically verified
KeyPackage object. The membership state machine consumes that value directly
when constructing the MLS Add; callers cannot extract a reference and later
pair it with a reconstructed or substituted KeyPackage.

Before policy approval, the inviter must:

1. parse the KeyPackage with the selected MLS implementation;
2. verify its signature, lifetime, protocol version, ciphersuite, credential
   type, and extension policy;
3. recompute its canonical KeyPackage reference;
4. extract the leaf credential identity and signature public key;
5. compare every extracted value with the signed admission context; and
6. pass that same verified KeyPackage object/reference to the MLS Add operation.

The initial `BasicCredential` identity is a fresh random session-scoped opaque
identifier. It is not a GitHub subject, DID, email, permanent account ID, or
trust statement. GitHub, credential, capability, and manual evidence authorizes
the complete binding tuple above.

## Required negative evidence

Before admission or MLS integration is considered complete, automated tests
must reject:

- proof for KeyPackage A combined with KeyPackage B;
- the same credential identity with a different leaf signature key;
- the same leaf signature key with a different credential identity;
- a KeyPackage changed after the admission proof was issued;
- a reference computed under another ciphersuite or protocol version;
- an expired, unsupported, malformed, or incorrectly signed KeyPackage; and
- replay of a valid binding under another invitation, challenge, request ID,
  realm, or verifier.

## Alternatives considered

### Bind only the leaf signature public key

Rejected. It leaves the credential identity, capabilities, lifetime, extensions,
and HPKE init key in the KeyPackage substitutable.

### Bind only opaque credential identity bytes

Rejected. A BasicCredential does not intrinsically bind those bytes to the leaf
signature key.

### Treat successful KeyPackage validation as admission

Rejected. MLS authenticates group operations; it does not decide Session Chat's
external identity, capability, realm-policy, or human-approval rules.

## Consequences

- Admission evidence cannot be evaluated without the exact candidate KeyPackage.
- The verified KeyPackage and its complete admission context remain owned by one
  linear value through the Add operation.
- Session-scoped MLS identity remains independent from external identity evidence.
- Join-request schemas and fixtures must carry this complete binding explicitly.

## Implemented evidence

The in-memory `admission-capability` adapter accepts only a request with private
HPKE-open provenance, independently validates its exact KeyPackage through the
pinned MLS provider, compares the canonical reference, `BasicCredential`
identity, and leaf signature key, and returns a private, non-`Clone`, non-`Debug`
one-shot value owning that parsed provider object. Substitution and rejection
tests retain unchanged replay state. The verifier retains the exact HPKE-opened
invitation signature, reserves matching local v2 state, and permits only an
explicitly approved one-shot value to enter MLS preparation. Rejected, expired,
failed, or abandoned work releases invitation and replay state without changing
membership; successful in-memory Add consumes the invitation. The approval is a
simulated API input, not human UI evidence. The SQLCipher laboratory atomically
retains the approved inviter MLS transition, invitation/replay/approval shadows,
and Welcome outbox, but it cannot reload them as one complete durable product
authorization owner and has no rollback anchor. The complete durable product
transaction is therefore not yet satisfied.
