# ADR 0002: Bind admission evidence to session-scoped member keys

Status: accepted for the v2 design baseline

Date: 2026-08-16

## Context

GitHub accounts, DIDs, verifiable credentials, and stable device identifiers can
be correlated across contexts. MLS still requires authenticated member key
material. Treating an external identity as the cryptographic member identity
would unnecessarily couple identity, privacy, and session security.

## Decision

Each join uses a fresh session- or invitation-scoped member key. External
identity and credential proofs are optional admission evidence bound to that
key, the invitation challenge, the verifier, and an expiration time.

Anonymous capability admission binds only capability possession and optional
manual/out-of-band approval to the fresh member key.

## Consequences

- Anonymous sessions have cryptographic membership without an external persona.
- A global DID or provider identifier need not appear in MLS credentials or
  transport envelopes.
- Key changes are new device/admission events, not silent continuity.
- Multi-device and recovery require an explicit future design.
- Credential presentation alone is insufficient unless holder and invitation
  binding verify successfully.
