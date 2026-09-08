# ADR 0033: Make transient MLS identities one-shot

- Status: Accepted
- Date: 2026-09-08

## Context

The transient `session-crypto-mls` client generated one random credential and
signing key but did not bind that identity to a group. Its reusable methods
could create multiple groups, generate multiple KeyPackages, or process more
than one Welcome with the same session-scoped identity. That contradicted the
session-local identity boundary and made otherwise separate sessions
correlatable.

Joiners cannot bind the client to a group at construction because the current
capability flow learns the MLS group identifier only from the Welcome. Durable
clients are different: their credential and signer must survive restart and are
already bound to one exact group.

## Decision

- A transient client may perform exactly one identity path: create one inviter
  group, or generate one KeyPackage followed by one Welcome attempt.
- The one-shot transition occurs before provider work. A failed group creation,
  KeyPackage generation, or Welcome parse/join consumes that transient path and
  cannot be retried with the same credential or signer.
- Concurrent attempts use an atomic state transition; only one caller can own
  the permitted operation.
- After a successful provider join, the adapter verifies that the resulting
  local credential and leaf signing key match the client that generated the
  pending KeyPackage. Shared provider storage therefore cannot substitute a
  different client as join owner.
- Durable clients remain reusable for replacement KeyPackages and group
  operations only within their constructor-bound group identifier.

## Consequences

Transient callers must create a fresh client after any failed one-shot attempt
or when constructing intentionally foreign test material. Credential and signer
reuse can no longer correlate two transient sessions through this API. Durable
restart and KeyPackage-replacement workflows retain their exact-group identity
continuity. This is an adapter lifecycle guarantee, not proof of unlinkability
against storage, transport, timing, endpoint, or application-layer observers.
