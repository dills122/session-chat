# ADR 0022: Use a provider-neutral, non-authorizing approval context

Status: accepted; Phase 1 approval seam implemented

Date: 2026-08-20

Numbering note: this record was originally introduced as a second ADR 0015 and
was renumbered to ADR 0022 without changing the accepted decision.

## Context

The Phase 1 headless client and later user interface need to present the same
approval decision regardless of whether evidence came from a secret capability,
GitHub, a credential, or another reviewed admission adapter. Letting those
callers import provider-specific proof and MLS types would collapse the intended
admission boundary.

A universal verified-admission or membership factory would create a different
risk. ADR 0009 requires one opaque, non-cloneable value to retain the exact
parsed KeyPackage and complete proof provenance through MLS Add. Type erasure,
detachable byte strings, or a reconstructible normalized record could permit a
provider proof for one KeyPackage to authorize another.

## Decision

Add an implementation-free `session-admission` crate with only:

- `ApprovalContext`, containing the verified admission method, invitation ID,
  join-request ID, canonical KeyPackage reference, and request expiration;
- `ApprovalDecision`, with explicit `Approve` and `Reject` variants; and
- an object-safe `PendingAdmission` observation trait that returns the
  display-only context.

The context is structurally validated, carries no proof or bearer authority,
and redacts its identifiers and KeyPackage reference from `Debug`. Copying or
reconstructing it cannot authorize membership. A decision is likewise only
input: the concrete provider must consume its original pending value and retain
its exact verified KeyPackage, replay reservation, invitation reservation, and
proof provenance.

`admission-capability` implements the observation trait for its pending approval
value and accepts the shared decision type. Its provider-specific verified,
approved, prepared, and committed types remain concrete and linear.

Do not add network-loaded admission plugins, a generic parsed-KeyPackage escape
hatch, or a universal membership factory. A future admission provider may
implement the observation seam only after its proof binding and one-shot
ownership contract are independently specified and tested.

## Consequences and limits

- `sessionctl` and later UI code can present one bounded approval shape without
  depending on capability-provider internals.
- Adding a presentation seam does not make different evidence sources
  equivalent and does not erase provenance.
- The concrete admission provider still owns verification, replay handling,
  release, approval consumption, and membership preparation.
- Human approval UX and policy evaluation remain unimplemented. The headless
  paths compose through the SQLCipher reloadable approval/replay owner without
  retaining provider evidence or live membership authority in durable state.
- The current enum contains only the implemented secret-capability method. New
  variants require a reviewed provider and updated evidence, not speculative
  placeholders.

## Alternatives considered

### Return a normalized cloneable `VerifiedAdmission`

Rejected. A normalized record cannot safely carry the provider-owned parsed
KeyPackage and reservation authorities required by ADR 0009.

### Put provider-specific proof details in the UI contract

Rejected. It couples the composition root to one adapter and encourages proof
or token material to reach display, logging, and telemetry surfaces.

### Define a universal membership factory now

Deferred. There is one admitted membership implementation. Generalizing its
provider and persistence semantics now would hide security differences rather
than establish a proven common contract.
