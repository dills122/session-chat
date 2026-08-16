# ADR 0001: Separate session security, admission, rendezvous, and transport

Status: accepted for the v2 design baseline

Date: 2026-08-16

## Context

Session Chat needs to support GitHub-targeted invitations, portable credential
proofs, secret capabilities, fast P2P delivery, and mixnet delivery. Coupling
any one identity provider to a transport would create separate protocols and
make security claims difficult to reason about.

## Decision

The v2 architecture has four independent layers:

1. MLS-based session security and membership
2. Admission evidence and policy
3. Encrypted pre-membership rendezvous and offline mailboxes
4. Opaque envelope delivery transports

Identity/admission implementations return a verified binding to a proposed
session member key. Transports carry encrypted protocol envelopes without
identity-specific fields. Invitation publication is out of band and is not a
transport function.

## Consequences

- GitHub and anonymous modes share the same session protocol.
- Fast and private delivery share the same envelope format.
- The project must define explicit interfaces and resist convenience shortcuts
  that leak provider data into transport objects.
- Cross-product combinations such as GitHub Private become possible without a
  fork.
- Testing must prove substitutability across at least two admission methods and
  two transports.
