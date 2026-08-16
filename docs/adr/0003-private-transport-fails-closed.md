# ADR 0003: Private transport fails closed

Status: accepted for the v2 design baseline

Date: 2026-08-16

## Context

A user selecting a mixnet-backed profile is choosing different metadata
guarantees from a direct or normal relay connection. An automatic fallback can
reveal participant IP addresses or communication relationships at exactly the
moment the privacy network is disrupted.

## Decision

Private transport never silently falls back to direct P2P, the fast relay, or
identity and content-fetch paths outside the selected profile. If private
delivery is unavailable, the session is unavailable.

A user may explicitly create or migrate to a differently named profile after
reviewing the changed guarantees. That action is a new security decision.

## Consequences

- Availability is intentionally lower in Private mode.
- The UI must communicate failure without pressuring an invisible downgrade.
- Network-isolation and packet-capture tests become release requirements.
- Update, telemetry, crash-report, avatar, preview, and identity traffic must be
  evaluated as part of the profile rather than ignored as unrelated traffic.
