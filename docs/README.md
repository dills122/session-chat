# Session Chat Re-Architecture Docs

This folder captures the proposed redesign for moving Session Chat from a proof-of-concept toward a secure, server-authoritative MVP.

## Documents

- [Rearchitecture Epic](./rearchitecture-epic.md): target architecture, security model, phased delivery, and technical decisions
- [Backlog](./backlog.md): decomposed work items with scope, dependencies, and acceptance criteria
- [Sprint Plan](./sprint-plan.md): prioritized delivery plan built from the backlog

## Intended Outcome

The redesign aims to make the backend authoritative for:

- room creation and lifecycle
- invite issuance and redemption
- participant membership
- websocket authentication and authorization
- room teardown and cleanup

The frontend becomes a presentation and orchestration layer instead of a trust boundary.
