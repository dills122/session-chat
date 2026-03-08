# Session Chat Prioritized Sprint Plan

This sprint plan assumes the goal is a secure MVP re-foundation, not feature expansion. It prioritizes removal of current trust-model flaws before UX polish or optional operability work.

## Planning Assumptions

- Sprint length: 2 weeks
- Team shape: 1 backend-focused engineer, 1 frontend/full-stack engineer, shared review capacity
- Delivery goal: secure vertical slice from room creation through invite redemption, authenticated chat, and host-driven room teardown

## Priority Framework

Work is prioritized by:

1. exploitability in the current system
2. dependency value for later implementation
3. ability to produce an end-to-end secure slice quickly
4. reduction of rework risk in frontend and websocket layers

## Sprint 0: Architecture and Contract Lock

Goal: freeze the redesign shape before implementation churn starts.

Included items:

- ARCH-001 Define target domain model
- ARCH-002 Define HTTP and websocket contracts
- ARCH-003 Choose token strategy
- DATA-001 Define Redis key schema
- OPS-001 Externalize runtime configuration cleanly

Expected outputs:

- agreed domain vocabulary
- documented endpoint and event contracts
- token and TTL rules
- env/config cleanup decisions

Exit criteria:

- no unresolved questions about room, invite, membership, and access token responsibilities
- implementation can begin without re-litigating auth boundaries

## Sprint 1: Secure Join Path

Goal: replace client-trusting invite and login behavior with backend-issued invite redemption and access tokens.

Included items:

- BE-ROOM-001 Create rooms module
- BE-ROOM-002 Add room status model and transitions
- BE-MEMBER-001 Create memberships module
- BE-AUTH-001 Create auth module for access tokens
- BE-INVITE-001 Create invites module
- BE-INVITE-002 Add invite status and TTL handling
- BE-INVITE-003 Implement invite redemption endpoint
- FE-001 Replace client-side invite generation logic
- FE-002 Build invite redemption flow
- SEC-002 Add input validation and DTO guards

Why this sprint is first:

- it removes the most dangerous client-side trust decisions
- it creates the secure path every later websocket action depends on

Exit criteria:

- host can create room through backend
- host can request invite through backend
- participant can redeem invite through backend
- participant receives backend-issued access token
- old client-side invite hash logic is removed

## Sprint 2: Authenticated Realtime Chat

Goal: make websocket chat authorization derive entirely from authenticated socket context.

Included items:

- WS-001 Add websocket handshake authentication
- WS-002 Refactor chat events to server-derived identity
- BE-AUTH-002 Remove trust in client-generated identity fields
- BE-AUTH-003 Add host authorization checks
- BE-MEMBER-003 Track membership state transitions
- FE-003 Refactor websocket connection auth
- TEST-001 Replace stale backend e2e tests
- TEST-002 Add auth and authorization integration tests

Why this sprint is second:

- it closes the forged identity and impersonation holes
- it converts chat into a secure continuation of the invite redemption flow

Exit criteria:

- unauthenticated sockets cannot join
- chat payloads no longer carry room or sender identity
- forged host and impersonation attempts fail in automated tests

## Sprint 3: Room End and Ephemeral Cleanup

Goal: make the product fulfill the core promise that the host can end the session and the room disappears operationally.

Included items:

- BE-ROOM-003 Implement end-room flow
- WS-003 Add room-ended and presence events
- DATA-002 Implement TTL on rooms and invites
- DATA-003 Implement teardown cleanup job/service
- FE-004 Implement host room management UI
- FE-005 Add ended-room and revoked-access UX

Why this sprint is third:

- room-end behavior only makes sense once membership and socket auth are authoritative
- cleanup is safer after room state transitions already exist

Exit criteria:

- host can end a room
- participants receive room-ended state
- active sockets disconnect
- ended rooms and invites cannot be reused

## Sprint 4: Hardening and Operability

Goal: improve resilience, test depth, and deployment readiness after the secure core exists.

Included items:

- BE-MEMBER-002 Enforce unique display-name policy
- BE-INVITE-004 Support invite policies
- WS-004 Add reconnect behavior
- SEC-001 Add rate limiting for room creation and invite redemption
- SEC-003 Add structured security event logging
- TEST-003 Add frontend integration tests for join and room-end states
- OPS-002 Add health checks for backend and Redis dependencies
- OPS-003 Update README and local setup docs

Exit criteria:

- abuse controls are in place
- reconnect behavior is defined
- deployment and operations posture is materially improved

## Recommended First Implementation Slice

If only one sprint can be funded immediately, the highest-value slice is:

- backend room creation
- backend invite issuance
- invite redemption
- access token issuance
- websocket handshake auth
- message event refactor
- minimal host end-room flow

That slice is enough to retire the current security model and establish a stable platform for the rest.

## Workload View By Discipline

### Backend-heavy items first

- ARCH-001
- ARCH-002
- ARCH-003
- BE-ROOM-001
- BE-ROOM-002
- BE-MEMBER-001
- BE-MEMBER-003
- BE-AUTH-001
- BE-INVITE-001
- BE-INVITE-002
- BE-INVITE-003
- WS-001
- WS-002
- DATA-002
- SEC-002

### Frontend follows contract stabilization

- FE-001
- FE-002
- FE-003
- FE-004
- FE-005

### Validation should run alongside implementation, not after

- TEST-001
- TEST-002
- TEST-003

## Priority Order Across The Entire Backlog

1. ARCH-001
2. ARCH-002
3. ARCH-003
4. OPS-001
5. DATA-001
6. BE-ROOM-001
7. BE-MEMBER-001
8. BE-AUTH-001
9. BE-INVITE-001
10. BE-INVITE-002
11. BE-INVITE-003
12. FE-001
13. FE-002
14. WS-001
15. WS-002
16. BE-AUTH-002
17. BE-AUTH-003
18. SEC-002
19. TEST-001
20. TEST-002
21. BE-ROOM-002
22. BE-ROOM-003
23. WS-003
24. DATA-002
25. DATA-003
26. FE-003
27. FE-004
28. FE-005
29. SEC-001
30. SEC-003
31. WS-004
32. BE-INVITE-004
33. BE-MEMBER-002
34. BE-MEMBER-003
35. TEST-003
36. OPS-002
37. OPS-003

## MVP Cut Line

If you need a strict MVP cut line, stop after these are complete:

- Sprint 0
- Sprint 1
- Sprint 2
- BE-ROOM-003
- WS-003
- DATA-002

That gives you:

- secure room creation
- secure invite redemption
- authenticated chat
- host-controlled room termination
- basic ephemeral expiry guarantees
