# Session Chat Rearchitecture Backlog

This backlog decomposes the rearchitecture epic into implementation-ready work items. IDs are grouped by theme and ordered roughly by dependency.

## Status Legend

- `Now`: prerequisite for secure MVP
- `Next`: important after the core trust model is corrected
- `Later`: useful hardening or follow-on work

## ARCH: Architecture and Contracts

### ARCH-001: Define target domain model

- Priority: `Now`
- Scope: document `Room`, `Invite`, `Membership`, and connection-session models
- Dependencies: none
- Acceptance criteria:
- canonical fields and statuses are documented
- backend and frontend teams can reference the same lifecycle vocabulary

### ARCH-002: Define HTTP and websocket contracts

- Priority: `Now`
- Scope: replace the current mixed event contract with explicit DTOs/events for room lifecycle and chat
- Dependencies: ARCH-001
- Acceptance criteria:
- request and response payloads are documented
- websocket events no longer require client-supplied auth fields in each message

### ARCH-003: Choose token strategy

- Priority: `Now`
- Scope: define invite token format, hashing, access token claims, TTL, and revocation rules
- Dependencies: ARCH-001
- Acceptance criteria:
- token lifetimes and scopes are documented
- backend validation rules are explicit

## BE-ROOM: Room Lifecycle Backend

### BE-ROOM-001: Create rooms module

- Priority: `Now`
- Scope: introduce a backend module/service/controller for room creation and retrieval
- Dependencies: ARCH-001, ARCH-002
- Acceptance criteria:
- host can create a room through HTTP
- room record is persisted with status and expiry metadata

### BE-ROOM-002: Add room status model and transitions

- Priority: `Now`
- Scope: implement `pending`, `active`, `ended`, `expired`
- Dependencies: BE-ROOM-001
- Acceptance criteria:
- room state transitions are validated server-side
- invalid transitions are rejected

### BE-ROOM-003: Implement end-room flow

- Priority: `Now`
- Scope: add host-only end-room command and teardown trigger
- Dependencies: BE-ROOM-001, BE-AUTH-003
- Acceptance criteria:
- host can end a room
- room moves to `ended`
- remaining chat activity is rejected

## BE-INVITE: Invite Backend

### BE-INVITE-001: Create invites module

- Priority: `Now`
- Scope: server-side invite issuance and storage
- Dependencies: ARCH-001, ARCH-002, ARCH-003, BE-ROOM-001
- Acceptance criteria:
- backend can mint opaque random invite tokens
- only token hashes are stored

### BE-INVITE-002: Add invite status and TTL handling

- Priority: `Now`
- Scope: implement `active`, `redeemed`, `expired`, `revoked`
- Dependencies: BE-INVITE-001
- Acceptance criteria:
- invite expiry is enforced
- invite status changes are recorded atomically

### BE-INVITE-003: Implement invite redemption endpoint

- Priority: `Now`
- Scope: validate invite token and create membership
- Dependencies: BE-INVITE-001, BE-MEMBER-001, BE-AUTH-001
- Acceptance criteria:
- invalid, expired, and already-used invites are rejected
- successful redemption returns an access token and membership metadata

### BE-INVITE-004: Support invite policies

- Priority: `Next`
- Scope: support one-time and bounded-use invite behavior
- Dependencies: BE-INVITE-002
- Acceptance criteria:
- invite max-use policy is configurable and enforced

## BE-MEMBER: Membership Backend

### BE-MEMBER-001: Create memberships module

- Priority: `Now`
- Scope: model authorized room participants separately from invites and connections
- Dependencies: ARCH-001
- Acceptance criteria:
- memberships are stored by membership id
- host and participant roles are represented explicitly

### BE-MEMBER-002: Enforce unique display-name policy

- Priority: `Next`
- Scope: decide and enforce whether duplicate display names are allowed
- Dependencies: BE-MEMBER-001
- Acceptance criteria:
- room-level naming policy is documented and enforced

### BE-MEMBER-003: Track membership state transitions

- Priority: `Now`
- Scope: mark members active, left, disconnected, revoked
- Dependencies: BE-MEMBER-001
- Acceptance criteria:
- membership status updates are persisted and queryable

## BE-AUTH: Auth Backend

### BE-AUTH-001: Create auth module for access tokens

- Priority: `Now`
- Scope: generate and validate room access tokens from server-side membership records
- Dependencies: ARCH-003, BE-MEMBER-001
- Acceptance criteria:
- tokens include room and membership claims
- token expiry is enforced

### BE-AUTH-002: Remove trust in client-generated identity fields

- Priority: `Now`
- Scope: eliminate use of client-provided `uid`, `referrer`, and per-message token payloads as auth sources
- Dependencies: BE-AUTH-001, WS-001
- Acceptance criteria:
- backend auth decisions are made only from backend-issued credentials and persisted state

### BE-AUTH-003: Add host authorization checks

- Priority: `Now`
- Scope: authorize invite creation and room ending using role-aware membership or admin credentials
- Dependencies: BE-AUTH-001, BE-ROOM-001
- Acceptance criteria:
- non-host users cannot create invites or end rooms

## WS: Realtime Chat and Presence

### WS-001: Add websocket handshake authentication

- Priority: `Now`
- Scope: authenticate once when the socket connects and attach membership context to the socket
- Dependencies: BE-AUTH-001
- Acceptance criteria:
- unauthorized sockets are rejected before room join
- socket context includes room and membership identity

### WS-002: Refactor chat events to server-derived identity

- Priority: `Now`
- Scope: remove `uid`, `room`, and token from chat send payloads
- Dependencies: WS-001
- Acceptance criteria:
- sender identity and room are derived from socket context
- impersonation by payload manipulation is blocked

### WS-003: Add room-ended and presence events

- Priority: `Now`
- Scope: broadcast participant joins/leaves and room-ended events from server-authoritative state
- Dependencies: WS-001, BE-ROOM-003, BE-MEMBER-003
- Acceptance criteria:
- room-ended event disconnects clients cleanly
- presence events reflect authenticated memberships

### WS-004: Add reconnect behavior

- Priority: `Next`
- Scope: define how transient disconnect/reconnect works for active memberships
- Dependencies: WS-001, BE-MEMBER-003
- Acceptance criteria:
- reconnect policy is documented and tested

## FE: Frontend Rework

### FE-001: Replace client-side invite generation logic

- Priority: `Now`
- Scope: frontend requests invite URLs from the backend instead of generating them locally
- Dependencies: BE-INVITE-001
- Acceptance criteria:
- no security-critical invite hash generation remains on the client

### FE-002: Build invite redemption flow

- Priority: `Now`
- Scope: new join screen posts invite token to the backend and receives room access data
- Dependencies: BE-INVITE-003
- Acceptance criteria:
- invalid and expired invite states are shown cleanly
- successful redemption stores only the backend-issued access token

### FE-003: Refactor websocket connection auth

- Priority: `Now`
- Scope: connect socket with access token during handshake
- Dependencies: WS-001, FE-002
- Acceptance criteria:
- chat send payload is reduced to message content
- socket auth failures are surfaced clearly

### FE-004: Implement host room management UI

- Priority: `Next`
- Scope: create invite and end-room controls for the host flow
- Dependencies: BE-ROOM-003, BE-INVITE-001
- Acceptance criteria:
- host can create invites and end the room from the UI

### FE-005: Add ended-room and revoked-access UX

- Priority: `Next`
- Scope: handle room end, revoked invite, and expired token states
- Dependencies: WS-003, FE-003
- Acceptance criteria:
- users are redirected or shown terminal states without broken screens

## DATA: Persistence and Cleanup

### DATA-001: Define Redis key schema

- Priority: `Now`
- Scope: formalize room, invite, membership, and presence key layout
- Dependencies: ARCH-001
- Acceptance criteria:
- key patterns and TTL ownership are documented

### DATA-002: Implement TTL on rooms and invites

- Priority: `Now`
- Scope: ensure rooms and invites expire automatically
- Dependencies: DATA-001, BE-ROOM-001, BE-INVITE-001
- Acceptance criteria:
- expired rooms and invites become unusable without manual cleanup

### DATA-003: Implement teardown cleanup job/service

- Priority: `Next`
- Scope: cleanup ended rooms, memberships, and presence data
- Dependencies: BE-ROOM-003, DATA-002
- Acceptance criteria:
- ending a room clears active runtime state

## SEC: Security Hardening

### SEC-001: Add rate limiting for room creation and invite redemption

- Priority: `Next`
- Scope: slow brute-force and abuse flows
- Dependencies: BE-ROOM-001, BE-INVITE-003
- Acceptance criteria:
- abusive request bursts are throttled with defined limits

### SEC-002: Add input validation and DTO guards

- Priority: `Now`
- Scope: validate request and event payloads on all public boundaries
- Dependencies: ARCH-002
- Acceptance criteria:
- malformed requests are rejected consistently

### SEC-003: Add structured security event logging

- Priority: `Next`
- Scope: log room creation, invite issuance, invite redemption, room end, and auth failures
- Dependencies: BE-ROOM-001, BE-INVITE-003, BE-AUTH-001
- Acceptance criteria:
- sensitive transitions are traceable without logging secrets

## TEST: Verification

### TEST-001: Replace stale backend e2e tests

- Priority: `Now`
- Scope: remove the old hello-world test and add lifecycle-focused backend tests
- Dependencies: BE-ROOM-001, BE-INVITE-003, BE-AUTH-001
- Acceptance criteria:
- e2e tests reflect actual public API behavior

### TEST-002: Add auth and authorization integration tests

- Priority: `Now`
- Scope: cover forged host claims, reused invites, impersonation attempts, and ended-room behavior
- Dependencies: BE-AUTH-002, WS-002, BE-ROOM-003
- Acceptance criteria:
- the current major exploit paths are covered

### TEST-003: Add frontend integration tests for join and room-end states

- Priority: `Next`
- Scope: validate user experience on valid and invalid invite flows
- Dependencies: FE-002, FE-005
- Acceptance criteria:
- UI behavior is covered for primary lifecycle paths

## OPS: Operability

### OPS-001: Externalize runtime configuration cleanly

- Priority: `Now`
- Scope: remove hardcoded frontend/backend endpoints and align ports and environment config
- Dependencies: none
- Acceptance criteria:
- local and deploy configs are consistent
- frontend websocket target is environment-driven

### OPS-002: Add health checks for backend and Redis dependencies

- Priority: `Next`
- Scope: expose service health for local and hosted deployment checks
- Dependencies: BE-ROOM-001
- Acceptance criteria:
- operators can verify backend readiness and dependency health

### OPS-003: Update README and local setup docs

- Priority: `Now`
- Scope: document the new room/invite/auth flow and development setup
- Dependencies: FE-002, WS-001, OPS-001
- Acceptance criteria:
- a new contributor can run and understand the secure flow from docs alone

## Dependency Highlights

Core critical path:

`ARCH-001 -> ARCH-002 -> ARCH-003 -> BE-ROOM-001 -> BE-MEMBER-001 -> BE-AUTH-001 -> BE-INVITE-001 -> BE-INVITE-003 -> WS-001 -> WS-002 -> FE-002 -> FE-003 -> BE-ROOM-003 -> WS-003 -> TEST-002`

## Definition of Done For Secure MVP

Secure MVP is considered reached when all `Now` items below are complete:

- ARCH-001
- ARCH-002
- ARCH-003
- BE-ROOM-001
- BE-ROOM-002
- BE-ROOM-003
- BE-INVITE-001
- BE-INVITE-002
- BE-INVITE-003
- BE-MEMBER-001
- BE-MEMBER-003
- BE-AUTH-001
- BE-AUTH-002
- BE-AUTH-003
- WS-001
- WS-002
- WS-003
- FE-001
- FE-002
- FE-003
- DATA-001
- DATA-002
- SEC-002
- TEST-001
- TEST-002
- OPS-001
- OPS-003
