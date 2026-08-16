# Legacy v1 behavior and lessons

Status: historical artifact; not a v2 protocol specification

This document extracts the useful behavior and design lessons from the v1
snapshot at `legacy-v1`. Exact implementation details remain available through
Git; this summary prevents future work from depending on stale source merely to
remember the product flow.

## Product flow worth remembering

1. An inviter chose their own display identifier and one participant identifier.
2. The browser generated a random room ID and a participant link.
3. The UI required explicit confirmation that the link and participant name had
   been shared before creating and joining the room.
4. The joiner opened the link, entered the expected identifier, and attempted to
   join.
5. Both participants received join/leave notices and exchanged text messages in
   a deliberately simple room UI.
6. Leaving a room with messages prompted the user that they might not be able to
   return.

The compact create, share, approve-by-possession, chat, and leave journey is
useful product input. V2 should preserve its low ceremony while replacing every
security-relevant mechanism beneath it.

## Historical event contract

The shared SDK defined these Socket.IO event names:

| Direction or purpose | Event |
| --- | --- |
| create a room | `createSession` |
| request/return login | `login` |
| leave a room | `logout` |
| client sends a message | `chatToServer` |
| server rebroadcasts a message | `chatToClient` |
| membership/status notice | `notification` |

Messages carried `message`, `room`, `uid`, `timestamp`, and the bearer `token`
in one object. Login requests carried `room`, `uid`, and a `referrer`; successful
responses returned an ES512 JWT. Notifications represented a new user, a user
leaving, login trouble, or a login timeout.

These names and shapes are historical observations only. They are not reserved
v2 wire values and must not be wrapped or reinterpreted as encrypted protocol
objects.

## Historical state and trust model

- The browser generated a UUID room ID.
- A participant link used `rid` plus a deterministic SHA-384 hash of
  `participant-id + "-" + room-id`.
- The backend hashed the full participant link with SHA-256 before recording its
  availability in Redis, then deleted that record after a successful join.
- Redis stored a server-authoritative room record containing its lead,
  participant list, creation timestamp, and an `everyoneJoined` flag.
- Socket.IO rooms and Redis membership controlled message delivery.
- The browser stored room, participant ID, and JWT in session storage.
- The backend received plaintext messages and rebroadcast the same message object.

The repository contained an expiry-capable Redis helper, but the room and
participant-link paths did not use it. A successful join made a link one-use;
it did not make the link or room time-bounded.

## Security findings to remember

The old model must not be revived through an adapter or compatibility layer:

- It was server-readable and server-authoritative, not end-to-end encrypted.
- The invitation hash was deterministic and unkeyed, so it was not a secure
  proof of identity or a general admission protocol.
- Room and link records lacked enforced TTLs in the active code paths.
- The JWT validation compared the decoded user ID to itself, so that comparison
  could never detect a caller-supplied user mismatch.
- Broad Socket.IO CORS and an unauthenticated broadcast-alert endpoint expanded
  the web attack surface.
- Reauthentication and return-to-session behavior were incomplete and carried
  state in browser storage.
- Most tests established component construction or happy-path event plumbing;
  they did not prove the security properties now required by v2.
- TLS and signed server tokens protected a client/server channel and assertions;
  they did not prevent the server from reading content or fabricating room state.

These observations support the v2 boundaries: client-owned keys, opaque bounded
transport envelopes, invitation-bound admission, explicit expiry and replay
handling, and state-machine tests independent of UI and network services.

## Product ideas retained for v2

- Keep two-person session creation fast and understandable.
- Keep invitation sharing separate from the chat transport.
- Tell inviters exactly what must be shared and what the recipient will verify.
- Preserve visible join, leave, timeout, and failure states.
- Warn before destructive session exit when appropriate.
- Keep display identity session-scoped unless a selected admission policy binds
  it to external evidence.
- Avoid attachments and rich-content fetching in the first client slice.

## Source pointers in `legacy-v1`

| Evidence | Archived path |
| --- | --- |
| event and payload types | `libs/shared-sdk/index.ts` |
| create/share UX | `apps/chat-frontend/src/app/features/create-session/` |
| join UX | `apps/chat-frontend/src/app/features/login/` |
| chat/leave UX | `apps/chat-frontend/src/app/features/chat-room/` |
| deterministic link construction | `apps/chat-frontend/src/app/services/link-generation/` |
| browser hashing and UUID generation | `apps/chat-frontend/src/app/services/crypto/` |
| server event handling | `apps/chat-backend/src/chat/chat.gateway.ts` |
| room/link state | `apps/chat-backend/src/infrastructure/redis/redis.service.ts` |
| JWT behavior | `apps/chat-backend/src/services/jwt-token/jwt-token.service.ts` |
| local topology | `docker-compose*.yml`, `.docker/`, and `rush.json` |

Use `git show legacy-v1:<path>` to inspect any pointer without restoring v1.
