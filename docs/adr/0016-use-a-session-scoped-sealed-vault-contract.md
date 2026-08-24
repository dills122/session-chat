# ADR 0016: Use a session-scoped sealed-vault contract

Status: accepted; deterministic lifecycle and opaque-inbox conformance model implemented

Date: 2026-08-20

## Context

The client owns invitation, mailbox, MLS, and session secrets. The existing
architecture did not define what a future client may do while those secrets are
sealed, how one selected session becomes available, or how delayed platform
events are prevented from reopening or resealing a newer state generation.

The retained client-vault hardening proposal compared whole-store wrapping,
session-scoped sealing, and portable recovery. Session-scoped sealing most
directly narrows the useful-secret window while still permitting bounded
receipt of opaque network work. The SQLCipher compatibility spike separately
showed one promising encrypted transaction engine on one macOS host, but did
not select production storage or a platform key protector.

## Decision

Adopt the session-scoped sealed-vault state and capability contract as the
target for bounded implementation experiments:

```text
Sealed -> Unlocking -> Open(session) -> Relocking -> Sealed
```

- Unlock and relock completions consume linear, generation-bound values.
  Delayed completions from an older generation fail without changing the
  current state.
- Only one exact session is open in the Phase 1 model.
- Explicit lock, idle timeout, screen lock, sleep, logout, and process exit
  immediately return the model to `Sealed` and drop the unsealed test key.
- While sealed or transitioning, decrypt, sign, admission, receive-capability
  read, acknowledgement, mailbox rotation, and MLS mutation fail before the
  requested work runs.
- Every lifecycle state may append only a pre-bounded, canonical
  `OpaqueEnvelope` to a count-, byte-, and lifetime-bounded inbox.
- Inbox import requires the exact currently open session and vault generation.
  Completion removes only the exact local insertion generation; it conveys no
  remote transport acknowledgement authority.
- The UI is not a vault or membership authority. A later application boundary
  must expose narrow commands rather than generic key or database access.

`session-storage` retains the first deterministic conformance model. Its clock
and key protector are explicitly non-production test providers. The model
stores no durable user data and exposes no network or UI path.

## Required future gates

Before any user-facing or durability claim:

- select and review an encrypted transactional store through a separate ADR;
- prove inviter-local MLS/invitation/replay/approval/Welcome-outbox atomicity
  through the actual MLS persistence call;
- separately prove joiner-local joined-state persistence and one-time
  KeyPackage deletion;
- measure platform-specific device binding, user presence, screen-lock,
  biometric-change, backup, and unlock-sharing behavior;
- test close, crash, disk-full, truncation, migration, rekey, backup, and
  deletion behavior; and
- select or explicitly defer a monotonic rollback anchor. Encryption at rest
  alone is not rollback resistance.

## Consequences

- Background opaque receipt does not require unsealing MLS or mailbox rights.
- Locked-mode behavior is now a falsifiable capability matrix rather than a
  generic `is_locked` boolean.
- Session scoping adds lifecycle and key-metadata complexity that the later
  storage format must own transactionally.
- Platforms unable to prove fresh user presence must expose a weaker named mode
  or fail closed; they may not silently inherit another platform's claim.
- Portable recovery remains deferred because it creates an offline guessing
  and device-continuity boundary.

## Alternatives considered

### Whole-store device wrapping

Retained as a fallback if per-session scoping cannot preserve atomicity or a
narrow UI/core boundary. It broadens the useful-secret window to every retained
session whenever the store is open.

### Portable passphrase recovery

Deferred until the single-device session-scoped model has retained evidence and
a separate recovery/device-continuity decision exists.

### Select SQLCipher in this decision

Rejected. The compatibility spike is local evidence only. Cross-platform
builds, dependency governance, lifecycle faults, actual Session Chat MLS
integration, and platform-vault behavior remain gates.
