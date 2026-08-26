# ADR 0021: Use bounded filesystem IPC for the L1 process runner

Status: accepted

Date: 2026-08-26

## Context

The retained `sessionctl` scenario proved the Phase 1 lifecycle and a real
SQLCipher close/reopen inside one process. The next test gate needed to prove
that two client processes and an untrusted service can exchange only reviewed
wire objects, and that a fresh Alice process can reload the committed identity
and group. Introducing a socket protocol or candidate network provider solely
for this test would prematurely select product transport behavior.

The controller and service must not receive the secret-capability invitation,
the SQLCipher key, plaintext, raw MLS state, or receive/acknowledgement
authority. Process waits, files, frames, outputs, and cleanup must remain
bounded on Linux, macOS, and Windows.

## Decision

Add a publish-disabled `sessionctl-l1` conformance binary with four bounded
child lifetimes: an untrusted forwarding service, Bob, Alice initialization,
and a fresh Alice reload process. Alice initialization exits only after the
inviter transaction and MLS group are committed. Alice reload then opens the
same SQLCipher owner, reloads the exact group-bound signing identity and group,
and resumes Welcome delivery before messaging, update, removal, and
post-removal rejection.

Use a test-only filesystem IPC v1 frame with fixed magic/version, a closed
message kind, a seven-step sequence, at most two parts, a 64 KiB bound per
part, canonical revalidation, a 30-second per-frame deadline, and atomic
publish. The relay accepts only these existing public wire objects:

- `ProtectedJoinRequest`;
- `LocalWelcomeDepositEndpoint` only when exercising that deposit authority;
- `OpaqueEnvelope`.

The bearer invitation uses a separate direct client channel. The raw 32-byte
SQLCipher key and exact group identifier use a mode-`0600` file where Unix
supports it, readable only by the fresh Alice test process and deleted on
load. This is disposable conformance state, not a vault, portable key-custody
design, or product credential handoff.

The controller accepts only fixed, bounded, secret-free child summaries and
emits a version-1 manifest under 2 KiB. It records coarse outcomes,
commit/dirty state when Git is available, lockfile digest, platform, command,
timestamps, and configured budgets. It omits hashes of authority-bearing
frames rather than creating a reusable confirmation/correlation artifact.
All children are reaped on success and killed/reaped on controller failure;
the marked disposable directory is then removed.

## Consequences

- Process exit and exact Alice close/reopen are now ordinary offline L1 merge
  evidence on every supported CI family.
- The forwarding process never receives the invitation, plaintext, database
  key, raw MLS state, or receive/acknowledgement authority.
- Filesystem IPC is not a transport profile, network adapter, privacy property,
  hosted service, or deployable client architecture.
- Graceful process exit does not prove abrupt kill, disk-full, power-loss,
  rollback, restore, secure deletion, or independently durable approval/replay
  state. Those remain L2 or later gates.
- The controller creates the disposable paths and could access them under the
  same OS account; this runner proves component data-flow discipline, not
  hostile local-controller isolation.

## Alternatives

### Add loopback sockets or a real relay provider

Rejected for this increment because it would combine the process boundary with
network-provider selection and packet-observation claims.

### Pass every value through the controller

Rejected because the controller would receive the bearer invitation and raw
database key, contradicting the evidence boundary.

### Keep Alice alive and simulate reload in one process

Rejected because the existing `sessionctl` scenario already provides that
evidence and cannot establish process-exit recovery.
