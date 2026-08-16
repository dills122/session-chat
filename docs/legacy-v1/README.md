# Legacy v1 archive index

Session Chat v1 was retired from the default branch after the first v2 protocol
foundation landed. Its source is intentionally not duplicated under a legacy
directory: Git already preserves the complete source snapshot.

## Canonical snapshot

- Tag: `legacy-v1`
- Peeled commit: `98178d943a201b61e61a79a79766c7f3599ca7a4`
- Snapshot date: 2026-08-16
- Retirement decision: [ADR 0006](../adr/0006-retire-v1-from-the-default-branch.md)

The tag includes the Angular frontend, NestJS/Socket.IO backend, Redis state,
shared TypeScript contracts, Docker/Rush tooling, tests, and the initial v2
design baseline. It predates the Rust protocol crate added by PR #247.

## Inspect or run the archived source

Inspect one file without changing the working tree:

```sh
git show legacy-v1:apps/chat-backend/src/chat/chat.gateway.ts
```

List the complete snapshot:

```sh
git ls-tree -r --name-only legacy-v1
```

Create a detached worktree when the old application itself is needed:

```sh
git worktree add --detach ../session-chat-legacy-v1 legacy-v1
```

The archived dependencies are historical and may contain known vulnerabilities.
Do not deploy or expose the snapshot without a fresh security review.

## What was preserved as documentation

- [Behavior and security lessons](BEHAVIOR_AND_LESSONS.md) records the useful
  product flow, event vocabulary, state model, and reasons those mechanisms do
  not carry forward as v2 protocol contracts.
- [Evidence brief](EVIDENCE_BRIEF.md) records the project chronology, evidence
  boundaries, and exact commits behind the pivot.
- The v2 [threat model](../THREAT_MODEL.md) retains the legacy attack classes
  that must not be reintroduced.

## What remains live on the default branch

- v2 product, architecture, threat-model, transport, admission, and roadmap docs
- ADR history, including the superseded parallel-build decision
- `crates/session-protocol` and its deterministic wire-format tests
- the sealed invitation-provider research spike
- AI Central setup and repository-specific agent guidance

The archive is evidence and a recovery point, not a compatibility promise.
