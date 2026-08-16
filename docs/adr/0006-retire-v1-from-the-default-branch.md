# ADR 0006: Retire v1 from the default branch

Status: accepted; supersedes ADR 0004 only on source-tree coexistence

Date: 2026-08-16

## Context

ADR 0004 required the Angular/NestJS prototype to remain beside v2 until the
first encrypted end-to-end milestone passed. That was a conservative sequencing
choice made before any v2 code existed. PR #247 has since established a clean
Rust workspace, bounded canonical envelope, negative parser tests, and dedicated
CI without depending on the old application.

The v1 tree now provides historical and UX reference value, but keeping it live
on the default branch also preserves its Rush, Angular, NestJS, Socket.IO,
Redis, Docker, browser-test, and deployment maintenance surfaces. The repository
contains no evidence of active consumers that require an in-tree migration
adapter. Git history and the annotated `legacy-v1` tag already provide a more
faithful recovery mechanism than a copied `legacy/` directory.

## Decision

Remove the v1 runtime and its dedicated toolchain from the default branch in one
reviewable follow-up PR.

Before removal, preserve:

1. the complete source and tests at `legacy-v1`, peeled to commit
   `98178d943a201b61e61a79a79766c7f3599ca7a4`;
2. a compact archive index with exact inspection and worktree commands;
3. the product flow, event vocabulary, state model, known security failures, and
   lessons that should inform v2;
4. an evidence brief tying important claims to paths and commits; and
5. the repository's MIT license at the root.

Keep the v2 design documents, ADR history, Rust workspace, sealed
invitation-provider spike, and AI Central integration. Update current guidance
and CI so they describe and validate only the retained repository.

Do not copy the old source beneath `legacy/`, publish build artifacts, retain
compatibility shims, or make old Socket.IO/JWT structures part of v2.

## Consequences

- The default branch becomes a smaller protocol-first repository with no
  runnable chat UI or network service yet.
- Legacy npm manifests and runtime/deployment configuration stop creating active
  dependency, CI, and attack-surface obligations on `master`.
- Historical behavior remains inspectable and recoverable from the named,
  annotated tag and compact documentation.
- Checking out and running v1 requires an explicit detached worktree and a fresh
  security review.
- ADR 0004 still governs Phase 1's two-person, capability-only, in-memory,
  headless scope and its acceptance evidence. Only its requirement to keep both
  source trees concurrently is superseded.
- The future desktop UI is a fresh implementation around proven core contracts;
  Angular is not selected or rejected by this retirement decision.

## Alternatives considered

### Keep v1 beside v2 until the complete encrypted milestone

Rejected. It preserves a misleading runnable product and a large unrelated
maintenance surface while offering no runtime compatibility needed by Phase 1.

### Move v1 into a `legacy/` directory

Rejected. This duplicates what Git already preserves and keeps dependency and
security scanners responsible for code that is not intended to ship.

### Export a source archive into the repository

Rejected. Generated archives are harder to review, search, and patch than the
tagged Git tree, and they can drift from the claimed snapshot.

## Recovery

Use `git worktree add --detach ../session-chat-legacy-v1 legacy-v1` to obtain the
complete retired tree without modifying the current checkout. Reverting the
retirement PR remains possible, but no compatibility guarantee is made after v2
development continues.
