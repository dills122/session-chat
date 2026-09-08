# ADR 0034: Bind evidence to in-process Git state and the build compiler

- Status: Accepted
- Date: 2026-09-08

## Context

L1 and L2 evidence derived repository cleanliness by executing bare `git`
through the caller's `PATH`. L2 additionally executed caller-selected `RUSTC`,
or a bare `rustc`, and accepted syntactically valid verbose output. Replacement
programs could therefore report a dirty checkout as clean or invent compiler
identity while the resulting record still said `result=pass`.

External GitHub attestation authenticates candidate bytes and workflow origin,
but it does not make forged builder assertions true. Git status also includes
index, worktree, untracked, and ignore semantics that should not be partially
reimplemented in evidence code.

## Decision

- L1 and L2 use pinned `git2`/vendored libgit2 locally, with no network features,
  to compare HEAD, index, and worktree in process. Status includes staged,
  tracked, untracked, unreadable, and ignore-aware results. Unsupported,
  malformed, bare, mismatched-worktree, or in-progress repository state fails
  closed.
- L1 refuses to emit passing evidence when repository provenance is dirty or
  unavailable. L2 candidate construction retains the same fail-closed rule.
- `sessionctl`'s build script asks Cargo's actual compiler for its sysroot,
  resolves the compiler inside that toolchain, captures its bounded verbose
  identity, and embeds a SHA-256 digest of those exact executable bytes.
- Candidate collection does not execute `rustc`. A runtime `RUSTC` override is
  accepted only when it is an absolute path to the same canonical embedded
  compiler, and the compiler file must still match the embedded digest.
- Candidate v3 is retired. Candidate v4 adds `rustc_sha256` and retains the
  narrower `secret_scan=pass`, `capture_completeness=unproven`, and
  `redaction=unverified` claims from ADR 0030. Frozen v2 and v3 fixtures remain
  negative compatibility cases.
- External attestation under ADR 0028 remains mandatory. Compiler and Git
  assertions identify what the reviewed builder checked; they do not establish
  reproducible builds or make a compromised builder trustworthy.

## Consequences

Fake `git` or `rustc` programs in inherited process state can no longer mint
clean or compiler provenance. Local L1 evidence now requires a clean checkout.
The compiler digest varies by platform and toolchain distribution and remains a
diagnostic field unless a consumer explicitly pins it. Vendored libgit2 adds a
reviewed local-status dependency and build cost, but avoids platform-specific
Git executable paths and shell behavior. No product wire or storage schema
changes.
