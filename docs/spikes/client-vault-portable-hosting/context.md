# Working context: client vault and portable realm hosting

Source root during review:
`/Users/dsteele/.codex/worktrees/92ff/session-chat`

Review date: 2026-08-16

This analysis was requested after the Phase 1 invitation foundation was
reviewed and opened as draft PR 252. It is design work, not proof that a client
vault or deployable realm exists. The working tree started from commit
`bdab910` on a separate stacked branch.

The evidence inventory is `evidence-manifest.txt`. Its SHA-256 digest is
recorded in `hardening.json`. Repository documents were read as current design
contracts. External sources were limited to primary specifications and vendor
documentation and were used to establish available primitives, not to select a
dependency.

The strongest constraints carried into the analysis were:

- MLS state, invitation consumption, request replay state, and the encrypted
  Welcome outbox require one durable application transaction.
- OpenMLS deletion semantics make storage copies and backups part of the
  forward-secrecy boundary.
- A realm operator may control availability and observe deployment-specific
  metadata, but must not receive client group keys or plaintext.
- Private transport cannot silently fall back to a less private path.
- Multi-device synchronization and account recovery remain deferred.
- The desktop shell, encrypted database, and production deployment stack are
  not selected.

No runtime performance, memory, recovery-time, or platform-prompt behavior was
measured in this analysis. Those are validation gates in the proposals.
