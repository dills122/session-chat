# Working context: client vault and portable realm hosting

Review date: 2026-08-16

This analysis was requested after the Phase 1 invitation foundation was
reviewed and opened as draft PR 252. It is design work, not proof that a client
vault or deployable realm exists. The working tree started from commit
`bdab9107e8e4e813a2156e46ec8e0bfea0da8b60` on a separate stacked branch.
That source snapshot was later merged with content-equivalent protocol changes
as `5006bdb41741c6a3c697220e9d2ef73c177a6dc0`. Git history, rather than a
developer-local checkout path, identifies the reviewed repository state.

The evidence inventory is `evidence-manifest.txt`. Its SHA-256 digest is
recorded in `hardening.json`; that digest authenticates the inventory text, not
snapshots of mutable external pages. Repository evidence is bound by the Git
revision. External sources record a retrieval date and use immutable versioned
references where the publisher offered them. They were limited to primary
specifications and vendor documentation and were used to establish available
primitives, not to select a dependency.

The strongest constraints carried into the analysis were:

- MLS state, invitation consumption, request replay state, and the encrypted
  Welcome outbox require one durable application transaction.
- MLS deletion semantics make storage copies and backups part of the
  forward-secrecy boundary.
- A realm operator may control availability and observe deployment-specific
  metadata, but must not receive client group keys or plaintext.
- Private transport cannot silently fall back to a less private path.
- Multi-device synchronization and account recovery remain deferred.
- The desktop shell, encrypted database, and production deployment stack are
  not selected.

No runtime performance, memory, recovery-time, or platform-prompt behavior was
measured in this analysis. Those are validation gates in the proposals.
