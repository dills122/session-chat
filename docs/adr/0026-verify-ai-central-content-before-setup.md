# ADR 0026: Verify AI Central content before setup

Status: accepted; locally verified on macOS, portable CI pending

Date: 2026-09-06

## Context

Matching AI Central HEAD to the reviewed commit does not authenticate its
working-tree installer, helpers, catalog, or linked skills. Dirty or untracked
code can execute with developer authority while the commit still matches.
Checking Git status alone also misses index flags and leaves a validation-to-
execution race. Links into a mutable checkout can change after installation.

## Decision

Keep the reviewed commit pin and non-overwriting maintained installer. Before
executing it, enumerate the pinned Git tree with replace objects disabled and
without inherited Git redirection variables. Accept only bounded regular-file
entries and ordinary contained paths. Reject source symlinks and compare every
file buffer to its exact Git blob identity, independently of status/index
optimization flags. Reject staged differences too. Apply the same checks before
recording a reviewed pin.

Build a fresh retained snapshot from those verified buffers, not a second read
of the source. Untracked and ignored files are omitted, so they cannot supply
installer helpers or skill content. Execute the installer inside the snapshot
and target skill links there. Refresh recognized AI Central template links
from the current checkout, earlier checkouts, and previous snapshots; reject a
managed link without a reviewed replacement. Preserve repository-owned files
and unrelated user skills. Retain snapshots referenced by applied links and
remove dry-run snapshots. Ignore the snapshot directory in Git.

## Consequences and limits

- Dirty installer, helper, catalog and skill bytes fail before execution.
- Later edits to the source checkout do not change the installed skills.
- Changing `AI_CENTRAL_HOME` cannot leave recognized links on an older mutable
  checkout while reporting setup success.
- The pinned maintained shell installer and its selected profiles/bundles stay
  unchanged. Tree format changes, symlinks, submodules, and larger catalogs need
  an explicit re-review rather than silent acceptance.
- Snapshot files are read-only, but this does not defend against malicious
  same-account code changing permissions or replacing local artifacts. Git,
  Node, the shell, local process integrity, and human pin review remain trusted.
- This does not authenticate unrelated user-owned skills or repository steering.
- The source checks and snapshot/link fixtures are portable Node tests. The
  actual shell installer was exercised on macOS; Windows shell execution is
  not newly claimed. Linux/macOS/Windows Rust CI remains required for the
  separate L1 pipe change.

## Evidence

The focused tests in `scripts/setup-codex-links.test.mjs` cover dirty files,
staged and assume-unchanged content, untracked helpers, symlink trees and source
aliases, source mutation after copying, pin-record preservation, managed-link
migration, and snapshot Git exclusion. An isolated checkout of the actual
reviewed revision also passed preview and apply, including migration from a
previous checkout and unchanged skill content after later source mutation.
