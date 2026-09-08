# ADR 0035: Bind local artifacts to created filesystem objects

Status: accepted

Date: 2026-09-08

## Context

Two local laboratory boundaries still authorized security decisions through
pathnames after separate checks. L1 cleanup validated a static root marker and
then recursively removed the same path, allowing a writer of a mutable ancestor
to replace the checked tree. The FastV1 Windows handoff inherited its parent
DACL and compared pathname metadata around a reopen, even though the file holds
deposit, receive, and acknowledgement rights.

Markers, timestamps, sizes, and repeated canonicalization cannot establish
stable object identity across a pathname race. Post-write permission repair is
also too late for bearer authority.

## Decision

L1 `ProcessRoot` retains a capability-directory handle immediately after
exclusive creation. Before initializing it, the process requires the named and
retained identities to match and the retained directory to remain empty; a
replacement introduced before handle acquisition is therefore rejected without
deletion. Cleanup enumerates and removes children relative to that handle. On
Unix the final owned directory is found and removed through the open capability;
on Windows the retained no-delete-sharing handle prevents rebinding while
contents are removed and only the final empty-directory removal occurs after
release. A replacement tree is never recursively removed. Hidden conformance
controller roles no longer delete roots they did not create; their caller
retains that cleanup authority.

FastV1 Windows handoff creation moves behind the safe `session-native-fs`
contract. Its isolated native implementation applies a protected DACL with
full-control allow entries only for Owner Rights and Local System during
exclusive creation, verifies the effective descriptor before any authority
bytes are written, and verifies publication retains the same file identity.
Windows join opens the selected path once with no-reparse semantics, checks
regular-file shape and handle-derived volume/file-index identity, verifies the
same restrictive DACL, and parses only from that handle. Unix keeps its
owner-only mode, `O_NOFOLLOW`, and device/inode comparison.

`cap-std` 4.0.3 supplies reviewed capability-directory traversal. Native
Windows calls remain in one publish-disabled crate with package-local audited
unsafe allowances; the `sessionctl` crate continues to forbid unsafe code.
The exact `winx` 0.36.4 Windows support dependency pulled by `cap-std` retains a
narrow cargo-deny exception for its `Apache-2.0 WITH LLVM-exception` license;
the exception does not authorize another crate or version.

## Consequences

- Rebinding an L1 root after marker validation cannot redirect recursive
  deletion into a replacement tree.
- Rebinding between root creation and capability acquisition fails if identity
  changes during validation or if the acquired object already contains data.
- A FastV1 handoff beneath a permissive Windows parent does not inherit broad
  read authority, and an inherited/permissive replacement fails before decode.
- Handoff bytes and CLI syntax do not change.
- Windows CI must run DACL, verification-failure, reparse, and same-length
  replacement regressions; Unix CI retains mode and link tests.
- Final Windows empty-directory removal can fail if a competing writer wins
  after the retained lock is released, but it cannot recurse into that object;
  cleanup then fails closed and may leave an empty owned directory.
- Same-account process inspection, privileged OS compromise, authenticated
  out-of-band transfer, secure deletion, and production platform custody remain
  outside these laboratory controls.
