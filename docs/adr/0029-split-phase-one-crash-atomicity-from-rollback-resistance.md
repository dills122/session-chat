# ADR 0029: Split Phase 1 crash atomicity from rollback resistance

Status: accepted; claim-ledger correction

Date: 2026-09-07

## Context

ADR 0004 originally combined two different persistence properties in one Phase
1 acceptance sentence: restoring an internally consistent transaction after an
application crash, and detecting restoration of an older but otherwise valid
snapshot. Phase 1 retained extensive application-kill and SQLite-visible
commit-window evidence for the first property. It did not add an external
monotonic counter, platform vault anchor, or equivalent rollback detector for
the second.

ADR 0025 and the closeout matrix stated that limit, but did not explicitly
supersede ADR 0004's combined completion criterion. The result was a categorical
completion status that contradicted a retained normative sentence.

## Decision

Split the old persistence criterion into two stable acceptance IDs:

- `P1-STATE-CRASH-ATOMICITY` remains a Phase 1 criterion and is passed by the
  retained exact-revision application-kill and SQLite commit-window evidence.
- `P1-STATE-STALE-SNAPSHOT` is superseded as a Phase 1 completion blocker. The
  security property remains unproved and moves to the existing Phase 3 exit
  criterion for a highest accepted generation that survives restart and rejects
  stale-snapshot rollback.

The Phase 1 evidence matrix is the normative ledger for every ADR 0004
acceptance ID. Each row is `passed`, `superseded`, or `incomplete`; passed rows
require retained evidence, superseded rows require an ADR, and a complete ledger
cannot contain an incomplete row. Repository policy checks those mappings.

## Consequences

Phase 1 remains complete only as a protocol laboratory with application-crash
atomicity. This decision creates no rollback-resistance, physical power-loss,
platform custody, secure-deletion, or production-readiness claim. Product and
Phase 3 work must continue to treat valid older database snapshots as an active
rollback threat until independently anchored state has portable evidence.

No wire format, storage schema, runtime behavior, or compatibility contract
changes.
