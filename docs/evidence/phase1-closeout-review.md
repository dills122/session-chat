# Phase 1 closeout independent review record

Status: implementation and plan review Ready; full portable completion gate passed

Base: `b85e92cd2f6be7caa06e0979c0be8b2b973ee95c`

Final reviewed code/CI revision:
`9c9e24d785015147849fecddca5e6fa96e6becb2`

Three fresh-context engineering review instances assessed the retained Phase 1
contracts, implementation, negative tests and closeout matrix. Each recorded a
preliminary assessment before reading the separate author explanation. The
reviewers did not change source. The configured three-instance limit is exhausted.

## Findings and disposition

| Instance | Scope / finding | Disposition and evidence |
| --- | --- | --- |
| 1 | Checkpoint A durable authority | No actionable defect found in the inspected P1-1–P1-3 boundaries. The historical absence of independently replayable red-before-green commits is disclosed in the [matrix](phase1-closeout.md), rather than reconstructed. |
| 1 | P2: foreign poll binding/cursor scope accepted | Accepted. The request exposes its read-only binding; the deterministic provider compares it with receive authority and validates the exact schema-2 cursor scope. Foreign bindings and legacy/rebound cursor tests reject. |
| 1 | P2: owner commits and acknowledgement leases lacked live instance identity | Accepted. Private owner/lease identities and invalidation on restart, recovery and terminal acceptance reject stale or foreign handles. |
| 1 | P2: reusable provider silently accepted foreign acknowledgement IDs | Accepted. Complete acknowledgement sets are validated before mutation. LocalV1's separately documented no-op behavior remains scoped to that profile. |
| 1 | P2: cumulative receive retention unbounded | Accepted. The owner rejects new deliveries before mutation at 64 unique deliveries or 4 MiB; duplicates at capacity remain valid. |
| 2 | Closeout at `3b80d5d2b9e89b4cb1659d58ae4cb6479bebf208`; P2 expiry recovery could rewind time and deliver expired work | Accepted. `b3a33c510960ec14bababd9541f16d78c1ffb39e` keeps recovery at or after the workload clock, requires no work at expiry, and validates all five final mutable fields. A retained negative rejects the previously accepted Delivered tuple and each forbidden field change. |
| 3 | Final code and CI at `9c9e24d785015147849fecddca5e6fa96e6becb2` | Ready. No actionable finding remains. The expiry correction and Checkpoint B fixes are supported; implementation, matrix, ADR, architecture, threat model and plan agree within laboratory scope. |

Executable rejection cases are retained in
[receive_owner.rs](../../crates/transport-conformance/tests/receive_owner.rs),
[welcome.rs](../../apps/sessionctl/src/l2_process/welcome.rs), and
[l2_outbox_crash_restart.rs](../../apps/sessionctl/tests/l2_outbox_crash_restart.rs).
The final reviewer inspected the corrected four-test application/engine suite,
22 checked library tests, ordinary workspace tests and ordinary/checked Clippy
execution logs. It independently ran repository/link policy, diff checks and the
seven coverage-policy tests. Cargo execution was parent-owned to avoid ordinary
and checked binaries replacing each other in the shared build directory.

## Limits and completion decision

PR #303's first Linux and macOS runs exposed a pause-marker publication race
after the reviewed revision: the controller could observe the filename before
the writer finished its contents. The CI follow-up writes and closes a temporary
marker before renaming it to the readiness filename, and gives malformed marker
reads a distinct coarse stage. This narrowly scoped test synchronization change
was author-reviewed and passed the corrected sweeps and subsequent CI; it
is not represented as part of the earlier independent verdict. No fourth review
instance was started.

The subsequent full Windows run exposed an existing retry-conflict probe failure
that a multi-command shell step could mask with a later success. PR #304 gives
each Cargo command its own native CI step and repeats that exact probe across
eight fresh fixtures with coarse diagnostics. The first failure did not
reproduce; this is not a claimed storage defect diagnosis. These CI/test changes
were author-reviewed, and no further independent review instance was started.

The independent review established implementation/plan readiness. Completion is
separately supported by the [full non-PR gate](phase1-closeout.md) on immutable
merged code revision `ac7acf198b926e8fdb80257c899cca5e59a3f0e9`, including hosted
positive promotion and all Linux, macOS and Windows suites. The later completion
metadata checkpoint cites that revision rather than its own subsequent hash.

The Welcome fixture's authorization/opening tables are empty; populated durable
authorization has separate executable evidence. Engine promotion hashes the
writer executable and relies on the exact Cargo/CI context for the separate
verifier. Neither an independent build attestation nor physical power-loss,
rollback resistance, secure deletion, production networking or platform key
custody is claimed. This is a bounded engineering review, not an exhaustive
cryptographic audit.
