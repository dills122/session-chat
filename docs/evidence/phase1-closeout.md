# Phase 1 protocol laboratory evidence matrix

Status: implementation and independent review ready; publication and merged
exact-revision three-platform completion gate pending

## Revision and completion rule

Baseline before this closeout: `b85e92cd2f6be7caa06e0979c0be8b2b973ee95c`
([PR #302](https://github.com/dills122/session-chat/pull/302)).
This document does not claim that the baseline ran tests introduced afterward.
The completion revision and its full CI run will be recorded only after merge
and successful non-PR verification. A later documentation-only commit will cite
that immutable tested revision without claiming to be the tested code revision.

The first merged candidate `36d99f5bc5c45aded88558a73189c2578d76c288`
([run 33972775578](https://github.com/dills122/session-chat/actions/runs/33972775578))
does not qualify: its Windows log contains a failing joiner retry-conflict probe.
The default Windows shell continued to later Cargo commands, so an aggregate
job result alone cannot establish passage. The follow-up gives every checked
Cargo command its own CI step and runs that exact probe in PR
smoke with coarse failure diagnostics. Completion remains pending a corrected
merged revision and a full passing run.

Every row below is required on Linux x64 (`ubuntu-24.04`), macOS arm64
(`macos-15`), and Windows x64 (`windows-2025`) through
[the CI workflow](../../.github/workflows/ci.yml). A local pass or a PR smoke
alone does not fill the portable completion cell.

## Requirements and exact executable evidence

| Requirement / canonical scenario | Retained executable evidence | Phase 1 assertion and limit |
| --- | --- | --- |
| GUI/network-independent two-client flow; `E2E-JOIN-001` | [phase_one.rs](../../apps/sessionctl/tests/phase_one.rs): `headless_flow_joins_exchanges_updates_and_removes`; [l1_process.rs](../../apps/sessionctl/tests/l1_process.rs): `independent_process_runner_emits_bounded_redacted_evidence` | Capability-only protected join, explicit simulated approval, exact MLS Add, durable commit, Welcome and full two-party lifecycle over local test channels. No human approval UX or hosted service. |
| P1-1–P1-3 durable authorization | [durable_authorization.rs](../../crates/storage-sqlcipher/tests/durable_authorization.rs), [invitation_opening_context.rs](../../crates/storage-sqlcipher/tests/invitation_opening_context.rs), [capability_composition.rs](../../crates/storage-sqlcipher/tests/capability_composition.rs), and [l1_process.rs](../../apps/sessionctl/tests/l1_process.rs): `app_storage_owner_recovers_abandonment_joiner_consumption_and_welcome_retry` | Opening context commits before publication; restart abandons lost live provider authority, retains replay and reconciles exact membership outcome. No reconstructed KeyPackage or second Add. No rollback anchor or platform vault. |
| P1-7 hostile first contact; `E2E-JOIN-002` | [l1_process.rs](../../apps/sessionctl/tests/l1_process.rs): `hostile_first_contact_matrix_rejects_every_remaining_process_case`, `hostile_replayed_join_is_rejected_before_durable_membership_mutation`, malformed IPC and role tests | Malformed, expired, copied, wrong invitation, wrong KeyPackage, wrong verifier, duplicate, reordered and replayed requests reject before approval/membership mutation; fresh inspector checks unchanged authority. Local controller is trusted. |
| Join crash atomicity; `E2E-TXN-001` | [l2_crash_restart_inviter.rs](../../apps/sessionctl/tests/l2_crash_restart_inviter.rs), [l2_crash_restart_joiner.rs](../../apps/sessionctl/tests/l2_crash_restart_joiner.rs), [l2_io_faults.rs](../../apps/sessionctl/tests/l2_io_faults.rs) | Every clean-observed application checkpoint, supported SQLite FULL/IOERR ordinal and commit-window pause recovers exact I0/I1 or J0/J1 with exact retry. Physical power loss and rollback remain excluded. |
| Encrypted bidirectional messaging; `E2E-MSG-001` | [phase_one.rs](../../apps/sessionctl/tests/phase_one.rs), [l1_process.rs](../../apps/sessionctl/tests/l1_process.rs), [faults.rs](../../apps/sessionctl/tests/faults.rs) | Client-owned MLS content, coarse milestones, bounded redacted manifests and no plaintext at the untrusted forwarder. No packet-capture or deployed relay claim. |
| P1-4–P1-6 adverse common transport; `E2E-MSG-002` | [memory.rs](../../crates/transport-conformance/tests/memory.rs): `memory_adapter_passes_the_composed_common_verdict_trace`, `queue_saturation_is_deterministic_and_detects_an_over_accepting_bridge`, `held_delivery_survives_bounded_arbitrary_virtual_delay_without_sleeping`, and deliberately defective bridge tests | Bounded loss, delay, duplicate, reorder, corruption, stale replay, acknowledgement loss, saturation, wake/drop and exact-byte retry. No eventual delivery guarantee. The lifecycle matrix inventory is an index, not an independent verdict. |
| P1-8 Welcome recovery; `E2E-MSG-002` | [l2_outbox_crash_restart.rs](../../apps/sessionctl/tests/l2_outbox_crash_restart.rs): `every_welcome_checkpoint_recovers_without_repeating_membership`, `every_welcome_engine_commit_window_recovers_one_complete_state`, `changed_membership_material_cannot_pass_welcome_recovery`; [welcome.rs](../../apps/sessionctl/src/l2_process/welcome.rs) coverage/frame negatives | Seven workloads, 40 application checkpoints, plus all clean-observed supported SQLite commit-window ordinals. Fresh production reopen checks exact complete lease/result state and immutable fields; actual coordinator retries exact Welcome/endpoint bytes. Adapter acceptance is simulated and distinct from recipient receipt. |
| Epoch advance and removal; `E2E-REMOVE-001` | [phase_one.rs](../../apps/sessionctl/tests/phase_one.rs): `headless_flow_joins_exchanges_updates_and_removes`; [l1_process.rs](../../apps/sessionctl/tests/l1_process.rs) full lifecycle; `session-crypto-mls` integration suite | Bidirectional messages, path update, removal and post-removal rejection. Two-party MLS only; no obsolete-secret erasure or recipient-side deletion claim. |
| Right and handle separation; `E2E-AUTH-001` | [local_welcome_mailbox.rs](../../crates/session-transport/tests/local_welcome_mailbox.rs); [receive_owner.rs](../../crates/transport-conformance/tests/receive_owner.rs): foreign checkpoint, foreign owner, pre-restart lease, terminal re-lease, foreign delivery-ID and cursor-rebinding rejection tests; [durable_outbox.rs](../../crates/storage-sqlcipher/tests/durable_outbox.rs): stale/foreign and previous-open-scope lease tests | Only exact operation authority may mutate its scope. Opaque IDs/checkpoints do not grant authority. LocalV1 unknown acknowledgement IDs remain no-ops; the reusable model rejects foreign sets. Predictable model credentials are not production credentials. |
| Expiry/retention subset; `E2E-RETENTION-001` | [durable_outbox.rs](../../crates/storage-sqlcipher/tests/durable_outbox.rs): `failed_attempts_terminalize_at_the_persisted_bound`, `expiry_terminalizes_work_and_rejects_a_late_result`; P1-8 exhaustion/expiry workloads; `session-core`, `admission-capability`, `session-storage` suites | Bounded generation/replay retention, lease attempts and terminal work; no resurrection after process restart. Backups, physical key erasure, notifications/log retention, product ciphertext deletion and secure deletion are later-phase evidence. |
| Compatibility subset; `E2E-UPGRADE-001` | [durable_outbox.rs](../../crates/storage-sqlcipher/tests/durable_outbox.rs): frozen v1/v2/v3 migrations, ambiguous identity migration rollback and invalid material rejection; [receive_owner.rs](../../crates/transport-conformance/tests/receive_owner.rs): schema-2 cursor fixture and legacy rejection; canonical protocol fixtures | Supported laboratory SQL schemas migrate or fail closed; old model cursors reject explicitly. Migration process-kill sweeps, signed product upgrades and rollback-resistant restore are not Phase 1 claims. |
| Bounded hostile work; `E2E-ABUSE-001` | Protocol parser/HPKE/admission suites; [memory.rs](../../crates/transport-conformance/tests/memory.rs) saturation; [receive_owner.rs](../../crates/transport-conformance/tests/receive_owner.rs): `owner_capacity_rejects_new_bytes_without_advancing_but_accepts_exact_duplicates`; L1 IPC bounds and L2 defective-evidence suites | Object, queue, attempts, retained receive count/bytes, process time and evidence surfaces are bounded. No public-service quotas, traffic amplification or operational rate-limit claim. |
| P1-9 evidence integrity | [l2_public_evidence.rs](../../apps/sessionctl/tests/l2_public_evidence.rs), [evidence.rs](../../apps/sessionctl/src/l2_process/evidence.rs) negative promotion/provenance/scanner tests, Welcome coverage negatives and repository documentation checks | Private constructors prevent promotion from arbitrary rows. Dirty/unbound provenance, missing/duplicate coverage, malformed fields and seeded secrets fail closed. |

## Gate commands and evidence surfaces

Ordinary gate:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo test --workspace --all-features --locked --offline
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked --offline
cargo deny --all-features --locked check
node --test scripts/check-rust-coverage.test.mjs scripts/check-repository.test.mjs scripts/setup-codex-links.test.mjs spikes/sealed-invitation-provider/test/provider.test.mjs
node scripts/check-repository.mjs
node scripts/check-rust-coverage.mjs
```

Checked L2 uses `RUSTFLAGS="--cfg session_chat_storage_fault_testing"` and one
test thread. The non-PR workflow runs all of `l2_outbox_crash_restart`,
`l2_public_evidence`, `l2_process::evidence::tests`, `l2_crash_restart_inviter`,
`l2_crash_restart_joiner`, and `l2_io_faults`. Welcome application and engine
manifests are separate complete sweep classes under `E2E-MSG-002`.
Only canonical `L2_PUBLIC_EVIDENCE_BEGIN`/`END` records enter CI logs. Raw keys,
fixtures, baseline databases and case traces remain disposable and non-public.

Local verification on 2026-09-05 passed for code/CI revision
`9c9e24d785015147849fecddca5e6fa96e6becb2`: ordinary workspace tests, ordinary
and checked Clippy, rustdoc, dependency policy, formatting, Node tooling and
repository checks. The checked inviter/joiner/IO/public suites passed at the
initial closeout revision `3b80d5d2b9e89b4cb1659d58ae4cb6479bebf208`. After the
localized Welcome-oracle correction, its suite passed all four tests and checked
L2 library tests passed 22 tests. Coverage passed at 92.88% lines, 88.11% regions and 90.17%
functions. Ordinary and checked Cargo invocations were run sequentially after a
concurrent run replaced their shared binary; local Iroh tests required loopback
socket access. These local results do not fill the portable CI completion cell.

The checked-only Welcome harness modules are explicitly non-instrumented in the
ordinary coverage inventory, alongside the existing L2 harness; checked L2 tests
exercise them separately. Coverage thresholds are unchanged. The Welcome fixture
preserves the legacy committed membership/approval baseline; its authorization
and opening-context tables are empty. Populated durable authorization is covered
by the separate P1-1–P1-3 suites above. Public engine manifests bind the writer
test executable; the separate fresh verifier relies on the same exact Cargo/CI
build context, rather than a second executable digest or build attestation.

## Independent review and historical limitation

The initial fresh-context Checkpoint A/B review found no actionable durable
access-control defect in A, and four P2 defects in B: poll provenance, opaque
owner/lease identity, acknowledgement ID scope and cumulative receive retention.
This closeout corrects those defects and retains the executable negative cases.
Review instance 2 assessed commit `3b80d5d2b9e89b4cb1659d58ae4cb6479bebf208`
and supported all four Checkpoint B corrections. It found one P2 in the Welcome
expiry oracle: recovery could use an old lease expiry before the workload's
observed clock. The correction keeps recovery time at or after that clock,
avoids an expired live-lease probe, and asserts the complete final mutable tuple.
The retained `expired_recovery_rejects_delivery_attempts_and_clock_rewind` test
rejects delivery, attempt/generation changes and retained lease fields for expired
work. Review instance 3 returned Ready with no actionable findings at
`9c9e24d785015147849fecddca5e6fa96e6becb2`; the
[retained review record](phase1-closeout-review.md) records all dispositions and
remaining execution limits. Checkpoints A and B are reconciled on that basis.

P1-1 has a closed transition/fixture matrix and current negative tests. The
original combined implementation did not retain independently replayable
red-before-green commits. That historical test-order limitation cannot be
recreated after the fact; it is recorded here rather than represented as missing
current behavior or fabricated passing history. Exact-source current tests and
the closeout review establish the retained laboratory verification.

## Explicit later-phase cells

`E2E-RESTORE-001`, product Fast/offline delivery, Private egress/packet captures,
external identity, desktop/platform-vault integration, operated abuse controls,
physical durability, secure deletion and release/update provenance remain later
roadmap gates. PR #302's Iroh frame link and public N0 smoke do not fill them.
The reusable Iroh Fast adapter remains after P1-10.
