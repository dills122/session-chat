# Real-world end-to-end security test strategy

Status: accepted test strategy; deterministic in-process protocol evidence and
isolated SQLCipher durability-laboratory evidence exist today

Date: 2026-08-20

## Purpose

Session Chat needs more than a final happy-path UI test. Each security claim
must be built from evidence at the smallest boundary that can prove it, then
re-run through processes, durable storage, real transports, and supported
platforms as those components become real.

This strategy defines the permanent test layers, scenario catalog, evidence
format, CI cadence, and release gates. A headless in-process client, isolated
SQLCipher durability laboratory, sealed-vault model, and deterministic memory
transport exist. It does not claim that a two-process runner, product-integrated
durable store, hosted realm, desktop client vault, or real-network adapter exists.

## Principles

- Every implemented invariant has a fast deterministic test in the required PR
  gate. A large E2E test never substitutes for a missing unit or contract test.
- The same logical scenario runs first against memory fakes, then against real
  process/storage/network adapters through shared conformance boundaries.
- Tests control clocks, schedules, faults, and non-security identifiers.
  Production cryptographic randomness is never weakened; deterministic crypto
  fixtures use explicit test-only providers or retained vectors.
- All tests are bounded by time, bytes, attempts, queue depth, and cleanup.
- Failures retain their seed, topology, toolchain, component revisions, and
  redacted trace. CI does not hide flakes with blind retries.
- Logs and evidence never retain plaintext, raw capabilities, group keys,
  provider tokens, or stable external identities.
- Passing functional conformance does not prove anonymity or privacy. Private
  profiles additionally require egress-denial, dependency traffic inventory,
  packet-capture analysis, and an explicit observer model.

## Test layers

| Layer | Environment | What it proves | Cadence |
| --- | --- | --- | --- |
| L0: type, unit, parser, and model | One process, offline | Canonical formats, bounds, state transitions, right separation, redaction, crypto vectors | Every PR through `CI / Gate` |
| L1: deterministic protocol E2E | Current in-process `sessionctl` two-client composition; later independent client/service processes | One complete invitation-to-message-to-removal flow under explicit time inputs | Every PR |
| L2: faulted component E2E | Multiple local processes, deterministic adverse scheduler, disposable real storage | Crash/restart, lost responses, duplicate/reordered delivery, lease recovery, rollback detection | Nightly and on affected PRs |
| L3: containerized realm E2E | Digest-pinned disposable realm with real service boundaries and storage | Deployment wiring, TLS, quotas, migrations, restore, service isolation, operational redaction | Nightly after a deployable realm exists |
| L4: real transport labs | NAT/relay, onion test service, SMP test servers, and local/test mixnets | Adapter conformance, outage behavior, latency/resource bounds, no unintended fallback | Scheduled and before adapter decisions |
| L5: hostile privacy and platform | Deny-by-default egress, packet capture, supported OS vaults, process inspection | Forbidden network paths stay closed; lock/delete/update behavior matches platform claims | Release candidate and security review |
| L6: operated release evidence | Staging deployment, restore drill, signed artifacts, vulnerability and dependency gates | The exact releasable artifact and operational procedures satisfy the approved claim set | Every security-focused release |

L0 and L1 are merge gates because they are deterministic and offline. L2-L6
become mandatory only when the resources they exercise exist, but a component
cannot advance to the next roadmap phase without its required layer.

## Canonical scenario catalog

| Scenario | Priority | First executable layer | Required result |
| --- | --- | --- | --- |
| `E2E-JOIN-001` protected capability join | P0 | L1 | Signed invitation, exact HPKE request, admission binding, explicit approval, MLS Add, atomic commit, and encrypted Welcome delivery complete once |
| `E2E-JOIN-002` hostile first contact | P0 | L1 | Malformed, expired, replayed, copied, wrong-invitation, wrong-KeyPackage, and wrong-verifier inputs fail before membership mutation |
| `E2E-TXN-001` crash at every join write boundary | P0 | L2 | No partial membership/outbox visibility; recovery never repeats MLS Add or releases a consumed invitation |
| `E2E-MSG-001` bidirectional encrypted messaging | P0 | L1 | Both clients exchange application messages; infrastructure artifacts contain no plaintext or group keys |
| `E2E-MSG-002` adverse delivery | P0 | L1/L2 | Loss, delay, duplication, reordering, stale replay, corruption, and queue saturation preserve protocol safety within budgets |
| `E2E-REMOVE-001` removal and epoch advance | P0 | L1 | Removed member cannot decrypt later messages; remaining member recovers from allowed reorder/loss cases |
| `E2E-AUTH-001` mailbox right separation | P0 | L0/L1 | Issued deposit, receive, acknowledgement, and rotation rights cannot substitute; identifiers never authorize mutation |
| `E2E-RETENTION-001` expiry and deletion | P0 | L2/L3 | Invitations, replay state, ciphertext, keys, queues, backups, and logs follow documented retention without resurrection after restart |
| `E2E-RESTORE-001` backup and stale snapshot | P0 | L3/L5 | Valid restore succeeds; stale generations and rollback attempts fail closed or trigger the documented trust-reset path |
| `E2E-FAST-001` direct and relay delivery | P1 | L4 | NAT, relay-only, peer-offline, route-change, and outage cases match the Fast observer and reliability contract |
| `E2E-PRIVATE-001` no private-profile downgrade | P0 | L4/L5 | Failure opens no DNS, clearnet, direct, telemetry, update, preview, or crash-report path outside the approved profile |
| `E2E-MIXNET-001` delayed private delivery | P1 | L4/L5 | Identical padded workload survives expected mixnet delay/loss while packet captures show no fast fallback; anonymity claims remain separately gated |
| `E2E-UPGRADE-001` compatibility and migration | P0 | L2/L3 | Supported old fixtures migrate or fail with an explicit version error; active MLS or transport state never silently changes backend/profile |
| `E2E-ABUSE-001` unauthenticated exhaustion | P0 | L2/L3 | Parser work, HPKE/admission work, queues, storage, retries, decompression, and rate limits stay within configured bounds |

Each scenario expands into positive, boundary, malformed, expired, replayed,
duplicated, reordered, unauthorized, and recovery cases wherever those inputs
are meaningful. Scenario identifiers remain stable so code tests, evidence
records, roadmap gates, and external audit findings can refer to the same case.

## System traceability

| Component | Evidence retained now | Next real-world evidence |
| --- | --- | --- |
| `session-protocol` | Canonical fixtures and malformed/boundary tests | Continuous fuzz corpus, compatibility corpus, and cross-version decode matrix |
| `session-core` | Invitation validation and lifecycle state tests | Two-process invitation/join orchestration with restart and concurrent request races |
| `admission-capability` | Exact binding, replay, expiry, and reservation tests | Full hostile first-contact scenario through the headless client and transaction boundary |
| `session-crypto-hpke` | RFC and independent-provider vectors plus hostile context rejection | Cross-process protected join with captured ciphertext inspection |
| `session-crypto-mls` | Two-party lifecycle, replay/reorder, update/removal, and storage-call evidence | Cross-implementation vectors where available, process restart, durable state, and corrupted-state tests |
| `session-inviter-transaction` | Deterministic atomicity/fault model plus LocalV1 coordinator owner-port acceptance, failure, and ambiguous exact-retry integration | Real database process-kill, disk-full/I/O failure, restore, and stale-snapshot evidence |
| `storage-sqlcipher` | Real inviter and joiner MLS transaction, rollback, ambiguous-result, and close/reopen laboratory tests | Product composition, process-kill, disk/power fault, restore, and stale-snapshot evidence |
| `session-transport`, `transport-memory`, and `transport-conformance` | Local and provider-neutral right separation, bounds, idempotency, canonical opaque envelopes, deterministic adverse controls, strict bounded double-replay conformance with defective bridges, fail-closed LocalV1 binding, a deposit-only coordinator, and cross-platform blocking supervision | Provider-wide conformance, durable owner-store composition, real network adapters, and packet-captured evidence |
| `sessionctl` | In-process two-client capability join, simulated approval, Welcome delivery, messaging, update, removal, and coarse output | Independent-process L1 runner and machine-readable redacted evidence producer |
| Client vault | Sealed lifecycle, opaque locked inbox, bounded unlock orchestration, and portable passphrase laboratory | Product storage composition, OS credential input, process isolation, crash-dump, rollback, recovery, and deletion evidence |
| Realm services | Design and disposable invitation-provider spike only | Container isolation, quotas, migration/restore, and operational redaction tests |

## Runner and topology contract

The current L1 test composes two logical clients in one process. The next L1
runner should launch two independent `sessionctl` processes and an untrusted
transport/service process. Tests communicate through public wire and core-facing
interfaces rather than calling private state directly. A scenario controller
supplies:

- a virtual clock and explicit deadlines;
- a deterministic delivery/fault schedule and retained seed;
- bounded ephemeral ports, directories, queues, and process lifetimes;
- disposable credentials and non-production realm keys;
- assertions over client-visible state and redacted service observations; and
- teardown that proves no child process or leased work remains.

L2 replaces one fake at a time with the real adapter under test. This isolates
failures and prevents a single all-real stack from becoming impossible to
diagnose. The exact same scenario must pass through the fake and real boundary
before the real component can replace it.

## Evidence bundle

Every medium, large, or release test emits a bounded manifest containing:

- scenario ID, seed, commit, dirty-state flag, toolchain, dependency lock
  digest, platform, topology, and component image/revision digests;
- exact command, start/end timestamps, configured budgets, injected faults,
  normalized result codes, and assertion summary;
- hashes of canonical public fixtures and encrypted artifacts, never their
  secret-bearing plaintext or capability material;
- a machine-checked redaction result for logs, errors, traces, and crash output;
- sanitized packet-flow and storage-inspection summaries; and
- links or digests for restricted raw packet captures when required for audit.

Raw packet captures can reveal addresses and relationships. They belong in
access-controlled test artifacts with retention limits, not in the public Git
repository. Public evidence records retain sanitized summaries and immutable
digests only.

## CI and execution policy

### Required pull-request gate

- Run the full locked workspace tests, doctests, Clippy, rustdoc, repository
  policy, and dependency policy already defined in `SECURE_DEVELOPMENT.md`.
- Keep the current in-process L1 scenario in ordinary workspace tests and add
  independent-process scenarios when that runner lands, keeping the required
  PR subset deterministic, offline, and below the job timeout.
- Run affected fuzz smoke corpora and model tests once their untrusted parser or
  state-machine surfaces land.
- A failure blocks merge. Re-running without a code, environment, or recorded
  seed change is not a fix.

### Nightly and scheduled gates

- Nightly: L2 process/crash/storage/adverse scenarios, sanitizers where
  supported, longer property/model runs, and bounded resource/soak tests.
- Weekly or explicit lab run: L3/L4 container and real-network matrices with
  topology isolation and retained evidence bundles.
- Release candidate: L5/L6 supported-platform, restore, deletion, egress-denial,
  packet-capture, dependency, artifact provenance, and independent-review gates.

External test networks are inherently variable. Their availability and latency
measurements may be informational, but authority violations, plaintext leaks,
forbidden egress, silent downgrade, and budget overruns are always hard
failures.

## Entry and exit criteria for a new component

Before a real storage, transport, identity, vault, or crypto adapter is adopted:

- its threat/observer model and exact versions are recorded;
- the fake/reference implementation passes the shared scenarios;
- the real adapter passes the same conformance cases and its component-specific
  negative cases;
- intentionally defective adapters prove the harness detects authority,
  idempotency, redaction, deadline, and recovery violations;
- evidence contains no forbidden secret material; and
- an independent review reconciles the implementation with the retained plan.

A component is not production-ready merely because it implements a trait or
passes a happy path.

## Implementation order

1. Connect the real SQLCipher transactions through the same sole-owner
   coordinator port, with process/disk-fault evidence before any durability
   claim.
2. Integrate the atomic inviter transaction and coordinator into the real
   admission/MLS product composition without repeating the existing MLS
   transition.
3. Extend the existing in-process `sessionctl` composition into the canonical
   independent-process L1 runner and redacted evidence producer.
4. Add provider-wide lifecycle/cursor conformance and only then retain a
   packet-captured network adapter experiment.
6. Add the containerized realm runner before deployment claims.
7. Evaluate Fast, Tor/Arti, SMP, and mixnet candidates through the same scenario
   IDs, evidence schema, and packet-capture policy.
8. Add platform vault, update, restore, and operated-release lanes only when
   their product surfaces exist.

## Current gaps

- No independent-process two-client/service runner or machine-readable evidence
  bundle exists; current `sessionctl` evidence is in process.
- The deterministic memory adapter covers explicit delivery, loss, duplication,
  hold/release reordering, retry, expiry, authority, capacity, outage,
  corruption, stale replay, and acknowledgement-result loss. The publish-disabled
  conformance crate parses retained traces and executes one normalized
  double-replay memory lifecycle, but no complete reusable adapter verdict or
  deliberately defective-adapter suite exists.
- SQLCipher transaction evidence exists, but no product-integrated durable flow,
  process-crash, disk/power-fault, restore, or stale-snapshot harness exists.
- The supported-platform CI matrix exists for current Rust foundations, but no
  real transport, packet-capture lane, containerized realm, desktop application,
  signed release, or operated release matrix exists.

These are missing evidence, not failed evidence. Until the relevant layer
passes, corresponding security, durability, privacy, and production claims
remain prohibited.
