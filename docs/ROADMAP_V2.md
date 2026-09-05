# Session Chat 2.0 roadmap

Status: proposed sequencing, not a delivery commitment

## Guiding approach

Build a new protocol core without carrying the retired application as active
source. Preserve its tagged history and documented UX lessons, but do not
incrementally reinterpret Socket.IO messages, JWTs, Redis membership, or
deterministic invitation hashes as cryptographic session state.

Each milestone should produce a runnable vertical slice and explicit evidence
for its security properties.

## Current target

**Decision:** Phase 1 is complete as a capability-only Rust protocol laboratory;
its exact evidence is recorded below. V1 is retired under ADR 0006;
do not turn that cleanup into GitHub integration, SSI, a production mailbox, a
GUI, or a reusable/product network transport. A separately invoked bounded
Iroh frame-link feasibility experiment exists, but it does not satisfy a Phase
1 exit criterion or the later Fast adapter milestone.

The complete scope, acceptance evidence, bounded research questions, and later
integration order are recorded in
[ADR 0004](adr/0004-build-v2-as-a-parallel-protocol-laboratory.md), with
source-tree coexistence superseded by
[ADR 0006](adr/0006-retire-v1-from-the-default-branch.md).

## Phase 0: freeze the design baseline

Deliverables:

- Product definition
- Architecture and identity boundaries
- Threat model and security invariants
- Transport downgrade policy
- Versioned invitation and envelope sketches
- Research backlog and ADR process

Exit criteria:

- GitHub, credential, capability, and manual admission fit one interface.
- Fast and private delivery fit one envelope interface.
- Product copy distinguishes verified, trusted, private, anonymous, and
  ephemeral.
- Unknowns remain marked as research rather than hidden assumptions.

## Phase 1: protocol laboratory

Implementation status: complete on tested code revision
`5a220bd9376d51b9b3943e997fc5c93ddcfa91ca`; the
[completion evidence](evidence/phase1-closeout.md) records the full portable gate
and distinguishes its later documentation checkpoint. Retained increments establish the Rust
workspace, bounded deterministic-CBOR opaque envelope, canonical
domain-separated Ed25519 secret-capability invitation, exhaustive field-boundary
fixtures, and a bounded inviter-owned invitation reservation/consumption state
machine. The isolated `session-crypto-mls` increment now retains bounded exact
KeyPackage validation, a two-member Add/Welcome lifecycle, application
messages, path updates, removal, adverse delivery cases, and explicit provider
storage timing with the reduced-feature `mls-rs`/AWS-LC graph selected by ADR
0012. The `session-crypto` crate now supplies the provider-neutral established-
session message seam from ADR 0013; backend negotiation and active-state
migration do not exist. ADR 0014's bounded canonical invitation-v2, protected
outer/inner, exact AAD, and local deposit-endpoint value types now exist. The
provider-neutral HPKE adapter adds fixed one-shot AWS-LC seal/open, RFC 9180
known-answer evidence, independent-provider opening, and hostile context
rejection. The capability-admission adapter now retains HPKE proof provenance,
independently validates and owns the exact KeyPackage, and reserves request IDs
and nonces within bounded in-memory generation state. It retains the exact
opened invitation signature, reserves the matching local v2 record, consumes an
explicit simulated approval decision, and permits only that approved value to
enter MLS. Rejection, expiry, failed preparation, and abandonment release both
reservations; successful in-memory Add consumes invitation state. A separate
bounded local transport adapter now models one-Welcome deposit, receive, and
acknowledgement under independent authorities. The approved in-memory join
result now carries its exact deposit endpoint beside the MLS outputs, with
retained local Welcome-delivery evidence. A separate bounded conformance model
now exercises the accepted inviter transaction's atomic visibility, exact retry,
ambiguous-result recovery, and Welcome-outbox leasing semantics under injected
memory-model faults. The in-memory inviter outbox now implements the LocalV1
coordinator owner port and retains exact acceptance/failure/ambiguous-retry
evidence against the real local mailbox. The real capability-admission/MLS path
now crosses the SQLCipher transaction through an explicit durability-pending
one-shot value, recovers an ambiguous commit, finalizes invitation state once,
reopens the owner store, and delivers the exact Welcome to the original joiner.
Human approval UX and reusable/product network transport remain later-phase
work. The bounded authenticated Iroh frame-link experiment is not an
`EnvelopeDelivery` provider, offline mailbox, or completed network profile.
The complete Phase 1 hostile first-contact matrix is now retained by the
independent-process runner: malformed, expired, copied, wrong-invitation,
wrong-KeyPackage, wrong-verifier, reordered, and exact-replay inputs reject
before approval, MLS Add, or durable membership mutation. The wrong-verifier
case specifically reaches the production expected-invitation reservation guard,
requires rejection, and proves its transient replay reservation is released;
fresh inspection proves the owner state unchanged. Welcome-delivery lease/result process-kill
recovery is retained with full portable evidence in the closeout matrix. The SQLCipher
laboratory now
implements the same sole-owner coordinator port with version-2 migration,
close/reopen leases, terminal states, and ambiguous exact-retry evidence; it is
now exercised by the independent-process L1 path. Schema version 3 adds the exact
client-identity owner required to reload the same Alice member and stored group;
version 4 binds it to that one group. Graceful process-exit and bounded
join-writer application-kill evidence now exist; power loss and stale-snapshot
rollback evidence remain open.

The provider-neutral right-specific transport trait and its separate
`transport-memory` adapter now retain deterministic drop, duplicate,
hold/release reordering, exact-retry, expiry, authority, and capacity evidence.
This completes the Phase 1 memory-transport test control, not network delivery.
The additive generalized contract values now also bound opaque cursors, poll
count/bytes/wait, deposit bytes, acknowledgement batches, and identifier-minimal
receipts before dispatch, while received batches enforce the originating poll's
count/byte limits and local expiry. The runtime-neutral generalized dispatch
trait and its deterministic memory adoption now add explicit clock/cancellation,
exact-set acknowledgement, fail-closed cursor, idempotency-conflict, and
provider-redaction evidence. The provider-neutral lifecycle contract now adds
bounded four-right issuance, generation-bound cursor validity,
compare-and-swap rotation, explicit resynchronization, and a separate atomic
receive-state owner port with exact committed-checkpoint reload, cursorless
successor revisions, page/checkpoint binding, owner-opaque commit evidence, and
explicit expiry checks. Exact checkpoint provenance includes cursor position
and bytes; owner-CAS resynchronization is restartable, recovered acknowledgement
leases survive crashes, and duplicate IDs fail at the batch boundary. Lifecycle declarations bind a nonlocal semantic
profile, cursor schema, drain policy, and wall-time validity to issuance and rotation; LocalV1
lifecycle declarations, issue requests, and cursor bindings fail closed. A conforming reusable provider and
durable product cursor persistence remain open.
A new publish-disabled `transport-conformance` crate now retains the strict
bounded adverse-trace v1 parser, hostile fixtures, and a first normalized
double-replay memory runner, while `transport-memory` adds
bounded outage, corrupt-poll, exact-byte stale-replay, acknowledgement-loss,
and secret-free state-probe controls. The retained runner proves deterministic,
quiescent adverse delivery, exact bindings, redaction, bounded wake/drop
behavior, queue-saturation rejection at the retained eight-envelope bound, and
common-suite detection of deliberately defective bridges. Bounded arbitrary-delay traces and the closed Phase 1 lifecycle/authority
matrix are retained; reference-model corrections and their regression tests
are described in ADR 0025. Production provider conformance remains a later gate. The
LocalV1 deposit-only coordinator adds one-attempt owner-store policy plus a
cross-platform blocking wake/cancel/deadline supervisor; neither is a network
or production-runtime claim.

The implementation-free `session-admission` crate now supplies the
provider-neutral, non-authorizing approval context and decision from ADR 0022.
It deliberately does not generalize provider proof verification or the exact
one-shot membership authority.

The `sessionctl` binary now completes the headless durable-component Phase 1
composition: a fresh Alice/Bob capability invitation and protected request,
explicit simulated approval, exact MLS Add, atomic SQLCipher inviter commit,
ambiguous-result recovery, exact Alice identity/group reload, reconstructed coordinator Welcome delivery,
bidirectional application messages, path update, removal, and post-removal
rejection. Its retained tests, coarse CLI output, and versioned redacted
scenario record satisfy the no-GUI/no-network laboratory acceptance path.
The ADR 0021 `sessionctl-l1` runner additionally places Alice, Bob, and an
untrusted forwarding service behind bounded local IPC, exits Alice after the
durable commit, reloads her exact identity/group in a fresh process, completes
the lifecycle, reaps every child, and emits a bounded redacted manifest.
The checked L2 suites add bounded inviter/joiner application-kill recovery.
Welcome-delivery application and SQLite commit-window kill recovery are now
implemented in the checked closeout suites. The [evidence matrix](evidence/phase1-closeout.md)
records their exact tests, independent review and passing merged-revision full
three-platform gate. Power-loss evidence, human
approval UX, and a network profile remain later gates.

The Rust source-coverage gate now measures production code through integration
targets without counting inline test helpers. The clean-master baseline was
90.78% workspace lines; retained behavior and negative-path tests keep the
measured result above the 92.23% ratchet, with every security- and
correctness-vital component at or above 90%. Stable region and function
ratchets are also enforced. `sessionctl` now uses named, secret-free
orchestration fault seams to cover cross-crate failure mapping, cleanup,
post-commit Welcome failure, dropped delivery, and exact Alice identity/group
reload. The dated observed snapshot, commands, variability note, and exclusions
are in [`CODE_COVERAGE.md`](CODE_COVERAGE.md).

The first `session-storage` increments now make the selected sealed-vault
lifecycle and locked-mode capability matrix executable. The deterministic
model permits bounded canonical opaque receipt in every state and binds local
import to the exact open session, vault generation, and inbox insertion. ADR
0020 now moves protector work outside the lifecycle owner, binds every result
to one vault instance/session/generation, bounds concurrent attempts, and uses
exact-session one-shot credentials. Cancellation stops work that has not
entered the provider and discards a late result; synchronous provider work
already running cannot be preempted. A
platform-linked durable client store, integrated product MLS persistence,
platform user-presence adapters, rollback resistance, broader crash recovery,
and secure-deletion evidence remain outstanding. The separate SQLCipher
laboratory adapter now commits the actual inviter MLS snapshot with bounded
transaction-model invitation, replay/approval, and Welcome-outbox records, and
separately commits joiner MLS state with exact one-time KeyPackage deletion.
Its version-2 schema is also the sole Welcome-delivery ledger and implements the
coordinator owner port with persistent store identity, bounded attempts,
generation/identity-bound leases, explicit terminal states, and version-1
migration fixtures. Tests cover rollback, stale/foreign leases, ambiguous
byte-identical delivery recovery, and close/reopen on the required Linux,
macOS, and Windows CI runners. Schema version 3 adds an insert-only, versioned
client identity, and version 4 adds the exact group binding and proves exact member/group
reload plus cross-group rejection after close/reopen. Graceful
independent-process reload now exists. Checked local sweeps now kill every
baseline-observed inviter and joiner application checkpoint and require exact
I0/I1 or J0/J1 recovery plus unchanged exact retry. The exact revision recorded
in the Phase 1 closeout matrix passed the portable three-OS public-evidence gate;
each later behavior or evidence revision must repeat that gate before the
completion record advances. Platform-vault, disk/power fault, production
packaging, and rollback-anchor gates remain.
The checked L2 storage fault protocol and reusable `sessionctl` process
controller/verifier are now retained. A publish-disabled named SQLite VFS also
delegates ordinary behavior to the captured process default, remains non-default
after registration, records bounded path-free operation evidence, and returns
actual `SQLITE_FULL`/extended `SQLITE_IOERR_*` codes only to explicitly named
connections. The checked `sessionctl` L2 I/O suite now derives its matrix from
clean named-VFS traces, injects one-shot and persistent FULL/extended-IOERR
results at every observed supported inviter/joiner ordinal, and kills a
separately supervised child at every observed journal/main commit-window pause
before fresh-process verification. Incomplete return-code or pause matrices
cannot emit complete matrix coverage. Raw case observations remain non-public.
The retained L2-8 gate lets sealed complete aggregates emit canonical per-case
`l2-evidence-v1` bundles only after binding clean Git, actual compiler, GitHub
run/workflow, the closed runner tuple, engine, test-binary, and encrypted-artifact
provenance and scanning every bounded surface for synthetic canaries and actual
case secrets. Portable
passage remains per-revision three-OS evidence, so this adds no power-loss,
filesystem, rollback-resistance, or production-durability claim.

ADR 0019 and `key-protector-passphrase` now retain the bounded portable
key-wrapper conformance experiment: exact Argon2id 0.5.3 and AWS-LC 1.16.3
AES-256-GCM, one fixed measurement profile, a closed 102-byte record,
authentication to the expected `SessionId`, coarse failures, and hostile-input
pre-work bounds.
This completes the isolated construction and bounded lifecycle-orchestration
checkpoints. The adapter now implements the exact-session protector and consumes
a one-shot credential without retaining it, but does not supply SQLCipher or
select a production portable baseline. Three-OS performance and memory
measurements, desktop credential acquisition, a production scheduler, atomic
persistence and key handoff, recovery, rekey and rollback policy,
offline-guessing UX, native enhancements, and independent boundary review
remain gates.

Contract hardening rules preserved by the current in-memory flow and required
for the remaining headless and durable composition:

- Descriptor validation is read-only and only local issuance creates lifecycle state.
- Invitation reservation and consumption follow ADR 0008.
- Admission binds the exact KeyPackage, credential, and leaf key under ADR 0009.
- Transport interfaces use the distinct authorities from ADR 0010.
- The MLS integration obeys the selection and stop conditions in ADR 0012.
- New sessions may select only a reviewed, compiled backend under ADR 0013;
  active sessions cannot silently switch implementations.
- The local capability join uses only the exact versions, HPKE contexts,
  verifier binding, closed response endpoint, and before-mutation ordering from
  ADR 0014.

The isolated MLS crate still uses only in-memory providers for deterministic
protocol tests, as ADR 0012 specifies. The SQLCipher-backed headless paths now
use one restartable durable owner for opening-context recovery, request replay,
invitation reservation, approval/result shadows, the exact MLS membership
transition, invitation consumption, and the encrypted Welcome outbox job.
Dropped or restarted pre-membership work returns the exact usable generation to
`Available` while retaining replay, and outcome-unknown recovery never repeats
MLS Add. This passes the laboratory composition gate without establishing a
networked, user-facing, rollback-resistant, or production-secure client.

ADR 0023 now freezes that recovery contract: invitation publication follows
durable retention of its exact signed descriptor and matching HPKE private key;
pending authorization persists only as a non-authorizing replay/conflict
shadow; and restart abandons rather than reconstructs a lost live KeyPackage.
The SQLCipher opening-context and authorization-shadow schema/API slices are
retained and used by both headless compositions. They enforce bounded replay
retention, restart abandonment, exact generation ownership, and
membership-transaction outcome reconciliation while the provider keeps its
exact parsed KeyPackage only for the live attempt.

The retained Phase 1 workspace includes the original foundation:

- `session-protocol`
- `session-core`
- `session-admission`
- `admission-capability`
- `session-crypto`
- `session-crypto-hpke`
- `session-crypto-mls`
- `session-inviter-transaction`
- `session-transport`
- `key-protector-passphrase`
- Deterministic in-memory transport
- `sessionctl` headless client

The completed work and the exact boundary between laboratory completion,
pre-network safety, and later production evidence are recorded in the historical
[Phase 1 protocol laboratory closeout plan](plans/PHASE1_PROTOCOL_CLOSEOUT.md).

The transport slice follows the profile-bound contract proposed in
[`TRANSPORT_ABSTRACTION_V1.md`](specs/TRANSPORT_ABSTRACTION_V1.md). Stabilize
the existing right-specific local Welcome adapter, then add the generalized
contract, deterministic adverse-network control path, and shared conformance
harness before any reusable network adapter. The separately authorised Iroh
frame-link feasibility slice is evidence only and does not change that order.
The detailed task order and
checkpoints are in the
[transport abstraction implementation plan](plans/TRANSPORT_ABSTRACTION_IMPLEMENTATION.md).
The cross-system scenarios, evidence format, and progression from deterministic
two-client tests to real storage, transports, packet captures, and platform
release gates are defined in the
[real-world E2E security test strategy](plans/REAL_WORLD_E2E_TESTING.md).

Capabilities:

- Create, parse, authenticate, and expire signed invitations without mutation
- Reserve a locally issued invitation after validated admission and consume it
  only with a successful membership transition
- Encrypt and decrypt join requests
- Reject replay and expiration
- Approve a secret-capability join
- Establish a two-person MLS group
- Exchange application messages
- Remove a member and advance the epoch

Exit criteria:

- Protocol tests run without a GUI or network service.
- Captured envelopes contain no plaintext.
- Duplicate, reordered, expired, and malformed objects fail safely.
- Key and state-machine invariants are covered by property or model-based tests
  where practical.
- The durable-authorization, common-transport, hostile-process, and
  exact-revision gates in the Phase 1 closeout plan pass.

## Early product-validation track

After the headless invitation/admission states are concrete, but before choosing
the desktop UI framework or completing Phase 3 services, build the fixture-driven
prototype defined in `PRODUCT_V2.md`. Test approval evidence, device-change
warnings, transport guarantees, and failure states with representative users.

Exit criteria:

- Users can distinguish verified account control from personal trust.
- Users understand that valid evidence still requires approval.
- Fast and Private mode wording does not imply equivalent metadata guarantees.
- Results are recorded as product evidence and do not become protocol authority.
- A separate ADR selects the desktop shell and UI framework only after this evidence.

## Phase 2: prove identity independence

Implement GitHub admission through a minimal identity bridge while keeping
secret-capability admission working.

Exit criteria:

- The same invitation/join state machine accepts either configured proof type.
- GitHub attestations bind provider subject, invitation challenge, audience,
  expiration, and the complete ADR 0009 tuple: canonical KeyPackage reference,
  session-scoped credential identity, leaf signature key, MLS version and
  ciphersuite, and join-request identifier.
- Copying a targeted invitation cannot admit another GitHub account.
- Anonymous capability mode makes no GitHub or bridge requests.
- Raw GitHub tokens never enter rendezvous, peer messages, or logs.

## Phase 3: rendezvous and fast delivery

Implement:

- Optional rotating receive-bundle directory and sealed first-contact mailbox
- Opaque capability-addressed mailboxes
- TTL and bounded storage
- Iroh or an equivalently evaluated direct/relay adapter
- Offline join, Welcome, and message delivery
- Docker Compose realm deployment

Exit criteria:

- Rendezvous and relay compromise does not reveal plaintext or group keys.
- The first-contact directory cannot read invitation traffic, and the sealed
  mailbox does not store external identity fields.
- Directory registrations and signatures bind the lookup address to the full
  rotating receive bundle.
- NAT and offline scenarios have repeatable integration tests.
- Abuse controls bound unauthenticated storage and computation.
- Operational logs remain useful without containing sensitive protocol data.
- Directory generation and previous-bundle digest update through one durable
  compare-and-swap transaction.
- The highest accepted generation survives restart and rejects stale-snapshot rollback.
- Crash recovery is tested before and after every registration write boundary.
- Concurrent competing successors across multiple service instances cannot both commit.
- Rotation history, draining mailboxes, and continuity-reset state recover consistently.

## Phase 4: desktop client

Create the desktop shell selected by its dedicated ADR around the Rust core.
Tauri is the leading privilege boundary; Angular or another UI framework is not
selected by the retirement history or this roadmap. ADR 0018 requires the
common local-app baseline to be implemented and tested across macOS, Windows,
and Linux together rather than treating ports as later phases.

Initial UX:

- Create a targeted or secret-capability invitation
- Open invitation deep links
- Review exactly what admission evidence was verified
- Compare a device fingerprint
- Approve or reject a request
- Exchange text messages
- Close a session and destroy retained keys according to policy
- Clearly show transport profile and metadata caveats

Exit criteria:

- The same baseline workflow and canonical state pass required build, lint,
  and conformance gates on Linux, macOS, and Windows.
- UI code cannot bypass core admission or MLS state transitions.
- Secrets use a reviewed protector whose measured capabilities satisfy the
  selected mode and are excluded from browser storage; native enhancements do
  not silently define the portable baseline.
- Deep-link parsing is fuzzed and treats links as attacker-controlled.
- Update signing and application provenance have a documented plan.

## Phase 5: private transport experiment

Add a Katzenpost-backed adapter and a deterministic adverse-network simulator.
After the primary Katzenpost integration boundary is understood, run a bounded
Nym comparison through the same canonical envelope workload, simulator trace,
observer matrix, and packet-capture format. This comparison does not add Nym,
its chain, or its credentials to the session security model.

Test:

- Delay
- Loss
- Duplication
- Reordering
- Corrupted envelopes
- Replay across epochs
- Service and route unavailability
- Queue exhaustion
- No-downgrade behavior

Exit criteria for experimental release:

- The client never opens fast paths in Private mode.
- Session behavior remains correct under the mixnet delivery model.
- The UI communicates latency and availability accurately.
- Network captures confirm the expected endpoint behavior.

Production privacy claims require additional evidence about anonymity set,
operator diversity, cover traffic, and real deployment conditions.

An independently scoped Tor/Arti onion-mailbox experiment may evaluate a
separately named low-latency Private Interactive profile. It is not a fallback
from Private Mixnet and does not inherit a mixnet traffic-analysis claim.

## Phase 6: credential admission experiment

Implement a wallet-facing admission adapter, preferably at an interoperable
presentation boundary such as OpenID4VP.

Start with:

- One credential format
- One configured trust model
- Holder binding
- Invitation challenge and verifier audience
- Local verification where possible
- Minimal claim disclosure
- Explicit correlation warnings

Exit criteria:

- An untrusted issuer cannot satisfy a trusted policy.
- A captured presentation cannot join another invitation or bind another key.
- Status and revocation behavior are documented and tested.
- The product does not claim unlinkability beyond demonstrated properties.

## Phase 7: hardening and external review

Before a security-focused public release:

- Protocol and wire-format review
- Dependency and cryptographic implementation review
- Desktop key-storage review
- Identity bridge assessment
- Mailbox abuse and denial-of-service assessment
- Reproducible packet-capture tests
- Fuzzing corpus for all untrusted decoders
- Signed update and release process
- Independent security review
- Published security policy and disclosure process

## Explicitly deferred

- Large groups
- Multi-device synchronization and account recovery
- Attachments
- Mobile background delivery
- Voice and video
- Federation
- Anonymous public rooms
- Post-quantum product claims
- Unlinkable credential claims without mature interoperable support

Deferral prevents these features from silently shaping the first protocol before
the two-person invitation and admission model is proven.
