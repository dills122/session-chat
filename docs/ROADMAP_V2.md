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

**Decision:** Phase 0 is sufficient to begin implementation. Continue Phase 1
as a capability-only Rust protocol laboratory. V1 is retired under ADR 0006;
do not turn that cleanup into GitHub integration, SSI, a production mailbox, a
GUI, or a real network transport.

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

Implementation status: in progress. Retained increments now establish the Rust
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
evidence against the real local mailbox. Human approval UX, integration of the
transaction with the real MLS/admission product path, durable cross-layer state
and outbox processing, and network transport work listed below remain
outstanding.

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
provider-redaction evidence. Lifecycle, valid cursor persistence, and
provider-wide capability issuance remain open.
A new publish-disabled `transport-conformance` crate now retains the strict
bounded adverse-trace v1 parser, hostile fixtures, and a first normalized
double-replay memory runner, while `transport-memory` adds
bounded outage, corrupt-poll, exact-byte stale-replay, acknowledgement-loss,
and secret-free state-probe controls. The retained runner proves deterministic,
quiescent adverse delivery, exact bindings, redaction, bounded wake/drop
behavior, and common-suite detection of deliberately defective bridges. The
LocalV1 deposit-only coordinator adds one-attempt owner-store policy plus a
cross-platform blocking wake/cancel/deadline supervisor; neither is a network
or production-runtime claim.

The implementation-free `session-admission` crate now supplies the
provider-neutral, non-authorizing approval context and decision from ADR 0015.
It deliberately does not generalize provider proof verification or the exact
one-shot membership authority.

The `sessionctl` binary now completes the headless in-memory Phase 1
composition: a fresh Alice/Bob capability invitation and protected request,
explicit simulated approval, exact MLS Add and Welcome delivery, bidirectional
application messages, path update, removal, and post-removal rejection. Its
retained test and coarse CLI output satisfy the no-GUI/no-network laboratory
acceptance path. Durable state, human approval, and a network profile remain
separate gates.

The Rust source-coverage gate now measures production code through integration
targets without counting inline test helpers. The clean-master baseline was
90.78% workspace lines; retained negative-path tests raise the enforced result
to 92.82%, with every security- and correctness-vital component at or above
90%. Stable region and function ratchets are also enforced. `sessionctl` now
uses named, secret-free orchestration fault seams to cover cross-crate failure
mapping, cleanup, post-commit Welcome failure, and dropped delivery while its
normal successful flow remains unchanged. Exact scope, commands, counts, and
exclusions are in
[`CODE_COVERAGE.md`](CODE_COVERAGE.md).

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
Tests cover rollback, ambiguous-result recovery, and close/reopen on the
required Linux, macOS, and Windows CI runners. Platform-vault, disk/power fault,
production packaging, and rollback-anchor gates remain.

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

The current MLS increment uses only isolated in-memory providers for
deterministic protocol tests, as ADR 0012 specifies. It does not establish
cross-implementation interoperability, durable recovery, or a product security
property. Before any networked or user-facing join path is enabled, one durable
transaction must own reservation
recovery, request replay state, the MLS membership transition, invitation
consumption, approval/result state, and the encrypted Welcome outbox job with
an idempotency key. Dropped or abandoned
reservation tokens must return safely to `Available` without permitting a
second concurrent admission. Until that gate passes, the laboratory makes no
networked, user-facing, durability, rollback-resistance, or product-security claim.

Create a Rust workspace containing:

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

The transport slice follows the profile-bound contract proposed in
[`TRANSPORT_ABSTRACTION_V1.md`](specs/TRANSPORT_ABSTRACTION_V1.md). Stabilize
the existing right-specific local Welcome adapter, then add the generalized
contract, deterministic adverse-network control path, and shared conformance
harness before any real network dependency. The detailed task order and
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
