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
machine. Capability proof and approval, HPKE, MLS, durable state, the headless
flow, and transport work listed below remain outstanding.

Contract hardening gate before HPKE or the isolated MLS laboratory:

- Descriptor validation is read-only and only local issuance creates lifecycle state.
- Invitation reservation and consumption follow ADR 0008.
- Admission binds the exact KeyPackage, credential, and leaf key under ADR 0009.
- Transport interfaces use the distinct authorities from ADR 0010.
- The MLS integration obeys the selection and stop conditions in ADR 0011.

The first MLS increment may use only isolated in-memory providers for
deterministic protocol tests, as ADR 0011 specifies. Before any networked or
user-facing join path is enabled, one durable transaction must own reservation
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
- `session-crypto-mls`
- `session-transport`
- Deterministic in-memory transport
- `sessionctl` headless client

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
selected by the retirement history or this roadmap.

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

- UI code cannot bypass core admission or MLS state transitions.
- Secrets use appropriate OS storage and are excluded from browser storage.
- Deep-link parsing is fuzzed and treats links as attacker-controlled.
- Update signing and application provenance have a documented plan.

## Phase 5: private transport experiment

Add a Katzenpost-backed adapter and a deterministic adverse-network simulator.

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
