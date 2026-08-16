# Session Chat 2.0 roadmap

Status: proposed sequencing, not a delivery commitment

## Guiding approach

Build a new protocol core alongside the legacy application. Preserve the
legacy history and UX lessons, but do not incrementally reinterpret current
Socket.IO messages, JWTs, Redis membership, or deterministic invitation hashes
as cryptographic session state.

Each milestone should produce a runnable vertical slice and explicit evidence
for its security properties.

## Current target

**Decision:** Phase 0 is sufficient to begin implementation. Start Phase 1 as a
capability-only Rust protocol laboratory beside the preserved legacy
application. Do not begin with broad cleanup, GitHub integration, SSI, a
production mailbox, a GUI, or a real network transport.

The complete scope, acceptance evidence, bounded research questions, and later
integration order are recorded in
[ADR 0004](adr/0004-build-v2-as-a-parallel-protocol-laboratory.md).

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

Implementation status: in progress. The first retained increment establishes
the `session-protocol` Rust workspace and its bounded deterministic-CBOR opaque
envelope. All invitation, admission, HPKE, MLS, state-machine, and transport
work listed below remains outstanding.

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

- Create and parse signed invitations
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

## Phase 2: prove identity independence

Implement GitHub admission through a minimal identity bridge while keeping
secret-capability admission working.

Exit criteria:

- The same invitation/join state machine accepts either configured proof type.
- GitHub attestations bind provider subject, invitation challenge, audience,
  session key, and expiration.
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

## Phase 4: desktop client

Create the Tauri shell and Angular interface around the Rust core.

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
