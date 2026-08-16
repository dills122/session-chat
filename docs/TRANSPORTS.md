# Delivery transports and metadata privacy

Status: proposed, with mixnet deployment research remaining open

## Scope

The transport layer moves opaque encrypted envelopes. It does not publish
invitations, evaluate admission proofs, define MLS membership, or see plaintext.

Content security and network-metadata privacy are separate properties:

- MLS protects application content and group membership state from the
  delivery service.
- A direct P2P transport can expose participant IP addresses to peers.
- An encrypted relay can observe connection endpoints, timing, and volume.
- A mixnet can reduce traffic correlation at the cost of latency, complexity,
  and weaker delivery semantics.

## Transport profiles

| Profile | Proposed implementation | Primary benefit | Primary cost |
| --- | --- | --- | --- |
| Local | In-memory or deterministic test adapter | Protocol testing and simulation | No production privacy claim |
| Fast | Direct encrypted QUIC with relay fallback | Low latency and NAT traversal | Peer or relay metadata exposure |
| Private | Katzenpost-backed mailboxes | Stronger resistance to peer-IP and timing correlation | Latency, unreliable delivery, operational complexity |
| Experimental | Veilid or another routed P2P adapter | Exploration of privacy-oriented routing | Maturity and interoperability risk |

An adapter is not automatically a supported product profile. It must pass the
profile-specific security, reliability, and operational acceptance tests.

## Invitation publication is separate

An invitation is an out-of-band object. It can be:

- Posted to GitHub
- Copied through an existing messenger
- Shown as a QR code
- Exchanged in person
- Published on a website

The transport begins when a client sends an encrypted join request to an opaque
rendezvous location. This keeps "GitHub-based product workflow" from becoming
"GitHub is part of the chat transport."

## Fast transport

The proposed fast mode uses a direct encrypted connection when possible and an
encrypted relay when necessary, plus a separate mailbox for offline delivery.

Expected privacy properties:

- A direct peer can learn the other peer's network address.
- A relay cannot read end-to-end encrypted content but can observe connection
  metadata, timing, and volume.
- A stateless relay is not an offline mailbox.
- Rendezvous and relay operators may collude unless deployments separate them.

The UI must disclose these properties. "End-to-end encrypted" must not be
presented as "anonymous."

## Mixnet transport

Katzenpost is the initial research target because it provides a Sphinx-based
mix network intended as a substrate for metadata-sensitive applications. The
network deliberately provides neither reliable nor in-order delivery, so
Session Chat must add application-level behavior.

Required behavior above the mixnet:

- Globally unique random envelope identifiers
- Per-mailbox replay detection and deduplication
- Sequence numbers within an MLS epoch where appropriate
- Explicit acknowledgements
- Bounded retries with jitter
- Expiration and stale-message rejection
- Reordering tolerance
- Padded size classes
- Bounded mailbox storage and polling
- Idempotent processing of join, Commit, Welcome, and application messages

MLS Commit ordering and concurrent group changes need particularly careful
treatment. Transport retries must not accidentally reapply state transitions.

## Mixnet threat-model caveats

A mixnet does not provide absolute anonymity:

- The entry provider can normally observe a client's network address.
- The destination service sees messages arriving for its service.
- A global observer may retain statistical advantages depending on network
  size, topology, delays, padding, and cover traffic.
- A network operated by one organization has weaker operator independence.
- A quiet private network has a poor anonymity set even if its cryptography is
  correct.
- Application behavior, packet sizes, polling schedules, and error patterns can
  create fingerprints above the transport.

A three-node local deployment is valuable for development and failure testing,
but it must not be marketed as strong real-world anonymity without evidence
about traffic volume, operator diversity, and the active threat model.

## No silent downgrade

**Decision:** A session configured for private transport fails closed if that
transport is unavailable.

It must not automatically:

- Connect directly
- Use a normal relay
- Contact an identity provider not required by the admission policy
- Fetch avatars or link previews outside the mixnet
- Send push, analytics, crash, or update traffic that identifies the session

A user may explicitly create a new session with a different profile after being
shown the changed guarantees. That is a new decision, not a transparent retry.

## Anonymous-mode network isolation

Anonymous Private mode needs a verifiable network-access policy. During an
active anonymous session, tests should confirm that the client makes no DNS or
HTTP requests to GitHub, the identity bridge, avatar hosts, analytics systems,
or fast-transport infrastructure.

Software updates and crash reporting need separate opt-in behavior. Otherwise
the surrounding application can defeat the privacy profile even while chat
envelopes use a mixnet.

## Mailboxes

Mailboxes should be capability-addressed and unlinkable to public user
identifiers. A mailbox capability may include separate rights for:

- Depositing an envelope
- Reading envelopes
- Acknowledging or deleting an envelope
- Rotating the mailbox

The service enforces:

- Maximum object and queue sizes
- TTLs
- Rate and resource limits
- Constant-shape error behavior where practical
- No plaintext indexing
- No logging of full capabilities

Mailbox identifiers should rotate between invitation, admission response, and
ongoing delivery contexts to reduce correlation.

## Transport acceptance tests

All production transports:

1. Carry byte-identical protocol envelopes without transport-specific identity
   fields.
2. Never receive plaintext or MLS epoch secrets.
3. Tolerate duplicate delivery without duplicate user-visible messages or
   repeated state transitions.
4. Reject expired envelopes.
5. Bound memory, disk, and retry growth under attacker-controlled input.
6. Exclude secrets and plaintext from logs.

Private transport additionally:

1. Never opens a direct or fast-relay connection.
2. Does not perform side-channel identity or content fetches.
3. Pads envelopes according to the selected policy.
4. Continues correctly under loss, delay, duplication, and reordering.
5. Produces a clear unavailable state rather than a downgrade.

## Research boundaries

The following remain research questions:

- Whether to use Katzenpost directly or through a mailbox service protocol
- Public network versus organization-operated network versus hybrid routing
- Cover traffic and polling budgets for desktop and later mobile clients
- Latency targets acceptable for interactive chat
- Attachment chunking without creating strong size fingerprints
- How realm discovery works without adding a correlating global directory
- Whether Veilid offers a useful additional profile after the core interfaces
  are proven
