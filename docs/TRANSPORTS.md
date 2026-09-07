# Delivery transports and metadata privacy

Status: proposed, with mixnet deployment research remaining open

The [Phase 1 closeout evidence matrix](evidence/phase1-closeout.md) is the
current requirement/test/claim index. [ADR 0025](adr/0025-close-phase-one-recovery-and-conformance-evidence.md)
adds checked Welcome application and SQLite commit-window process kills,
fresh complete-state verification, and deterministic lifecycle model fixes.
All findings from the authorized independent-review closeout are remediated,
and the immutable merged revision recorded in the matrix passed the full
three-platform gate. Later behavior or evidence revisions require their own
exact-revision result.

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
| Private Interactive (research) | Tor/Arti onion-hosted delivery | Public anonymity network, endpoint-IP hiding, and interactive latency | End-to-end timing correlation remains possible; mailbox integration required |
| Private Mixnet | Katzenpost-backed mailboxes, compared with Nym | Stronger resistance to peer-IP and timing correlation | Latency, unreliable delivery, operational complexity |
| Experimental | Veilid, Reticulum, or another explicitly evaluated adapter | Routed P2P or disruption-tolerant exploration | Maturity, metadata, and interoperability risk |

An adapter is not automatically a supported product profile. It must pass the
profile-specific security, reliability, and operational acceptance tests.

## Transport abstraction

A profile names a versioned semantic and egress contract. An adapter names one
local implementation. These are deliberately different:

- more than one adapter may satisfy a profile;
- one network technology may expose multiple configurations with materially
  different metadata behavior; and
- an adapter name alone says nothing about deployment topology, operator
  diversity, cover traffic, network isolation, or the justified product claim.

The protocol core uses one profile-bound envelope-delivery contract. The
owner-local transaction store owns durable outbox truth and leases. A delivery
coordinator executes that leased work and owns adapter-independent expiry
checks, deduplication, polling, acknowledgement scheduling, and total retry
policy without creating a second outbox ledger. The adapter receives canonical
bounded envelope bytes, the right-specific mailbox capability for one
operation, and a bounded operation budget.

Adapters do not select profiles or generic fallback chains. They use either a
profile-scoped network broker or a separately isolated process/OS egress
boundary. Adapter capability declarations are configuration inputs rather than
proof of privacy. Private profiles require packet-capture and egress-denial
evidence.

The common portable semantics are unordered and duplicate-capable. The
coordinator makes bounded attempts while work remains eligible, but loss,
omission, arbitrary delay, expiry, and unavailability mean there is no eventual
delivery guarantee. A stronger adapter guarantee is an optimization and must
not become a hidden session-core dependency.

See the proposed
[transport abstraction version 1](specs/TRANSPORT_ABSTRACTION_V1.md),
[ADR 0015](adr/0015-bind-transport-adapters-to-versioned-profiles.md), and the
[retained technology landscape](research/TRANSPORT_SECURITY_LANDSCAPE_2026-08-20.md).

## Invitation publication is separate

Publication depends on the invitation mode. Only a future targeted or verified-
request descriptor whose admission policy does not rely on a secret in the
link may be posted to GitHub or a public website. That public invitation mode
is not implemented in the current laboratory.

Current signed capability invitation v1/v2 objects contain a bearer secret.
Transfer the complete invitation only to the intended recipient over an
**authenticated confidential channel**, including a private messenger file
attachment or an in-person handoff. A signature authenticates the object; it
does not hide the capability. Never publish these invitations on GitHub, a
website, a public QR code, or an unauthenticated download endpoint.

The L1 and network demonstrations use **simulated automatic approval** after
capability verification. Anyone who copies the complete invitation can submit
their own KeyPackage and win the single-use admission race. There is no human
confirmation or intended-person identity check in those scripted runs. The
public Iroh endpoint ID is a locator and may be shared publicly; the invitation
file is separate admission authority.

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

The retained FastV1 UI fixture says that content is end-to-end encrypted, both
participants must be online, direct peers can learn network addresses, relays
can observe endpoint identifiers, network addresses, timing, and volume, and
address lookup, DNS, and NAT traversal add observers. It explicitly marks Fast
as neither anonymous nor offline-capable.

ADR 0024 selects pinned Iroh 1.1.0 for the first explicit FastV1 online-link
experiment. The headless cross-computer path uses authenticated Iroh endpoint
IDs in one canonical text form and bounded Session Chat frames. Its operations
use checked absolute deadlines no longer than five minutes, and graceful close
rejects peer reset or connection failure instead of treating either as a
receipt. Its caller-selected frame bound has a 256 KiB crate-wide ceiling, and
a failed, timed-out, or cancelled partial frame poisons the ordered link rather
than permitting desynchronized reuse. ADR 0027 extends this to the whole delivery
request/response exchange, including a dropped future after a complete send.
Both host harnesses retain the listener across rejected peers under one
32-candidate/five-minute bound, check invitation or mailbox authority before
session ownership, and never count denied requests as completion. This bounds
work; it does not guarantee availability under sustained attack. The bearer invitation is transferred
over an authenticated confidential channel outside Iroh; the first Iroh frame
is the HPKE-protected join request, so an unauthorised first connector cannot
retrieve admission authority. The public N0 preset may use direct paths, relay forwarding, address
lookup, DNS, NAT discovery, and port mapping. This selection does not turn the
relay into an offline mailbox or make Iroh endpoint identity an admission
credential.

The reusable-adapter evidence harness can remove Iroh's direct IP transports
for a relay-only run. It records address-free initial and final selected-path
classes from Iroh's connection path API. Its separately transferred canonical
v2 test file binds the selected path policy and contains all three mailbox
rights. A mode mismatch fails before public endpoint creation. The harness
renders the complete Fast disclosure before either role starts public network
work. This remains an operator-only conformance artifact, not a product
invitation or sender endpoint.

## Mixnet transport

Katzenpost is the initial research target because it provides a Sphinx-based
mix network intended as a substrate for metadata-sensitive applications. The
network deliberately provides neither reliable nor in-order delivery, so
Session Chat must add application-level behavior.

Nym is a comparative public-network research candidate. It must run through the
same envelope workload, adverse-network traces, observer matrix, and
packet-capture format as Katzenpost. Its public network, chain, credentials, or
token economics do not become Session Chat membership or protocol authority.

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

These rights are separate types, not flags on one bearer identifier:

- `DepositEndpoint` contains only the route and authority a sender needs to deposit.
- `ReceiveCapability` authorizes bounded reads but not deposit, deletion, or rotation.
- `AcknowledgementCapability` authorizes deletion/acknowledgement for the
  relevant mailbox or delivery scope.
- `RotationCapability` authorizes continuity changes and is never supplied to
  normal send, receive, or acknowledgement calls.

Secret-bearing authority types do not implement `Debug` or `Display`, do not
enter generic transport metadata, and are not obtained from ambient global
credentials. A `DeliveryId` is an untrusted identifier, not acknowledgement
authority. See ADR 0010.

The service enforces:

- Maximum object and queue sizes
- TTLs
- Rate and resource limits
- Constant-shape error behavior where practical
- No plaintext indexing
- No logging of full capabilities

Mailbox identifiers should rotate between invitation, admission response, and
ongoing delivery contexts to reduce correlation.

### Local Phase 1 Welcome mailbox

ADR 0014 accepts a narrower local-only response profile for deterministic
laboratory work. The joiner creates separate deposit, receive, and
acknowledgement capabilities, sends only the deposit endpoint inside the
HPKE-protected join request, and retains the other rights locally. The endpoint
is a closed fixed-array object containing only a local transport instance,
mailbox, high-entropy deposit capability, profile, and expiration. It has no
network route or rotation operation.

The endpoint's canonical value type and hostile parser fixtures exist in
`session-protocol`. `session-transport` now implements the separate local
deposit, receive, and acknowledgement operations in bounded in-memory state.
The mailbox stores at most one bounded `OpaqueEnvelope`. An exact retry with the
same envelope ID and bytes is idempotent; a different second envelope is
rejected without replacement. Acknowledgement deletes retained ciphertext while
keeping one bounded commitment for exact-retry recognition. Delivery identifiers
remain untrusted and remote acknowledgement never gates or rolls back inviter
membership. The committed in-memory approved-join result carries the exact
authenticated deposit endpoint beside its MLS outputs, and retained integration
evidence deposits that encrypted Welcome. This is local protocol evidence, not
durability, outbox atomicity, networking, anonymity, or a production profile.

### Deterministic Phase 1 envelope transport

`session-transport` defines a narrow compatibility trait and a generalized
budget-aware trait whose provider-neutral deposit, receive, and acknowledgement
outer rights prevent direct cross-position substitution even if inner provider
types alias. Provider conformance—not the wrappers alone—must make inner
authority non-derivable across rights and exact-scope validated, with cloning
and serialization policy reviewed per right. Controlled deposit transfer is
allowed; receive and acknowledgement authority should be non-cloneable by
default. The
generalized boundary uses runtime-neutral futures plus explicit
monotonic deadline, fallible wall-clock, and cancellation observations. The
separate `transport-memory` adapter
implements both contracts for headless tests. Its bounded action queue can
deliver, drop, hold, release out of order, or duplicate one accepted attempt.
Exact retries retain one logical delivery identifier, while changed bytes under
the same envelope identifier report a normalized conflict without overwrite.
Live memory deliveries repeat byte-identically across direct receive and
cursorless poll calls until exact acknowledgement; expiry is the only
receive-side removal transition. The shared connected-delivery oracle polls
before acknowledgement twice and checks absence both before and after an
idempotent acknowledgement retry.
Its additive adverse controls model persistent outage, one normalized corrupt
poll, digest-checked exact-byte stale replay, and acknowledgement-result loss
before or after deletion, all behind bounded test-only queues and secret-free
count snapshots. The publish-disabled conformance crate now parses a strict,
bounded, canonical, alias-only trace v1 and runs a first exact-byte normalized
trace twice against fresh memory adapters. A composed verdict covers the
retained adverse vocabulary, and paired deliberately defective bridges prove
receipt, scope, deadline, drop-cleanup, and redaction enforcement. The bounded Phase 1 common verdicts are retained; production network
provider conformance remains a later gate.

The first profile-binding implementation is intentionally LocalV1-only. It
accepts one exact versioned memory-adapter manifest with full mailbox
operations, coordinator-owned retries, no cursor support, no background work,
no egress, and in-process no-network enforcement. It produces a non-secret
binding record containing only profile, adapter/version, configuration
fingerprint, enforcement mode, and selection time. Reserved Fast and Private
IDs are rejected by the binder and no API accepts a fallback list.

The first coordinator increment is also LocalV1-only and deposit-only. It
leases at most one exact owner-store job, validates canonical envelope and
endpoint material, creates an operation budget with `max_attempts == 1`, and
invokes only the narrow sender-side `EnvelopeDeposit` surface. Adapter success
means deposit acceptance only—not receipt, acknowledgement, or application
processing. Adapter failure releases only the exact owner lease; dropping a
pending coordinator future drops adapter-owned work and leaves authoritative
recovery to lease expiry. The in-memory inviter transaction model implements
the port and proves normal acceptance, adapter failure, and exact retry after an
unrecorded remote acceptance without repeating membership. The retained
standard-library blocking supervisor wakes on legal future notifications and
external cancellation, enforces a monotonic deadline, and drops unfinished
adapter work; it is a cross-platform headless/worker-thread baseline, not a UI
runtime choice. The SQLCipher laboratory now implements the same sole-owner
port and retains close/reopen delivery, stale/foreign lease, exhaustion,
expiry, persisted-attempt-ceiling, old-open-scope rejection, and ambiguous
exact-retry evidence. A retained real
capability-admission/MLS integration recovers an ambiguous SQL commit, reopens
that owner store, and delivers the exact Welcome once. `sessionctl` now uses the
same transaction, reloads Alice's exact MLS identity/group, and reconstructs a
coordinator owner from SQLCipher. The ADR 0021 independent-process runner uses
the same path after graceful Alice process exit, with Bob and the untrusted
forwarder in separate processes. This adds no network transport or abrupt-kill
result to the product path. A separate checked L2 storage laboratory now covers
baseline-derived SQLite-visible FULL/extended-IOERR failures and direct writer
kills at observed engine commit-window pauses and every baseline-observed
inviter/joiner application checkpoint before fresh reopen. That narrow local
storage evidence is supplemented by ADR 0025 Welcome-delivery recovery.
Neither establishes power-loss safety,
rollback resistance, platform key custody, or production transport behavior.
Its raw observations remain non-public; the retained L2-8 gate lets only sealed
complete aggregates emit self-reported candidate v2 bundles with execution-time
binary/artifact binding and secret/canary scans. ADR 0028 requires external
attestation verification before hosted provenance is accepted,
and portable passage remains conditional on the exact revision's required
three-OS CI result.

`RetryAdvice::Never` ends attempts under the current budget. It does not assert
that a deposit did not commit; the coordinator may reconcile an ambiguous
completion only with the exact same idempotency identity under a fresh budget
while owner-local state still permits that operation.

Generalized cursorless polls enforce request count/byte limits and revalidate
expiry with the final wall-clock observation. The
memory profile rejects every supplied cursor until persisted cursor state
exists. Acknowledgement accepts one distinct exact identifier set under separate
authority and makes unknown or repeated identifiers indistinguishable no-ops.
Fixed hard ceilings bound policy inputs, live bytes, and scheduled work.

The adapter receives an `OpaqueEnvelope`; it does not encrypt or authenticate
the bytes inside that container. Its capabilities are provider-generated and
stored only as commitments, but the adapter remains single-process test code.
It provides no network routing, persistence, anonymity, metadata privacy,
crash recovery, or rollback resistance.

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
7. Reject an operation when given a capability for another right, mailbox, or delivery.
8. Never serialize receive, acknowledgement, or rotation authority into send metadata.

Private transport additionally:

1. Never opens a direct or fast-relay connection.
2. Does not perform side-channel identity or content fetches.
3. Pads envelopes according to the selected policy.
4. Continues correctly under loss, delay, duplication, and reordering.
5. Produces a clear unavailable state rather than a downgrade.

## Research boundaries

The following remain research questions:

- Whether Tor/Arti can support a separately named Private Interactive profile
  with verifiable egress isolation and acceptable desktop behavior
- Whether SimpleX SMP should carry Session Chat envelopes directly or remain
  prior art for an independently specified mailbox protocol
- Whether to use Katzenpost directly or through a mailbox service protocol
- Whether an existing Nym anonymity set outweighs its additional operational
  and economic dependencies
- Public network versus organization-operated network versus hybrid routing
- Cover traffic and polling budgets for desktop and later mobile clients
- Latency targets acceptable for interactive chat
- Attachment chunking without creating strong size fingerprints
- How realm discovery works without adding a correlating global directory
- Whether Veilid offers a useful additional profile after the core interfaces
  are proven
- Whether Reticulum or a Briar-style local synchronization model justifies a
  later, explicitly selected off-grid profile
