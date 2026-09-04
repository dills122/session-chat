# Session Chat transport abstraction version 1

Status: accepted for incremental internal implementation; a generalized
runtime-neutral dispatch trait exists, the deterministic memory adapter has
adopted it, and no production network adapter exists

Date: 2026-08-20

Governing decisions: ADR 0001, ADR 0003, ADR 0010, and accepted ADR 0015

## Purpose

This document defines the contract that the existing `session-transport` crate
must expose when it is generalized beyond its local one-Welcome adapter. It is
intentionally independent of Iroh,
Tor/Arti, SimpleX SMP, Katzenpost, Nym, Veilid, Reticulum, or any service
operator.

The abstraction exists to make transport substitution safe. It is not a claim
that every adapter provides the same privacy, reliability, ordering, latency,
or availability.

## Normative language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** describe the proposed contract that implementation work must either
follow or explicitly revise through the ADR process.

## Goals

The contract must make these properties easy to preserve:

- the protocol core emits one canonical opaque envelope format;
- identity and admission data never enter transport-specific metadata;
- mailbox operations receive only the authority required for that operation;
- unordered and duplicate delivery cannot repeat protocol state transitions;
- retry, expiry, resource, and polling work remain bounded;
- a selected profile cannot silently weaken itself through adapter fallback;
- a transport can be replaced without changing MLS or admission semantics;
- adapter behavior can be tested through one deterministic conformance suite;
  and
- user-visible claims are attached to reviewed profiles and deployments, not to
  an adapter name alone.

## Non-goals

The abstraction does not:

- publish or discover invitations;
- verify admission evidence;
- create or mutate MLS membership;
- define application-message ordering;
- make unreliable networks reliable without protocol-level state;
- assign a scalar privacy or anonymity score;
- allow arbitrary fallback chains;
- turn a DHT, relay, onion network, or mixnet into a trust anchor;
- hide adapter-specific deployment and observability requirements; or
- provide evidence for a public security claim by type-checking alone.

## Layer model

The design has five layers with one-way authority flow:

```text
Session and MLS state machines + owner-local transaction store
  atomic membership/outbox truth, idempotency keys, and leases
        |
        | one leased canonical bounded opaque-envelope operation
        v
Delivery coordinator
  expiry checks, deduplication, retry policy, cursors, acknowledgements
        |
        | right-specific mailbox capability + bounded operation
        v
Profile-bound delivery runtime
  local policy, adapter binding, no-downgrade rule, redacted status
        |
        | scoped network/process authority
        v
Transport adapter or composite adapter
  Iroh, Tor/Arti, SMP, Katzenpost, Nym, memory, later experiments
        |
        v
Network path and optional mailbox/rendezvous service
```

The session state machine MUST depend only on the delivery contract. It MUST
NOT call an adapter, network connector, relay, or mailbox implementation
directly.

### Delivery coordinator

The coordinator owns behavior that must be consistent across adapters:

- execution of one leased outbox operation without creating a competing
  membership or outbox record;
- send and poll deadlines;
- retry and total-work budgets;
- expiration checks before send and after receive;
- replay detection and deduplication by envelope identifier;
- acknowledgement scheduling;
- bounded pagination and backpressure; and
- normalized, redacted status for the caller.

The owner-local transaction store remains authoritative for durable outbox
records, idempotency keys, lease state, attempt counters, and ambiguous commit
recovery. The coordinator drives that store's bounded state transitions and
must not persist an independent copy of membership or outbox truth. For the
Phase 1 Welcome flow, `session-inviter-transaction` is the existing conformance
model for this owner boundary.

An adapter performs one bounded logical operation. It MAY use protocol-required
internal retransmission, but the maximum internal work MUST be declared,
bounded, cancelable, and included within the caller's deadline. It MUST NOT
start an unbounded background retry loop.

### Profile-bound delivery runtime

The runtime binds exactly one locally authorized `TransportProfileId` to one
adapter or to one explicitly reviewed composite adapter before network I/O.
Binding validates compatibility, supplies scoped network authority, and records
the non-secret implementation/configuration evidence used for diagnostics.

The runtime MUST NOT accept an ordered list of arbitrary fallbacks. A composite
strategy is allowed only as its own named and versioned profile whose every
path satisfies the profile contract.

### Adapter

An adapter maps normalized delivery operations to one implementation. It may
combine a path substrate with mailbox behavior internally. Those internal
pieces are not exposed to the protocol core because some candidates combine
them and others do not.

Adapter capability declarations are configuration inputs. They are not proof
of anonymity, privacy, operator independence, correct padding, or network
isolation.

## Stable profile identity versus adapter identity

`TransportProfileId` describes user-visible semantics and security policy.
`AdapterId` describes a local implementation. They MUST NOT be interchangeable.

Initial reserved profile identifiers are:

| Profile identifier | Intended semantics | Initial status |
| --- | --- | --- |
| `session-chat.transport.local.v1` | Deterministic local testing; no network or privacy claim | Phase 1 target |
| `session-chat.transport.fast.v1` | Low latency; direct peer address or relay metadata may be exposed | Later implementation |
| `session-chat.transport.private-interactive.v1` | Low-latency anonymity network; no direct peer or ordinary relay path; timing-correlation caveat | Research |
| `session-chat.transport.private-mixnet.v1` | Delayed mixing, padding, and fail-closed network isolation | Research |
| `session-chat.transport.off-grid.v1` | Explicit disruption-tolerant non-Internet path | Deferred research |

An adapter vendor or protocol name MUST NOT appear in an `OpaqueEnvelope`.
Adapter IDs are local configuration and diagnostic values. Profile selection is
session configuration and will require an authenticated protocol binding when
network negotiation is introduced; it is not inferred from received traffic.

Remote advertisement of a supported profile is untrusted input. Local realm
policy and local client policy decide whether that profile is allowed.

## Profile requirements

A profile is a closed, versioned set of concrete constraints, not a collection
of optional marketing labels. Its requirements include:

- whether the peer network address may be revealed;
- permitted path classes and service endpoints;
- ordinary DNS and clearnet HTTP policy;
- whether store-and-forward delivery is required;
- timing model: no resistance claimed, low-latency onion routing, or delayed
  mixing;
- padding classes and maximum observable object sizes;
- cover-traffic and polling policy where applicable;
- operation deadlines and total retry budgets;
- side-traffic policy for identity, update, telemetry, preview, crash, and
  notification systems; and
- required enforcement mode and evidence.

The implementation SHOULD model closed enums and validated structs rather than
independent booleans that permit contradictory combinations.

Profiles MUST NOT be ordered from "less secure" to "more secure." Their
properties are different and threat-model-dependent. The UI must describe the
actual exposure and availability trade-offs.

## Core data types

The following Rust-shaped types are illustrative. Exact ownership and async
mechanics may change during implementation, but their authority and semantic
boundaries are normative.

```rust
struct TransportProfileId(/* validated, versioned identifier */);
struct AdapterId(/* local implementation identifier */);

struct CanonicalEnvelope {
    // Exact deterministic bytes produced by session-protocol.
    bytes: BoundedBytes,
    envelope_id: EnvelopeId,
    expires_at: Timestamp,
}

struct DepositEndpoint {
    route: OpaqueRoute,
    authority: DepositAuthority,
}

struct ReceiveCapability {
    route: OpaqueRoute,
    authority: ReceiveAuthority,
}

struct AcknowledgementCapability {
    scope: AcknowledgementScope,
    authority: AcknowledgementAuthority,
}

struct RotationCapability {
    scope: MailboxContinuityScope,
    authority: RotationAuthority,
}

struct OperationBudget {
    deadline: MonotonicDeadline,
    max_network_bytes: u64,
    max_attempts: u16,
}

trait DispatchControl {
    fn monotonic_now(&self) -> Instant;
    fn wall_now_unix_seconds(&self) -> Option<u64>;
    fn is_cancelled(&self) -> bool;
}

struct PollRequest {
    cursor: Option<Cursor>,
    max_envelopes: u16,
    max_encoded_bytes: u32,
    wait: PollWait,
    budget: OperationBudget,
}
```

`CanonicalEnvelope.bytes` MUST be byte-identical across adapters. Derived
fields are validated views over those bytes and MUST NOT create a second wire
representation.

Secret-bearing authority values MUST NOT implement `Debug` or `Display`, MUST
be redacted from errors and telemetry, and SHOULD be zeroized when ownership
permits. Receive, acknowledgement, and rotation capabilities SHOULD be
non-`Clone` by default. A deposit endpoint is intentionally transferable to a
sender and may require controlled cloning or serialization.

`DeliveryId` and `Cursor` are attacker-controlled opaque identifiers. Neither
is authority. Both MUST be size-bounded, scoped to the adapter/profile context,
and safe to reject after restart or rotation.

### First implemented contract values

The first internal stabilization increment implements only:

- the five closed reserved version 1 `TransportProfileId` values;
- a 96-byte lowercase ASCII `AdapterId` grammar for local binding and diagnostics;
- a non-`Clone`, non-`Debug` `CanonicalEnvelope` that owns exact validated
  `session-protocol` bytes and rejects an all-zero envelope identifier;
- nonzero byte/attempt `OperationBudget` values with a monotonic deadline;
- retry delays capped at one hour before they enter `RetryAdvice`; and
- the context-free `TransportFailureCode`, `RetryAdvice`, and
  `TransportFailure` boundary.

This value increment did not itself implement capability erasure or delivery.
A later Phase 1 increment added a narrow synchronous `EnvelopeTransport` trait
with associated right-specific types and a separate deterministic
`transport-memory` implementation. A subsequent additive increment implements
the budget-aware `EnvelopeDelivery` trait below in that memory adapter while
retaining the narrow compatibility surface. Later increments add LocalV1
binding and coordination plus the provider-neutral lifecycle/receive-owner
contract described below. Durable product receive state, a reusable lifecycle
provider, and networking remain separate work.

The first binding increment adds a LocalV1-only manifest and binder. It admits
exactly one selected profile and no fallback list; requires schema version 1,
the exact local byte/count ceilings, full deposit/poll/acknowledgement support,
coordinator-owned retries, zero cursor support, no egress, no background work,
and in-process no-network enforcement; and emits a non-secret binding record.
All reserved nonlocal profiles remain rejected until their own reviewed
requirements and enforcement exist.

### First local capability-boundary evidence

The next internal sub-increment extracts the existing local receive and
acknowledgement capabilities behind private fields and crate-only constructors.
Compile-fail tests prove that the local deposit, receive, and acknowledgement
rights cannot occupy one another's typed positions, that receive and
acknowledgement authority are not `Clone` or `Debug`, and that `DeliveryId`
cannot authorize acknowledgement. A seeded rejection fixture proves ordinary
error diagnostics contain neither authority nor ciphertext bytes.

This is evidence for the local compatibility boundary, not a provider-neutral
capability representation. The local one-use profile still issues no rotation
authority. The later provider-neutral lifecycle contract does not retrofit
rotation onto LocalV1; provider implementation, revocation storage, and
serialization remain gated on P1-5 or a separately reviewed profile.

### First bounded operation-request values

The next additive internal increment fixes these provider-neutral ceilings
before adapter dispatch:

- an opaque cursor is 1 through 256 bytes;
- one poll requests 1 through 64 envelopes and at most 4 MiB of aggregate
  canonical bytes;
- a requested poll wait is immediate or 1 through 60 seconds and remains
  subordinate to the monotonic operation deadline;
- the poll byte ceiling cannot exceed the operation's total network-byte budget;
- a deposit request owns exactly one `CanonicalEnvelope` and rejects it when
  its already-encoded bytes exceed the operation's total network-byte budget;
  and
- one acknowledgement request contains 1 through 64 distinct untrusted
  `DeliveryId` values plus its operation budget.

Full cursor, delivery-identifier, and ciphertext-bearing request or receipt
values omit ordinary `Debug` and `Display` output. `DepositReceipt` carries only
the non-authorizing delivery identifier. `AcknowledgementReceipt` is an
identifier-free unit-like accepted outcome so implementations cannot reveal
which identifiers were previously absent or acknowledged.

The initial request/receipt sub-increment did not implement a received batch.

The additive receive-batch value then pairs each non-authorizing delivery ID
with one `CanonicalEnvelope` and validates the result against the originating
`PollRequest`. It rejects excess item count, aggregate canonical bytes above the
request, and any envelope expired at the supplied local wall time. Empty results
are valid, duplicate delivery IDs are rejected, and a next cursor remains only an opaque continuation hint. The batch
and each item omit ordinary diagnostics. A reusable checkpoint creates a poll
request carrying its complete non-authorizing binding, owner CAS revision,
checkpoint-position kind, and exact cursor bytes;
`ReceiveBatch` preserves that marker so only the exact originating checkpoint
can construct the page-commit transition. Ordinary LocalV1 polls remain
unbound and cannot enter the reusable receive-state path.

This batch validation does not replace an adapter's requirement to bound remote
response bytes before allocation or decoding, validate cursor state, or stop
work at the monotonic deadline. The subsequent dispatch and lifecycle
increments fix the shared async/clock and state-transition mechanics described
below. A reusable provider and provider-wide conformance evidence remain P1-5
work; the deterministic LocalV1 memory adapter remains cursorless.

## Delivery interfaces

```rust
trait EnvelopeDelivery: Send {
    type DepositEndpoint: Sync;
    type ReceiveCapability: Sync;
    type AcknowledgementCapability: Sync;

    fn deposit<'a>(
        &'a mut self,
        destination: &'a DepositRight<Self::DepositEndpoint>,
        request: DepositRequest,
        control: &'a dyn DispatchControl,
    ) -> impl Future<Output = Result<DepositReceipt, TransportFailure>> + Send + 'a;

    fn poll<'a>(
        &'a mut self,
        authority: &'a ReceiveRight<Self::ReceiveCapability>,
        request: PollRequest,
        control: &'a dyn DispatchControl,
    ) -> impl Future<Output = Result<ReceiveBatch, TransportFailure>> + Send + 'a;

    fn acknowledge<'a>(
        &'a mut self,
        authority: &'a AcknowledgementRight<Self::AcknowledgementCapability>,
        request: AcknowledgementRequest,
        control: &'a dyn DispatchControl,
    ) -> impl Future<Output = Result<AcknowledgementReceipt, TransportFailure>> + Send + 'a;
}

trait MailboxLifecycle: Send {
    type DepositEndpoint: Sync;
    type ReceiveCapability: Sync;
    type AcknowledgementCapability: Sync;
    type RotationCapability: Sync;

    fn issue<'a>(
        &'a mut self,
        expected_contract: LifecycleProviderContractV1,
        request: MailboxIssueRequestV1,
        control: &'a dyn DispatchControl,
    ) -> impl Future<Output = MailboxIssueOutcomeV1</* associated types */>> + Send + 'a;

    fn rotate<'a>(
        &'a mut self,
        expected_contract: LifecycleProviderContractV1,
        authority: &'a RotationRight<Self::RotationCapability>,
        request: RotationRequestV1,
        control: &'a dyn DispatchControl,
    ) -> impl Future<Output = MailboxRotationOutcomeV1</* associated types */>> + Send + 'a;
}
```

The three provider-neutral outer wrappers remain different Rust types even if
an adapter reuses one inner provider-material type. They prevent direct
substitution of an already-issued wrapper at another operation position. They
do not make cross-right derivation safe: every adapter issuance path must ensure
material for one right cannot derive another and must validate operation,
mailbox, generation, and expiry scope. Cloning and serialization policy is
reviewed per right: deposit endpoints may support controlled transfer, while
receive, acknowledgement, and rotation capabilities should be non-`Clone` by
default as stated above. Public wrapper construction and borrowing exist so
adapters can live in separate crates; they are not authority factories. The
retained narrow compatibility surface remains separate. This closes only the
positional gap in using associated type names alone; provider conformance closes
the authority-issuance gap.

`MailboxLifecycle` is separate because direct and transient delivery adapters
may not own mailbox continuity. The service or adapter that implements rotation
must consume or transactionally replace the supplied rotation authority. Normal
delivery operations never receive it.

Reusable mailboxes use monotonically non-reused continuity generations with
fresh independent authority for every right. Rotation is compare-and-swap bound
to the predecessor generation and caller-supplied rotation ID; an exact retry
returns the same successor while a competing or stale request fails closed.
Routine rotation may explicitly drain an old generation under bounded policy,
but compromise revocation permits no overlap. The implemented result wrapper
rejects a changed profile/configuration/continuity, non-successor generation,
reused receive scope, changed cursor schema/provider epoch, or unexpected
expiry before the result crosses the contract.

Every persisted cursor is paired with a `CursorBindingV1` containing the exact
profile, non-secret configuration fingerprint, mailbox continuity ID,
generation, receive-scope fingerprint, cursor-schema version, provider-state
epoch, and expiry. A partial match is invalid. A fresh generation may poll with
no cursor. A successfully committed page that supplies no continuation cursor
advances to a distinct successor-revision cursorless checkpoint, so restart and
later compare-and-swap still retain the latest owner revision. Returning to no
cursor from a cursor-bearing checkpoint requires an explicit recorded
resynchronization caused by invalid cursor or provider-state reset. That
resynchronization is an owner compare-and-swap transition: it persists the
reason and successor revision before returning a checkpoint that may poll from
none, and restart reloads the recorded state.

The adapter does not own durable receive progress. `ReceiveStateOwnerPort`
accepts one `ReceivePageCommitV1` and must atomically compare-and-swap the
expected checkpoint, retain each canonical envelope or its durable duplicate
outcome, persist the exact acknowledgement intent, and advance the checkpoint.
Construction rejects a receive batch whose carried binding or revision differs
from the expected checkpoint.
The owner port reloads the latest committed checkpoint for an exact live
binding, enabling both the next page and restart resume without an
implementation-specific state API. Only the resulting committed handle can
lease immediate acknowledgement work. The owner chooses an opaque associated
committed-page type: callers may inspect its binding, successor revision,
outcomes, and intent but cannot construct or disassemble its commit token.
Implementations reject a deduplication-outcome count different from the page
item count before mutation. After restart,
recovery can lease only a matching intent that was already committed under the
complete binding. Acceptance removes that exact intent; ambiguous
acknowledgement releases it for bounded retry. Implementations must reject a
stale or cursor-colliding checkpoint, foreign binding, forged/rebound commit handle, or expired
binding without partial mutation. Explicit wall time is supplied to checkpoint
construction/load, commit, immediate lease, and restart recovery.

`LifecycleConformanceCaseV1` is the closed P1-5 fixture vocabulary. It includes
fresh issuance; persist-before-acknowledge; cursor advance, committed-checkpoint
loading (including cursorless successor revisions), and overlap dedup; restart
and owner-recorded explicit resynchronization; acknowledgement recovery,
post-lease crash recovery, acceptance, and ambiguous release; routine,
compromise, and exact-retry rotation; cross-right rejection; every
cursor-binding mismatch; expiry; stale checkpoint CAS; outcome-cardinality and
acknowledgement-intent integrity; mismatched page/checkpoint binding and cursor
position; duplicate delivery IDs; forged commit evidence; expired owner and
issuance operations; foreign owner binding; stale and competing
rotation; and generation exhaustion. P1-5 adds the exhaustive right/resource
matrix and provider implementation without changing these semantics.

Before use, each reusable provider returns a non-secret
`LifecycleProviderContractV1`. It names one nonlocal semantic profile, fixes the cursor schema, and declares
owner-bound restartable cursor persistence with a provider epoch, monotonically
non-reused generations, compare-and-swap rotation with a nonzero maximum routine
drain, exact-set generation-scoped acknowledgement, and an external atomic
receive-state owner. The provider validates each routine rotation against the
declared drain bound at its observed wall time. Issuance and rotation operations
receive the expected declaration; their result validation requires the request,
predecessor, and returned binding to match its profile, cursor schema, and drain
policy, and issuance results reject expiry at explicit observed wall time.
Constructing a reusable declaration, issue request, or cursor binding
for LocalV1 fails closed;
the declaration does not itself enable any nonlocal profile in the binder.

The implemented internal Phase 1 boundary uses static dispatch and explicit
standard-library futures. This avoids selecting an async runtime and permits a
`Send` future requirement. It is deliberately not dyn-compatible; a future
composition root may use a closed reviewed enum to select a provider for a new
session. Boxed futures or an actor boundary require new direct evidence before
replacing this API.

`DispatchControl` is checked before provider entry and after every await or
provider boundary. `Instant` is used only for live operation deadlines and is
never persisted. Fallible Unix wall time is used only for externally timestamped
values; a clock failure fails closed rather than fabricating zero. The caller
owns timer/cancellation wakeups and drops the returned future to stop further
adapter-owned work. A remote operation may still have committed before drop,
so retries retain the exact idempotency identity.

## Portable delivery semantics

The common baseline is:

- the coordinator makes one or more bounded attempts while work remains
  eligible, but there is no eventual-delivery guarantee;
- delivery is **unordered**;
- duplication is expected;
- omission and arbitrary delay are possible;
- the service may become unavailable;
- acknowledgements are idempotent;
- receipt does not prove application processing;
- deposit acceptance does not prove recipient receipt; and
- transport success never means MLS or admission success.

This is a duplicate-tolerant attempt model, not an “at least once delivery”
claim. Expiry, bounded retry, service outage, or permanent loss can end work
without recipient delivery.

An adapter MAY provide stronger ordering or latency behavior, but the protocol
core MUST NOT depend on it. Adapter-specific guarantees can inform UI status or
optimization only after profile review.

### Deposit idempotency

The canonical envelope ID is the deposit idempotency key within the envelope's
lifetime and destination scope.

- Repeating the same destination, ID, and canonical bytes MUST be safe.
- Reusing an ID with different canonical bytes MUST produce a conflict and MUST
  NOT overwrite or ambiguously accept the earlier object.
- A successful deposit receipt means the adapter accepted responsibility under
  its declared semantics. It does not authorize acknowledgement.

### Polling and pagination

Every poll is bounded by envelope count, encoded bytes, wait policy, and a
monotonic deadline. An adapter may return fewer objects. It MUST NOT allocate or
decode an unbounded response before enforcing the byte limit.

A cursor is only a continuation hint. Replaying, corrupting, crossing mailbox
scope, or presenting a stale cursor MUST fail safely without granting access or
rolling state backward.

`None` starts from the earliest currently eligible item in the authorized
mailbox generation. An invalid or expired cursor returns `InvalidCursor`; only
the coordinator may explicitly retry from `None`, after durable receive-side
deduplication is available. Restart may preserve a cursor only when its schema,
adapter binding, mailbox generation, and provider persistence contract still
match. Rotation always invalidates old cursors for the successor generation.

### Acknowledgement

Acknowledgement requires a right-specific capability under ADR 0010. A
`DeliveryId`, cursor, receive capability, transport profile, or ambient adapter
credential alone MUST NOT authorize deletion.

Acknowledging an already acknowledged or expired delivery SHOULD be idempotent
and return a normalized result that does not reveal unnecessary mailbox state.
One request acknowledges an exact bounded identifier set only. Cumulative,
range, prefix, or cursor-based destructive acknowledgement is outside the
portable contract. Provider receipt handles that carry destructive authority
remain inside a right-specific capability or protected adapter state.

### Expiration

The coordinator rejects locally expired envelopes before deposit and after
poll. Services also enforce TTL as defense in depth. Adapter or service clocks
are untrusted; a remote timestamp cannot extend the signed or canonical
envelope expiration.

### Retry and backpressure

The coordinator owns end-to-end retry policy while the owner-local store owns
the authoritative persisted lease and attempt state. Adapter errors provide
bounded retry advice, not commands. Server-supplied delays are clamped to local
policy.

Queue-full, rate-limit, and unavailable results MUST surface as explicit
states. They MUST NOT trigger a path or profile change. Retry jitter MUST come
from reviewed randomness and remain within the total work and expiration
budgets.

## Error contract

Errors are typed, stable, and redacted:

```rust
enum TransportFailureCode {
    InvalidAuthority,
    AuthorityScopeMismatch,
    ExpiredEnvelope,
    EnvelopeTooLarge,
    IdempotencyConflict,
    InvalidCursor,
    QueueFull,
    RateLimited,
    Unavailable,
    DeadlineExceeded,
    Cancelled,
    CorruptRemoteResponse,
    PolicyViolation,
    Misconfigured,
    Internal,
}

enum RetryAdvice {
    Never,
    Backoff,
    After(BoundedDuration),
}

struct TransportFailure {
    code: TransportFailureCode,
    retry: RetryAdvice,
    public_context: RedactedContext,
}
```

Adapter error strings, remote response bodies, routes, full mailbox IDs,
capabilities, envelope bytes, and network addresses MUST NOT enter
`public_context`. Detailed local diagnostics must use a separately reviewed,
redacted event schema.

`RetryAdvice::Never` means no further adapter attempt under the current
operation budget. It does not prove that a request failed before commit. After
an ambiguous result, the coordinator may use a fresh budget to reconcile the
exact same idempotency identity only while owner-local state still marks that
operation eligible. It must not change the identity, recreate membership, or
start a competing logical operation. `Backoff` and `After` remain suggestions
bounded by the coordinator's current operation and retry policy.

`Unavailable` means the selected profile is unavailable. It never means
"attempt a different profile."

## Adapter declaration and binding

Each adapter exposes a non-secret manifest containing:

- adapter ID and exact implementation version;
- supported profile contracts;
- maximum envelope, batch, and cursor sizes;
- mailbox operations implemented;
- declared internal retry and connection behavior;
- required network protocols, endpoints, name resolution, and background work;
- process or in-process execution model; and
- configuration schema version.

The profile binder compares the manifest with local profile policy and rejects
unknown, contradictory, broader, or unsupported behavior. A private profile
MUST reject an adapter that requests direct peer access, ordinary relay access,
unrestricted DNS, or undeclared background egress.

The runtime records a local, non-secret `TransportBindingRecord` containing the
profile ID, adapter ID/version, configuration fingerprint, enforcement mode,
and selection time. This supports diagnosis and retained evidence. It is not a
wire object, user identity, or proof that the adapter behaved correctly.

## Network authority and isolation

Code-level adapter selection is insufficient to enforce private-mode egress.
Every production adapter MUST use one of these reviewed enforcement modes:

1. a profile-scoped network broker that grants only the required connection,
   DNS, and endpoint capabilities; or
2. a separate process or equivalent OS boundary with an allowlisted egress
   policy and an authenticated local IPC contract.

An adapter MUST NOT receive ambient global network credentials or a generic
HTTP client in a private profile. Libraries that open sockets internally must
run behind the second enforcement mode unless their behavior can be completely
constrained and tested.

Application side traffic is part of the selected profile. Update checks,
telemetry, crash reporting, identity calls, link previews, avatars, DNS, and
notifications require separate policy and cannot bypass the transport boundary.

## Profile selection, negotiation, and change

Profile selection occurs above the adapter and follows these rules:

1. The inviter offers versioned profile IDs in authenticated invitation or
   session context when that wire contract is introduced.
2. The joiner intersects them with locally allowed profiles.
3. The selected profile is authenticated as part of the join/session context
   and persisted with session state.
4. The local profile binder selects an allowed implementation without changing
   the profile ID.
5. The adapter is never asked to negotiate a weaker profile.

Changing a profile with different exposure requires explicit user review under
ADR 0003. It is a new session or an explicitly specified authenticated migration,
not a retry branch. The Phase 1 capability invitation does not yet carry this
negotiation and remains local-memory only.

## Composite and multipath adapters

Multiple paths MAY be used only through an explicitly named composite profile.
Every path and control-plane request must satisfy that profile's egress and
metadata contract. A composite adapter must define:

- path selection and failure behavior;
- whether duplicates are intentional;
- correlation introduced by simultaneous paths;
- shared identifiers or timing across paths;
- total combined retry and bandwidth budgets; and
- how packet captures prove no forbidden fallback occurred.

Generic "try adapters until one works" behavior is forbidden.

## Observability

Allowed normalized events include:

- adapter and profile version selected;
- coarse availability state;
- bounded operation duration bucket;
- success, duplicate, queue-full, timeout, and normalized error counters;
- encoded size class; and
- retry count bucket.

Events MUST NOT contain plaintext, ciphertext bytes, full envelope or mailbox
identifiers, routes, capabilities, peer addresses, admission evidence, stable
external identity, or a cross-session correlation identifier. Private-profile
telemetry is disabled unless its network path and anonymity impact are part of
the reviewed profile.

## Conformance suite

Every adapter must pass the same contract tests before it can back a supported
profile.

### Common tests

- canonical envelope bytes are unchanged;
- maximum-size and oversized objects are handled before unbounded allocation;
- duplicate deposit of identical bytes is idempotent;
- same ID with different bytes conflicts;
- delivery is safe under loss, duplication, delay, and reordering;
- expired objects are rejected before send and after receive;
- malformed and oversized cursors fail safely;
- poll count, byte, wait, and deadline limits are enforced;
- acknowledgement with the wrong right, mailbox, or delivery scope fails;
- repeated acknowledgement is safe;
- dropped futures or canceled operations stop bounded work;
- retry advice cannot exceed local budgets;
- queue exhaustion does not produce memory, disk, CPU, or network amplification;
- errors, logs, panics, and metrics redact authority and envelope material; and
- restart and stale adapter state cannot roll core replay or outbox state back.

### Profile tests

Fast profiles record which peers, relays, discovery services, and DNS systems
can observe traffic.

Private Interactive profiles prove that no direct peer, normal relay, ordinary
DNS, identity, preview, update, telemetry, or crash path opens during the test
session and retain Tor-specific timing-correlation caveats.

Private Mixnet profiles additionally test padding, polling, cover-traffic
configuration, entry-provider behavior, mix/service outage, delayed replies,
route churn, and the configured operator/adversary matrix.

Packet-capture and egress-denial tests are required evidence for private
profiles. Adapter self-report is insufficient.

### Deterministic memory adapter

The deterministic memory adapter currently scripts exact delivery, loss,
duplication, and hold/release reordering under the generalized boundary. It
also supplies bounded persistent outage, one-shot corrupt polling, exact-byte
stale replay, before/after-commit acknowledgement-result loss, and a
secret-free count snapshot. It rejects every supplied cursor until persisted
cursor state is implemented. The publish-disabled conformance crate owns the
strict canonical adverse-trace v1 parser, hostile fixtures, and a first
normalized virtual-control runner. That runner generates test-only fixtures in
memory, maps randomized provider values to aliases only after exact canonical
byte comparison, replays one retained lifecycle trace twice against fresh
memory adapters, and rejects non-quiescent adapter-reported completion. It is
LocalV1-only and rejects other profile labels until binding exists.

Receipt aliases are exact bindings: an idempotent retry reuses the same alias,
mailbox, envelope, and provider receipt. Poll normalization verifies that exact
binding before emitting an alias pair. `poll-once-drop` has one terminal
`future-dropped` expectation. The bounded driver waits up to one second for a
wake after `Poll::Pending`, including before that drop, and rejects a
future that does not wake within the harness bound. Adapter snapshots include
active operations so drop cleanup participates in final quiescence. Normalized
retry delays use the exact closed token `after-ns:<nanoseconds>`, bounded from 1
through 3,600,000,000,000, rather than a lossy whole-second representation.

The composed LocalV1 verdict fixture now executes corruption, stale replay,
cursor invalidation, both acknowledgement-loss points, total unavailability,
duplication, and expiry. Deliberately defective adapter bridges prove that the
runner rejects changed exact-retry receipts, cross-mailbox batches, skipped
deadline checkpoints, and leaked work after drop; seeded provider context
cannot enter its closed diagnostics. The complete shared verdict suite still
needs executable cases for:

- arbitrary delay;
- exhaustive authority and resource-bound combinations; and
- profile-specific cases once bindings exist.

Queue saturation is retained separately: the bounded eight-envelope fixture
rejects the ninth deposit, drains and acknowledges the accepted set, reaches
quiescence, double-replays byte-identically, and detects an over-accepting
bridge.

The same scripted trace format should drive later adapter integration tests
where practical.

The retained trace v1 format is LF-delimited lowercase ASCII with a fixed
version header, closed tokens, numeric aliases, bounded relative clocks and
fixture sizes, at most 64 KiB, 512 bytes per line, 256 steps, 64 aliases per
kind, and eight checkpoint directives per operation. It contains no raw
plaintext, ciphertext, canonical envelope bytes, identifiers, routes,
capabilities, provider errors, admission data, or stable identities. Unknown,
noncanonical, duplicate, forward-referenced, and oversized input fails before
retention. This parser contract and first memory runner do not by themselves
establish complete adapter conformance.

## Versioning and compatibility

The core contract follows additive evolution:

- profile and manifest schemas are explicitly versioned;
- unknown profile versions fail closed;
- new optional manifest fields do not weaken old requirements;
- removing or changing an observable semantic requires a new profile version;
- adapter upgrades retain conformance traces and packet-capture expectations;
- persisted cursors and binding records declare their schema versions; and
- canonical envelope versions remain owned by `session-protocol`.

The initial Rust API can change while the Phase 1 laboratory is internal, but
the authority boundaries and portable semantics cannot be weakened without
updating ADR 0010 or superseding ADR 0015.

## Deferred decisions after the first dispatch increment

- Whether later evidence justifies replacing the static future-returning trait
  with an actor or boxed object-safe boundary. The current internal API does not
  require either cost or lifecycle model.
- The concrete durable storage implementation for owner-bound cursors,
  receive-side deduplication, and acknowledgement scheduling. Their ownership
  and provider-neutral load/commit/lease transitions are fixed; owner-local
  transaction stores separately retain durable outbox truth and leases.
- Whether acknowledgement authority is long-lived per mailbox or issued per
  delivery/batch by each provider protocol.
- Future authenticated profile negotiation and its wire binding. The local
  Rust boundary initially uses the closed reserved version 1 profile set.
- Network-broker design for libraries that normally own sockets.
- Stable redacted diagnostic context beyond the initial context-free error
  code and retry advice.
- Whether the generalized memory control path should be extracted from
  `session-transport` after the first stabilization slice; the existing local
  Welcome evidence remains in place during that slice.

These are implementation-planning questions. They do not reopen the decisions
that transport is opaque, right-specific, profile-bound, and fail-closed.
