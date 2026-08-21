# Session Chat transport abstraction version 1

Status: proposed generalized contract; a narrow local Welcome adapter exists,
but no common multi-adapter API or production network adapter exists

Date: 2026-08-20

Governing decisions: ADR 0001, ADR 0003, ADR 0010, and proposed ADR 0015

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

## Delivery interfaces

```rust
trait EnvelopeDelivery {
    async fn deposit(
        &self,
        destination: &DepositEndpoint,
        envelope: &CanonicalEnvelope,
        budget: OperationBudget,
    ) -> Result<DepositReceipt, TransportFailure>;

    async fn poll(
        &self,
        authority: &ReceiveCapability,
        request: PollRequest,
    ) -> Result<ReceiveBatch, TransportFailure>;

    async fn acknowledge(
        &self,
        authority: &AcknowledgementCapability,
        deliveries: BoundedDeliveryIds,
        budget: OperationBudget,
    ) -> Result<AcknowledgementReceipt, TransportFailure>;
}

trait MailboxLifecycle {
    async fn rotate(
        &self,
        authority: RotationCapability,
        request: RotationRequest,
        budget: OperationBudget,
    ) -> Result<RotationResult, TransportFailure>;
}
```

`MailboxLifecycle` is separate because direct and transient delivery adapters
may not own mailbox continuity. The service or adapter that implements rotation
must consume or transactionally replace the supplied rotation authority. Normal
delivery operations never receive it.

The final Rust design MAY use generic traits, boxed futures, or actor messages.
It MUST preserve the operation and authority separation above and MUST provide
one mockable core-facing boundary.

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

### Acknowledgement

Acknowledgement requires a right-specific capability under ADR 0010. A
`DeliveryId`, cursor, receive capability, transport profile, or ambient adapter
credential alone MUST NOT authorize deletion.

Acknowledging an already acknowledged or expired delivery SHOULD be idempotent
and return a normalized result that does not reveal unnecessary mailbox state.

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

The first implementation is a memory adapter and adverse-network controller
that can script:

- exact delivery;
- loss;
- arbitrary delay;
- duplication;
- reordering;
- corruption;
- stale replay;
- queue saturation;
- cursor invalidation;
- acknowledgement loss; and
- total unavailability.

The same scripted trace format should drive later adapter integration tests
where practical.

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

## Open decisions before implementation

- Whether the first Rust boundary is generic, actor-based, or object-safe.
- Exact storage ownership for cursors, receive-side deduplication, and
  acknowledgement scheduling; owner-local transaction stores already own
  durable outbox truth and leases.
- Whether acknowledgement authority is long-lived per mailbox or issued per
  delivery/batch by each provider protocol.
- Exact `TransportProfileId` encoding and where future authenticated profile
  negotiation is bound.
- Network-broker design for libraries that normally own sockets.
- Stable redacted diagnostic schema.
- Whether the generalized memory control path should be extracted from
  `session-transport` after the first stabilization slice; the existing local
  Welcome evidence remains in place during that slice.

These are implementation-planning questions. They do not reopen the decisions
that transport is opaque, right-specific, profile-bound, and fail-closed.
