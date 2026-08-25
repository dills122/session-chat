# Transport dispatch and mailbox semantics decision research

Status: decision applied to the internal Phase 1 contract; network-provider
behavior, durable cursor state, and mailbox lifecycle implementation remain open

Date: 2026-08-24

## Question

What is the smallest cross-platform Rust dispatch boundary that preserves
right-specific mailbox authority, supports bounded asynchronous providers, and
does not select one runtime or provider protocol? Which acknowledgement, cursor,
and rotation semantics must be portable before a network adapter is attempted?

## Local constraints

- The workspace is pinned to Rust 1.97.1 and edition 2024.
- `session-transport` has no executor, channel, or async-runtime dependency.
- The narrow `EnvelopeTransport` compatibility trait and deterministic memory
  adapter already preserve three provider-specific authority types.
- The owner-local transaction store remains authoritative for outbox truth,
  idempotency, leases, and ambiguous completion recovery.
- A provider is selected from reviewed compiled code; arbitrary network-loaded
  transport plugins are not a requirement.

## Dispatch decision

Use a static `EnvelopeDelivery` trait whose methods return explicit
`std::future::Future + Send` values. Keep provider material in associated types,
but place it inside distinct provider-neutral `DepositRight`, `ReceiveRight`,
and `AcknowledgementRight` outer wrappers. Use `&mut self` for the first
single-operation-at-a-time adapter boundary.

This shape:

- adds no runtime or dependency;
- makes the future's `Send` requirement explicit;
- keeps provider secrets in provider-owned types;
- prevents an already-issued outer wrapper from direct cross-position
  substitution even if an implementation aliases its inner associated types;
- supports deterministic generic fakes and the existing memory adapter; and
- allows later runtime selection through a closed reviewed enum without making
  the trait dyn-compatible.

Object-safe boxed futures remain possible but would add an allocation per call
without solving heterogeneous provider authority by themselves. An actor
boundary would additionally require channel bounds, request identity, worker
lifecycle, shutdown, cancellation acknowledgement, and executor/process
decisions. Neither cost is justified by current evidence.

Rust's Reference confirms that methods returning opaque futures are not
dyn-compatible. Rust's async guidance also distinguishes inert, owned futures
from separately spawned work. A returned future therefore must not detach
adapter-owned work. Dropping it stops further local progress and runs ordinary
destructors, but cannot prove that a remote deposit sent before cancellation did
not commit.

A fresh-context security review compiled a counterexample against the initial
associated-type-only shape: Rust permits all three associated types to name the
same concrete type. A subsequent review also showed that public wrapper
construction cannot repair provider material that can derive another right. The outer
wrappers are therefore retained as positional tags, while adapter conformance
must separately prevent cross-right derivation, validate exact scope, and review
cloning/serialization policy per right. A deposit endpoint may support
controlled transfer; receive and acknowledgement authority should be
non-cloneable by default. The memory adapter supplies three distinct private provider
types and domain-separated scope commitments; this is provider-specific
evidence, not a universal property of the wrapper.

`RetryAdvice::Never` terminates attempts under one current budget. It is not a
negative commit receipt. For an ambiguous deposit, a coordinator may reconcile
only the exact same idempotency identity under a fresh budget while owner-local
state still considers the operation eligible. This distinction is required for
post-commit cancellation, deadline, and clock-failure recovery.

## Clock and cancellation decision

`DispatchControl` exposes three separate observations:

- monotonic `Instant` for a live operation deadline only;
- fallible Unix wall time for canonical expiry and authority lifetime; and
- cooperative cancellation state.

`Instant` is opaque, platform-dependent, and not persisted. `SystemTime` is not
monotonic and conversion relative to the Unix epoch can fail, so clock failure
must fail closed instead of substituting zero. This interface does not solve
wall-clock rollback; trusted-time or max-seen-time policy belongs to later
coordinator/storage work.

A boolean cancellation probe cannot wake a pending future. The composition
runtime must race timer/cancellation signals with the adapter future and drop the
future. The adapter checks control before provider entry and after every await
or provider boundary. Observed cancellation has its own normalized `Cancelled`
code; caller-side drop produces no adapter result.

## Mailbox authority decision

A cursor or `DeliveryId` is always a bounded opaque identifier, never
acknowledgement, deletion, or rotation authority. Every destructive
acknowledgement requires a separately typed capability.

The portable acknowledgement baseline is:

- authority scoped to operation right, mailbox continuity generation, expiry,
  and provider-defined permitted scope;
- an exact bounded set of distinct delivery IDs;
- no cumulative, range, prefix, or cursor-based deletion; and
- an identifier-free accepted receipt so unknown, expired, already-acknowledged,
  and newly acknowledged IDs need not create an existence oracle.

Mailbox-generation-scoped acknowledgement authority is the first common shape.
A provider may additionally require a batch- or delivery-attempt condition, but
that receipt handle stays inside the right-specific capability or protected
adapter state. It must not be exposed as a logical `DeliveryId`.

## Cursor decision

`None` means the earliest currently eligible item in the authorized mailbox
generation. A cursor is a continuation hint whose replay may overlap or return
duplicates. Corrupt, expired, wrong-mailbox, wrong-binding, or wrong-generation
cursors fail with normalized `InvalidCursor` and cannot roll durable processing
state backward.

After an invalid cursor, only the coordinator may explicitly restart from
`None`, and only once durable receive-side deduplication exists. A restart may
resume a cursor only when its schema, adapter binding, mailbox generation, and
provider persistence contract still match. Rotation invalidates old cursors for
the successor generation.

The current memory profile has no persisted cursor state and therefore rejects
every supplied cursor. This is a truthful bounded profile, not evidence for
restart recovery.

## Rotation decision

Reusable mailboxes will use monotonically non-reused continuity generations and
fresh independent authority for deposit, receive, acknowledgement, and
rotation. Rotation is compare-and-swap bound to the predecessor generation and
consumes or transactionally replaces its one-shot rotation authority. An exact
retry returns the same successor; competing or stale requests fail closed.

Routine rotation may create a successor and then drain an old generation under
bounded explicit policy. Compromise revocation permits no convenience overlap.
Active-session endpoint changes must be authenticated by session-member state;
realm redirects, DNS, or hosting migration never grant continuity authority.

## Protocol and platform evidence

| Source | Relevant evidence | Session Chat use |
| --- | --- | --- |
| [Rust trait dyn compatibility](https://doc.rust-lang.org/1.97.1/reference/items/traits.html#dyn-compatibility) | Opaque-return and async trait methods are not dyn-compatible | Prefer static RPITIT until dynamic dispatch has direct evidence |
| [Rust `Future`](https://doc.rust-lang.org/1.97.1/std/future/trait.Future.html) | Futures are polled; separately spawned work can proceed independently | Do not detach adapter-owned work from one operation future |
| [Rust `Instant`](https://doc.rust-lang.org/1.97.1/std/time/struct.Instant.html) | Monotonic but not steady; opaque and platform-dependent | Use only for live deadlines, never persistence |
| [Rust `SystemTime`](https://doc.rust-lang.org/1.97.1/std/time/struct.SystemTime.html) | Not monotonic; duration conversion can fail | Make wall time fallible and fail closed |
| [Rust async cancellation guidance](https://rust-lang.github.io/async-book/part-guide/more-async-await.html#cancellation) | Drop cancellation and cooperative-token limits | Test pending drop and explicit checkpoints without claiming remote rollback |
| [Google AIP-158](https://google.aip.dev/158) | Page tokens are continuation, not authorization, and may expire | Keep cursors non-authorizing and safely invalidatable |
| [Amazon SQS identifiers](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-queue-message-identifiers.html) | Message ID differs from the latest receipt handle needed for deletion | Keep logical delivery ID separate from provider-private destructive condition |
| [Azure Delete Message](https://learn.microsoft.com/en-us/rest/api/storageservices/delete-message2) | Deletion requires message ID, latest pop receipt, and authorized request | Retain provider attempt state inside acknowledgement authority/storage |
| [Google Pub/Sub acknowledge](https://docs.cloud.google.com/pubsub/docs/reference/rest/v1/projects.subscriptions/acknowledge) | Ack IDs are subscription-scoped and separately authorized | Do not treat an adapter receipt as portable authority |
| [RabbitMQ acknowledgements](https://www.rabbitmq.com/docs/confirms) | Cumulative acknowledgement can delete a range through one delivery tag | Reject cumulative semantics in the unordered portable profile |
| [SimpleX SMP](https://github.com/simplex-chat/simplexmq/blob/stable/protocol/simplex-messaging.md) | Recipient queue key remains authority while message ID selects an ACK target | Useful separation prior art, but its broader recipient authority is not copied |
| [IMAP UIDVALIDITY](https://www.rfc-editor.org/rfc/rfc9051.html#section-2.3.1.1) | Mailbox generation invalidates stale identifier assumptions | Bind cursors and provider receipt state to continuity generation |

## Evidence retained in this increment

- generalized wrong-right compile failures, including cursor and delivery-ID
  substitution;
- pre-entry cancellation/deadline and wall-clock failure with zero mutation;
- post-provider cancellation and deadline rejection before local commit;
- pending-future drop cleanup;
- deterministic memory adoption with exact canonical bytes and normalized
  idempotency conflict;
- distinct exact-set idempotent acknowledgement;
- explicit cursor rejection and poll-page no-dequeue behavior; and
- fixed memory-policy and live-byte ceilings plus seeded diagnostic redaction.

## Remaining research and implementation

- durable cursor, receive-deduplication, and provider-private receipt ownership;
- a one-shot rotation/lifecycle Rust contract and crash/ABA model;
- a runtime-specific coordinator that supplies wakeups without entering the
  provider-neutral crate;
- an adverse trace for corruption, replay, acknowledgement loss, invalidation,
  outage, cancellation, and deadlines; and
- the shared adapter conformance harness before any real network adapter.
