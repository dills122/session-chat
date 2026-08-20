# ADR 0013: Use a provider-neutral message-session interface

Status: accepted; established-session message seam implemented

Date: 2026-08-19

## Context

ADR 0012 selects one exact `mls-rs`/AWS-LC graph for the Phase 1 laboratory,
while explicitly allowing that a better-audited implementation may replace it
after equivalent review. Application message code should not depend on
`mls-rs` configuration generics, provider errors, or serialized provider types.
At the same time, treating cryptographic implementations as arbitrary plugins
would weaken the reviewed dependency boundary and imply that live MLS state can
move safely between incompatible implementations.

An established MLS group has implementation-specific ratchet state, pending
operations, storage semantics, protocol-version behavior, and deletion duties.
Selecting a different backend for a new session is a composition decision.
Changing the backend of an active session is a state migration and
interoperability problem, not an ordinary dependency injection operation.

## Decision

Add a small, implementation-free `session-crypto` crate containing the stable
application-facing message contract:

- `ProtectedMessage` owns opaque bytes and enforces a 64 KiB outer bound before
  backend parsing or storage;
- `ApplicationMessage` bounds decrypted application bytes and redacts them from
  `Debug` output;
- `MessageEvent` exposes bounded application bytes, epoch advancement, or removal;
- `MessageSessionError` exposes only `InputTooLarge` or `Rejected`;
- `MessageSession` exposes epoch and member-count observations, application
  message protection, and protected-message processing; and
- the application plaintext bound is shared by every implementation.

The trait is object-safe. A future client composition root may put an
established implementation behind `Box<dyn MessageSession>` and select from an
explicitly compiled and reviewed allowlist for each newly created session.
`session-crypto-mls` implements the contract and maps all `mls-rs` failures to
the coarse interface errors. Its existing concrete lifecycle API remains the
only current creation, validation, join, and membership implementation.

A backend means the reviewed MLS implementation, cryptographic provider,
feature set, ciphersuite policy, persistence adapter, and platform packaging as
one unit. Session Chat will not load network-supplied code, arbitrary dynamic
libraries, or caller-provided cryptographic primitives through this interface.

An active session is pinned to the backend, protocol version, ciphersuite, and
storage format used to create it. Silent mid-session switching is prohibited.
Any future migration requires a separate protocol and storage decision,
versioned fixtures, rollback tests, explicit user-visible failure behavior, and
cross-implementation evidence where applicable.

Admission binding, exact KeyPackage ownership, membership prepare/apply,
Welcome ownership, one-time KeyPackage deletion, and owner-local durable
transactions remain explicit lifecycle contracts. They are not collapsed into
a universal provider factory until two implementations demonstrate a common
interface without hiding different security semantics.

## Consequences and limits

- Application message loops no longer need an `mls-rs` type or error.
- The protected-message wrapper is transport-neutral; it does not send data and
  does not replace the `OpaqueEnvelope` transport contract.
- Adding a backend requires conformance tests through `MessageSession` plus its
  own dependency, malformed-input, lifecycle, persistence, platform, and
  interoperability review. Trait conformance alone is not approval.
- Backend choice can be an application option for new sessions after the choice
  is represented in a signed/versioned session contract. That negotiation is
  not implemented yet.
- There is still no deployable client, durable group state, network transport,
  migration path, or production-security claim.

## Alternatives considered

### Expose `mls-rs` types to the application

Rejected. This would couple message handling, errors, and future UI code to the
current laboratory implementation and make replacement needlessly invasive.

### Support arbitrary runtime crypto plugins

Rejected. Dynamic or downloaded implementations enlarge the code-loading and
supply-chain boundary, complicate platform hardening, and make the reviewed
provider graph meaningless.

### Define a universal creation and membership factory now

Deferred. There is only one retained implementation, and its exact
KeyPackage-ownership and persistence behavior are security-critical. A broad
factory designed from one example would likely hide rather than normalize
those differences.

## Upgrade and removal conditions

- Keep the shared message bounds at least as strict as every concrete backend.
- Treat changes to event meaning, error classification, or protected-message
  ownership as contract changes requiring negative and compatibility tests.
- Do not add a selectable backend until its identifier, dependency graph,
  supported suites, storage behavior, and evidence packet are reviewed.
- Supersede this ADR before permitting active-session migration or external
  provider loading.
