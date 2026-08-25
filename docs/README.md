# Session Chat 2.0 design documents

Status: Phase 1 protocol laboratory in progress

These documents describe the proposed Session Chat 2.0 pivot. They are a
working design baseline, not a claim that the current protocol laboratory
implements the described security properties.

The central product idea is:

> Publish the door, not the key.

The [secure-development policy](SECURE_DEVELOPMENT.md) maps the repository's
threat and supply-chain boundaries to the required CI and GitHub merge gates.
The [Rust code-coverage policy](CODE_COVERAGE.md) records the production-only
measurement method, clean-master baseline, enforced ratchets, and exclusions.

For an outside review, start with the
[independent-audit brief](INDEPENDENT_AUDIT_BRIEF.md). It separates current
code-backed evidence from accepted-but-unimplemented contracts, proposed
experiments, deferred work, and explicit non-goals.

Session Chat should provide disposable, end-to-end encrypted conversations
between people who can be admitted using an external identity, a portable
credential, a secret capability, or manual approval. Identity and network
privacy are independent choices: a GitHub-verified conversation can travel
over a mixnet, while an anonymous conversation can use no external identity at
all.

## Document map

- [Product definition](PRODUCT_V2.md) defines the product promise, primary
  workflows, user-visible modes, and non-goals.
- [Architecture](ARCHITECTURE_V2.md) separates session security, admission,
  rendezvous, and transport.
- [Identity and admission](IDENTITY_AND_ADMISSION.md) covers GitHub, verifiable
  credentials, SSI/DIDs, capability admission, and session-scoped identities.
- [Transports](TRANSPORTS.md) covers fast delivery, mixnets, offline mailboxes,
  reliability, and privacy downgrade rules.
- [Transport abstraction specification](specs/TRANSPORT_ABSTRACTION_V1.md)
  defines the accepted, partially implemented profile-bound and right-specific
  envelope-delivery contract.
- [Transport and security technology landscape](research/TRANSPORT_SECURITY_LANDSCAPE_2026-08-20.md)
  compares candidate transport families, threat assumptions, and evidence gaps
  without selecting a production provider.
- [Transport dispatch and mailbox semantics research](research/TRANSPORT_DISPATCH_AND_MAILBOX_SEMANTICS_2026-08-24.md)
  records the runtime-neutral dispatch, clock/cancellation, acknowledgement,
  cursor, rotation, and restart decisions behind the current increment.
- [Adverse trace and conformance research](research/TRANSPORT_ADVERSE_TRACE_AND_CONFORMANCE_2026-08-25.md)
  records the strict secret-free trace schema, ownership, bounds, and runner
  seams used to build Tasks 5 and 6.
- [Receive cursor and mailbox lifecycle research](research/TRANSPORT_RECEIVE_CURSOR_LIFECYCLE_2026-08-25.md)
  records generation-bound cursor, persist-before-acknowledge, rotation, and
  restart requirements without selecting a network provider.
- [Welcome delivery coordinator research](research/WELCOME_DELIVERY_COORDINATOR_2026-08-25.md)
  maps the implemented deposit-only coordinator and standard-library
  supervision baseline to the inviter-owned outbox while preserving the
  remaining durable-storage and UI-runtime gaps.
- [Transport abstraction implementation plan](plans/TRANSPORT_ABSTRACTION_IMPLEMENTATION.md)
  sequences stabilization of the existing local adapter and outbox model, the
  generalized contract, conformance harness, coordinator, and later
  real-network experiments.
- [Real-world end-to-end security test strategy](plans/REAL_WORLD_E2E_TESTING.md)
  defines permanent scenario IDs, layered environments, evidence bundles, CI
  cadence, and release gates without claiming unavailable integrations.
- [Local transport baseline evidence](evidence/transport-local-baseline.md)
  maps the implemented one-Welcome adapter and inviter outbox model to the
  generalized contract without overstating missing behavior.
- [Local transport capability-boundary evidence](evidence/transport-capability-boundaries.md)
  records ownership, movement, redaction, zeroization, and compile-time
  right-separation evidence without claiming a generalized provider contract.
- `transport-conformance` retains the canonical adverse-trace parser, hostile
  fixtures, and a first normalized double-replay runner over the real memory
  adapter. The complete common verdict and deliberately defective-adapter suite
  remain future work.
- [Threat model](THREAT_MODEL.md) defines assets, trust boundaries, attackers,
  invariants, and severity calibration.
- [Rust code-coverage policy](CODE_COVERAGE.md) defines the source-based
  production measurement, vital component gates, baseline, and ratchet path.
- [Roadmap](ROADMAP_V2.md) proposes an incremental implementation and validation
  sequence.
- [Phase 1 build decision](adr/0004-build-v2-as-a-parallel-protocol-laboratory.md)
  commits the next slice to a capability-first Rust protocol laboratory.
- [Signed invitation specification](specs/SIGNED_INVITATION_V1.md) defines the
  exact Phase 1 capability wire object, signature boundary, and replay policy.
- [Invitation signature decision](adr/0007-sign-capability-invitations-with-ed25519.md)
  selects scoped Ed25519 keys, strict verification, and application-domain separation.
- [Invitation lifecycle decision](adr/0008-use-an-inviter-owned-transactional-invitation-lifecycle.md)
  separates read-only descriptor validation from reservation and post-membership consumption.
- [Admission-to-KeyPackage decision](adr/0009-bind-admission-to-the-mls-key-package.md)
  binds every admission method to the exact MLS leaf proposed for membership.
- [Mailbox authority decision](adr/0010-use-right-specific-mailbox-capabilities.md)
  separates deposit, receive, acknowledgement, and rotation authority in transport APIs.
- [Current MLS implementation decision](adr/0012-select-mls-rs-for-the-phase-1-laboratory.md)
  selects a pinned, reduced-feature `mls-rs`/AWS-LC boundary for the isolated
  laboratory and defines its ownership, audit, and persistence stop conditions.
- [Provider-neutral message interface decision](adr/0013-use-a-provider-neutral-message-session-interface.md)
  keeps established-session message handling independent of the selected MLS
  backend while prohibiting arbitrary plugins and silent active-session swaps.
- [Protected capability join decision](adr/0014-use-hpke-psk-and-a-local-welcome-deposit-for-phase-1.md)
  selects the exact local Phase 1 HPKE PSK profile, capability verifier, closed
  join schemas, and one-Welcome response authority without claiming an
  implementation or hosted transport.
- [Provider-neutral approval-context decision](adr/0015-use-a-provider-neutral-approval-context.md)
  gives headless and later UI composition one display-only decision seam while
  concrete providers retain exact proof, reservation, and KeyPackage authority.
- [Session-scoped sealed-vault decision](adr/0016-use-a-session-scoped-sealed-vault-contract.md)
  defines the locked-mode capability matrix, linear lifecycle transitions, and
  bounded opaque receipt contract without selecting durable storage.
- [Durable storage laboratory decision](adr/0017-use-sqlcipher-for-the-durable-storage-laboratory.md)
  selects the exact SQLCipher graph for real inviter/joiner MLS transaction
  evidence without making a production or platform-vault claim.
- [Cross-platform local-app decision](adr/0018-require-cross-platform-local-app-baselines.md)
  requires one common macOS, Windows, and Linux baseline and merge gate before
  any native local capability is considered implemented.
- [Portable key-wrapper laboratory decision](adr/0019-use-argon2id-and-aes-gcm-for-the-portable-key-wrapper-laboratory.md)
  fixes one Argon2id/AES-256-GCM conformance construction and its limits without
  selecting a production key-protection baseline.
- [Vault unlock orchestration decision](adr/0020-separate-vault-unlock-work-from-lifecycle-acceptance.md)
  separates bounded credential/protector work from generation-bound lifecycle
  acceptance without claiming preemptive KDF cancellation or durable key use.
- [Protected capability join specification](specs/PROTECTED_CAPABILITY_JOIN_V1.md)
  assigns the fixed-array layouts, code points, cryptographic contexts, parsing
  order, mailbox lifecycle, and retained-evidence gates for ADR 0014.
- [Inviter join transaction specification](specs/INVITER_JOIN_TRANSACTION_V1.md)
  defines the exact all-or-nothing inviter state and recovery contract that a
  durable storage adapter must satisfy.
- [HPKE and capability join-request research](research/HPKE_JOIN_REQUEST_PROFILE.md)
  records the bounded RFC 9180 PSK comparison and provider evidence behind ADR
  0014.
- [Phase 1 response-deposit and verifier-context research](research/PHASE1_RESPONSE_DEPOSIT_AND_VERIFIER_CONTEXT.md)
  records the verifier and authority analysis behind ADR 0014's local
  one-Welcome endpoint and 21-field inner request.
- [Inviter storage and vault-key decision packet](research/INVITER_STORAGE_ENGINE.md)
  compares transaction engines and recommends a bounded SQLCipher compatibility
  spike without selecting a production storage dependency.
- [Platform key-protector decision packet](research/PLATFORM_KEY_PROTECTOR.md)
  separates macOS, Windows, and Linux protection semantics and frames the
  bounded portable laboratory and remaining production decision gates.
- [Portable vault-key baseline implementation plan](plans/PORTABLE_VAULT_BASELINE_IMPLEMENTATION.md)
  tracks the decision, closed format, hostile-input tests, three-OS evidence,
  and explicit stop before SQLCipher or product wiring.
- [Superseded OpenMLS decision](adr/0011-select-openmls-for-the-phase-1-laboratory.md)
  retains the bounded OpenMLS evaluation and its dependency blocker.
- [MLS implementation comparison](research/MLS_IMPLEMENTATION_COMPARISON.md)
  compares exact released provider graphs and records the disposable ownership
  and storage-boundary evidence behind ADR 0012.
- [OpenMLS 0.8.1 applicability map](research/OPENMLS_0_8_1_APPLICABILITY.md)
  maps all published audit findings and the separately scoped provider to the
  evaluated in-memory boundary and records the dependency-policy blocker.
- [Profile-bound transport decision](adr/0015-bind-transport-adapters-to-versioned-profiles.md)
  records the accepted separation of stable profile policy, delivery
  coordination, adapter identity, and scoped network authority while the
  generalized transport API is implemented in reviewed increments.
- [V1 retirement decision](adr/0006-retire-v1-from-the-default-branch.md)
  removes the old runtime while preserving its exact tagged snapshot and lessons.
- [Legacy v1 archive index](legacy-v1/README.md) records recovery commands,
  behavior, security lessons, and project-history evidence.
- [Research backlog](RESEARCH_BACKLOG.md) records unresolved questions without
  prematurely turning them into architecture decisions.
- [Reference ledger](REFERENCES.md) records the standards and projects that
  informed the current baseline, including their status when reviewed.
- [Sealed invitation provider spike](spikes/SEALED_INVITATION_PROVIDER.md)
  explores first-contact delivery without an external messaging platform.
- [Sealed invitation provider protocol](spikes/SEALED_INVITATION_PROVIDER_PROTOCOL.md)
  develops the spike into roles, objects, lifecycles, abuse policies, and
  deployment profiles.
- [Client vault and portable realm hardening review](spikes/client-vault-portable-hosting/hardening.md)
  compares sealed client-state and replaceable self-hosting designs without
  selecting a desktop store or deployment dependency.
- [Architecture decision records](adr/) record the foundational decisions that
  other documents rely on.

## Decision labels

The documents use the following labels:

- **Decision**: the current design baseline. Changing it should update an ADR.
- **Proposed**: preferred direction, but not yet validated enough for an ADR.
- **Research**: deliberately unresolved.
- **Deferred**: potentially useful, but outside the currently named milestone.

## Retired v1 versus v2

The retired Angular, NestJS, Socket.IO, JWT, and Redis application is preserved
at `legacy-v1`. It is useful as product and UX history, but it is not the
security foundation for v2. Its wire format sent the message body and bearer
token together, and the backend validated server-managed membership before
rebroadcasting the same message object. The v2 design instead requires clients
to own session keys and infrastructure to handle opaque encrypted envelopes.

Nothing in these documents should be read as retroactively describing the
legacy application as end-to-end encrypted.

## Current implementation

The final unchanged legacy baseline is preserved by the `legacy-v1` tag and
indexed under `docs/legacy-v1/`; it is no longer present in the active source
tree. Phase 1 now implements the bounded opaque envelope, the canonical signed
secret-capability invitation from ADR 0007, and the bounded inviter-owned
`Available -> Reserved -> Consumed` lifecycle from ADR 0008. Releasing a
reservation returns it from `Reserved` to `Available`; it is not a terminal
stored state. The separate `session-crypto-mls` crate now retains an isolated,
in-memory two-party MLS 1.0 lifecycle: bounded exact KeyPackage validation,
Add/Welcome, encrypted application messages, path updates, removal, replay and
reordering rejection/recovery evidence, and explicit-only provider storage
writes.
The implementation-free `session-crypto` crate now defines the bounded,
object-safe application message seam, and `session-crypto-mls` is its only
current implementation. This defines where a future client can select a
reviewed backend for a new session; it does not yet provide backend negotiation
or migrate active MLS state.
The implementation-free `session-admission` crate now defines an object-safe,
display-only approval context and shared decision. It exposes no proof, bearer
capability, parsed KeyPackage, reservation, or membership authority.

The `admission-capability` crate accepts only an HPKE-authenticated request,
retains the exact signed-invitation provenance, independently validates and owns
its exact provider KeyPackage, verifies the ADR 0009 tuple, and reserves the
request ID and nonce in bounded in-memory state. It now binds that value to the
exact local v2 invitation, consumes an explicit simulated approval decision,
and permits only the approved one-shot value to reach MLS preparation. Its
pending value implements the shared approval observation seam without releasing
the provider-owned evidence or exact KeyPackage.

The invitation's self-contained key proves descriptor integrity only. The
registry accepts provider-generated invitation v2 and models its bounded
reservation lifecycle. The approval-gated in-memory path now connects it to
automated admission and MLS sequencing.
ADR 0014 now defines the HPKE capability-proof and local response contracts.
Their bounded canonical invitation-v2, protected outer/inner, exact AAD, and
deposit-endpoint value types are implemented with retained fixtures. The
one-shot HPKE operation has RFC and independent-provider evidence. Replay-safe
automated capability admission, explicit simulated approval, exact v2
reservation, failure release, and post-Add consumption now have retained
in-memory evidence. Human approval UX, atomic durable membership/replay state,
rollback protection, and durable or network transport remain unimplemented at
product level. A bounded fault-injectable model now retains evidence for the
required atomic visibility, retry, and Welcome-outbox state semantics without
claiming disk durability. A right-specific local one-Welcome mailbox now has
bounded in-memory evidence, and the committed approved-join result carries its
exact deposit-only endpoint beside the encrypted MLS Welcome. The current
sequential delivery path is not a durability or crash-atomicity claim.
The separate `transport-memory` adapter now implements both the narrow and
generalized right-specific opaque-envelope traits with bounded deterministic
loss, duplication, reordering, retry, expiry, clock/cancellation, cursor
rejection, exact-set acknowledgement, and redaction controls for headless tests.
It is not a network, encryption, or privacy implementation.
The `sessionctl` binary now composes the implemented local boundaries into one
fresh two-client run covering protected capability admission, explicit
simulated approval, Welcome delivery, bidirectional MLS application messages,
path update, removal, and post-removal rejection. It prints only coarse
milestones and is neither a durable nor networked client.
The `session-storage` crate now retains a deterministic in-memory conformance
model for one-session unsealing, bounded external unlock work, exact-session
one-shot credential acquisition, forced relock events, stale/foreign-owner
completion rejection, post-provider unlock-deadline enforcement, and bounded
canonical opaque receipt/import. Cancellation invalidates work that has not
entered the provider and discards a key returned by already-running work; it
does not preempt that provider operation. The crate provides no encrypted
persistence, production scheduler, durability, rollback, or crash-recovery
claim.
The separate `key-protector-passphrase` crate now retains ADR 0019's bounded
portable wrapping experiment: one fixed Argon2id/AES-256-GCM construction and
closed 102-byte record authenticated to an expected `SessionId`. It reports
only `ApplicationWrapped`, device-binding `Unknown`, user-presence `None`, and
`MayBackup` capabilities. Its exact-session protector owns the wrapped record
and consumes one passphrase through ADR 0020's bounded lifecycle contract. It
does not supply SQLCipher, provide product credential UI, or establish a
production key-protection baseline.
The separate `storage-sqlcipher` crate now exercises both owner-local
transactions through the real MLS storage path and recovers them after close
and reopen on the required Linux, macOS, and Windows CI runners. It is not wired
to the vault lifecycle and adds no production packaging, broader platform,
rollback-resistance, or production-storage claim.

## Reference standards and projects

- [RFC 9420: Messaging Layer Security](https://www.rfc-editor.org/rfc/rfc9420)
- [RFC 9750: MLS Architecture](https://www.rfc-editor.org/rfc/rfc9750)
- [RFC 9180: Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180)
- [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [W3C Decentralized Identifiers 1.0](https://www.w3.org/TR/did-core/)
- [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [Katzenpost specifications](https://katzenpost.network/docs/specs/)
- [Iroh documentation](https://docs.iroh.computer/)

References indicate relevant standards and prior art. They do not commit the
project to a particular library, credential format, DID method, network, or
service operator.
