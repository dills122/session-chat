# Session Chat repository threat model

Status: design baseline for the v2 architecture and protocol laboratory

The [Phase 1 closeout evidence matrix](evidence/phase1-closeout.md) is the
current requirement/test/claim index. [ADR 0025](adr/0025-close-phase-one-recovery-and-conformance-evidence.md)
adds checked Welcome application and SQLite commit-window process kills,
fresh complete-state verification, and deterministic lifecycle model fixes.
All findings from the authorized independent-review closeout are remediated,
and the exact Phase 1 revision recorded in the matrix passed the full Linux,
macOS, and Windows public-evidence gate. Each later behavior or evidence
revision must repeat that exact-revision gate.

## Overview

Session Chat is a privacy- and security-sensitive messaging project. The active
repository contains a headless Rust protocol laboratory and design artifacts;
it does not yet contain a deployable client or network service. The laboratory
currently has a bounded opaque envelope, canonical domain-separated Ed25519
secret-capability invitation v1/v2 layouts, bounded protected outer/inner join
request and local deposit-endpoint value types, a provider-neutral one-shot HPKE
PSK adapter with RFC/cross-provider evidence, exhaustive hostile fixtures, and
a bounded inviter-owned invitation v1/v2 reservation/consumption state machine.
Local v2 state can be created only from the provider-generated invitation
wrapper; validating a remotely supplied descriptor remains read-only. The
capability-admission adapter accepts only proven HPKE opens, owns the exact
provider-validated KeyPackage, and performs bounded in-memory request-ID/nonce
replay reservation for one invitation generation. It retains the exact opened
invitation signature, binds the admission to local v2 state, and consumes an
explicit simulated approval decision before MLS preparation. Its pending value
implements a provider-neutral, display-only approval context while retaining
the exact provider evidence, KeyPackage, and reservation authorities. Copying
that context or its decision grants no membership authority. Rejection and
pre-commit failure release invitation and replay state. The legacy in-memory
apply consumes the invitation immediately; durable composition instead returns
a one-shot applied result that preserves both reservations until SQL recovery
proves commit or rollback. It does not perform human UI approval or
rollback-resistant persistence. ADR 0023 specifies the restartable successor.
SQLCipher now commits the exact signed invitation and matching HPKE private key
before publication, revalidates that opening context after restart, and owns
the bounded authorization replay/conflict shadow. Loss of a live verified or
approved KeyPackage abandons that attempt, retains replay state through the
generation expiry, and releases the generation only when its exact opening
context reloads successfully. The single-process and independent-process
headless admission paths now use this owner; their provider-owned parsed
KeyPackage remains live and non-serializable through MLS Add. A local transport adapter implements
bounded one-Welcome deposit, receive, and acknowledgement with independent
provider-generated authorities. The approved in-memory join result carries only
the authenticated deposit endpoint beside its MLS outputs, and a retained test
delivers the encrypted Welcome through that mailbox. This provides no durable
outbox or network behavior in the sequential admission path. The generalized transport contract now has a closed
profile set, bounded local adapter identifiers, exact canonical-envelope
ownership without ordinary debug output, finite operation budgets, bounded
retry advice, context-free failures, bounded operation requests and receipts,
and post-receive batch validation. Later Phase 1 increments added the
runtime-neutral dispatch trait, deterministic memory adapter, LocalV1 binder,
deposit-only coordinator, and the provider-neutral four-right mailbox lifecycle
plus receive-state owner contract. No reusable lifecycle provider or network
authority is implemented. A separate bounded, fault-injectable model exercises
all-or-nothing inviter state, ambiguous-result recovery, and Welcome-outbox
leasing semantics without providing storage or connecting to that sequential
join path. The SQLCipher laboratory now implements the same sole-owner port
with versioned migration and close/reopen lease recovery. A retained real
capability-admission/MLS composition crosses that boundary, including ambiguous
commit recovery and exact post-restart Welcome delivery. Schema version 3
retains Alice's exact MLS credential/signing identity, and version 4 binds it to
her group. ADR 0021 now exercises that owner across graceful Alice process exit
and a fresh reload process while Bob and an untrusted forwarding service remain
separate. The bounded test-only IPC admits only canonical protected-join,
exercised LocalV1 deposit, and opaque-envelope objects; the bearer invitation
and disposable raw owner key stay on separate client-only channels. This does
not establish hostile local-controller isolation, platform key custody, or
abrupt-kill recovery. A separate deterministic memory transport uses right-specific
authorities and bounded explicit drop, duplicate, hold/release, retry, expiry,
and capacity behavior for headless tests. It accepts structurally opaque bytes
but neither encrypts them nor provides a network or privacy property. The MLS
crate operates a two-party MLS 1.0 lifecycle behind the reduced-feature
`mls-rs`/AWS-LC boundary selected by ADR 0012. Its default product path remains
in memory; a generic persistence boundary is exercised only by the separate
SQLCipher laboratory. Upstream's missing full independent `mls-rs` audit
remains a release risk rather than inherited assurance. The retired v1
Angular/NestJS application used a server-readable, server-authoritative model.
The proposed v2 product replaces it with client-owned MLS sessions, encrypted
pre-membership rendezvous, optional external admission evidence, and pluggable
delivery transports.

This document is repository-scoped. It covers both:

- The archived v1 trust failures that future work must not reintroduce.
- The v2 security architecture being designed in this repository, so new code
  can be assessed against explicit invariants from its first commit.

The retired application sent a `MessageFormat` containing the message body,
room, user ID, timestamp, and token. The backend checks membership and JWT
validity and rebroadcasts that object. Redis stored room membership and
invitation-link state. Its `CryptoService` hashed strings and generated UUIDs;
it did not provide end-to-end encryption. TLS could protect connections from
outside observers, but the backend remained inside the plaintext trust boundary.

The v2 goal is narrower and stronger: admitted clients hold plaintext and
session keys; normal identity, rendezvous, mailbox, and relay infrastructure
handles only the minimum information required for its role.

### Primary assets

- Message and attachment plaintext
- MLS group, epoch, exporter, and application secrets
- Device-root, session-member, invitation, mailbox, and transport private keys
- Admission capabilities and invitation secrets
- OAuth access and refresh tokens
- GitHub attestations and verifiable presentations
- Local encrypted history and metadata
- Membership state and the integrity of add, remove, update, and Commit events
- Identity-to-session-key bindings
- Participant network addresses and communication relationships
- Mailbox capabilities and undisclosed realm endpoints
- User expectations about verification, ephemerality, and privacy profiles
- Update-signing and release credentials

### Primary security objectives

1. Only explicitly admitted member devices can derive current session content
   keys.
2. Infrastructure cannot read application content or fabricate authenticated
   member messages.
3. Admission evidence cannot be replayed to another invitation, verifier,
   KeyPackage, credential identity, or MLS leaf signature key.
4. Targeted public invitations do not act as bearer membership credentials.
5. Removed members cannot derive later group epochs; new members cannot decrypt
   earlier application history unless explicitly shared.
6. External identities are not silently conflated with trust, device
   continuity, or global cryptographic identity.
7. Anonymous sessions make no identity-provider calls or other avoidable
   correlating network requests.
8. A private transport profile never silently downgrades to a fast/direct
   profile.
9. Expiration, deletion, and retention behavior match user-visible claims.
10. Untrusted inputs cannot cause unbounded storage, CPU, memory, retry, or
    network amplification.
11. A transport adapter cannot broaden the selected profile's network authority,
    select a weaker path, or turn implementation capabilities into a product
    privacy claim.

## Threat Model, Trust Boundaries, and Assumptions

### Actors

- **Participant**: a person operating one or more client devices. A participant
  may be honest, malicious, compromised, or coerced.
- **Inviter**: a participant who creates an invitation and controls admission
  to the initial session.
- **Joiner**: a party submitting an admission request. Before approval, all
  joiner-controlled data is hostile.
- **Realm operator**: deploys identity, rendezvous, mailbox, relay, and admin
  services. The operator may be honest-but-curious, compromised, or malicious.
- **Identity provider**: GitHub or another system that authenticates an
  external account.
- **Identity bridge**: converts provider authorization into a short-lived,
  invitation-bound attestation.
- **Credential issuer/wallet/status provider**: creates, holds, presents, or
  reports status for verifiable credentials.
- **Transport operator**: runs relays, gateways, mixes, service nodes, or PKI
  components.
- **Network attacker**: observes, delays, drops, reorders, duplicates, injects,
  or redirects traffic within their position.
- **Software supply-chain attacker**: compromises dependencies, build systems,
  update infrastructure, developer credentials, or release artifacts.

### Trust boundary: local UI to protocol core

Deep links, clipboard data, rendered messages, user-entered text, and webview
content cross from attacker-influenced UI inputs into the privileged Rust
protocol and storage core. The core must validate all objects independently;
the UI is not an admission or cryptographic authority.

Assumptions:

- The application shell can constrain webview privileges and expose a narrow
  command surface.
- Cryptographic decisions remain in reviewed core code.
- XSS or compromised UI dependencies can still request privileged operations,
  display deceptive evidence, or exfiltrate plaintext available to the UI;
  interface authorization and output minimization remain necessary.

### Trust boundary: client to identity provider and bridge

OAuth callbacks, authorization codes, provider responses, bridge attestations,
organization claims, and error messages cross this boundary.

Assumptions:

- TLS and provider application configuration are correct.
- The bridge is trusted to attest provider bindings honestly but is not trusted
  with message content.
- A compromised provider account can produce a technically valid account
  proof; Session Chat cannot prove the real-world person remains in control.
- A malicious bridge can issue a false external-identity binding unless clients
  have transparency, multi-attestation, or another detection mechanism. This is
  an explicit authentication-service risk.

### Trust boundary: wallet and credential ecosystem

Credential presentations, issuer metadata, DID documents, resolution results,
status information, redirects, and wallet responses are attacker-controlled
until verified.

Assumptions:

- Realm policy identifies trusted issuers, credential types, securing
  mechanisms, and claim constraints.
- Control of an arbitrary DID is not equivalent to a trusted semantic claim.
- Online issuer, resolution, or status calls can create availability and
  correlation risks even when the presentation verifies cryptographically.

### Trust boundary: client to rendezvous/mailbox

Invitation mailboxes receive unauthenticated or capability-authorized encrypted
objects. The service controls delivery order, availability, retention, and
observable metadata, but must not control plaintext membership or group keys.

Assumptions:

- A malicious service can drop, delay, replay, reorder, duplicate, or withhold
  envelopes.
- It can observe mailbox access, timing, sizes, and network endpoints according
  to the selected transport.
- It cannot forge valid inviter, joiner, or MLS signatures or decrypt properly
  constructed envelopes without endpoint key compromise.

### Trust boundary: client to first-contact directory and invitation mailbox

An optional invitation directory maps a verified address or unguessable receive
code to a signed, rotating receive bundle. A separate first-contact mailbox
stores fixed-size invitation ciphertexts under random mailbox identifiers.

Assumptions:

- A normal directory learns the target address and lookup timing.
- An OHTTP relay can learn the requester network address while the gateway
  learns the target lookup; the privacy improvement depends on separation and
  non-collusion.
- The mailbox can observe deposits and polls but must not receive the directory
  identity or read capability.
- Directory signatures prevent undetected field substitution but do not stop a
  malicious authorized directory from equivocation or denial of service. An
  independent address-attestor signature over the complete receive bundle is
  required to prevent directory-only receive-key substitution.
- A public receive bundle is a deposit capability and creates spam and resource
  exhaustion pressure even though the invitation remains encrypted.

### Trust boundary: client to fast transport

Direct peers can learn each other's network addresses. Relays can observe
source and destination addresses, timing, and volume. Neither receives MLS
secrets by design.

Assumptions:

- Content encryption does not imply anonymity.
- NAT traversal and discovery services may add further metadata observers.
- A relay may drop, replay, or delay traffic.
- The explicitly selected Iroh Fast experiment authenticates endpoint public
  keys at QUIC setup, but that identity does not authorize Session Chat
  admission or MLS membership. Direct paths expose peer addresses; the N0
  relay, address-lookup, and DNS services can observe endpoint, timing, size,
  and lookup metadata. Its first bounded online link is not an offline mailbox
  and uses ephemeral endpoint keys.
- The experiment accepts only the host's canonical lowercase hexadecimal
  endpoint text. Each timed operation rejects zero or greater-than-five-minute
  bounds and uses one checked absolute deadline. Caller frame bounds cannot
  exceed 256 KiB; failed, timed-out, or cancelled partial frame I/O poisons the
  ordered link. Graceful close requires both acknowledged outbound bytes and a
  clean inbound finish; a reset or connection error cannot be reported as
  receipt.
- The first connected `EnvelopeDelivery` slice authenticates one exact server
  endpoint and uses independent random deposit, receive, and acknowledgement
  capabilities. The volatile service stores domain-separated digests rather
  than raw capabilities; a capability cannot be substituted for another
  operation. Its versioned CBOR request/response frames reject malformed,
  trailing, noncanonical, wrong-version, and oversized input before use.
- The service bounds live mailboxes, mailbox lifetime, logical envelope count,
  retained canonical bytes, poll size, requests per connection, and one
  absolute deadline per request/response exchange. Its 40-byte continuation
  cursor authenticates the position with a per-mailbox HMAC key and grants no
  receive authority by itself. Exact deposit and acknowledgement retries are
  idempotent; a same-ID deposit with different canonical bytes fails.
- All connected mailbox state is in memory. Process loss discards envelopes,
  cursors, acknowledgements, and authorities, so this evidence establishes no
  offline delivery, durability, rollback protection, or recovery guarantee.
  Relay, NAT, route-change, peer-offline, outage, and packet-capture evidence
  remains open.
- The bearer capability invitation must cross an authenticated confidential
  out-of-band channel. It is never sent to an unauthenticated first Iroh
  connector; the first network frame is the joiner's HPKE-protected request.
  A first connector can still deny service by occupying or closing the sole
  experimental connection, but cannot obtain admission authority from it. The
  operator handoff is bounded to five minutes. The joiner rejects directories,
  links, FIFOs, and other non-regular invitation paths before network work.

### Trust boundary: client to mixnet

The entry provider can observe the client connection. Mix and service operators
observe their local role. The anonymity claim depends on topology, delays,
padding, cover traffic, usage, and non-collusion assumptions, not solely on
packet cryptography.

Assumptions:

- Mixnet delivery can be delayed, lost, duplicated, and reordered.
- A small or single-operator deployment has a weaker anonymity set and weaker
  resistance to operator collusion.
- Application traffic patterns can undermine transport-layer privacy.
- Private mode is allowed to become unavailable rather than downgrade.

### Trust boundary: delivery coordinator, profile binder, and adapter

The session core supplies canonical opaque envelopes to a coordinator. Local
policy binds one versioned profile to one adapter or explicitly reviewed
composite adapter. The adapter then crosses a scoped network or process
boundary.

Assumptions:

- Adapter manifests and capability declarations are configuration input, not
  proof that the implementation or deployment provides the claimed behavior.
- A compromised or misconfigured adapter may attempt undeclared DNS, direct,
  relay, telemetry, update, discovery, or background connections.
- Adapter SDKs may retry, cache, reconnect, resolve names, or start background
  work without the coordinator's knowledge unless constrained.
- Code-level type separation cannot by itself enforce network isolation;
  private profiles require a scoped network broker or process/OS egress policy.
- The owner-local transaction store owns durable outbox truth and leases. The
  coordinator, not the adapter, owns total retry policy, expiry checks,
  deduplication, cursor, and acknowledgement execution without maintaining a
  competing outbox ledger.
- The retained LocalV1 coordinator slice is deposit-only. Its sender-only
  adapter surface, exact canonical reconstruction, one-attempt budget, coarse
  failures, and drop-on-supervision evidence now include the in-memory inviter
  owner port, exact retry after an unrecorded remote acceptance, and
  cross-platform wake/cancel/deadline supervision with pending-work drop for the
  standard-library blocking baseline. They do not prove durable restart
  recovery, receipt, recipient processing, or future UI-runtime wiring.
- The FastV1 binder accepts only the exact Iroh adapter declaration: canonical
  64 KiB envelopes, 192 KiB poll batches, 64 envelopes, 40-byte cursors,
  deposit/poll/acknowledgement operations, coordinator-owned retry, declared
  background work, in-process execution, and ambient network egress. The
  resulting enforcement record explicitly says the network is ambient; it
  does not turn a manifest into OS-enforced isolation or a Private profile.

### Trust boundary: local persistent storage and operating system

Device roots, MLS state, local history, caches, notifications, logs, crash
reports, swap, and backups cross this boundary.

Assumptions:

- OS keychains and secure hardware improve key protection but do not make a
  fully compromised unlocked endpoint safe.
- Cryptographic deletion cannot remove plaintext copied by a participant or
  endpoint malware.
- Backups and OS snapshots can preserve data beyond application TTLs unless
  explicitly designed and tested.

### Trust boundary: build, dependencies, and updates

The desktop application, Rust crates, JavaScript packages, containers, CI, code
signing, and update channels can introduce privileged code.

Assumptions:

- A malicious signed client can access plaintext at an endpoint and defeat
  nearly all protocol guarantees.
- Release provenance, dependency review, reproducibility, and signed updates
  are part of the product security boundary.

### Attacker-controlled inputs

- Invitation URLs, fragments, deep links, QR contents, and clipboard values
- Join requests, KeyPackages, credential presentations, and attestations
- Mailbox identifiers, encrypted envelopes, acknowledgements, cursors, and
  transport frames
- MLS proposals, Commits, Welcome messages, and application messages
- GitHub/OAuth callback parameters and provider API responses
- DID documents, issuer metadata, credential schemas, status data, and redirects
- Message text, formatting, URLs, display names, avatars, and notification data
- Timestamps, object versions, suite identifiers, sizes, sequence numbers, and
  retry signals
- Configuration supplied by a self-hosting operator

### Operator-controlled inputs

- Allowed identity methods, issuers, transports, and session profiles
- Service endpoints, TLS certificates, bridge and realm signing keys
- TTL, participant, attachment, mailbox, and rate limits
- Mixnet topology or provider selection in organization-controlled deployments
- Logging, telemetry, backups, updates, and retention configuration

Unsafe operator configuration should be rejected or clearly identified rather
than silently weakening a named security profile.

### Developer-controlled inputs

- Dependencies and feature flags
- Protocol versions and cryptographic suites
- Serialization rules and domain separation
- Tauri command exposure and webview policy
- Container images, CI workflows, release scripts, and update manifests
- Test vectors, fuzzing dictionaries, and development-only bypasses

Development and test bypasses must not be compiled or enabled silently in
production artifacts.

### Out-of-scope guarantees

The system does not claim to prevent:

- A participant from copying, photographing, or exporting plaintext
- Malware with access to an unlocked endpoint from capturing plaintext
- A compromised GitHub account from producing a valid account-control proof
- Coercion or social engineering outside the protocol
- All traffic analysis against every adversary and deployment
- Availability when infrastructure or networks intentionally refuse service
- Real-world personhood from an arbitrary DID or self-issued credential

These limitations do not make false UI statements, key leakage, identity
misbinding, or privacy downgrade acceptable.

## Attack Surface, Mitigations, and Attacker Stories

### Invitations and deep links

Relevant attacks include malformed-object parsing, oversized input, signature
confusion, scheme downgrade, replay, clock manipulation, capability leakage,
open redirects, command injection through URI handling, and accidental server,
browser-history, shell-log, or clipboard disclosure.

Required controls include canonical signed encoding, strict size and depth
bounds, explicit version and suite allowlists, domain-separated signatures,
random invitation identifiers, short expiration, replay tracking, fragment-safe
landing behavior, and fuzzing of every decoder.

Current evidence covers the canonical fixed-field encoding, exact size bounds,
explicit version/suite/mode/use-policy allowlists, application-domain-separated
strict Ed25519 verification, structural nonzero identifiers/challenges/
capabilities, configurable time policy, exhaustive per-field malformed fixtures,
and the inviter-owned v1/v2 `Available -> Reserved -> Consumed` lifecycle, with a
release edge from `Reserved` back to `Available` rather than a stored
`Released` state.
Descriptor validation is read-only and remote self-signed objects cannot create
registry state. V2 issuance accepts only the provider-generated complete
invitation wrapper. Reservation authority is bound to the schema and exact
signed local record,
so it cannot cross an expiry/reissue boundary even if invitation and request IDs
recur. Random generation quality, durable atomic consumption with MLS, rollback
protection, deep-link leakage, fuzzing, and ADR 0014's cross-state admission
integration remain open. Invitation v2 itself now has an independent
signature domain, exact fixture, closed suite/profile code points, and the same
pre-parse size and canonical-decoding controls as v1.

ADR 0023 closes the recovery-contract ambiguity. Its first retained slice
implements the requirement that, before publication, the durable owner retains
the exact canonical signed invitation and its matching invitation-scoped HPKE
private key. Returning a reservation to `Available` after restart is allowed
only after that context reloads, revalidates, and remains unexpired; otherwise
the generation becomes terminally unusable. This prevents identifier-only state
from masquerading as a usable invitation and prevents silent key regeneration
under an existing signed generation.

Attacker story: an attacker copies a public targeted invitation and submits a
validly encoded join request for their own key. Correct behavior is a policy
mismatch or explicit rejection, not membership.

### Protected capability join and local Welcome response

Relevant attacks include weak or leaked invitation capabilities, HPKE mode or
suite downgrade, cross-protocol key reuse, wrong recipient keys, context/AAD
substitution, replay across invitation generations, KeyPackage substitution,
verifier confusion, parser amplification, capability logging, cross-right
mailbox authorization, competing deposits, Welcome replacement, and retry
amplification.

ADR 0014 requires one exact RFC 9180 PSK suite, independent invitation-scoped
HPKE/signature keys, typed and domain-separated contexts, fixed canonical
schemas, complete cross-context equality before mutation, the exact ADR 0009
KeyPackage tuple, coarse provider errors, high-entropy creation, and a closed
local deposit endpoint. Deposit, receive, and acknowledgement authority remain
separate. The mailbox admits one logical bounded envelope and treats only the
same envelope ID and exact bytes as an idempotent retry.

The canonical invitation-v2, protected outer/inner, exact outer AAD, local
deposit-endpoint values, and one-shot HPKE operation are implemented and
tested. Evidence includes exact fixtures, the official RFC PSK vector,
independent-provider opening of AWS-LC output, wrong-key/context and tampering
rejection, closed code points, strict bounds, structural time/lifetime checks,
and coarse secret-free public failures. The capability-admission adapter accepts
only HPKE-opened provenance, retains the exact invitation signature, enforces
current time and request lifetime, independently validates and owns the exact
provider KeyPackage, compares the reference/credential/leaf tuple before
mutation, and reserves both request ID and nonce in bounded in-memory state. It
binds that value to exact local v2 state and requires an explicit simulated
approval token before MLS preparation. Rejected, expired, failed, or dropped
preparation releases invitation and replay reservations while leaving
membership unchanged. Apply rechecks request and invitation expiry using a
fresh caller-supplied time before MLS mutation, and independently rechecks the
shorter-lived response endpoint. Tests cover substitution,
same-generation replay, expiry/reissue with reused request values, stale-release
ABA, foreign-verifier reservation rejection, capacity preservation, delayed
expiry, and unchanged state after rejection or abandonment.

The separate local transport adapter generates independent deposit, receive,
and acknowledgement authorities, stores only their domain-separated
commitments, bounds mailbox count, lifetime, and envelope size, and accepts one
logical envelope. Tests reject foreign or expired authority, changed competing
deposits, and capacity violations without replacement or mutation; exact
deposit and acknowledgement retries are idempotent. The committed approved-join
result carries only the authenticated deposit endpoint alongside its MLS
outputs; a retained integration test deposits the exact encrypted Welcome and
proves later delivery failure does not roll back membership. Expired endpoints
fail before replay reservation or MLS mutation. This evidence does not establish
durability, outbox atomicity, rotation, networking, anonymity, or production
transport behavior.

The provider owns one complete invitation-v2 creation API covering every secret
and random field; callers supply only issue and expiration times. The in-memory
approval path applies MLS and then consumes invitation state before returning
the committed outputs, but that sequencing is not crash-atomic. The durable
path instead retains a one-shot applied value across SQL staging, write, and
transaction-ID recovery; it finalizes the in-memory shadow only for a proven
commit and releases it only for a proven rollback. A separate
conformance model tests the accepted inviter transaction's all-or-nothing
components, exact retries, stale-generation rejection, ambiguous commit
recovery, and bounded outbox leases over in-memory records. The SQLCipher
laboratory now supplies the corresponding real MLS transaction and durable
coordinator owner port, and a retained integration test wires it to capability
admission through restart delivery and real joiner processing. The exact Phase 1
implementation revision recorded in the closeout matrix passed the composed ADR
0023 owner and ADR 0025 process-kill suites through bounded public-manifest and
Linux, macOS, and Windows CI gates. Each later behavior or evidence revision must
repeat those exact-revision gates before the completion record advances.
Remaining product requirements include human approval UX, rollback protection,
vault-backed confidentiality, and broader disk/power-fault evidence. The
separate checked L2 laboratory covers baseline-derived SQLite-visible
FULL/extended-IOERR failures, observed engine commit-window process kills, and
every baseline-observed inviter/joiner application checkpoint. Raw observations
remain non-public; only complete, secret-free aggregate manifests may enter the
portable CI evidence record.

Attacker story: Mallory captures a protected request and resubmits it after the
invitation expires and is reissued with the same invitation and request IDs.
The fresh challenge, signing key, HPKE key/key ID, exact local record, and replay
state must reject it before reservation. A stale request cannot use or replace
the new Welcome mailbox.

### First-contact directory and sealed invitation mailboxes

Relevant attacks include unauthorized address registration, receive-key
substitution, record replay, equivocation, lookup enumeration, hashed-identifier
dictionary attacks, mailbox flooding, read-capability theft, unbounded lifetime
deduplication state, traffic correlation, and private-profile direct lookup.

Required controls include authorization bound to the stable lookup address and
complete receive bundle, an independent address-attestor signature over that
context, directory response signatures, short-lived rotating records, random
mailbox IDs, separate read capabilities, fixed envelope sizes, queue and
lifetime deposit limits, generic errors, idempotent envelope IDs, and
privacy-aware lookup transport. Hashing public usernames is not a privacy
control.

Attacker story: Mallory registers their receive key under Bob's GitHub subject
or rebinds Bob's signed bundle under Mallory's directory entry. Registration
authorization and the directory signature must bind the lookup address, key,
mailbox, and expiry so the substitution fails.

### Admission and identity binding

Relevant attacks include OAuth code interception, callback confusion, token
leakage, mutable-login targeting, false bridge attestations, untrusted issuer
acceptance, audience or nonce omission, holder-binding failure, credential
replay, DID resolution substitution, status-check tracking, and deceptive UI.

Required controls include PKCE, exact redirect matching, provider stable subject
IDs, short-lived attestations, invitation/audience/key binding, issuer and
credential allowlists, local verification where possible, minimal disclosure,
explicit evidence provenance, and manual approval where required.

Attacker story: Mallory captures Bob's valid presentation and substitutes
Mallory's MLS KeyPackage. Verification must fail because the presentation binds
the canonical KeyPackage reference, credential identity, leaf signature key,
invitation challenge, request identifier, ciphersuite, and verifier under ADR 0009.

### MLS and session state

Relevant attacks include invalid KeyPackages, malformed or conflicting Commits,
rollback, replay across epochs, state desynchronization, key reuse, nonce misuse,
failure to erase obsolete secrets, incorrect member removal, and concurrency
bugs.

Required controls include a reviewed MLS implementation, strict state-machine
encapsulation, persistent monotonic state, transactionally stored epoch changes,
idempotent delivery processing, explicit pending-Commit handling, known-answer
and interoperability tests, fuzzing, and safe failure on unrecoverable state.
Backend selection must come from a compiled, reviewed allowlist for new
sessions. Network-supplied code, arbitrary dynamic crypto plugins, and silent
mid-session implementation or storage-format switching are prohibited.

Current isolated evidence covers bounded exact KeyPackage/Welcome/message
parsing, retained KeyPackage ownership through Add and Welcome targeting,
two-member roster enforcement, explicit prepare/apply and abandoned-pending
handling, replay, reordering, temporarily lost epoch commits, path updates,
removal, explicit-only group-state writes, and the provider-neutral established-
session message interface from ADR 0013. The headless `sessionctl` acceptance
flow now composes fresh capability admission, an atomic SQLCipher inviter
transaction, ambiguous-result recovery, exact identity/group reload, reconstructed coordinator Welcome
delivery, bidirectional protected messages, path update, removal, and
post-removal rejection across the local adapters. It adds durable-component
integration evidence, not rollback resistance or networking. The ADR 0021 L1
runner adds graceful independent-process exit and exact Alice identity/group
reload plus bounded child cleanup. It does not add abrupt kill,
disk/power-fault, rollback-resistance, or network evidence.
The separate inviter-transaction model
covers only the application-level all-or-nothing and recovery semantics over
bounded memory records. The checked SQLCipher L2 laboratory additionally
injects every baseline-derived supported FULL/extended-IOERR result and kills a
direct writer at every observed journal/main commit-window pause before a fresh
verifier accepts only I0/I1 or J0/J1 with exact retry. Separate local checked
sweeps now kill every baseline-observed inviter/joiner application checkpoint
and enforce the same complete-state and retry invariants, including
missing/duplicate coverage rejection. Raw case observations remain non-public.
The retained L2-8 gate lets only sealed complete aggregates emit canonical
per-case bundles after actual compiler/GitHub-run/runner-tuple, engine, binary,
and artifact provenance plus synthetic-canary and actual-secret scans across
every bounded evidence surface; portable passage remains per-revision three-OS CI
evidence. Current evidence still does not cover product-client recovery,
cross-implementation fixtures,
cross-device acknowledgement semantics, old-secret deletion, power loss,
filesystem faults, rollback resistance, or fuzzing.

Attacker story: a malicious delivery service withholds one Commit and later
replays it after a subsequent epoch. The client must reject it without rolling
back or corrupting group state.

### Rendezvous, mailbox, and abuse

Relevant attacks include mailbox enumeration, capability guessing or leakage,
queue flooding, oversized ciphertexts, decompression bombs, retry amplification,
timing or error oracles, retained-expired data, deletion of join requests, and
cross-mailbox correlation.

Required controls include high-entropy capabilities, separated deposit/read
rights plus distinct acknowledgement and rotation authority, object and queue
bounds, TTLs, quotas, idempotency, constant-shape errors where practical,
capability rotation, no plaintext indexing, and logs that omit full identifiers
and capabilities. Delivery identifiers never authorize acknowledgement.

The implemented local one-use Welcome profile deliberately has no rotation
operation. Its tested deposit, receive, and acknowledgement separation is local
state-machine evidence only; reusable and network mailboxes still require
explicit rotation, revocation, abuse controls, and metadata analysis.

The local receive and acknowledgement values now have private fields and
crate-only constructors, compile-fail evidence rejects cross-right substitution
and use of a delivery identifier as authority, and a seeded foreign-deposit
fixture proves coarse diagnostics omit known authority and ciphertext bytes.
The generalized lifecycle boundary adds non-cloneable/non-debuggable rotation
authority, rejects receive-right or cursor substitution at compile time, and
tests that coarse failures omit seeded configuration, continuity, receive-scope,
and rotation-authority bytes. These checks do not establish operating-system
memory erasure, process isolation, network-metadata privacy, or that an
unimplemented provider generates non-derivable authority material.

The additive generalized operation values reject empty or oversized cursors,
zero or excessive poll counts, aggregate poll-byte limits above either the 4 MiB
contract ceiling or the caller's total operation budget, waits above 60 seconds,
deposit bytes above their operation budget, and acknowledgement batches outside
one to 64 distinct identifiers. Cursor, request, bounded-ID, and deposit-receipt types
that own full identifiers or ciphertext omit ordinary diagnostics. Received
batches also reject excess items, excess aggregate canonical bytes, and locally
expired envelopes before crossing the contract. The subsequent generalized
dispatch boundary preserves distinct provider authority types and supplies
bounded requests through runtime-neutral standard-library futures. Explicit
checkpoints separate monotonic deadlines, fallible local wall time, and
cooperative cancellation; pre-entry evidence rejects mutation, while a staged
test adapter proves it can recheck cancellation before its own local commit and
a pending test future runs cleanup on drop. Remote or already-applied provider
mutation remains explicitly ambiguous. The deterministic memory adapter now
adopts this boundary with fixed
configuration and live-byte ceilings, exact-byte delivery, normalized
idempotency conflict, exact-set idempotent acknowledgement, cursor rejection,
final-observation expiry revalidation, and seeded diagnostic redaction evidence
while retaining the narrow fault tests. Provider-neutral outer right wrappers
prevent direct positional substitution even if an implementation aliases its
inner provider material. They do not prevent a defective provider from cloning,
forging, or reminting that material into another right, so conformance must
prevent cross-right derivation, validate exact scope, and review duplication
policy per right. Controlled deposit transfer remains allowed; receive and
acknowledgement authority should be non-cloneable by default. The current
memory provider retains three private, distinct capability types and
domain-separated commitments. Ambiguous post-commit cancellation, deadline,
and clock failure are reconciled only with the exact same idempotency identity
under a fresh budget; `RetryAdvice::Never` ends the current budget rather than
asserting non-commit.

The reusable-mailbox contract binds every persisted cursor to the exact
profile/configuration, continuity ID, generation, receive scope, cursor schema,
provider-state epoch, and expiry. Missing or mismatched fields fail closed;
polling again from no cursor after initialization requires an explicit recorded
resynchronization. Rotation requires a separate right, exact predecessor,
successor generation, and idempotent rotation ID. Routine overlap is bounded;
compromise rotation has none. A separate receive-state owner must atomically
compare-and-swap its checkpoint, retain canonical envelopes or duplicate
outcomes, persist exact acknowledgement intents, and advance the cursor before
it leases immediate or restart-recovered acknowledgement work. The owner port
reloads only the latest checkpoint for the exact live binding, including a
successor revision with no continuation cursor. The reusable poll request and
validated batch carry the exact binding, owner revision, checkpoint-position
kind, and cursor bytes into commit; duplicate delivery IDs fail validation.
Explicit resynchronization is owner-CAS recorded before polling from none and is
restart reloadable.
Owner-defined opaque commit evidence cannot be constructed or token-spliced by
callers, and explicit wall time gates commit, load, immediate lease, and restart
recovery. Mismatched outcome cardinality, page binding, commit evidence, CAS
revision, or expiry fails before owner mutation. The adapter has no method that
can commit this owner state.

Reusable providers must declare these cursor, generation, rotation/drain,
acknowledgement-scope, and ownership semantics before use; the declaration is
non-secret and does not prove implementation behavior. Its nonlocal profile,
cursor schema, and routine-drain policy must match issuance and rotation, and
expired issuance results fail at explicit observed wall time;
LocalV1 lifecycle declarations, issue requests, and cursor bindings fail closed,
and no declaration enables a profile in the binder.

The adverse-control increment remains test-only: `transport-memory` can
script persistent outage, one normalized corrupt poll, digest-checked stale
replay, and acknowledgement-result loss before or after deletion. Its snapshot
contains counts and enums only. The publish-disabled conformance crate parses a
strict 64 KiB/256-step canonical trace whose aliases, relative clocks, fixture
sizes, controls, and normalized expectations contain no raw protocol or
authority bytes. Unknown, noncanonical, forward-referenced, and oversized input
fails before retention. Its first normalized runner generates fixtures only in
memory, keeps rights behind adapter aliases, compares canonical bytes exactly,
replays one trace against two fresh memory adapters, and rejects non-quiescent
adapter-reported state. It accepts only LocalV1 and rejects unbound profile
labels. A stale replay is an explicitly injected provider response and
never restores acknowledged provider-owned state. A composed verdict and
paired defective bridges exercise the retained adverse slice, and the bounded Phase 1 common verdict matrix is retained. This does not
certify a production network adapter.

Within the retained runner, exact retries reuse one mailbox/envelope-bound
receipt alias; poll normalization rejects a known receipt crossing mailbox
scope or carrying another fixture's bytes. A pending future must arrange a wake
before the bounded driver may drop it.

These checks do not prove remote rollback after ambiguous deposit,
preemptive cancellation inside a provider library, a trusted or rollback-safe
wall clock, incremental remote-response parsing, a conforming reusable mailbox
provider, durable product cursor recovery, or any network adapter. The P1-5 deterministic provider and owner model exercise the closed
positive/stale vocabulary. ADR 0025 adds exact checkpoint/authority matching,
owner-instance commit provenance, distinct live lease identities, terminal
acknowledgement invalidation, foreign-ID rejection and a 64-item/4 MiB
retention ceiling. Capacity rejects before mutation and never evicts live
deduplication history; restart invalidates prior live handles.

The first binder slice reduces local misbinding risk without granting network
authority: it accepts only LocalV1, one exact no-egress manifest/configuration
schema, coordinator-owned retries, complete local mailbox operations, no cursor
support, no background work, and in-process no-network enforcement. Unknown
versions, nonlocal profiles, broader limits, ambient egress, adapter-managed
retry, and zero binding fingerprints fail closed. The resulting record is
non-secret local evidence, not proof of adapter behavior or wire-level profile
negotiation.

Attacker story: an unauthenticated sender floods a public request mailbox with
maximum-sized objects. The service must bound per-invitation and global storage,
CPU, and outgoing work without requiring identity in Anonymous Private mode.

### Transport and metadata

Relevant attacks include direct-IP disclosure, malicious fallback, DNS or
telemetry side channels, traffic fingerprinting, active delay and replay,
malicious route selection, packet-size correlation, low anonymity sets, and
colluding operators.

Required controls include explicit profile selection, fail-closed Private mode,
network allowlisting or isolation, padding, retry jitter, bounded polling,
cover-traffic research, packet-capture tests, and conservative claims tied to a
documented deployment.

The profile and adapter are separate identifiers. Required controls also
include manifest validation, bounded operation budgets, typed redacted errors,
no generic fallback list, no ambient mailbox or network authority, and common
conformance tests. An adapter's self-description cannot satisfy a privacy
acceptance gate without external egress and packet-capture evidence.

Attacker story: the mixnet is temporarily unavailable. The client must show the
session as unavailable and must not connect to the peer or fast relay.

### Client UI and content rendering

Relevant attacks include XSS, unsafe link navigation, deceptive identity text,
clipboard leakage, notification plaintext, screen preview leakage, privileged
Tauri command abuse, and link-preview requests that expose participation.

Required controls include safe text rendering, strict content security policy,
external navigation confirmation, a narrow Tauri allowlist, no remote code,
redacted notifications, privacy-aware clipboard behavior, and no automatic
external content fetches in private profiles.

### Local storage and ephemerality

Relevant attacks include plaintext databases, weak local key derivation, key
and ciphertext colocated without OS protection, backup retention, partial
deletion, crash dumps, logs, and silent history retention.

Required controls include a documented key hierarchy, reviewed key wrapping
with factual capability reporting, encrypted databases, lock and idle behavior,
transactional deletion, log and panic redaction, backup analysis, and tests that
map implementation behavior to the selected retention policy. A stronger mode
may require OS-backed device binding or fresh user presence, but a platform name
alone does not establish either property.

ADR 0018 treats portability drift as a security risk. The baseline local vault,
storage format, failure behavior, and lifecycle must pass the same conformance
suite on macOS, Windows, and Linux before being called implemented. Native
enhancements remain isolated adapters and cannot silently alter the core format
or lower the selected policy on one platform. A missing platform implementation
blocks the feature gate; it is not deferred as a later port.

ADR 0016 and `session-storage` now make part of the client-vault proposal a
deterministic conformance boundary: sealed mode may append only bounded
canonical opaque envelopes, while decrypt, signing, admission, MLS mutation,
acknowledgement, and rotation require the exact open session. Linear vault and
inbox generations reject delayed completion and identifier-reuse ABA in the
model. ADR 0020 additionally separates provider work from lifecycle ownership:
an unlock request is bound to one process-local vault instance, exact session,
generation, and minimum policy; one shared limiter rejects excess work without
queueing; and an exact-session credential can be acquired only once. Explicit
lock, expiry polling, or a replacement generation invalidates work before
credential acquisition/provider entry when observed and makes any already
prepared result unusable. This is not encrypted or durable storage, and the
deterministic key protector is not platform protection evidence. Platform key
stores have different user-presence and unlock-sharing semantics, so production
adapters must report and test their actual behavior. Database encryption does
not establish rollback resistance, and malware controlling an unlocked session
remains out of scope.

ADR 0017's `storage-sqlcipher` adapter adds keyed, encrypted file-backed
evidence for both real owner-local MLS transactions. The inviter snapshot and
join/outbox state share one SQL commit; the joiner snapshot and exact one-time
KeyPackage deletion share another. Wrong-key, pre-commit rollback,
ambiguous-result recovery, close/reopen, and closed-file checks are retained on
the required Linux, macOS, and Windows CI runners. Schema version 2 also makes
that inviter row the sole Welcome-delivery ledger with persistent store
identity, exact canonical material, bounded attempts, generation/identity-bound
leases, a persisted attempt ceiling, and delivered/exhausted/expired terminal
states. The schema version is paired with SQLite's application `user_version`,
migration is exclusive, and retained configuration is read back on open.
Retained tests reject old-open-scope, stale, and foreign results and reconcile
an ambiguous prior adapter acceptance byte-identically after reopen. Schema
version 3 adds one opaque, versioned client-identity record; version 4 adds the
exact nonzero group binding. Creation is insert-only; reload validates the binding,
stored credential, signer/public-key match, provider/version identifiers, and
the loaded group's local member before MLS use. The durable client also rejects
creation, join, or reload for another group. Retained tests cover absence,
malformed records, replacement, cross-group use, fresh-client mismatch, and
exact close/reopen reload. The record contains signing secret material and
therefore crosses the public storage boundary only as a non-`Clone`,
non-`Debug`/non-`Display` opaque secret type and remains inside the keyed
database and outside logs, transport, and evidence output. The real capability path additionally recovers
an ambiguous SQL commit before finalizing its in-memory invitation shadow,
reopens the store, delivers once, and proves the original joiner consumes that
Welcome without a second MLS Add. The headless flows also reload Alice's exact
identity and group after close/reopen, including one graceful
independent-process exit/reload path. The test-only raw key handoff is a
mode-`0600` file where Unix supports it and is deleted on load; it is not a
vault or product credential path. This does not establish a deployable
independent-process client, platform key protector, rollback resistance,
production packaging, behavior on broader hardware/OS versions, power-loss
safety beyond the checked local L2 process-kill laboratory, or secure deletion.

ADR 0023 adds active invitation opening context and non-authorizing
authorization shadows to the SQLCipher laboratory state. The canonical signed
invitation contains the bearer
capability, and its paired HPKE private key can open requests for that exact
generation. Both are therefore high-value local secrets: issuance must commit
before publication, loading must prove their exact public/private binding, and
expiry, consumption, corruption, or missing material must make the generation
unusable without fallback regeneration. The implemented authorization shadows
retain request ID, nonce, fingerprint, verifier, and the ADR 0009 tuple for
replay/conflict recovery, but never KeyPackage bytes or provider-owned
membership authority. They abandon lost pre-membership authority after restart.
Reservation repeats opening-context restoration under its write transaction;
decode or restoration failure atomically marks the exact available generation
unusable and zeroes its opening key, including corruption introduced after an
earlier successful load.
The authorized membership transaction consumes a provider-created binding for
the exact applied KeyPackage tuple, group/epoch, Welcome, group-instance state
revision, and one-shot originating-thread write authority. An MLS-owned
provider-facing wrapper additionally fingerprints the exact serialized group
state and ordered epoch insert/update records before any caller-supplied
storage wrapper runs; SQLCipher recomputes that domain-separated SHA-256 digest
from the callback it receives. It rechecks the resulting binding with the
exact authorization and fresh monotonic elapsed time under the database write
lock, and commits the terminal authorization and invitation states atomically
with MLS and outbox state; exact
non-commit recovery that wins the lock first fences any staged writer. Store
open also rejects contradictory terminal cross-row state. The headless
admission compositions use this owner and settle their bounded in-memory
shadows only after exact durable recovery.
This contract still depends on SQLCipher confidentiality with a caller-supplied
key and remains vulnerable to stale-snapshot rollback; platform custody,
rollback detection, and secure deletion are later gates.

ADR 0019 and `key-protector-passphrase` add only a bounded portable conformance
construction, now connected to the deterministic ADR 0020 lifecycle boundary.
The fixed 102-byte record authenticates its complete public
prefix and a caller-supplied expected `SessionId`; unknown versions, suites,
profiles, parameter values, lengths, and trailing bytes fail before Argon2 work.
Wrong passphrases, record tampering, and cross-session substitution expose only
coarse failures. Passphrase size is bounded before orchestration; one shared
nonzero limiter bounds concurrent provider work before the synchronous KDF
begins.

A copied record still permits unlimited offline guesses, and Argon2id cannot
create passphrase entropy. The fixed `m=65,536 KiB`, `t=3`, `p=4` profile is a
three-OS measurement starting point, not a production parameter claim. Rust
owners apply best-effort zeroization to the passphrase, KEK, caller-owned Argon2
blocks, and temporary plaintext, but native AEAD key-schedule cleanup, registers,
swap, dumps, UI copies, and OS snapshots remain unproved. Work already running
cannot be cancelled preemptively; only a later lifecycle result may be rejected.
The exact-session protector owns only the wrapped record and consumes a
separately supplied passphrase credential once per attempt. It provides no
device binding, fresh user presence, desktop credential UI, recovery, rollback
resistance, secure deletion, SQLCipher key handoff, or unlocked-endpoint
protection, and no durable or product path currently uses it.

The current deterministic `session-storage` model rechecks the unlock deadline
after a protector returns and remains sealed when completion is late. A shared
active-generation marker prevents work that observes cancellation before
provider entry and rejects foreign-vault or stale-generation completions. Work
already inside the synchronous KDF still runs through cleanup. This is
conformance evidence for pre-entry cancellation and result discard only; it
does not prove a production scheduler, threading, process isolation, or secure
desktop-to-core credential path.

### Realm replacement and disaster recovery

Relevant attacks include DNS or TLS-account takeover being treated as realm
continuity, stale database restore, online service-key compromise gaining
long-term migration authority, capability confusion during endpoint changes,
backup retention, and a Private-mode failover to ordinary HTTPS.

The [portable-hosting design spike](spikes/client-vault-portable-hosting/proposals/portable-realm-hosting.md)
proposes separating a pinned realm identity from its current network location.
Any future implementation must keep realm configuration signatures distinct
from admission, MLS membership, and right-specific mailbox authority. Clients
must reject non-monotonic realm state, session members must authenticate active
session endpoint rotation, and loss of an offline realm root must require an
explicit new-realm trust decision rather than silent recovery.

### Retired legacy web application

The Angular/NestJS application is no longer present on the default branch. Its
historical attack classes included authentication and authorization bypass,
forged or replayed participant links, weak JWT configuration, Socket.IO input
validation, Redis state races, room enumeration, XSS through message rendering,
denial of service, secret leakage, CORS and TLS misconfiguration, and plaintext
exposure to the server.

TLS, JWT validation, and deleting a participant link after successful use were
useful controls within the legacy model, but they did not create end-to-end
encryption. New work must not revive that server-trusted architecture through a
compatibility layer. See `docs/legacy-v1/` and the `legacy-v1` tag for evidence.

### Supply chain and updates

Relevant attacks include dependency compromise, lockfile manipulation,
unreviewed cryptographic features, malicious build scripts, signing-key theft,
rollback to a vulnerable client, and unsigned or ambiguously sourced updates.

Required controls include pinned dependencies, minimal crypto dependencies,
reviewed feature sets, CI isolation, artifact signing, protected release keys,
version rollback policy, provenance, and an independent security review before
strong public claims.

## Severity Calibration (Critical, High, Medium, Low)

Severity assumes a realistic production deployment and considers content,
identity, metadata, membership integrity, affected population, exploitability,
and whether the violation contradicts a named profile guarantee.

### Critical

Critical issues generally allow broad, unauthenticated, or infrastructure-level
compromise of the product's central guarantees.

Examples:

- Rendezvous, relay, or realm infrastructure can derive MLS group keys or
  decrypt arbitrary sessions by design or through a remotely exploitable flaw.
- An unauthenticated remote attacker can forge MLS membership or authenticated
  messages across sessions.
- A signed update path permits remote arbitrary code execution across clients.
- A protocol-wide nonce, key-derivation, signature-validation, or downgrade flaw
  systematically defeats message confidentiality or membership integrity.
- The identity bridge exposes raw provider tokens for many users and permits
  account takeover at scale.

### High

High issues compromise a session or a promised privacy boundary with practical
preconditions, but are narrower than a protocol-wide failure.

Examples:

- A copied targeted invitation admits the wrong GitHub account.
- A captured admission presentation can be rebound to an attacker's session
  key.
- Removing a member fails to prevent future message decryption.
- Private mode silently connects directly or through the fast relay.
- A remotely supplied deep link achieves code execution or extracts local
  session secrets.
- The mailbox service can substitute a joiner's key without detection.
- Anonymous Private mode automatically calls an identity or telemetry endpoint
  with session-correlating data.

### Medium

Medium issues cause meaningful but bounded confidentiality, integrity,
availability, or privacy impact and normally require additional conditions.

Examples:

- Logs contain stable participant identifiers, full mailbox IDs, or admission
  presentation payloads but not private keys or message plaintext.
- A malicious joiner can exhaust one invitation mailbox until its TTL.
- Message loss or reordering causes a recoverable session desynchronization or
  duplicate user-visible messages.
- Expired ciphertext persists beyond the documented TTL without remaining
  decryption keys.
- UI wording materially overstates a credential or GitHub account proof in a
  way that can influence an approval decision.
- An external link preview leaks that a client opened a particular conversation
  in a profile not claiming full anonymity.

### Low

Low issues have limited security effect, require unusual local conditions, or
primarily weaken defense in depth without violating a core guarantee.

Examples:

- Non-sensitive operational errors reveal software versions already otherwise
  visible.
- Rate limits allow modest extra work without sustained service impact.
- A locally authenticated user can recover non-secret UI preferences after a
  session closes.
- A development-only diagnostic includes opaque identifiers but is excluded
  from production and requires explicit local enablement.
- A minor timing difference exists where the attacker lacks the observations or
  anonymity set needed to extract meaningful information.

An issue may move upward when it violates an explicit named-profile guarantee,
affects many sessions, exposes durable secrets, enables remote code execution,
or composes with an infrastructure position. It may move downward when the
necessary attacker control is absent from real deployments, only test tooling
is affected, data is already public, or independent cryptographic verification
prevents the claimed outcome.

Provenance: living repository threat model updated with ADRs 0008-0014, the
inviter-owned invitation lifecycle, the isolated MLS lifecycle, and the
accepted ADR 0015 transport boundary. Git history is the authoritative reviewed
version boundary; do not copy a commit hash forward without re-reviewing the
document against that commit.
