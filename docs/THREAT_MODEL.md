# Session Chat repository threat model

Status: design baseline for the v2 architecture and protocol laboratory

## Overview

Session Chat is a privacy- and security-sensitive messaging project. The active
repository contains a headless Rust protocol laboratory and design artifacts;
it does not yet contain a deployable client or network service. The laboratory
currently has a bounded opaque envelope, a canonical domain-separated Ed25519
secret-capability invitation, exhaustive fixed-field rejection fixtures, and a
bounded inviter-owned invitation reservation/consumption state machine. It
does not yet encrypt join requests, prove capability possession, approve a
member, operate MLS, or persist rollback-resistant state. The retired v1
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
and the inviter-owned `Available -> Reserved -> Consumed` lifecycle, with a
release edge from `Reserved` back to `Available` rather than a stored
`Released` state.
Descriptor validation is read-only and remote self-signed objects cannot create
registry state. Reservation authority is bound to the exact signed local record,
so it cannot cross an expiry/reissue boundary even if invitation and request IDs
recur. Random generation quality, durable atomic consumption with MLS,
rollback protection, deep-link leakage, fuzzing, HPKE, and admission proof
implementation remain open.

Attacker story: an attacker copies a public targeted invitation and submits a
validly encoded join request for their own key. Correct behavior is a policy
mismatch or explicit rejection, not membership.

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

Required controls include a documented key hierarchy, OS-backed key wrapping,
encrypted databases, lock and idle behavior, transactional deletion, log and
panic redaction, backup analysis, and tests that map implementation behavior to
the selected retention policy.

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

Provenance: living repository threat model updated with ADRs 0008-0011 and the
inviter-owned invitation lifecycle. Git history is the authoritative reviewed
version boundary; do not copy a commit hash forward without re-reviewing the
document against that commit.
