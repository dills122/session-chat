# Session Chat site copy

Generated from the production Astro build by `npm run dump:copy`. Edit the Astro source, not this file.

## Global navigation

SC Session Chat Private chat research
Overview
Explore ↓
Choose the level of detail.
Start with the product overview, then inspect the architecture, security evidence, or current status.
Architecture Who owns keys, decisions, storage, and delivery.
Security What is proven, missing, and impossible to promise.
Project What runs today and what comes next.
Status
Search Ctrl K
GitHub ↗

## Command palette

Search Session Chat Esc
Start Overview What Session Chat is meant to do
Start Session flow How a device joins, talks, and leaves
Technical Architecture Who owns keys, decisions, storage, and delivery
Technical Crate map How the Rust workspace implements those jobs
Evidence Security model What is proven, missing, and impossible to promise
Evidence Claim ledger Evidence status for each security property
Project Current status What can be run today
Project Roadmap What must happen before people can use it
↑↓ move ↵ open esc close

## Global footer

Temporary conversations should not require permanent accounts.
Session Chat
Architecture
Security
Project
Source ↗
MIT · Phase 1 prototype

## Page: Overview

Route: `/session-chat/`

Page title: Session Chat · Private conversations without permanent accounts

Meta description: Session Chat is an experimental system for temporary, end-to-end encrypted conversations between two people without permanent chat accounts.

Phase 1 laboratory complete
The encrypted join and messaging flow runs in tests and a command-line demo. There is no installable app or online service yet. Do not use it for real conversations.
# Private conversations without permanent accounts.
Session Chat is being built as a temporary, encrypted room for two people. One person creates the room, shares a private invitation, approves the other device, and ends the session when the conversation is over.
See the session flow
Inspect current evidence
Current profile Prototype
Participants — 2 devices
Access — private invitation + approval
Encryption — MLS 1.0
Join proof — one-shot HPKE
Delivery — local test adapter
Interface — command-line demo
## How one conversation moves through the system.
Creating an invitation, approving a device, adding it to the encrypted group, delivering messages, and ending the session are separate actions. A copied link or compromised service should not gain all of those powers at once.
- 1.0 · invite
### Alice creates a short-lived invitation.
The signed invitation tells Bob how to ask for access, but it does not contain the conversation keys. Its capability is the secret value that grants the right to make that request, so Alice must share it privately.
Boundary `InvitationDescriptor`
- 2.0 · request
### Bob asks to join with one exact device key.
His request is tied to the invitation and to one exact MLS KeyPackage: the public cryptographic material for that device. Replaying the request or substituting another key must fail.
Current evidence `RFC 9180 PSK open`
- 3.0 · approve
### Alice reviews the request and chooses.
A valid proof shows that the request matches the invitation and device key. It does not prove Bob is trustworthy or add him to the group. The prototype simulates Alice’s decision because the approval screen is not built yet.
Authority `ApprovalContext ≠ membership`
- 4.0 · join
### The encrypted group adds only the approved device.
Messaging Layer Security (MLS) consumes the approved KeyPackage once, adds that device, and creates its encrypted Welcome message. The invitation protects first contact; MLS protects group membership and later messages.
Current evidence `Add → Commit → Welcome`
- 5.0 · talk
### Transport carries encrypted envelopes, not chat text.
A transport can move data but cannot approve a person or add a device. The current adapter only runs in memory and tests loss, duplication, delay, reordering, retry, expiry, and separate mailbox rights.
Current limit `no network transport`
- 6.0 · end
### Removing a device blocks it from future messages.
The in-memory MLS test proves that a removed device cannot derive later message keys. A future app may delete its own keys and stored copies, but it cannot erase plaintext that another participant saved.
Current evidence `remove → update → reject`
## What the design protects—and what it cannot.
Message encryption, identity evidence, network privacy, and local deletion solve different problems. The product must explain each guarantee on its own.
### Target protections for the finished product
- Keep message content hidden from mailbox, relay, and realm services.
- Stop copied invitations or substituted device keys from silently changing membership.
- Never let Private mode silently fall back to a more revealing transport.
- Use a new cryptographic identity for each session instead of a permanent chat identity.
- Limit how much parsing, storage, retry, and unauthenticated work hostile input can trigger.
### Limits that remain
- A participant can copy, export, photograph, or screenshot plaintext.
- Malware controlling an unlocked device can read what the user can read.
- Proof that someone controls an account does not prove they are trustworthy.
- Different transport modes expose different amounts of IP, timing, and volume metadata.
- A network or service operator can still refuse or disrupt service.
Check the evidence behind each claim.
The repository marks each property as implemented and tested, required but unimplemented, proposed, deferred, or out of scope. This site uses the same evidence states.
Read the security model →

## Page: Architecture

Route: `/session-chat/architecture/`

Page title: Architecture · Session Chat

Meta description: How Session Chat keeps conversation keys, access decisions, mailboxes, and message delivery under separate authorities.

Architecture
# The clients keep the keys. Each support service gets one narrow job.
Clients own the session keys and decide membership. Identity providers supply evidence, mailboxes hold bounded ciphertext, and transports carry encrypted envelopes. Replacing one service should not change the authority of another.
## Three services support the conversation without owning it.
Each boundary exposes only the authority needed for one job, even when a provider or transport changes.
Client-owned authority
### Session protocol core
Creates and expires invitations, approves exact device keys, owns MLS group state, rejects replay, and manages local encrypted state.
Evidence
### Admission
Checks whether one exact device key may be considered. The prototype supports private capability invitations; other evidence types come later.
`may approve one KeyPackage`
Storage edge
### Rendezvous mailbox
Temporarily stores bounded ciphertext in mailboxes addressed by separate secret capabilities.
`may retain ciphertext`
Network edge
### Envelope delivery
Moves opaque encrypted envelopes. The current adapter is local; real Fast and Private network profiles come later.
`may move opaque bytes`
## A join request passes through five guarded steps.
Each step owns the exact value it checked. A later caller cannot swap the device key or treat successful delivery as proof of membership.
- 1.0 · parse
### Reject bad input before it reaches state.
Oversized, malformed, non-canonical, unknown-version, expired, or context-mismatched objects stop here.
Owner `session-protocol`
- 2.0 · verify
### Tie the proof to one invitation and one device.
The verifier owns the exact parsed KeyPackage and checks its invitation, challenge, replay context, credential identity, leaf key, version, and ciphersuite.
Owner `admission-capability`
- 3.0 · decide
### Show Alice enough evidence to approve or reject.
The approval view cannot add a member. The provider keeps the proof, replay reservation, and exact one-shot MLS input.
Seam `session-admission`
- 4.0 · commit
### Add the approved device once.
The MLS adapter consumes the approved value, creates Add and Welcome, advances the group, and later protects messages, updates, and removal.
Owner `session-crypto-mls`
- 5.0 · deliver
### Retry delivery without adding the device twice.
The accepted design commits the MLS snapshot, replay state, consumed invitation, decision, and encrypted Welcome outbox as one transaction. The product path does not implement that durable transaction yet.
State `accepted contract`
## Each mailbox key grants one action.
Deposit, receive, acknowledge, and rotate use separate capabilities. Knowing a delivery identifier never grants permission to delete it.
Deposit — Place one bounded opaque envelope into the addressed mailbox.
Cannot read, acknowledge, or rotate.
Receive — Read a bounded batch from one mailbox under the selected profile.
Cannot deposit, delete, or rotate.
Acknowledge — Confirm or delete the relevant delivery scope.
Cannot receive new objects or rotate.
Rotate — Change continuity for a reusable network mailbox.
Never supplied to normal delivery calls.
## How the Rust code maps to those jobs.
Each crate implements a narrow protocol or storage boundary. The names below describe tested laboratory components, not a finished security product.
Wire + lifecycle — `session-protocol` · `session-core`
implemented in memory
Admission — `session-admission` · `admission-capability` · `session-crypto-hpke`
capability profile only
Group security — `session-crypto` · `session-crypto-mls`
two-party lifecycle
Delivery — `session-transport` · `transport-memory`
no network adapter
Transactions + storage — `session-inviter-transaction` · `session-storage` · `storage-sqlcipher`
separate laboratories
Headless composition — `sessionctl`
retained integration evidence
Use the architecture document for exact contracts.
This page provides the mental model. The repository document defines the detailed invariants, object contracts, and current evidence boundary.
Open architecture ↗

## Page: Security

Route: `/session-chat/security/`

Page title: Security model · Session Chat

Meta description: A plain-language ledger of what Session Chat proves today, what remains unimplemented, and which risks encryption cannot remove.

Security model
# What is proven today—and what is still only a design.
The repository is ready for architecture and protocol review. It is not ready to protect real conversations because it has no production client, integrated durable state, network service, or hosted realm.
## Read every security claim with its evidence status.
“Implemented and tested” describes a bounded laboratory result. It does not mean the complete product or deployment is secure.
Invitation and join formats — Versioned, size-bounded formats reject malformed, expired, unknown, and context-mismatched input before state changes.
Implemented + tested
Private invitation proof bound to one device — A one-shot HPKE check ties the exact signed invitation to one exact MLS KeyPackage, reserves replay values, and records a simulated approval decision.
Implemented + tested
Two-device MLS lifecycle — The in-memory adapter adds a device, exchanges protected messages in both directions, updates the group, removes the device, and tests replay and reordering.
Implemented + tested
Local delivery under faults — Separate deposit, receive, and acknowledgement rights are tested under deterministic loss, duplication, delay, reordering, retry, expiry, and bounds.
Implemented + tested
Durable product join transaction — Approval, replay, invitation consumption, MLS state, and encrypted Welcome outbox must commit as one recoverable owner-local transaction.
Required, not integrated
Production vault and desktop client — The common macOS, Windows, and Linux baseline needs reviewed key protection, a selected shell, safe deep links, updates, and packaging.
Required, unimplemented
Network and metadata-private delivery — Fast and Private profiles need real adapters, egress isolation, packet captures, operational evidence, and explicit unavailability behavior.
Later roadmap phases
GitHub and portable credential admission — Designed behind the same exact KeyPackage binding, but intentionally kept out of the Phase 1 capability-only laboratory.
Later roadmap phases
## Assume every input and supporting service can be hostile.
Invitations, links, envelopes, provider responses, mailbox objects, storage, and network input remain untrusted until the component responsible for them validates them.
### Threats included in the design
- A malicious or compromised participant before and after admission.
- A curious or compromised realm, mailbox, relay, or transport operator.
- A network adversary that delays, drops, reorders, duplicates, injects, or observes.
- A supply-chain attacker targeting dependencies, builds, updates, or signing credentials.
- A deceptive identity or credential ecosystem that produces technically valid but misleading evidence.
### Required behavior
- Reject ambiguity, expiry, replay, substitution, and unknown suites before mutation.
- Bound storage, parsing, retries, queues, and unauthenticated work.
- Keep plaintext, keys, capabilities, raw tokens, and stable identity out of transport and logs.
- Fail closed when a private transport is unavailable.
- Make every visible guarantee match retained evidence.
## Encryption protects message content, not every trace of a conversation.
Identity, network metadata, device security, and message retention each have different observers and failure modes.
A private message can still leave metadata.
A direct peer may learn the other peer’s IP address. A relay may observe endpoints, timing, and volume. A mixnet can reduce correlation but adds latency, loss, and deployment assumptions. None of those layers may read MLS content, but they do not provide the same privacy.
The device can still expose the message.
Session Chat cannot stop a participant from saving plaintext or protect an unlocked device controlled by malware. Ephemeral deletion can remove only Session Chat’s own retained copies and cryptographic access, not copies on another person’s device.
See the release gates →
Use source-backed evidence for real decisions.
The independent-audit brief is the canonical index for code-backed evidence, required but unimplemented contracts, proposed experiments, deferred work, and explicit non-goals.
Open audit brief ↗

## Page: Project

Route: `/session-chat/project/`

Page title: Project status · Session Chat

Meta description: What can be run in Session Chat today, what is still missing, and the evidence gates before a usable desktop product.

Current project status
# Today: a command-line protocol demo, not a chat app.
Phase 1 laboratory work is complete: the headless two-person flow, hostile inputs, deterministic delivery faults, and encrypted SQLCipher recovery passed the Linux, macOS, and Windows gate. Product key custody, a human approval screen, desktop packaging, and reusable network transports remain later work.
## What you can run today.
The `sessionctl` command runs an Alice-and-Bob flow through the composed laboratory components and deterministic local transport.
Create → protect → approve → join → message → update → remove.
`sessionctl` creates a private capability invitation, protects Bob’s join request, records a simulated approval, delivers the MLS Welcome, exchanges protected messages in both directions, updates the group, removes Bob, and confirms that Bob’s post-removal access is rejected.
The independent-process runner and checked fault suites also retain restart and Welcome-delivery recovery evidence. The
Phase 1 evidence matrix
records the exact tested revision and the remaining product, physical-durability, and platform-key limits.
Protocol objects — Canonical envelopes, invitation v1/v2, protected join framing, exact AAD, and local deposit endpoint.
bounded fixtures retained
Admission path — HPKE provenance, exact KeyPackage ownership, durable laboratory replay reservation, local invitation binding, and simulated approval.
laboratory composition
MLS path — Two-member Add/Welcome, protected messages, update, removal, replay, and reordering behavior.
isolated adapter
Delivery path — Right-specific local Welcome mailbox and a deterministic adverse memory transport.
not networked
Storage evidence — Composed SQLCipher transaction and process-recovery evidence; separate sealed-vault and passphrase-wrapper laboratories.
laboratory only
Platform baseline — Workspace build, lint, and test matrix on Linux, macOS, and Windows CI.
CI gate active
## What must happen before people can use it.
This roadmap shows the proposed order of evidence, not delivery dates. Completing one laboratory phase does not prove the whole product is ready.
Phase 1
Protocol prototype — Capability invitation access, two-party MLS, hostile input handling, deterministic delivery faults, and process recovery passed the three-platform laboratory gate.
complete
Validation track
Product understanding — Test whether people understand the difference between account proof and trust, verification and approval, device changes, and Fast versus Private network metadata.
before UI selection
Phase 2
Identity independence — Add GitHub control evidence through a minimal bridge while the capability path continues to work unchanged.
planned
Phase 3
Rendezvous + fast delivery — Opaque capability mailboxes, offline delivery, bounded service behavior, a fast direct/relay adapter, and self-hosted realm deployment.
planned
Phase 4
Desktop client — A selected shell around the Rust core, one macOS/Windows/Linux baseline, safe deep links, visible evidence, text chat, and honest retention controls.
planned
Phase 5–6
Privacy + credentials — Private transport experiments and one interoperable credential-admission boundary under the same envelope and KeyPackage contracts.
experimental
Phase 7
Hardening + review — Fuzzing, release provenance, signed updates, dependency review, endpoint and network evidence, operated disclosure, and independent security review.
release gate
## How to contribute without overstating progress.
Keep changes small, test failure cases at every untrusted boundary, and make documentation say exactly what the tests prove.
### Start with the review package
- Read the independent-audit brief and exact claim states.
- Inspect the relevant ADR before changing a boundary.
- Run the smallest relevant test, then the complete gate.
- Add malformed, expired, replayed, reordered, and unauthorized cases where they apply.
Open the repository ↗
### Keep the first product small
- Two participants.
- Capability admission before provider identity.
- Text before attachments, voice, or video.
- One common desktop baseline before platform-specific claims.
- No private-mode fallback that changes the guarantee.
