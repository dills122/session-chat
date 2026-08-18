# Session Chat 2.0 independent-audit brief

Status: architecture and protocol-laboratory review package

This brief is the entry point for an independent review of Session Chat 2.0.
It deliberately separates code-backed evidence from accepted design contracts,
research proposals, and deferred work. It is suitable for an architecture and
protocol review now. It is not a request to certify a production application,
because no production client, MLS integration, durable store, network service,
or deployable realm exists.

An auditor should record the exact Git commit, parent or comparison base,
`Cargo.lock` digest, enabled Cargo features, and tool versions used for the
review. Git history is the authoritative snapshot; this living document does
not embed a revision that would become stale on its next edit.

## Claim states

Every claim in this package has one of these states:

| State | Meaning |
| --- | --- |
| **Implemented and tested** | Present in retained code with deterministic evidence. |
| **Accepted contract, unimplemented** | Required by an accepted ADR or normative design contract, but absent from runtime code. |
| **Proposed experiment** | Research-backed recommendation that still needs a spike and decision record. |
| **Deferred** | Deliberately outside the current phase. |
| **Out of scope** | Not promised, including resistance to a compromised unlocked endpoint or a participant copying plaintext. |

Document-level headings such as “proposed architecture” do not override these
per-claim states. “Opaque” means content-agnostic framing, not encryption.
Method names such as `reserve_after_admission` and `consume_after_membership`
state caller preconditions; the current crate does not verify admission or
perform MLS membership changes.

## Current system in one page

The checked-in runtime consists of:

- `session-protocol`: bounded, canonical opaque-envelope framing and a
  canonical, signed, secret-capability invitation descriptor;
- `session-core`: an inviter-owned, in-memory invitation registry with
  issue/expiry, reservation, release, and consumption transitions; and
- a disposable Node.js sealed-post-office simulator used only to test boundary
  semantics such as schema rejection, right-specific authorization ordering,
  rotation, and capacity limits.

There is no join request, capability-proof verifier, HPKE, MLS group, durable
transaction, production transport, client vault, desktop shell, hosted realm,
or headless end-to-end client. OpenMLS is selected for a bounded future
laboratory, but its current provider graph is blocked by repository dependency
policy and is not a workspace dependency. The Node simulator's custom
composition of platform crypto and placeholder address control is explicitly
non-production.

```mermaid
flowchart LR
  I["Implemented: canonical invitation"] --> R["Implemented: in-memory lifecycle"]
  E["Implemented: bounded opaque envelope"]
  N["Non-production Node boundary simulator"]
  R -. future .-> A["Admission owns exact validated KeyPackage"]
  A -. future .-> M["MLS Add / Commit / Welcome"]
  M -. future .-> T["Right-specific transport"]
  M -. future .-> V["Atomic durable state and sealed vault"]
  T -. proposed .-> H["Portable self-hosted realm"]
```

## Claims and evidence ledger

| Property | State | Evidence or condition |
| --- | --- | --- |
| Opaque envelope has a versioned canonical encoding and an input-size bound | Implemented and tested | `session-protocol` fixtures and malformed/oversized negative tests |
| Opaque envelope bytes are encrypted | Not established | Current fixture can contain literal plaintext bytes; future HPKE/MLS producers must establish confidentiality |
| Secret-capability invitation is canonical, strictly Ed25519-verified, time-bounded, and signed over all accepted fields | Implemented and tested | ADRs 0005/0007, signed-invitation fixtures and negative tests |
| Invitation reservation is tied to the exact record instance, including expiry/reissue with reused invitation and request IDs | Implemented and tested | `InvitationReservation.record_signature` and stale release/consume regression tests |
| Invitation state is durable or rollback resistant | Accepted contract, unimplemented | ADR 0008 and the roadmap require a later cross-layer transaction |
| Admission owns the exact validated MLS KeyPackage, credential identity, and leaf signature key | Accepted contract, unimplemented | ADR 0009; no admission crate or MLS dependency exists |
| MLS membership, forward secrecy, post-compromise security, and removal isolation | Accepted contract, unimplemented | ADR 0011 selects OpenMLS for evaluation; integration is blocked by the provider dependency-policy result |
| Welcome delivery is idempotent and atomic with MLS, replay, approval, and invitation state | Accepted contract, unimplemented | Architecture transaction invariant; no durable store exists |
| Deposit, receive, acknowledge, and rotate rights are non-interchangeable | Accepted contract plus simulator evidence | ADR 0010; Node tests do not establish a production transport |
| Unknown, cyclic, accessor-backed, symbol-keyed, deep, or oversized provider input fails before cloning or authorization | Non-production simulator evidence | Retained Node adversarial tests at directory and attestor entry points |
| Client secrets are sealed when not in an active user-approved session | Proposed experiment | Session-scoped vault proposal with whole-store fallback; no dependency selected |
| A realm can be replaced without giving its operator content or membership authority | Proposed experiment | Compose and signed-realm-descriptor proposal; no service exists |
| GitHub and credential admission, recovery, multi-device, mixnets, and federation | Deferred | Later roadmap phases |

## Intended architecture and authority boundaries

Session security, admission, rendezvous, and transport are independent layers.
No layer inherits authority merely because it carries another layer's bytes.

- MLS membership, not transport delivery, authorizes participation in a group.
- Admission proves authorization for one exact proposed member key; it neither
  adds that member nor grants mailbox rights.
- Invitation possession permits only the versioned invitation flow and never
  implies a stable external identity.
- Directory or address-attestor signatures bind routing material but do not
  grant receive, acknowledgement, rotation, admission, or MLS authority.
- Deposit, receive, acknowledgement, and rotation capabilities are distinct.
- A realm operator may control availability and observe profile-specific
  metadata. It must not receive client plaintext or MLS group secrets.
- Private transport must fail closed instead of silently using a faster,
  less-private path.

The future join path is conditional on one ownership chain:

1. Bound and parse an untrusted canonical join request.
2. Verify its proof over the invitation, challenge, verifier audience, exact
   KeyPackage, credential identity, leaf key, expiration, and replay context.
3. Return a linear `VerifiedAdmission` that owns the parsed KeyPackage.
4. Obtain explicit inviter approval and reserve the invitation instance.
5. Use that same owned object for MLS Add/Commit; no caller may substitute bytes
   or a separately supplied digest.
6. Atomically persist MLS state, replay state, approval/result, invitation
   consumption, and an encrypted idempotent Welcome outbox item.
7. Release the reservation on pre-commit failure; after commit, resume delivery
   without replaying membership.

Only two crash-recovery outcomes are acceptable: uncommitted and safely
releasable, or committed and consumed with resumable Welcome delivery.

## Data and trust-boundary inventory

| Component | Allowed input/state | Must never receive or retain |
| --- | --- | --- |
| UI/webview | Redacted display models, explicit user decisions | Vault roots, database keys, MLS secrets, raw provider tokens, unrestricted mailbox capabilities |
| Session core | Validated protocol objects and narrowly owned capabilities | Unbounded or side-effecting decoded input |
| Future MLS adapter | Session credential/key material, exact admitted KeyPackage, group state | Stable external identity as an MLS identity claim |
| Future admission adapter | Minimum evidence needed for the invitation policy | Reusable provider tokens after verification, unrelated identity fields |
| Directory | Public or recipient-authorized routing bundle and freshness data | Conversation plaintext, MLS secrets, receive or membership authority |
| Sealed mailbox | Bounded opaque items and one exact right per operation | Plaintext, group keys, interchangeable rights, stable sender identity by default |
| Fast/private transport | Opaque encrypted envelopes and profile-required routing metadata | Admission authority or an implicit profile downgrade |
| Realm operator | Service policy, public descriptor, role-scoped service keys, operational metadata | Client vault keys, MLS group keys, plaintext, offline root in online services |
| Logs/telemetry/crash reports | Bounded redacted operational events | Invitations, capabilities, tokens, plaintext, keys, raw protocol objects |
| Backups | Versioned encrypted state required by an explicit recovery policy | Decrypted client state or a path that silently restores stale MLS state |
| Build/update system | Source, lockfiles, immutable action references, signed release inputs | Long-lived credentials in logs or untrusted pull-request execution |

## Cryptographic inventory

Implemented dependencies are pinned in `Cargo.toml` and `Cargo.lock`:

- `ed25519-dalek` 3.0.0 with strict verification for invitation signatures;
- `minicbor` 2.3.0 for the restricted deterministic CBOR profile; and
- `zeroize` 1.9.0 for best-effort clearing of owned secret buffers.

Selected but unimplemented candidates are OpenMLS 0.8.1 and
`openmls_rust_crypto` 0.5.1 with the RFC 9420 mandatory-to-implement
X25519/AES-128-GCM/SHA-256/Ed25519 ciphersuite. The
[applicability map](research/OPENMLS_0_8_1_APPLICABILITY.md) reviews all eight
published findings, the selected provider boundary, and the newer advisory set
that blocks retaining the resolved graph. The published OpenMLS review did not
cover its crypto or storage providers, left one Low issue unresolved at
publication, and is not inherited assurance for Session Chat.

HPKE, encrypted storage, OS key protectors, realm signing, and signed updates
have not been selected. Citations in the reference ledger are research inputs,
not dependency decisions.

## Conditional target guarantees

These are release gates, not present-tense promises:

| Target claim | Required evidence before the claim is allowed |
| --- | --- |
| Content confidential from infrastructure | Interoperable MLS/HPKE vectors, negative tests, packet/storage inspection, and no server-held content keys |
| Only approved members participate | Exact KeyPackage admission ownership, explicit approval, MLS membership tests, replay rejection, and cross-layer transaction evidence |
| Removed members cannot read future messages | Deterministic removal/epoch tests plus persistence and reordered/lost-message tests |
| Compromise recovery | Key updates and epoch advancement tested against the stated MLS compromise model; endpoint compromise limitations remain explicit |
| Ephemeral local state | Retention policy, deletion/backup/swap/notification tests, and honest recipient-copy language |
| Locked client data is unusable | Per-platform vault conformance, sealed-operation matrix, memory/IPC/crash-dump checks, and rollback analysis |
| Private profile does not downgrade | Network-deny integration tests, dependency traffic inventory, packet captures, and explicit failure UX |
| Metadata-private or anonymous operation | Named observer and non-collusion assumptions, measured traffic, anonymity-set requirements, and abuse controls |
| Replaceable self-hosted realm | Digest-pinned deployment, scoped service keys, tested restore/migration, signed monotonic discovery, and explicit trust-reset behavior after root loss |
| Production-ready software | Independent implementation review, operated vulnerability response, signed reproducible updates, release provenance, platform tests, and all roadmap gates |

## Storage, rollback, deletion, and recovery questions

Encryption at rest does not prove freshness. The future persistence design must
test every write boundary involving MLS state, invitation consumption, replay
records, approval, and Welcome delivery. Copies, backups, database pages, swap,
notifications, and crash reports are within the deletion boundary.

The proposed vault permits only bounded opaque receipt and non-sensitive
settings while sealed. Decrypt, sign, admission, MLS mutation,
acknowledgement, and capability rotation require the relevant session to be
unsealed with user presence. A whole-device snapshot can still roll encrypted
state back; a monotonic anchor remains an open research question. Recovery and
multi-device synchronization are deferred because they can undermine deletion,
device continuity, and forward-secrecy assumptions.

## Hosting and disaster-recovery questions

The proposed first deployment is a one-host, digest-pinned Compose appliance
with automatic TLS, scoped secrets, durable storage, and tested restore. The
next design level separates stable realm identity from DNS and any one host with
an offline-root-signed, monotonic realm descriptor and online role keys. Active
session endpoint rotation remains member-authenticated and right-specific.

Host loss may cause availability loss. A planned migration may preserve a
pinned realm only through a newer valid descriptor. Loss of the offline root
requires an explicit new-realm trust decision; DNS or TLS alone must not
silently re-establish continuity. None of this is implemented today.

## Recommended audit stages

1. **Now — architecture and protocol contracts:** assess layer separation,
   authority, invitation state, canonical formats, threat completeness, and
   feasibility of the accepted future invariants.
2. **After the MLS and durable-state increments — implementation review:**
   assess the crypto provider, exact KeyPackage ownership, Add/Commit/Welcome,
   removal, storage calls, crash injection, rollback, and deletion.
3. **After the first client and hosted vertical slice — endpoint/network review:**
   assess the vault, IPC/UI privilege boundary, updates, platform artifacts,
   packet captures, deployment, operations, and disaster recovery.

High-value questions for the current review include:

- Can the selected OpenMLS provider participate in the required single
  application transaction without split-brain membership or Welcome state?
- Is the proposed linear ownership API sufficient to prevent KeyPackage,
  credential, or leaf-key substitution at every seam?
- Which monotonic anchor can reject stale device or database snapshots without
  creating a new availability or tracking oracle?
- Can any directory, realm root, redirect, or transport component acquire a
  right it did not already possess?
- Are the clock, expiry, replay, reservation, and restore rules fail closed?
- Are the proposed observer and non-collusion assumptions strong enough for
  each Fast, Private, or future Anonymous label?
- Can build dependencies or signed updates bypass all endpoint guarantees?

## Near-term research and implementation sequence

The recommended next bounded feature remains an isolated two-party
`session-crypto-mls` laboratory, but the selected provider graph must first pass
the repository's advisory and GitHub dependency-review gates without broad
exceptions. The audit/provider applicability map is retained. Stop if the exact
validated KeyPackage cannot remain owned through the future admission/Add seam,
or if provider-write behavior makes the required transaction infeasible.

The next decision-producing research tasks are:

1. OpenMLS provider release or replacement that clears the dependency policy.
2. RFC 9180 HPKE library, suite, context-label, schema, and vector comparison.
3. OpenMLS `StorageProvider` call trace and cross-layer crash/rollback model.
4. Parser fuzzing and invitation/admission state-machine property-test plan.
5. RNG and clock-source contracts for expiry, replay, and deterministic tests.

Then implement, in order: the isolated MLS lifecycle; the canonical capability
proof and linear admission contract; the HPKE join-request contract;
right-specific adverse in-memory transport; the headless in-memory flow; and
only then durable persistence and a networked/client vertical slice.

GitHub/credential admission, OHTTP, Privacy Pass, desktop-framework selection,
mixnets, recovery, and federation should not interrupt the capability-only
in-memory Phase 1 path.

## Reproduction and evidence index

Run from a clean checkout of the exact revision under review:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
node --test scripts/setup-codex-links.test.mjs
node --test spikes/sealed-invitation-provider/test/provider.test.mjs
git diff --check
```

Relevant source documents:

- [`PRODUCT_V2.md`](PRODUCT_V2.md): conditional product outcomes and non-goals
- [`ARCHITECTURE_V2.md`](ARCHITECTURE_V2.md): components, dependency direction,
  join transaction, and current implementation boundary
- [`IDENTITY_AND_ADMISSION.md`](IDENTITY_AND_ADMISSION.md): evidence and exact
  member-key binding
- [`TRANSPORTS.md`](TRANSPORTS.md): profiles, rights, metadata, and no-downgrade
- [`THREAT_MODEL.md`](THREAT_MODEL.md): assets, adversaries, mitigations, and
  residual risk
- [`ROADMAP_V2.md`](ROADMAP_V2.md): phase gates and exclusions
- [`RESEARCH_BACKLOG.md`](RESEARCH_BACKLOG.md): unresolved decisions
- [`REFERENCES.md`](REFERENCES.md): standards and primary research inputs
- [`adr/`](adr/): accepted decisions and their scope
- [`specs/SIGNED_INVITATION_V1.md`](specs/SIGNED_INVITATION_V1.md): implemented
  invitation wire and caller-precondition limits
- [`spikes/SEALED_INVITATION_PROVIDER_PROTOCOL.md`](spikes/SEALED_INVITATION_PROVIDER_PROTOCOL.md): non-production first-contact contract
- [`spikes/client-vault-portable-hosting/hardening.md`](spikes/client-vault-portable-hosting/hardening.md): proposed vault and realm options

CI demonstrates only the commands and policies it actually runs. Repository
settings such as required checks, branch protection, secret scanning, and
private vulnerability reporting require separate GitHub configuration evidence.
