# Research backlog

Status: open

This file records questions that should be answered before implementation or a
corresponding product claim. Completing research does not automatically adopt a
technology; conclusions should update the relevant design document and, for
foundational changes, an ADR.

## Prioritization

- **P0** blocks the protocol or threat model.
- **P1** blocks a product profile or first implementation.
- **P2** is useful exploration after the core is proven.

## Cryptographic protocol

### Decision recorded: MLS implementation selection

- ADR 0012 selects exact `mls-rs` 0.56.0 and `mls-rs-crypto-awslc` 0.25.0
  versions, the RFC 9420 mandatory-to-implement ciphersuite, and a reduced
  non-FIPS feature set for a bounded Phase 1 integration spike. ADR 0011
  retains the rejected OpenMLS 0.8.1 evaluation.
- ADR 0009 defines the BasicCredential, leaf signature key, and KeyPackage
  binding that admission must authenticate.
- The `mls-rs` selection does not resolve durable cross-layer atomicity. It
  exposes an explicit group-state write, but joining-client KeyPackage deletion
  uses a subsequent repository call. Session Chat must transact both with
  invitation consumption, replay state, approval/result state, and Welcome work.
- The May 2026 SRLabs audit left one Low-severity issue unresolved at
  publication. The
  [applicability map](research/OPENMLS_0_8_1_APPLICABILITY.md) records all eight
  findings against the exact 0.8.1 tag. It also records a newer locked HPKE and
  libcrux advisory set that blocks adding the selected provider to the
  workspace under the current dependency policy.
- The OpenMLS audit excluded cryptographic and storage providers and does not
  transfer to `mls-rs`. Upstream states that `mls-rs` has not received a full
  independent third-party audit. Review the selected AWS-LC provider boundary,
  the protocol adapter, and the Session Chat storage adapter as separate scopes.
- Confirm how KeyPackages, Welcome messages, epoch state, and pending Commits
  are stored and recovered.
- **Isolated evidence retained:** `session-crypto-mls` now covers removal, a
  path update, out-of-order application delivery, a temporarily lost epoch
  Commit, abandoned pending Commits, and explicit-only group-state writes.
  Durable recovery, joining-KeyPackage deletion, and cross-layer atomicity are
  still open.

Immediate gate: retain the isolated ADR 0012 laboratory with exact KeyPackage
ownership, two-party lifecycle, removal, reordered/lost message, and
interoperability fixtures. The lifecycle portion is implemented; independent
cross-implementation fixtures remain open. Before a durable or networked path,
add the transactional storage, crash, rollback, deletion, and pending-Commit
evidence required by ADR 0012.

### P0: invitation protocol

- **Encoding decision:** ADR 0005 selects a restricted RFC 8949 deterministic
  CBOR profile and exact wire fixtures.
- **Signature decision:** ADR 0007 selects `ed25519-dalek` 3.0.0 strict Ed25519
  verification and the `session-chat/signed-invitation/v1` application domain
  for the secret-capability descriptor. HPKE domain separation remains open.
- **Implemented boundary:** version 1 is single-use, uses explicit issue and
  expiration times, accepts realm-configured maximum lifetime and future skew,
  and models the inviter-owned lifecycle in ADR 0008. Descriptor validation is
  read-only; durable cross-layer transactions remain open.
- Select the HPKE suite and encrypted join-request schema.
- Implement durable transactional replay state, rollback protection,
  revocation, reservation recovery, and bounded-multi-use state machines.
- Define the capability-proof wire schema over the exact ADR 0009 binding.
- Decide public, encrypted, and local-only fields for targeted GitHub and
  credential invitations. The current capability descriptor is a secret bearer
  object and is not publicly postable.

Expected output: wire-format draft plus test vectors.

### P1: cryptographic agility

- Determine which algorithm identifiers are required in persisted objects.
- Define rejection rules for unsupported and downgraded suites.
- Plan migrations without advertising unsupported post-quantum guarantees.

## GitHub identity

### P0: GitHub App and OAuth flow

- Confirm GitHub App versus OAuth App behavior for desktop clients.
- Confirm authorization-code with PKCE and callback/deep-link constraints.
- Define minimum scopes for stable account ID, organization, team, repository,
  and collaborator claims.
- Determine which claims require organization installation or approval.

### P0: attestation format and bridge trust

- Decide whether the bridge issues a project-specific signed object, a
  verifiable credential, or both.
- Define bridge key rotation, issuer discovery, revocation, and audit behavior.
- Define how self-hosted realms trust one or more bridges.
- Model a malicious or compromised bridge issuing a false account binding.

### P2: bridge-free GitHub proof

- Evaluate signed commit or tag challenges.
- Determine usability, signature-policy ambiguity, replay handling, and account
  key discovery limitations.

## Verifiable credentials and SSI

### P1: presentation interoperability

- Evaluate OpenID4VP wallet support on desktop and mobile.
- Select the smallest initial credential format and securing mechanism.
- Define holder binding to a fresh session member key.
- Define verifier identity and cross-device presentation flows.

### P1: trust and status

- Define issuer allowlists or trust frameworks.
- Compare status-list, short-lived credential, and online-validation designs.
- Measure correlation introduced by status retrieval and issuer metadata.
- Determine how organization revocation propagates to offline clients.

### P2: unlinkable and predicate proofs

- Track BBS cryptosuite standardization and interoperable implementations.
- Compare BBS, one-time credentials, pairwise identifiers, and other
  privacy-preserving presentations.
- Test whether non-cryptographic metadata defeats claimed unlinkability.

### P2: DID method evaluation

- Determine whether any use case actually requires a DID.
- If so, compare resolution availability, privacy, key rotation, recovery,
  registry dependence, and offline verification.
- Do not choose a DID method merely to label the system SSI-compatible.

## Transport and rendezvous

### Spike completed: sealed invitation post office

- See [the sealed invitation provider spike](spikes/SEALED_INVITATION_PROVIDER.md).
- See the deeper
  [provider protocol draft](spikes/SEALED_INVITATION_PROVIDER_PROTOCOL.md).
- The spike recommends independently deployable directory and sealed-mailbox
  roles with rotating receive bundles.
- The extended simulator now exercises monotonic bundle rotation and rollback
  rejection.
- Remaining work includes OHTTP lookup privacy, production HPKE, anonymous
  deposit authorization, key transparency, persistence, concurrency, and
  realistic envelope-size measurement.
- The production gate requires durable generation/digest compare-and-swap,
  crash recovery, stale-snapshot rejection, and competing-successor tests
  across multiple service instances; simulator-only rotation is insufficient.

### P1: private first-contact lookup

- Spike an RFC 9458 OHTTP relay/gateway path for directory lookups.
- Bind directory signatures to lookup address, receive bundle, and expiration.
- Compare ordinary HTTPS, OHTTP, and mixnet lookup metadata using packet
  captures and an explicit observer matrix.
- Evaluate equivocation detection and whether short-lived recipient-signed
  bundles are sufficient before considering transparency logs.

### P1: anonymous invitation abuse control

- Spike RFC 9578 Privacy Pass one-use stamps or another unlinkable
  bounded-deposit authorization.
- Separate token issuance from redemption in time and operator context.
- Measure whether token type, issuer configuration, or redemption context
  partitions the anonymity set.
- Keep strict mailbox lifetime quotas as a required control even with tokens.
- Track the batched-token publication process and the active Anonymous
  Rate-Limited Credential drafts; do not depend on the expired per-origin
  rate-limited token draft.

### P1: receive-bundle authenticity and transparency

- Bind the complete receive bundle to the GitHub subject or credential through
  an address-attestor signature independent of directory storage.
- Specify routine rotation, draining generations, explicit continuity reset,
  and client rollback-cache behavior.
- Track IETF KEYTRANS architecture and protocol maturity.
- Compare mature KEYTRANS adoption with a smaller independently reviewed
  transparency mechanism only after requirements and monitoring state are
  measured.

### P0: fast transport and mailbox division

- Verify direct/relay metadata exposure and relay operational requirements.
- Decide which Iroh services are adopted and which mailbox functions remain
  separate.
- Model offline delivery, NAT changes, and mobile suspension.

### P1: Katzenpost application integration

- Determine the correct client and service integration boundary.
- Measure interactive latency and delivery variance.
- Design SURB/reply, mailbox polling, retry, acknowledgement, and expiration
  behavior.
- Confirm how client authentication to an entry provider affects linkability.

### P1: anonymity-set requirements

- Define the adversaries a private profile intends to resist.
- Determine required operator diversity, cover traffic, concurrent users, and
  padding.
- Establish which privacy claims are justified for local, private-realm, and
  public-network deployments.

### P1: no-downgrade verification

- Build integration tests that deny direct and normal relay connections.
- Audit DNS, update, telemetry, avatar, preview, crash, and identity traffic.
- Decide whether private mode uses process-level or OS-level network isolation.

### P2: Veilid experiment

- Reassess project maturity and threat model after the generic transport API is
  proven.
- Compare DHT discovery metadata, routed operations, offline behavior, and
  operational complexity with the other profiles.

## Client and storage

### P0: desktop security boundary and UI framework

- Validate approval, evidence, fingerprint, and transport-profile UX with the
  early fixture-driven prototype in `PRODUCT_V2.md`.
- Evaluate Tauri's command/permission boundary and alternative desktop shells.
- Select the UI framework only after privilege separation, update signing,
  accessibility, packaging, and dependency surface are compared.
- Record the selection in a dedicated ADR. V1's Angular history is evidence,
  not a default choice.

### P0: device and session key storage

- **Design spike completed:** the
  [client-state vault proposal](spikes/client-vault-portable-hosting/proposals/client-state-vault.md)
  recommends testing a session-scoped sealed vault with a bounded opaque inbox,
  OS user-presence adapters, and a whole-store fallback. This is not an
  implementation or dependency selection.
- Evaluate Tauri and Rust integration with platform keychains and secure
  hardware.
- Define database encryption, key hierarchy, lock behavior, and crash recovery.
- Decide which keys are device-root, invitation-scoped, session-scoped, or
  epoch-scoped.
- Measure platform-specific device binding, prompt, backup, biometric-change,
  and cross-application unlock behavior rather than treating "keychain" as one
  uniform guarantee.
- Prove that sealed mode permits only bounded opaque receipt and rejects
  decrypt, sign, admission, MLS mutation, acknowledgement, and rotation.

### P0: deep links and invitation handling

- Define HTTPS landing-to-app and custom-scheme behavior by platform.
- Test browser, shell, log, clipboard, referrer, and crash-report leakage.
- Fuzz all descriptor decoders and bound decoded object sizes.

### P1: ephemerality behavior

- Define local retention modes and cryptographic erasure.
- Test backups, OS snapshots, notifications, search indexes, and swap behavior.
- Write user-facing language that distinguishes deletion from preventing a
  recipient copy.

### P2: multi-device and recovery

- Compare independent MLS clients with synchronized state.
- Define device addition, revocation, recovery, and visible key-change events.
- Avoid designing recovery before the first single-device model is secure.

## Operations and self-hosting

### P1: realm packaging

- **Design spike completed:** the
  [portable realm hosting proposal](spikes/client-vault-portable-hosting/proposals/portable-realm-hosting.md)
  recommends a digest-pinned single-host Compose appliance followed by a
  client-pinned, offline-root-signed realm descriptor. This is not a deployable
  service or accepted protocol decision.
- Define the minimum Docker Compose realm and service separation.
- Establish TLS, service signing keys, secret rotation, backups, and upgrades.
- Ensure backups cannot recover client group keys or plaintext.
- Define planned and sudden replacement semantics, including monotonic realm
  generations, role-key delegation, bounded old/new overlap, and explicit
  trust reset when the realm root is lost.
- Keep active session endpoint rotation authenticated by session members; realm
  discovery or redirects must not grant receive, acknowledgement, rotation,
  admission, or MLS membership authority.

### P1: abuse resistance

- Bound unauthenticated mailbox writes, object sizes, queue depth, and CPU.
- Compare rate limits, capabilities, proof-of-work, anonymous tokens, and
  invitation quotas without destroying anonymous-mode privacy.
- Define constant-shape rejection behavior where useful.

### P1: observability without surveillance

- Define allowed metrics and structured log fields.
- Prohibit message bodies, private keys, raw tokens, full capabilities,
  presentation payloads, and stable identifiers by default.
- Test redaction on error and panic paths.

## Product and usability

### P0: assurance language

- User-test the distinction between account control, personhood, and trust in
  the early product-validation track before Phase 3/4 commitments.
- Explain fast, private, pseudonymous, and anonymous profiles accurately.
- Make transport failure and non-downgrade understandable.

### P1: approval and safety numbers

- Determine which evidence is useful without overwhelming users.
- Test fingerprint and QR comparison flows.
- Make device-key changes and new admission events difficult to miss.

### P2: competitive and protocol study

- Compare SimpleX, Signal, Matrix, Session, Cwtch, Veilid-based applications,
  and relevant mixnet messengers.
- Focus on invitation semantics, metadata threat models, offline delivery,
  self-hosting, abuse resistance, and recovery rather than feature checklists.
