# Reference ledger

Last reviewed: 2026-08-16

This is a research starting point, not a dependency manifest. Standards and
project maturity must be rechecked when an implementation decision is made.

## Session cryptography

### Invitation signatures

- [RFC 8032: Edwards-Curve Digital Signature Algorithm](https://www.rfc-editor.org/rfc/rfc8032)
- [`ed25519-dalek` 3.0.0 documentation](https://docs.rs/ed25519-dalek/3.0.0/ed25519_dalek/)
- [`zeroize` 1.9.0 documentation](https://docs.rs/zeroize/1.9.0/zeroize/)

Relevance: ADR 0007 uses strict Ed25519 verification for invitation integrity,
an application-defined signature domain, invitation-scoped signing keys, and
zeroization of owned capability and temporary signing buffers.

Caveat: an embedded verifying key authenticates the descriptor against
mutation; it does not by itself identify the inviter or authenticate the
channel that delivered the invitation.

### Messaging Layer Security

- [RFC 9420: The Messaging Layer Security Protocol](https://www.rfc-editor.org/rfc/rfc9420)
- [RFC 9750: The Messaging Layer Security Architecture](https://www.rfc-editor.org/rfc/rfc9750)

Relevance: MLS provides asynchronous group end-to-end encryption, membership
changes, forward secrecy, and post-compromise security. Its architecture
separates the Authentication Service from the Delivery Service, matching the
proposed identity/admission and transport split.

Open questions: OpenMLS version and review status, persistence model,
credential representation, concurrent Commit handling, and interoperability.

### Pre-membership encryption

- [RFC 9180: Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180)

Relevance: HPKE is a candidate standard construction for encrypting a join
request to an invitation key before the joiner is an MLS member.

Open questions: exact suite, key lifecycle, authenticated context, canonical
encoding, and test vectors.

## Identity and credentials

### Verifiable Credentials

- [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [W3C Verifiable Credential Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/)
- [W3C Data Integrity ECDSA Cryptosuites 1.0](https://www.w3.org/TR/vc-di-ecdsa/)
- [W3C Bitstring Status List 1.0](https://www.w3.org/TR/vc-bitstring-status-list/)

Status at review: VC Data Model 2.0 and the listed companion specifications
became W3C Recommendations on 2025-05-15.

Relevance: portable issuer/holder/verifier claims, data minimization, securing
mechanisms, and status information.

Caveat: the data model explicitly warns about identifier-, signature-,
metadata-, device-, validation-, and usage-based correlation. A verifiable
credential is not automatically an unlinkable credential.

### Decentralized identifiers

- [W3C Decentralized Identifiers 1.0](https://www.w3.org/TR/did-core/)
- [DID specification history](https://www.w3.org/standards/history/did-core/)

Status at review: DID 1.0 is a W3C Recommendation; DID 1.1 was on the Candidate
Recommendation track.

Relevance: subject-controlled key and service discovery where a use case
actually requires a DID.

Caveat: stable DIDs, verification methods, and service endpoints can be
correlating. Pairwise DIDs can help but do not help if their documents reuse
correlating material.

### Presentation protocol

- [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)

Status at review: both were OpenID Final Specifications.

Relevance: interoperable wallet-facing request, presentation, audience,
challenge, holder-binding, and credential-query behavior.

Open questions: wallet support on target platforms, initial credential format,
verifier identity, cross-device flow, and session-key binding.

### Unlinkable presentations

- [W3C Data Integrity BBS Cryptosuites 1.0](https://www.w3.org/TR/vc-di-bbs/)

Status at review: Candidate Recommendation Draft dated 2026-04-07, not a final
Recommendation.

Relevance: selective disclosure and unlinkable derived proofs.

Caveat: application, issuer, status, and network metadata can defeat
cryptographic unlinkability. The first Session Chat credential adapter should
not depend on BBS or claim unlinkability.

## GitHub admission

- [GitHub OAuth app best practices](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/best-practices-for-creating-an-oauth-app)
- [GitHub App authorization](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)
- [GitHub commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification)

Relevance: authorization-code and PKCE behavior, scope minimization, secure
token handling, and possible advanced bridge-free proofs.

Open questions: GitHub App versus OAuth App, desktop callback behavior, stable
subject claims, organization installation, minimum scopes, and bridge
attestation format.

## Client shell and crypto implementation

- [Tauri 2 deep linking](https://v2.tauri.app/plugin/deep-linking/)
- [Tauri security documentation](https://v2.tauri.app/security/)
- [OpenMLS repository](https://github.com/openmls/openmls)

Relevance: installed-client deep links, constrained native/webview boundary,
platform integration, and a Rust MLS implementation candidate.

Open questions: platform key storage, Tauri command surface, dependency version
floor, OpenMLS review remediations, and signed update design.

## Fast transport

- [Iroh documentation](https://docs.iroh.computer/)
- [Iroh relays](https://docs.iroh.computer/iroh-services/relays)

Relevance: encrypted QUIC connectivity, NAT traversal, direct paths, and relay
fallback.

Caveat: direct peers learn network addresses; relays and discovery services can
observe connection metadata. A relay is not automatically an offline mailbox.

Open questions: exact Iroh services, production relay operation, endpoint
identity, mailbox separation, and current project maturity.

## Mixnets and routed privacy transports

### Privacy partitioning and anonymous resource control

- [RFC 9458: Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458)
- [RFC 9614: Partitioning as an Architecture for Privacy](https://www.rfc-editor.org/rfc/rfc9614)
- [RFC 9576: Privacy Pass Architecture](https://www.rfc-editor.org/rfc/rfc9576)
- [RFC 9577: Privacy Pass HTTP Authentication Scheme](https://www.rfc-editor.org/rfc/rfc9577)

Relevance: separating a client-facing relay from a request-decrypting gateway
can prevent one non-colluding service from learning both requester address and
target lookup. Privacy Pass is a candidate building block for bounded anonymous
deposits without stable sender accounts.

Caveat: collusion, low-volume traffic, padding differences, issuer metadata,
token timing, and distinct configurations can partition anonymity sets. These
standards do not remove the need for strict mailbox resource bounds.

Status note: the older IETF per-origin rate-limited token draft expired in
2024. Anonymous Rate-Limited Credential cryptography and Privacy Pass issuance
were active Working Group drafts when reviewed, while batched token issuance
had been submitted to the IESG for publication. None should be treated as a
finished anonymous per-sender quota solution for the first prototype.

- [Privacy Pass batched token draft](https://datatracker.ietf.org/doc/draft-ietf-privacypass-batched-tokens/)
- [Privacy Pass ARC protocol draft](https://datatracker.ietf.org/doc/draft-ietf-privacypass-arc-protocol/)
- [Privacy Pass ARC cryptography draft](https://datatracker.ietf.org/doc/draft-ietf-privacypass-arc-crypto/)
- [Expired rate-limited token draft](https://datatracker.ietf.org/doc/draft-ietf-privacypass-rate-limit-tokens/)

### Key transparency

- [IETF KEYTRANS architecture draft](https://datatracker.ietf.org/doc/draft-ietf-keytrans-architecture/)
- [IETF KEYTRANS protocol draft](https://datatracker.ietf.org/doc/draft-ietf-keytrans-protocol/)

Relevance: a receive-bundle directory can otherwise associate an
attacker-controlled public key with a recipient address or show different key
histories to different senders. Key transparency is designed to make such
modification and forked views detectable while supporting targeted lookup.

Status at review: both were active Internet-Drafts, not final RFCs. The v2
prototype should preserve monotonic bundle generations, prior-bundle digests,
and monitoring hooks but must not invent a custom transparency protocol or
claim mature KEYTRANS protection.

### Oblivious pseudorandom functions

- [RFC 9497: Oblivious Pseudorandom Functions](https://www.rfc-editor.org/rfc/rfc9497)

Relevance: VOPRFs are a building block for privacy-preserving protocols in
which a server does not learn a client's input.

Caveat: using a VOPRF on an address is not by itself a complete private
directory, private information retrieval system, enumeration defense, or
authenticated receive-bundle protocol.

### Katzenpost

- [Katzenpost specifications](https://katzenpost.network/docs/specs/)
- [Katzenpost mix network specification](https://katzenpost.network/docs/specs/pdf/mixnet.pdf)
- [Katzenpost administration guide](https://katzenpost.network/docs/admin_guide/)

Relevance: Sphinx/Loopix-style mixnet substrate, SURBs, service nodes, and a
metadata-sensitive transport experiment.

Caveat: the transport is neither reliable nor in order and is not itself a
user-facing messaging system. Privacy also depends on topology, traffic,
padding, cover traffic, delays, providers, and operator diversity.

Open questions: client/service API, public versus realm networks, interactive
latency, polling, acknowledgements, cover traffic, mobile constraints, and
credible anonymity sets.

### Veilid

- [Veilid project](https://veilid.com/)
- [Veilid developer documentation](https://veilid.gitlab.io/veilid/)

Relevance: possible later experiment with privacy-oriented routed P2P and DHT
operations.

Open questions: maturity, security review, metadata threat model, offline
delivery, interoperability, and operational fit. It is not selected as the v2
foundation.

## Comparative systems

- [SimpleX Chat](https://simplex.chat/)
- [Signal specifications](https://signal.org/docs/)
- [Matrix specifications](https://spec.matrix.org/)
- [Cwtch documentation](https://docs.cwtch.im/)
- [Session documentation](https://docs.getsession.org/)

These systems should be studied for invitation semantics, asynchronous
delivery, metadata threat models, group state, recovery, self-hosting, abuse
resistance, and failure behavior. Their existence does not establish that a
specific design is suitable for Session Chat.

## Research hygiene

For every implementation decision:

1. Recheck the primary source and current specification status.
2. Record the exact library/version or protocol profile evaluated.
3. Distinguish standardized behavior from project-specific extensions.
4. Record security-review results and unresolved assumptions.
5. Add testable acceptance criteria, not only a technology name.
6. Update the relevant ADR when the decision changes a foundational boundary.
