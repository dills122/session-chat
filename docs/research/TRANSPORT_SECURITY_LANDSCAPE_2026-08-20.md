# Transport and security technology landscape

Date: 2026-08-20

Status: retained research; recommendations are inputs to ADRs and roadmap
decisions, not dependency selections or product-security claims

Decision owner: Session Chat maintainers

## Decision question

Which transport, privacy, admission, transparency, update, and cryptographic
technologies are credible candidates for Session Chat 2.0, and how should they
influence the transport abstraction without coupling the session protocol to a
particular network?

This matters before the existing local-only `session-transport` crate is
generalized because an API designed only around one mailbox, direct relay, or
mixnet could make later adapters unsafe, force transport-specific fields into
protocol envelopes, or allow an adapter to weaken a selected privacy profile.

## Scope and method

The review considered technologies that can contribute at least one of:

- delivery of opaque envelopes;
- endpoint- or relationship-metadata protection;
- asynchronous or disruption-tolerant delivery;
- decentralized or independently operated infrastructure;
- privacy-preserving lookup or abuse control;
- identity-to-key consistency;
- secure software delivery; or
- migration to standardized post-quantum mechanisms.

Primary specifications and official project documentation were preferred.
Published project security reviews were recorded where found. No candidate was
installed or experimentally reproduced in this review, so this packet contains
documented facts, inferences, and unknowns but no implementation observations.

Comparison criteria were:

1. fit with opaque, bounded Session Chat envelopes;
2. compatibility with right-specific mailbox capabilities;
3. metadata protection under a stated observer model;
4. decentralization and operator-diversity potential;
5. asynchronous and offline behavior;
6. Rust and desktop integration fit;
7. protocol and implementation maturity;
8. operational and dependency burden;
9. ability to test failure and downgrade behavior; and
10. reversibility if the candidate is later replaced.

The review stops at a prioritized experiment portfolio. It does not authorize
production integration, change the Phase 1 scope, or establish anonymity,
privacy, post-quantum, or production-readiness claims.

## Executive conclusion

No single transport is best for every Session Chat profile. The architecture
should support a portfolio with sharply different, non-interchangeable
guarantees:

- Iroh or an equivalently evaluated direct/relay substrate for low-latency
  **Fast** delivery;
- Tor through Arti as the strongest pragmatic candidate for a separately named,
  low-latency **Private Interactive** experiment;
- Katzenpost as the primary delayed **Private Mixnet** experiment, benchmarked
  against Nym rather than assumed to be the only viable mixnet;
- SimpleX Messaging Protocol as a high-priority asynchronous queue and mailbox
  integration study; and
- Veilid and Reticulum as later laboratory candidates for routed P2P and
  disruption-tolerant/off-grid profiles.

The more immediate security investments are not additional chat transports:
OHTTP for first-contact lookup, Privacy Pass for unlinkable bounded deposit
authorization, update-framework and transparency controls for desktop releases,
and monitoring-compatible receive-bundle history for later key transparency.

The common transport interface must therefore model observable delivery
semantics and explicit policy constraints, not advertise a single scalar
"privacy level." Profile policy must be owned above adapters, and an adapter
must never choose its own fallback or obtain ambient mailbox authority.

## Transport candidates

### Tor onion services through Arti

**Documented fact:** Tor onion services provide self-authenticating service
addresses, end-to-end encrypted paths inside Tor, service-location hiding, and
outbound-only connectivity that works through NAT. Arti is the Tor Project's
modular Rust implementation and supports accessing and hosting onion services.

**Documented fact:** Tor explicitly does not defend against an observer that
can correlate both ends of a low-latency connection by timing and volume.

**Inference:** Tor/Arti is the best candidate for a usable low-latency private
profile because it has a long-lived public network and avoids requiring Session
Chat to create its own anonymity set. It must not be labeled or tested as a
mixnet equivalent.

**Unknown:** desktop resource usage, onion-service lifecycle and key storage,
mailbox behavior during client suspension, bootstrap/censorship behavior, and
whether Arti exposes every isolation control the profile requires.

**Recommendation:** run a bounded onion-mailbox experiment after the generic
memory transport. Name the profile separately from both Fast and Private
Mixnet, and apply ADR 0003 fail-closed behavior.

Sources:

- [Tor onion-service overview](https://community.torproject.org/onion-services/overview/)
- [Tor traffic-correlation limitations](https://support.torproject.org/about-tor/security/attacks-on-onion-routing/)
- [Arti documentation](https://arti.torproject.org/)

### SimpleX Messaging Protocol

**Documented fact:** SMP defines persistent, asynchronous, unidirectional
queues with different sender and recipient identifiers and cryptographic
credentials. It uses fixed-size 16 KiB transport blocks, supports two-router
onion forwarding, and treats routers as independently operated infrastructure.

**Documented fact:** SimpleX reports a 2022 implementation assessment and a
2024 cryptographic protocol review by Trail of Bits. Its 2026 security policy
also states that a further implementation assessment was scheduled for June
2026; the result was not established in this review.

**Inference:** SMP is unusually close to Session Chat's deposit, receive, and
acknowledgement capability model. It may be useful either as an opaque-envelope
adapter or as prior art for the Session Chat mailbox protocol. Adopting its
full chat or end-to-end encryption layer would duplicate MLS and blur the
architecture boundary.

**Unknown:** direct protocol interoperability effort, current audit-result
status, exact fixed-block overhead for Session Chat envelopes, Rust binding or
process boundary, and AGPL implications of embedding implementation code.

**Recommendation:** compare two spikes: carrying canonical Session Chat
envelope bytes over SMP queues, and independently implementing only the
required mailbox semantics. Require a license review before embedding code.

Sources:

- [SimpleX Messaging Protocol](https://github.com/simplex-chat/simplexmq/blob/stable/protocol/simplex-messaging.md)
- [SimpleX network architecture and threat model](https://github.com/simplex-chat/simplexmq/blob/stable/protocol/overview-tjr.md)
- [SimpleX security policy](https://github.com/simplex-chat/simplex-chat/security)

### Katzenpost

**Documented fact:** Katzenpost is a Sphinx-based continuous-time mixnet with
client-selected delays, service nodes, and single-use reply blocks. It is not a
reliable or in-order messaging protocol.

**Inference:** Katzenpost remains the cleanest research target for testing the
hard delivery conditions already named in the Session Chat roadmap: delay,
loss, duplication, reordering, polling, acknowledgement, route outage, and
queue exhaustion.

**Unknown:** acceptable interactive latency, public-network availability,
operator diversity, entry-provider linkability, client and service integration
boundary, cover-traffic budgets, and deployment evidence sufficient for any
public privacy claim.

**Recommendation:** keep Katzenpost as the primary Phase 5 mixnet experiment.
Treat a small realm-operated network as failure-testing infrastructure, not as
evidence of strong real-world anonymity.

Sources:

- [Katzenpost specifications](https://katzenpost.network/docs/specs/)
- [Katzenpost mixnet specification](https://katzenpost.network/docs/specs/pdf/mixnet.pdf)
- [Katzenpost administration guide](https://katzenpost.network/docs/admin_guide/)

### Nym

**Documented fact:** Nym operates a decentralized mixnet with independently
operated nodes and cover traffic. Its system includes the Nyx Cosmos-based
chain and offers application integration paths including Rust and TypeScript
software.

**Inference:** an existing public network may offer a more meaningful
anonymity set than a new Session Chat-operated mixnet. The chain, credentials,
and token economics are additional operational dependencies and must not enter
the Session Chat protocol or membership trust model.

**Unknown:** stable application-facing Rust API, mailbox and reply semantics,
provider authentication linkability, latency distribution, availability,
cost, network governance, and current audit coverage for the exact components
Session Chat would use.

**Recommendation:** benchmark Nym and Katzenpost through the same conformance
harness. Do not select Nym merely because the network is public or
decentralized.

Sources:

- [Nym network overview](https://nym.com/network)
- [Nym source organization](https://github.com/nymtech)
- [Nym security review](https://nym.com/nym-audit-report-draft-202109-3.pdf)

### Veilid

**Documented fact:** Veilid provides encrypted DHT operations and public and
private routed operations through a Rust core. Its own developer handbook calls
the protocol and framework beta-like and not ready for production-grade apps.

**Inference:** Veilid is useful for proving that the abstraction is not tied to
a mailbox relay or mixnet, but it is not evidence for a named production
privacy profile.

**Unknown:** independent security review, Sybil and route-selection exposure,
offline semantics, long-term wire stability, anonymity properties under
realistic observers, and operational availability.

**Recommendation:** retain as a P2 experiment after the generic transport API
and its conformance suite exist.

Sources:

- [Veilid developer handbook](https://gitlab.com/veilid/developer-book)
- [Veilid core](https://gitlab.com/veilid/veilid/-/blob/main/veilid-core/README.md)

### Reticulum and Briar-style disruption tolerance

**Documented fact:** Reticulum is a cryptography-based networking stack that
can operate over IP, packet radio, LoRa, serial, and other low-bandwidth or
high-latency links. Its reference implementation and manual define encrypted
single-destination traffic, forward-secret links, multi-hop routing, and no
source address in ordinary packets.

**Documented fact:** Briar synchronizes directly over Bluetooth and Wi-Fi when
offline and over Tor when Internet access is available, without making a
central service the content authority.

**Inference:** these are valuable models for a later, explicitly selected
disruption-tolerant or off-grid profile. They are not automatic fallback paths
for an active private session.

**Unknown:** independent review of Reticulum's current protocol and reference
implementation, Rust integration, metadata exposure on shared radio media,
regulatory constraints, and envelope fragmentation behavior.

**Recommendation:** retain as future research after Phase 1. Use Briar as
design prior art rather than an assumed embeddable transport library.

Sources:

- [Reticulum overview](https://reticulum.network/manual/whatis.html)
- [Reticulum network construction](https://reticulum.network/manual/networks.html)
- [Briar architecture](https://briarproject.org/how-it-works/)

## Cross-cutting security technologies

### OHTTP for private first-contact lookup

**Documented fact:** RFC 9458 separates a relay that sees the client connection
from a gateway that decrypts the HTTP request. The gateway does not learn the
client address and the relay does not learn the request plaintext, assuming
the roles do not collude. OHTTP does not by itself stop traffic analysis.

**Recommendation:** keep the existing P1 spike and make ordinary HTTPS, OHTTP,
and mixnet lookup share an observer-matrix and packet-capture test format.

Source: [RFC 9458](https://www.rfc-editor.org/rfc/rfc9458)

### Privacy Pass for anonymous bounded deposit authorization

**Documented fact:** Privacy Pass defines unlinkable authorization tokens. Its
privacy properties depend on deployment roles, anonymity sets, configuration
consistency, and separation of issuance from redemption in time or network
context.

**Recommendation:** spike one-use deposit stamps while retaining strict mailbox
TTL, object, queue, and global work limits. Tokens supplement capabilities and
resource bounds; they do not replace them.

Sources:

- [RFC 9576: Privacy Pass Architecture](https://www.rfc-editor.org/rfc/rfc9576)
- [RFC 9577: Privacy Pass HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577)
- [RFC 9578: Privacy Pass Issuance](https://www.rfc-editor.org/rfc/rfc9578)

### Key transparency

**Documented fact:** the IETF KEYTRANS working group is designing public
verifiability for identity-to-public-key bindings and globally consistent
views. Its architecture and protocol were active Internet-Drafts at the review
date, not final RFCs.

**Recommendation:** preserve monotonic generations, prior-bundle digests,
auditor hooks, and client monitoring state. Do not invent a custom transparency
protocol or make the current wire format depend on draft KEYTRANS messages.

Sources:

- [IETF KEYTRANS working group](https://datatracker.ietf.org/group/keytrans/)
- [KEYTRANS protocol draft](https://datatracker.ietf.org/doc/draft-ietf-keytrans-protocol/)

### Secure updates and release transparency

**Documented fact:** The Update Framework is designed to resist arbitrary
software installation, rollback, freeze, fast-forward, and signing-key
compromise scenarios. Sigstore records signing events in a transparency log;
Sigsum defines a smaller witness-oriented transparency system.

**Inference:** update compromise can bypass the entire messaging protocol, so
this work is a prerequisite for security-focused desktop claims rather than a
late operational convenience.

**Recommendation:** evaluate offline or threshold release keys, TUF-style root,
targets, snapshot, and timestamp metadata, client rollback state, and an
independently witnessed release log before Phase 7.

Sources:

- [TUF overview](https://theupdateframework.io/docs/overview/)
- [TUF security model](https://theupdateframework.io/docs/security/)
- [Sigstore signing overview](https://docs.sigstore.dev/cosign/signing/overview/)
- [Sigsum documentation](https://github.com/sigsum/sigsum)

### Credential presentation and unlinkable proofs

**Documented fact:** OpenID for Verifiable Presentations 1.0 is a final
specification and requires verifier- and transaction-bound holder proofs for
replay protection. The W3C BBS cryptosuite was a Candidate Recommendation Draft
at the review date.

**Recommendation:** use OpenID4VP as the future wallet-facing boundary. Keep BBS
as an optional format experiment and do not infer application-level
unlinkability from selective-disclosure cryptography alone.

Sources:

- [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [W3C BBS cryptosuite](https://www.w3.org/TR/vc-di-bbs/)

### Post-quantum hybrids

**Documented fact:** hybrid ML-KEM/traditional key agreement is standardized
for TLS 1.3. Post-quantum and hybrid MLS ciphersuites and HPKE KEMs were still
active drafts at the review date. OpenMLS has experimental hybrid support, but
its published description notes draft code points and possible interoperability
limits.

**Recommendation:** preserve explicit suite identifiers, downgrade rejection,
and migration fixtures. Do not change the pinned Phase 1 MLS suite or advertise
post-quantum protection until the selected standards and implementations are
stable, interoperable, and reviewed.

Sources:

- [RFC 10024: PQ/T hybrid TLS groups](https://www.rfc-editor.org/rfc/rfc10024)
- [MLS ML-KEM ciphersuite draft](https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites/)
- [OpenMLS post-quantum experiment](https://blog.openmls.tech/posts/2024-04-11-pq-openmls/)

### PAKE-based manual pairing

**Documented fact:** SPAKE2 allows parties sharing a password to derive a
strong key without disclosing the password. OPAQUE is a standardized augmented
PAKE that avoids storing a password-equivalent at a server and resists offline
guessing after server compromise within its stated model.

**Recommendation:** consider PAKE only for a future low-entropy human pairing
mode or device-linking flow. It must not replace the current high-entropy
invitation capability, and online attempts must remain strictly bounded.

Sources:

- [RFC 9382: SPAKE2](https://www.rfc-editor.org/rfc/rfc9382)
- [RFC 9807: OPAQUE](https://www.rfc-editor.org/rfc/rfc9807)

## Comparative recommendation

| Candidate | Metadata objective | Decentralization | Offline delivery | Maturity signal | Disposition |
| --- | --- | --- | --- | --- | --- |
| Iroh | Fast encrypted direct/relay delivery; no anonymity claim | Self-hostable relays | Requires separate mailbox | Rust-native project; exact production version remains a selection gate | Retain for Fast evaluation |
| Tor/Arti | Endpoint-IP hiding and censorship resistance; timing correlation remains | Large volunteer network | Requires mailbox/service availability | Long-lived network; official Rust implementation | High-priority experiment |
| SimpleX SMP | Queue unlinkability, fixed blocks, two-router separation | Independently operated routers | Native asynchronous queues | Published protocol and security reviews | High-priority spike |
| Katzenpost | Delayed mixing against stronger traffic analysis | Deployment-dependent | Service/mailbox integration required | Research-oriented implementation and specifications | Primary mixnet experiment |
| Nym | Public mixnet with cover traffic | Independent operators plus chain governance | Integration-dependent | Live network and reviewed components | Comparative mixnet benchmark |
| Veilid | Private routed P2P and DHT operations | Peer-to-peer | DHT-dependent | Project describes itself as beta-like | Watch/laboratory |
| Reticulum | Disruption-tolerant encrypted multi-hop networking | Community-operated nodes | Medium-dependent store/forward | Stable reference API; review evidence unknown | Future off-grid research |

The table records objectives, not proven guarantees. Every named profile still
requires an explicit adversary model, deployment description, conformance
evidence, and user-visible limitations.

## Rejected shortcuts

- Do not store invitations, membership state, or message traffic directly on a
  blockchain. Public persistence, linkability, cost, and deletion conflicts do
  not improve MLS security.
- Do not publish message or invitation ciphertext permanently to IPFS or an
  unscoped public DHT. Encryption does not remove enumeration, retention,
  access-pattern, and traffic-analysis concerns.
- Do not infer anonymity from decentralization. Operator diversity, route
  selection, cover traffic, timing, and client behavior remain decisive.
- Do not invent cryptographic packet splitting, mixing, onion routing, or
  post-quantum combiners.
- Do not allow automatic transport hopping. A deliberately named composite
  profile may use multiple paths only when every path satisfies that profile's
  contract and the composition is separately tested.

## Implications for the transport abstraction

The common contract must:

1. accept only canonical, bounded opaque envelope bytes and minimal delivery
   metadata;
2. preserve distinct deposit, receive, acknowledgement, and rotation rights;
3. expose unordered, duplicate-capable bounded attempts with no eventual-delivery
   guarantee as the portable baseline;
4. keep durable outbox truth in the owner-local transaction store while making
   adapter-independent expiry, deduplication, and retry policy coordinator-owned;
5. separate stable profile identifiers from local adapter/vendor identifiers;
6. bind an adapter to locally authorized profile requirements before I/O;
7. prohibit adapter-selected fallback and ambient network or mailbox authority;
8. expose typed, redacted, bounded errors and retry advice;
9. support network-broker or process-isolation enforcement for private modes;
10. provide a conformance harness shared by memory, Iroh, Tor, SimpleX,
    Katzenpost, Nym, and later experimental adapters; and
11. treat adapter capability declarations as configuration inputs, not proof of
    metadata privacy.

These implications are developed in
[`TRANSPORT_ABSTRACTION_V1.md`](../specs/TRANSPORT_ABSTRACTION_V1.md) and the
associated proposed ADR.

## Confidence, limitations, and evidence that would change the recommendation

Confidence is high in the architectural recommendation to keep transports
pluggable, profile-bound, and fail-closed. Confidence is medium in the relative
experiment priority because no candidate was run in the Session Chat
environment.

Material limitations:

- project documentation can overstate security or omit deployment caveats;
- audit existence does not prove applicability to the exact current version or
  feature set;
- network size does not alone establish an anonymity set for Session Chat
  traffic;
- mobile background behavior was not evaluated and remains deferred; and
- licenses and transitive dependencies were not reviewed in depth.

The recommendation should change if a candidate cannot carry bounded canonical
envelopes without exposing transport-specific identity, cannot meet capability
separation, cannot be isolated from forbidden egress, lacks a maintainable
integration boundary, or fails the shared adverse-network and packet-capture
tests. A candidate that publishes independent current audits, stable Rust APIs,
and reproducible deployment evidence may move earlier in the experiment order.

## Next gate

The next decision is the generalized `session-transport` contract, not a
production network selection. After that contract and the generalized
deterministic memory control path pass their tests, conduct bounded Tor/Arti
and SimpleX SMP spikes, then compare Katzenpost
and Nym through the same simulator, observer matrix, and packet-capture format.
