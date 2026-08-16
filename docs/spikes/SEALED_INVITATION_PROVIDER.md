# Spike: optional sealed invitation provider

Status: spike validated; production design remains proposed

Date: 2026-08-16

Implementation: [`spikes/sealed-invitation-provider`](../../spikes/sealed-invitation-provider/)

Deeper protocol draft:
[sealed invitation provider protocol](SEALED_INVITATION_PROVIDER_PROTOCOL.md)

## Question

The current v2 design deliberately treats invitation publication as out of
band. That is safe as a protocol boundary, but it leaves a product gap:

> How does Alice reach Bob for the first time if Session Chat should not require
> Alice to deliver the invitation through GitHub, email, Slack, or another chat
> platform?

No protocol can contact an otherwise unknown device without some pre-existing
address, discoverable directory record, shared capability, or third-party
channel. The design choice is therefore not whether first contact has a trust
and metadata cost; it is where that cost lives and how narrowly it can be
contained.

## Recommendation

Build an optional **Session Post Office** with two independently deployable
roles:

1. An invitation directory maps a verified address to a short-lived receive
   bundle.
2. A sealed mailbox stores fixed-size encrypted invitation envelopes under a
   random capability-derived address.

This service delivers only first-contact invitations and admission responses.
It is not a plaintext messaging provider, a permanent account system, an MLS
membership authority, or a canonical chat-history service.

```text
Bob                                      Directory
 |                                           |
 | create rotating receive key + mailbox    |
 | register verified address -> bundle       |
 |------------------------------------------>|
                                             |
Alice                                        |
 | lookup Bob's address                      |
 |------------------------------------------>|
 | receive signed bundle                     |
 |<------------------------------------------|
 |
 | HPKE-seal invitation to Bob's receive key
 v
Sealed Mailbox -------------------------> Bob polls and acknowledges
  random mailbox ID                        with separate read and acknowledgement
  fixed-size ciphertext                    and decrypts locally
  TTL and strict bounds
```

Directory and mailbox separation matters. A normal directory request reveals
the target address. A normal mailbox connection reveals a network source and
random mailbox. When separately operated and accessed through privacy-aware
transports, no one ordinary service needs to learn sender IP, recipient
identity, and invitation content together.

## Receive bundle

A directory lookup returns a signed record resembling:

```text
claims:
  version
  directory address binding
  complete receive-bundle body
  address-attestor signature over the body
  optional recipient/device continuity signature over the body
directory signature over the complete claims
```

The address attestor must bind the stable subject, lookup scope, and complete
receive-bundle body. The directory signature must additionally bind the lookup
address, every body field, and the complete attestation and continuity-signature
objects carried in the record claims. Neither signature covers its own field.
Otherwise a valid receive bundle could be substituted under a different
account. The sender validates both; the directory is not the only authority for
the recipient encryption key.

The directory must authorize registration using one of:

- A short-lived GitHub attestation for the stable provider subject
- A trusted verifiable credential and holder proof
- A signature from the key controlling an existing record
- An administrator-controlled realm policy

A display name alone cannot authorize registration. Hashing a public username
does not hide it because the directory or an attacker can perform a dictionary
attack.

## Address modes

### Verified address

Examples:

```text
github:user:789012
credential-subject under a configured trust framework
organization-local employee identifier
```

This removes GitHub as the invitation delivery platform while still allowing
GitHub to be the identity attestor. The directory learns which verified address
is queried unless a stronger lookup design is used.

### Receive code

Bob can generate a high-entropy receive code and communicate it verbally, by QR
code, on a business card, or during an earlier encounter. The directory maps
the unguessable code to Bob's receive bundle without learning a public identity.

This is useful for pseudonymous contact, but the code still needs an initial
exchange. It solves provider independence, not the fundamental first-contact
problem.

### Public handle

A permanent human-readable Session Chat handle would recreate an account
directory and durable social graph. It is not recommended for the first
product. If explored later, it requires namespace, impersonation, moderation,
recovery, enumeration, and privacy designs well beyond this spike.

## Invitation envelope

Production envelopes should use RFC 9180 HPKE. The recipient's rotating receive
key is the HPKE recipient key. Authenticated context binds at least:

- Protocol and envelope version
- Mailbox ID
- Random envelope ID
- Expiration time
- Size class
- Intended object type

The encrypted content contains a normal signed Session Chat invitation and a
reply rendezvous descriptor. The provider does not authenticate the inviter or
admit them to a session. Bob's client decrypts the object, validates the
invitation signature and policy, presents the evidence, and decides whether to
respond.

The first provider should accept only a small number of fixed-size invitation
envelopes. It should not become a generic pre-admission message service. An
arbitrary anonymous message inbox creates avoidable harassment, phishing,
moderation, storage, and rendering risks before the participants have admitted
each other.

## Provider knowledge

| Party | Normally observes | Must not receive |
| --- | --- | --- |
| Directory | Lookup address, rotating receive bundle, lookup timing | Invitation ciphertext or plaintext |
| OHTTP relay | Sender network address, encrypted lookup request size/timing | Target lookup address or response |
| OHTTP gateway/directory | Target lookup and response, relay address | Original sender network address |
| Mailbox | Random mailbox ID, fixed ciphertext, access timing, source address unless hidden | Directory identity, invitation plaintext, read or acknowledgement capabilities |
| Recipient | Decrypted invitation and inviter-provided evidence | Nothing beyond the selected admission flow |

If directory, relay, gateway, mailbox, and identity attestor are operated by one
colluding entity, the separation provides much less metadata privacy. The
deployment and UI claims must state their non-collusion assumptions.

## Lookup privacy options

### Baseline: ordinary HTTPS

Simplest, but the directory observes both requester network address and target
lookup. Suitable for the Fast profile with honest product language.

### Recommended next step: Oblivious HTTP

RFC 9458 separates the client-facing relay from the gateway that decrypts the
request. The relay sees the client connection but not the target lookup; the
gateway sees the lookup but not the client's original address when the two
roles do not collude.

OHTTP is privacy partitioning, not a full mixnet. Traffic analysis, low-volume
requests, distinct padding, relay-added metadata, and collusion remain relevant.
Queries and responses should use fixed size classes and shared configurations
to avoid tiny anonymity sets.

### Private profile: mixnet access

Directory lookup, deposit, and polling can travel through the selected mixnet.
This is consistent with Anonymous Private and GitHub Private profiles, but it
inherits mixnet latency, reliability, anonymity-set, and operator assumptions.

### Deferred: OPRF or private information retrieval

An oblivious pseudorandom function or private information retrieval could hide
the target lookup more strongly from the directory. These approaches add
substantial protocol, availability, abuse, and implementation complexity. A
hashed-username lookup is not an acceptable substitute.

## Abuse resistance

Publicly discoverable receive bundles are deposit capabilities. Anyone who can
look up Bob can attempt to fill Bob's queue. End-to-end encryption prevents the
provider from safely moderating content, so resource protection must operate on
opaque envelopes.

Baseline controls:

- Recipient opt-in
- Rotating receive keys and mailboxes
- Short bundle and envelope TTLs
- Fixed envelope size
- Strict per-mailbox queue and lifetime-deposit caps
- Per-route and global resource budgets
- Idempotency by random envelope ID
- Recipient acknowledgement
- Generic error responses
- No automatic rendering or link fetching before local validation
- Client-side reject/block and mailbox rotation

Possible later control: Privacy Pass tokens can authorize bounded deposits
without giving the mailbox service a stable sender account. RFC 9576 was
motivated partly by privacy-aware abuse control, but deployment separation,
token caching, anonymity sets, and issuance metadata require careful analysis.
It should be a separate spike.

Requiring every sender to authenticate with GitHub would simplify abuse control
but would eliminate anonymous first contact. That may be an allowed policy for
some realms, not a protocol requirement.

## Availability and malicious-provider behavior

The post office cannot guarantee delivery. It can:

- Drop or delay a registration or invitation
- Return a stale record
- Equivocate by showing different records to different senders
- Correlate timing and access patterns
- Exhaust or falsely report mailbox capacity
- Refuse a participant or realm

The independent address-attestor signature prevents a directory-only attacker
from inventing a new receive key. It does not prevent omission, stale responses,
or a compromised attestor from issuing a false binding. Potential later
controls include short validity, recipient signatures, key-continuity warnings,
auditable transparency logs, multiple independent directories, and direct
fingerprint comparison.

The provider must never be described as a trusted delivery oracle. Session
security must tolerate denial of service and reject substitution.

## Push notifications

Platform push services can disclose device identifiers, timing, and the fact
that a Session Chat mailbox received activity. They also create a mobile
availability dependency.

The first safe design should use bounded polling. Push can be researched later
as an explicitly less-private optimization with generic, content-free signals
and careful token separation.

## Spike implementation

The dependency-free simulator implements:

- Separate directory and mailbox classes
- Independent address-attestor signing over the address and complete bundle
- Authorized directory registration using the attestation
- Snapshotted bundle/proof inputs across asynchronous authorization
- Bounded registration, address-control proof, and acknowledgement inputs
- A closed provisional receive-bundle schema whose authenticated projection is
  exactly the stored projection; unknown and recursive extras are rejected
- Directory signatures bound to lookup key and bundle
- Monotonic receive-bundle generation, chaining, and rollback rejection
- Post-authorization predecessor recheck so one in-process concurrent successor wins
- X25519 receive and ephemeral keys
- HKDF-SHA-256 plus AES-256-GCM sealed envelopes
- 1 KiB padded plaintext blocks
- Random mailbox, read-capability, envelope, and delivery identifiers
- TTL, queue bounds, lifetime deposit bounds, retry deduplication, fetch, and
  acknowledgement
- Confidentiality, authorization, attestation binding, tamper, expiry, replay,
  substitution, rotation, rollback, and competing-successor tests

The composition is intentionally a simulation, not an HPKE implementation. A
production protocol must replace it with a reviewed RFC 9180 library and test
vectors. The in-process predecessor recheck is not a durable transaction;
production requires the compare-and-swap, crash, restart, and multi-instance
evidence in the protocol draft and roadmap.

## Spike result

The architecture is viable and fills the product gap without turning the
provider into a plaintext chat server.

Recommended status:

- Adopt the directory/mailbox split as a **proposed optional v2 component**.
- Keep external invitation sharing and secret receive codes available.
- Implement ordinary HTTPS only for an explicitly metadata-visible Fast
  profile.
- Spike OHTTP before claiming private identity lookup.
- Route all three operations through the mixnet for the Private profile.
- Do not offer arbitrary pre-admission messages.
- Do not select Privacy Pass, PIR, an OPRF design, or transparency mechanism
  until each receives a focused spike.

## Acceptance criteria for a production prototype

1. The provider cannot decrypt invitation envelopes.
2. Mailbox storage contains no external identity or plaintext read or
   acknowledgement capability; it stores only their one-way digests.
3. Directory storage and logs contain no invitation traffic.
4. Registration authorization binds lookup address, receive key, mailbox, and
   expiry.
5. An independently verified address attestation binds the stable subject to
   the complete receive-bundle body.
6. Directory responses are signed over closed claims containing the lookup
   address, complete body, attestation, and any continuity signature.
7. Envelopes use reviewed HPKE and published test vectors.
8. Queues, total lifetime writes, sizes, retries, and computation are bounded.
9. Expired, duplicate, malformed, and tampered objects fail safely.
10. Private profile lookups, deposits, and polls never use direct network paths.
11. The UI distinguishes invitation delivery from inviter verification and MLS
    admission.
12. Registration uses durable compare-and-swap over generation and previous
    bundle digest; concurrent competing successors cannot both commit.
13. Crash, restart, and stale-snapshot tests prove monotonic bundle continuity
    across multiple service instances.

## Primary references

- [RFC 9180: Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180)
- [RFC 9458: Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458)
- [RFC 9576: Privacy Pass Architecture](https://www.rfc-editor.org/rfc/rfc9576)
- [RFC 9614: Partitioning as an Architecture for Privacy](https://www.rfc-editor.org/rfc/rfc9614)
