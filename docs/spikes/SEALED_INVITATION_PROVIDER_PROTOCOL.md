# Sealed invitation provider protocol draft

Status: exploratory protocol design; not an implementation specification

Date: 2026-08-16

Related material:

- [Initial spike and recommendation](SEALED_INVITATION_PROVIDER.md)
- [Runnable boundary simulator](../../spikes/sealed-invitation-provider/)
- [Identity and admission design](../IDENTITY_AND_ADMISSION.md)
- [Transport design](../TRANSPORTS.md)

## Viability conclusion

The provider is viable if its promise stays narrow:

> Deliver a bounded, sealed first-contact invitation to a rotating recipient
> inbox without becoming the conversation server or MLS membership authority.

Content-confidential first contact is practical with reviewed HPKE, strict
mailbox bounds, and a recipient receive bundle authenticated independently of
the directory.

Metadata-private first contact is also architecturally possible, but only under
explicit deployment assumptions. A single operator serving ordinary HTTPS
directory lookup, deposit, and polling can correlate a social graph even though
it cannot decrypt invitations. OHTTP, separate operators, caching, delay, and a
mixnet reduce different portions of that exposure; none should be collapsed
into an unqualified claim of anonymity.

The hardest unresolved product case is a publicly discoverable inbox that
accepts anonymous senders while remaining resistant to targeted queue
exhaustion. The first release should not claim to solve that case.

## Goals

- Deliver an invitation without GitHub, email, or another messenger carrying
  the invitation itself.
- Keep invitation plaintext and reply rendezvous details off the provider.
- Authenticate the recipient receive key independently of directory behavior.
- Support GitHub, credential, and high-entropy receive-code addressing.
- Bound storage, computation, retries, and lifetime writes.
- Support Fast, privacy-partitioned, and mixnet access profiles.
- Rotate receive keys and mailboxes without silent rollback.
- Keep the invitation inbox separate from MLS session delivery.

## Non-goals

- Permanent Session Chat usernames or public social discovery
- Arbitrary messages before admission
- Server-readable moderation
- Proof that a provider delivered, displayed, or decrypted an invitation
- Guaranteed availability
- Guaranteed anonymity against a global observer or colluding operators
- Multi-device recovery in the first protocol version
- Designing new HPKE, anonymous-token, PIR, or transparency cryptography

## Roles

### Recipient

Creates the invitation receive key, distinct mailbox read and acknowledgement
capabilities, bundle generation, and optional continuity signature. Polls the
mailbox, decrypts invitation knocks, validates their inner protocol objects,
and decides whether to respond.

### Sender

Resolves the intended recipient address, validates the receive-bundle
attestation and continuity, creates a signed Session Chat invitation, seals it
to the receive key, and deposits the resulting fixed-size envelope.

### Address attestor

Verifies control of an external address and signs the complete receive-bundle
binding. This can be the GitHub identity bridge, a trusted credential issuer or
verifier, or a realm authority. It is an authentication service, not a
directory or mailbox.

### Invitation directory

Distributes current receive bundles and freshness information. It can refuse,
delay, replay, or fork responses, but it must not be able to substitute a
receive key without invalidating the address attestation.

### Sealed mailbox

Stores opaque fixed-size envelopes under random mailbox identifiers. It knows
mailbox access metadata but not the external address, invitation plaintext, or
MLS group state.

### Privacy relay or mixnet

Reduces the ability of the directory or mailbox to associate requests with a
client network address. OHTTP provides relay/gateway privacy partitioning; the
mixnet provides a different, higher-latency traffic-analysis threat model.

### Deposit authorization issuer

Optionally issues one-use or bounded-use deposit stamps. It is separate from
invitation identity: a stamp authorizes a small amount of mailbox work but is
not proof that the recipient should trust or admit the sender.

## Trust reduction through signed receive bundles

The directory must not be the sole authority for the recipient's encryption
key. Otherwise a compromised directory can replace Bob's key with its own,
receive Alice's sealed invitation, and learn its plaintext.

A receive bundle therefore carries an address attestation over the complete
security context:

```text
external address type and stable subject
display alias, if relevant
realm and directory scope
bundle generation
previous bundle digest
invitation HPKE public key and suite
random mailbox deposit identifier
mailbox service and transport profile
deposit policy
not-before and expiration
protocol and serialization versions
```

Alice verifies the attestation using a configured address-attestor key. A
directory signature can additionally authenticate freshness and the response
shape, but it is not the identity-to-key security foundation.

Consequences:

- A directory-only compromise can deny service or return stale data but cannot
  silently substitute an unattested receive key.
- A compromised address attestor can still issue a false binding.
- First contact still depends on trusting the selected attestor or receive
  code.
- Key transparency can later make targeted attestor or service equivocation
  detectable; it is not required to validate the basic directory split.

## Address modes

### GitHub address

The user-facing address may be a mutable login such as `@bob`, but the signed
binding contains GitHub's stable provider subject identifier. The lookup flow
must resolve the alias and show both values:

```text
Requested: @bob
Verified provider subject: github:user:789012
Receive bundle generation: 4
Attestation age: 12 minutes
```

If Alice previously contacted the stable subject, a changed subject behind the
same login is an identity change, not a transparent rename.

### Credential address

A realm can identify a recipient using an organization-local subject or a
credential-derived address. The accepted issuer and claim policy remain realm
configuration. A self-issued DID alone does not establish the semantic
identity.

### Receive code

A receive code contains or derives an unguessable directory lookup key and an
expected bundle or continuity-key commitment. It creates a pseudonymous
capability address without a public identity.

The code still needs an initial exchange, but Session Chat can carry all later
invitations without another platform. A human-readable short code with low
entropy is not sufficient unless paired interactively with rate limits and a
second verification step.

### No permanent Session Chat handle

A global human-readable handle would require enumeration protection,
impersonation handling, namespace policy, recovery, moderation, and durable
account state. It also recreates the permanent social directory that the
product is trying to avoid. It remains out of scope.

## Protocol objects

The following structures are illustrative. Final objects require canonical
binary serialization, explicit suite registries, strict bounds, and test
vectors.

### `ReceiveBundleBodyV1`

```text
version
bundle_id                    random 256-bit identifier
generation                   monotonic positive integer
previous_bundle_digest       null for generation 1
recipient_address_binding    typed stable subject or receive-code scope
invite_hpke_suite
invite_hpke_public_key
mailbox_service_id
mailbox_deposit_id           random 256-bit identifier
deposit_policy
envelope_size_class
not_before
expires_at
```

The mailbox read and acknowledgement capabilities are never included. A full
receive-code payload may contain additional secret material, but the directory
record must not.

Every receive-bundle body version is a closed schema. Unknown fields are
rejected; new transport, suite, policy, or privacy-profile fields require a new
supported schema whose canonical digest covers every body field.
The current simulator deliberately implements only `version`, `generation`,
`previousBundleDigest`, `mailboxId`, `recipientPublicKey`, and `expiresAt`.

### `AddressAttestationV1`

```text
claims:
  issuer
  subject_type
  stable_subject
  display_alias?
  realm
  receive_bundle_body_digest
  issued_at
  expires_at
  assurance claims
signature
```

This object is intentionally similar in spirit to join admission attestations,
but its audience and purpose are different. A receive-bundle attestation only
says that an address authorized an invitation receive key. It does not admit
that key to an MLS session. Its signature covers the canonical `claims` object
and never covers the `signature` field itself.

### `AttestedReceiveBundleV1`

```text
body                          ReceiveBundleBodyV1
recipient_continuity_signature?
address_attestation           AddressAttestationV1
```

The address attestation signs the canonical `ReceiveBundleBodyV1` digest and
the address scope. An optional continuity signature signs an explicitly
domain-separated projection of that same body. Neither signature is a field of
the body it authenticates.

### `DirectoryRecordV1`

```text
claims:
  version
  directory_lookup_key
  attested_receive_bundle     AttestedReceiveBundleV1
  issued_at
  expires_at
directory_signature
```

The directory signature covers the canonical `claims` object, including every
field and nested signature in the attested bundle, but never covers the
`directory_signature` field itself. Each body, claims, attestation, and wrapper
version is independently closed. Implementations reject unknown fields instead
of authenticating one projection while storing or returning another.

### `SealedInviteEnvelopeV1`

Visible header:

```text
version
mailbox_deposit_id
bundle_id or bundle_digest
random envelope_id
expires_at
size_class
HPKE encapsulated key
ciphertext
```

HPKE authenticated context includes the visible header and a domain separation
label such as `session-chat/invite-knock/v1`. The receive key is not reused for
chat content, attachments, join requests, or MLS operations.

Encrypted fixed-size body:

```text
object_type = InviteKnockV1
signed invitation descriptor
inviter admission evidence?
reply rendezvous descriptor
client compatibility information
random padding
```

An inviter attestation remains optional and is verified only after decryption.
The mailbox cannot prioritize senders based on encrypted identity unless a
separate deposit-stamp class is deliberately exposed.

### `MailboxBatchV1`

```text
mailbox generation
poll nonce
zero or more fixed-size sealed envelopes
dummy slots up to the response size class
next cursor
service signature or MAC
```

Padding empty and non-empty polling responses reduces simple size leakage but
increases bandwidth. Exact batch classes and polling cadence require
measurement.

## Lifecycle

### Registration

1. Bob creates a dedicated invitation HPKE key plus distinct mailbox read and
   acknowledgement capabilities.
2. Bob asks the mailbox service to create a random deposit mailbox with strict
   TTL, queue, and lifetime-write limits.
3. Bob constructs generation 1 of `ReceiveBundleBodyV1`.
4. Bob proves control of the selected external address to the address attestor,
   or binds the body to a private receive code.
5. The attestor signs the complete body digest and address scope.
6. Bob constructs `AttestedReceiveBundleV1` and uploads it to the directory.
7. The directory validates authorization, record shape, expiry, and generation,
   then returns `DirectoryRecordV1`, whose signature covers its complete claims.
8. Bob stores the directory record and begins polling the mailbox.

The directory must validate proof type, encoded size, nesting depth, entry
count, and bundle structure before invoking complex attestation logic. It must
snapshot the complete validated bundle body and proof before any asynchronous
authorization and authorize, sign, and store that same snapshot. Exact-schema
normalization must happen before recursive cloning: fixed field types and
lengths bound the entire accepted body, while unknown, oversized, deep, cyclic,
accessor-backed, or symbol-keyed properties fail closed.

### Lookup

1. Alice canonicalizes the address type and input.
2. Alice queries the appropriate realm directory using the selected privacy
   profile.
3. The directory returns a padded positive or negative response.
4. Alice validates the directory response, address attestation, requested
   address, stable subject, expiry, supported suites, and bundle continuity.
5. Alice caches the validated record subject to its expiry and privacy policy.

Negative responses should be indistinguishable in size and close in timing to
positive responses where practical. This does not prevent a directory from
learning an ordinary lookup.

### Deposit

1. Alice creates a normal signed Session Chat invitation and reply mailbox.
2. Alice encodes it as a strictly typed `InviteKnockV1` body.
3. Alice pads and seals the body with reviewed HPKE to Bob's receive key.
4. Alice acquires the required deposit authorization for the bundle's policy.
5. Alice sends a fixed-size deposit through the selected transport.
6. The mailbox validates only visible bounds, expiry, duplicate envelope ID,
   mailbox state, and deposit authorization.
7. The mailbox stores the opaque envelope and returns an acceptance identifier.

Acceptance is not proof of recipient delivery or decryption.

### Poll and acknowledgement

1. Bob polls using the read capability through the profile's required path.
2. The mailbox returns a bounded padded batch with at-least-once semantics.
3. Bob durably stores the envelopes locally before acknowledgement.
4. Bob attempts decryption and strict typed decoding.
5. Bob uses the separate acknowledgement capability to acknowledge valid,
   malformed, undecryptable, and locally rejected envelopes so poison objects
   do not loop forever.
6. Bob deduplicates by envelope ID independently of provider state.
7. The UI quarantines new invitations until local validation completes.

Acknowledgements can be delayed or included in a later padded poll to reduce a
simple fetch-to-ack timing signal.

### Invitation response

Bob does not reply through the receive inbox. The decrypted invitation contains
an invitation-scoped response rendezvous descriptor. Bob submits the normal
encrypted join request there. After approval, MLS and the selected session
transport take over.

This boundary prevents the post office from becoming the ongoing conversation
server.

## State machines

### Receive bundle

```text
Unregistered
    |
    v
Active generation N -----> Rotating N+1
    |                           |
    |                           v
    |                     Grace for N
    |                           |
    +-----> Revoked             v
    |                        Expired N
    v
Expired
```

The old mailbox can remain readable during a short grace interval so in-flight
envelopes are not lost, but new directory lookups return only generation N+1.

### Envelope

```text
Created -> Sealed -> Accepted -> Fetched -> Acknowledged
               |         |          |
               |         |          +-> Rejected locally
               |         +-> Expired
               +-> Rejected by mailbox
```

The provider observes only its delivery states. It does not learn whether local
decryption, validation, display, approval, or MLS admission succeeded.

### Mailbox

```text
Open -> Draining -> Closed
  |         |
  +-------> Expired
```

`Draining` rejects new deposits while allowing the recipient to fetch remaining
objects during rotation or revocation.

## Rotation, rollback, and recovery

### Routine rotation

Each new bundle contains:

- `generation = previous generation + 1`
- The digest of the complete previous bundle
- A fresh invitation receive key
- A fresh mailbox with distinct read and acknowledgement capabilities
- A fresh address attestation
- Optionally, a signature from the prior continuity key

The directory rejects non-successors according to its stored state. Clients
with cached state independently reject rollback or a non-chained generation.
The simulator exercises this local rule and rechecks the predecessor after
asynchronous authorization so only one in-process competing successor commits.

Directory enforcement is not sufficient against a malicious directory that
maintains different histories for different users. Cached continuity detects
some rollback; an out-of-band fingerprint detects some substitution; complete
fork detection requires a transparency or multi-party design.

### Durable registration transaction

The in-memory simulator's generation check is feasibility evidence only. A
production directory must update one address record through a durable
compare-and-swap transaction whose precondition includes both the current
generation and complete previous-bundle digest. Authorization may be verified
before the transaction, but the precondition must be rechecked inside it.

The committed record contains the highest accepted generation, current bundle
digest, continuity/reset status, expiry, and the bounded rotation history needed
for draining. A restart or restored snapshot must not lower that monotonic state.
If the backing store cannot provide compare-and-swap plus rollback detection,
the deployment cannot claim safe receive-bundle continuity.

Required production evidence includes:

- two concurrent successors for generation `N + 1` cannot both commit;
- multiple directory processes produce the same result;
- crashes before and after every write boundary recover to either generation
  `N` or one complete generation `N + 1`, never a partial record;
- restart with stale durable state is detected and fails closed;
- the old mailbox drains according to the same committed rotation; and
- an explicit continuity reset cannot be confused with ordinary rotation.

### Recovery

Loss of all continuity keys requires a new address-control proof. The resulting
record must be marked as a continuity reset rather than pretending to be an
ordinary rotation.

Previously contacting clients display a high-visibility key-change warning and
may require manual or out-of-band confirmation. First-contact clients can only
rely on the current address attestation and any transparency proof.

### Revocation

Short bundle and mailbox lifetimes are the baseline revocation mechanism.
Explicit revocation can stop new lookup and deposit sooner, but cannot erase a
sealed envelope already copied by an attacker or prevent decryption by someone
who retained the old receive private key.

## Key transparency

Key transparency directly addresses a malicious service associating an
attacker-controlled public key with a user's address or showing forked histories
to different contacts. The IETF KEYTRANS architecture and protocol are highly
relevant to receive-bundle distribution.

As of this review, the architecture and protocol are active Internet-Drafts,
not final RFCs. They should inform the data model and monitoring hooks, but the
first prototype should not invent a custom transparency tree or make production
claims based on unfinished drafts.

MVP protections:

- Address-attestor signature over the complete bundle
- Monotonic generation and previous-bundle digest
- Client caching of the highest validated generation
- Explicit continuity-reset warnings
- Optional out-of-band fingerprint comparison
- Short record lifetimes

Future path:

- Adopt a mature KEYTRANS-compatible log or independently reviewed equivalent
- Provide inclusion and consistency evidence with directory results
- Support owner and contact monitoring
- Preserve monitoring state across client upgrades and backups
- Define auditor/non-collusion deployment policy

## Deposit policies and abuse

The receive bundle declares one deposit policy. A sender cannot downgrade it.

### `PrivateCapability`

The high-entropy receive code or private bundle is itself the ability to locate
the deposit mailbox. This is the best anonymous MVP because it avoids an open
public inbox. Queue and lifetime limits still apply after capability leakage.

### `AuthenticatedFast`

The mailbox requires a short-lived provider authorization obtained after a
sender signs in or satisfies realm policy. This is implementable now and useful
for GitHub Fast, but the provider can learn more of the contact graph. Product
copy must say so.

The sender identity included inside the sealed invitation remains separately
verified by Bob. Provider authorization is only an abuse-control decision.

### `AnonymousStamp`

The mailbox requires a one-use anonymous token issued before the deposit. Basic
Privacy Pass protocols are standardized, and batched issuance is progressing,
but privacy depends on issuance/redemption separation, challenge scope,
configuration consistency, attester behavior, and anonymity-set size.

The older per-origin rate-limited token draft expired. New Anonymous
Rate-Limited Credential work is active but remains draft-stage as of this
review. Session Chat should not implement novel ARC cryptography or claim a
mature anonymous per-sender quota yet.

Pragmatic research sequence:

1. Strict mailbox limits under every policy.
2. Authenticated Fast deposits for public verified addresses.
3. Private-capability deposits for anonymous contacts.
4. A focused RFC 9578 Privacy Pass spike using pre-issued, one-use realm-wide
   stamps.
5. Track batched-token and ARC maturity.
6. Do not enable an open anonymous public inbox until queue-starvation tests
   demonstrate acceptable behavior.

### `OpenBounded`

No sender authorization; only mailbox bounds and optional proof of work. This
is simple but permits cheap targeted denial of service. Proof of work is an
accessibility and resource-pricing tradeoff, not an identity or trust proof. It
should remain a development experiment.

## Privacy and deployment profiles

### Single-operator Fast

```text
Client -> Realm directory
Client -> Realm mailbox
```

The operator can correlate network addresses, target lookups, mailbox IDs,
timing, and polling. It cannot decrypt correctly sealed invitations. This is a
useful provider-independent delivery profile, but not metadata-private.

### Split OHTTP

```text
Client -> independent OHTTP relay -> directory gateway
Client -> independent OHTTP relay -> mailbox gateway
```

The relay sees the client network address and encrypted request boundaries. The
gateway sees the directory or mailbox operation but not the original client
address, assuming the relay does not forward identifying metadata and the roles
do not collude.

Lookup followed immediately by deposit can still be correlated by timing at a
shared gateway or colluding services. Caching receive bundles, fixed sizes,
randomized delay, shared configurations, and operator separation improve but do
not eliminate this.

### Mixnet Private

```text
Client -> mixnet -> directory service
Client -> mixnet -> mailbox service
```

Lookup, deposit, polling, and acknowledgement all use the selected mixnet. The
profile inherits mixnet latency, loss, reordering, cover-traffic, anonymity-set,
gateway, and operator assumptions. It must never fall back to the direct/OHTTP
path silently.

### Split operators without a privacy relay

Separating the directory and mailbox databases prevents an ordinary single
service from directly joining identity records to mailbox contents, but each
service still observes client network addresses. This is defense in depth, not
sender anonymity.

## What each party can correlate

| Observer | Fast profile | Split OHTTP | Mixnet Private |
| --- | --- | --- | --- |
| Directory | Sender IP, target address, timing | Target address, relay, timing | Target address/service request, mixnet-local metadata |
| Mailbox | Client IP, mailbox, timing, volume | Mailbox, relay, timing, volume | Mailbox/service request, mixnet-local metadata |
| OHTTP relay | Not used | Client IP, gateway, padded sizes/timing | Not required |
| Address attestor | Identity proof and bundle issuance | Same unless issuance is separately protected | Same unless issuance uses private transport |
| Network observer | Client-to-service flows | Client-to-relay flows | Client-to-entry-provider flow |
| Recipient | Decrypted invitation and included evidence | Same | Same |

No column implies protection against endpoint compromise or a fully colluding
global observer.

## API sketch

These endpoints describe semantics, not final HTTP paths.

### Directory

```text
POST directory/registration-challenges
PUT  directory/records/{typed-address}
GET  directory/records/{typed-address}
POST directory/records/{typed-address}/revoke
GET  directory/configuration
```

Requirements:

- Registration and revocation are authenticated.
- Lookup supports OHTTP encapsulation and fixed-size responses.
- Address parsing is canonical and bounded.
- Missing, expired, and unauthorized records use non-enumerating response
  shapes where practical.
- Configuration and signing keys rotate with explicit overlap.

### Mailbox

```text
POST mailbox/mailboxes
POST mailbox/deposit/{mailbox-deposit-id}
POST mailbox/poll
POST mailbox/acknowledge
POST mailbox/rotate-or-drain
GET  mailbox/configuration
```

Requirements:

- Mailbox creation is recipient-authorized and quota-bound.
- Deposit accepts exactly supported fixed envelope shapes.
- Poll authenticates using proof of the read capability; acknowledgement uses
  proof of a distinct acknowledgement capability. Neither is sent in a URL.
- Missing mailbox, wrong capability, expired mailbox, and closed mailbox avoid
  useful enumeration differences.
- Deposit authorization is validated before expensive or persistent work.
- Acknowledgement accepts only a bounded list of canonical delivery identifiers
  no larger than the mailbox queue bound.
- Retry and acknowledgement are idempotent.

The mixnet adapter can carry equivalent binary operations without HTTP.

## Provisional bounds to measure

The simulator uses a 1 KiB plaintext block, queue depth and acknowledgement
batch limit 16, lifetime deposit limit 64, registration-proof limit 8 KiB with
bounded nesting/entries, address-control proof limit 4 KiB, and seven-day
mailbox lifetime only to demonstrate boundaries. They
are not selected production values.

Before choosing limits, encode realistic objects containing:

- Signed invitation descriptor
- GitHub or credential evidence where included
- Reply mailbox descriptor
- Protocol negotiation fields
- HPKE and signature overhead
- Canonical serialization overhead

Then select as few size classes as possible. Many distinctive classes can leak
admission or client information; one unnecessarily large class increases abuse
cost and cover-traffic bandwidth.

## Retention and observability

Directory may retain:

- Current and short rotation history required for continuity
- Address-attestation digest and issuer
- Expiry and generation
- Aggregated operational metrics

Mailbox may retain:

- Opaque envelope bytes
- Random mailbox, envelope, and delivery identifiers
- Expiry, acknowledgement, and bounded quota counters

Neither service logs:

- Invitation plaintext
- Read capabilities
- Full bearer deposit credentials
- OAuth tokens
- MLS secrets
- Decrypted sender evidence

Access logs and IP retention remain security-sensitive metadata. A deployment
cannot claim metadata minimization merely because application logs omit
plaintext.

## Failure behavior

- Directory unavailable: use a still-valid cached bundle or report unavailable;
  never substitute an unverified key.
- Directory returns stale generation: warn/reject according to cached state.
- Bundle expired: do not deposit; refresh through the selected profile.
- Mailbox full: report invitation not accepted; do not claim delivery.
- Deposit response lost: retry the same envelope ID and bytes.
- Poll response duplicated: recipient deduplicates locally.
- Envelope cannot decrypt: acknowledge and record only a privacy-safe local
  diagnostic.
- Private transport unavailable: fail closed.
- Address attestor unavailable: existing valid bundles remain usable until
  expiry; new or recovery registration waits.
- Continuity reset: show a key-change warning and require the selected policy's
  re-verification.

## Recommended MVP slice

Build only:

- GitHub stable-subject and high-entropy receive-code addresses
- Address-attestor signature over the complete receive-bundle body
- One active bundle plus one short draining generation
- Fresh receive key and mailbox on rotation
- Fast HTTPS transport with explicit metadata language
- `AuthenticatedFast` for public GitHub address deposits
- `PrivateCapability` for anonymous/pseudonymous deposits
- Fixed-size `InviteKnockV1` objects only
- Polling, no platform push
- Strict queue, lifetime-write, object, retry, and TTL bounds
- Client caching of generation and previous-bundle digest
- Explicit continuity-reset warnings

Do not include initially:

- Open anonymous public inboxes
- Generic pre-admission messages
- Custom key-transparency trees
- Custom anonymous rate-limiting cryptography
- Permanent Session Chat handles
- Push notifications
- Multiple devices per address
- Claims that Fast mode hides the contact graph

## Research gates after MVP

1. OHTTP relay/gateway interoperability and traffic-correlation measurements.
2. Mixnet directory, deposit, poll, and acknowledgement integration.
3. Privacy Pass one-use stamp issuance separated from redemption in time and
   operator role.
4. KEYTRANS draft maturity and compatibility with rotating receive bundles.
5. Multi-device receive bundles and recovery without silent continuity.
6. Envelope size measurements and padding policy.
7. Queue-starvation simulation under authenticated and anonymous policies.
8. Push notification metadata and mobile suspension behavior.

## Primary sources reviewed

- [RFC 9180: Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180)
- [RFC 9458: Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458)
- [RFC 9576: Privacy Pass Architecture](https://www.rfc-editor.org/rfc/rfc9576)
- [RFC 9578: Privacy Pass Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578)
- [RFC 9497: Oblivious Pseudorandom Functions](https://www.rfc-editor.org/rfc/rfc9497)
- [IETF KEYTRANS Architecture draft](https://datatracker.ietf.org/doc/draft-ietf-keytrans-architecture/)
- [IETF KEYTRANS Protocol draft](https://datatracker.ietf.org/doc/draft-ietf-keytrans-protocol/)
- [Privacy Pass Batched Tokens draft](https://datatracker.ietf.org/doc/draft-ietf-privacypass-batched-tokens/)
- [Privacy Pass ARC Protocol draft](https://datatracker.ietf.org/doc/draft-ietf-privacypass-arc-protocol/)
- [Privacy Pass ARC Cryptography draft](https://datatracker.ietf.org/doc/draft-ietf-privacypass-arc-crypto/)
