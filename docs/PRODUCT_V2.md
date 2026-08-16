# Session Chat 2.0 product definition

Status: proposed

## Product thesis

Session Chat 2.0 is an ephemeral, self-hostable secure rendezvous system for
opening temporary conversations between externally identified, credentialed,
pseudonymous, or anonymous participants.

It is not intended to become a permanent social network or another hosted chat
service with accounts, server-readable history, and a durable social graph.

The defining workflow is:

> I know someone through an existing context, but I need a private temporary
> conversation without learning or exchanging their phone number, email
> address, or permanent chat username.

The invitation publishes enough information to request admission, but it does
not publish a session key or unrestricted membership credential.

## Product promises

Session Chat should eventually be able to make the following narrow promises:

- Conversation content is end-to-end encrypted between admitted devices.
- Delivery infrastructure does not receive the group keys or plaintext.
- A publicly copied targeted invitation is not sufficient for admission.
- The inviter sees what admission evidence was actually verified.
- Sessions and retained encrypted envelopes expire automatically.
- The user explicitly selects the identity and network-privacy profile.
- A private transport profile never silently falls back to a less private one.
- Self-hosting does not require the operator to receive message plaintext.

The product must not promise that a verified account is a trustworthy human,
that recipient devices cannot retain plaintext, or that all metadata is hidden
in every transport profile.

## Primary workflows

### Targeted GitHub invitation

1. Alice creates a temporary session and selects a GitHub account as the
   expected recipient.
2. Alice publishes a signed, expiring invitation in an issue, pull request,
   discussion, profile, or another channel.
3. Bob opens the invitation and proves control of the expected GitHub account.
4. The proof is bound to this invitation and Bob's complete ADR 0009 tuple:
   canonical KeyPackage reference, session-scoped credential identity, leaf
   signature key, MLS version and ciphersuite, and join-request identifier.
5. Alice reviews the verified account and device fingerprint.
6. Alice approves the join request.
7. Bob is added to the MLS group and receives an encrypted Welcome.

The interface should say that the device proved control of a GitHub account at
a specific time. It must not say that the account owner is inherently trusted
or that an account cannot be compromised.

### Anonymous capability invitation

1. Alice creates a high-entropy, expiring secret capability.
2. Alice shares it through a channel appropriate to her threat model.
3. Bob opens it without contacting GitHub or another identity provider.
4. Bob creates a fresh session-scoped key and submits a capability proof.
5. Alice optionally performs an out-of-band fingerprint comparison and
   approves Bob.
6. Bob joins the same MLS-based session protocol used by identified sessions.

"Anonymous" means no external persona is attached. It does not mean the
protocol operates without cryptographic member keys.

### Credential-based invitation

A session can request a verifiable presentation such as "active member of the
incident-response team" or "credential issued by example.org." The admission
policy decides which issuers and claims are accepted. This provides portable
admission evidence but does not make arbitrary self-issued claims trustworthy.

### GitHub identity over a mixnet

GitHub admission and mixnet delivery may be combined. In that profile, the
participants intentionally reveal the GitHub identity to each other while the
mixnet reduces exposure of IP addresses and traffic relationships. This is a
private identified conversation, not an anonymous one.

## User-visible profiles

The UI should present profiles in terms of their concrete guarantees, not a
single ambiguous "secure" toggle.

| Profile | Admission | Delivery | Intended guarantee |
| --- | --- | --- | --- |
| GitHub Fast | Targeted GitHub proof and approval | Direct or encrypted relay | Strong content security with low latency |
| GitHub Private | Targeted GitHub proof and approval | Mixnet | Identified participants with stronger network-metadata protection |
| Credential Private | Trusted credential and approval | Mixnet | Policy-based admission with stronger network-metadata protection |
| Anonymous Private | Secret capability and approval | Mixnet | No external identity and stronger network-metadata protection |

Deployment policy may disable profiles, identity providers, or transports. A
session may only select a profile allowed by its realm.

## Invitation modes

| Mode | Publicly postable | Admission rule |
| --- | ---: | --- |
| Targeted | Yes | Expected external identity or credential plus approval |
| Verified request | Yes | Any accepted identity or credential may request; inviter approves |
| Secret capability | No | Possession of an unguessable, expiring capability permits a request |
| Anonymous request | Risky | Anyone may request; requires abuse controls and explicit approval |

A URL fragment can carry an invitation descriptor so a normal landing-page
request does not send that descriptor to the web server. The descriptor still
must be signed, versioned, expiring, and safe to disclose according to its
invitation mode.

### Optional first-contact provider

Session Chat may operate a Session Post Office so the invitation itself does
not have to be delivered through GitHub, email, or another messenger. An
invitation directory maps a verified address or unguessable receive code to a
rotating receive bundle. A separately deployable sealed mailbox stores only
fixed-size encrypted invitations.

This is an optional delivery convenience, not an account system or membership
authority. Ordinary directory lookup exposes the target address to the
directory. Private profiles must use a privacy-partitioned or mixnet lookup and
state the remaining operator-collusion assumptions. See the
[sealed invitation provider spike](spikes/SEALED_INVITATION_PROVIDER.md).

## Ephemerality

"Ephemeral" should mean:

- Relay and mailbox ciphertexts have enforced TTLs.
- Invitations expire and can be consumed or revoked.
- Clients can destroy session and invitation keys.
- Removed members cannot derive later MLS epochs.
- Local encrypted history can be disabled or automatically deleted.
- The service holds no server-side plaintext transcript.

It cannot guarantee that a participant did not copy plaintext, take a
screenshot, photograph a display, export a transcript, or run a compromised
client. Product language should promise deletion of Session Chat's own retained
copies and cryptographic access, not impossible control over recipient devices.

## Delivery milestones

These labels are deliberately distinct. Passing a laboratory milestone does
not create a user-ready product, and a UX prototype does not prove protocol
security.

### Phase 1 protocol laboratory

Included:

- Headless two-client test flow
- Secret-capability admission with explicit simulated approval
- Two-person MLS session over deterministic memory transport
- Invitation, admission, membership, replay, removal, and expiration tests
- No external identity, network service, desktop shell, or deployment claim

### Early UX-validation prototype

Before committing to the desktop framework or completing network services,
validate a non-production interactive prototype with representative users. It
must test whether people can correctly understand:

- what GitHub, credential, capability, and manual evidence proves;
- why a valid proof still requires an approval decision;
- device fingerprints and key-change warnings;
- Fast versus Private transport availability and metadata caveats; and
- the difference between rejecting a request, retrying delivery, and closing a session.

This prototype uses fixtures or the headless core and carries no security or
deployment claim. Its results inform, but cannot bypass, core policy.

### First user-testable product slice

Included:

- Desktop application around the proven headless client
- Local device storage and session-scoped member keys
- Targeted GitHub admission
- Secret-capability admission with no external provider calls
- Explicit inviter approval
- Two-person MLS session
- Text messages
- Fast direct/relay transport
- Encrypted offline rendezvous mailbox
- Configurable expiration
- Docker Compose self-hosting

The desktop shell and UI framework remain research until a dedicated ADR
selects them. Tauri with a Rust security core is the leading boundary, but
Angular is neither selected nor required by this product definition.

Designed but initially experimental:

- Mixnet delivery
- Verifiable credential admission
- Groups larger than two

Deferred:

- Voice and video
- Public group discovery
- Permanent usernames or social graph
- Contact syncing
- Attachments
- Multi-device synchronization
- Cross-realm federation
- Anonymous public chatrooms
- Claims of guaranteed recipient-side deletion

### Initial security-focused release

The first release that makes security-focused product claims additionally
requires the Phase 7 hardening gates, durable rollback-resistant state,
release/update provenance, external protocol and implementation review, and
published operational limits. A successful user-testable slice alone is not
that release.

## Success criteria

The architecture is successful when the same encrypted session core can run
once with GitHub admission and fast transport, and again with capability
admission and mixnet transport, without changing MLS, message formats, or the
session state machine.
