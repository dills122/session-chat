# Identity and admission

Status: proposed, with credential-format research remaining open

## Terminology

Session Chat should avoid using "identity" for several different concepts.

- **Device root**: locally protected material used to establish continuity on a
  device. It is not automatically disclosed to peers.
- **Session member key**: a fresh key used by one member in one session or
  invitation context.
- **External identity**: an application-meaningful account such as a stable
  GitHub subject identifier.
- **Credential claim**: a statement made by a configured issuer, such as
  organization membership or role.
- **Admission proof**: evidence bound to a specific invitation and proposed
  session member key.
- **Trust**: a human or policy decision. Successful cryptographic verification
  is evidence, not a declaration that a person is trustworthy.

The preferred modern standards terminology is "verifiable credentials" and
"decentralized identifiers." "SSI" can remain useful shorthand, but it should
not imply that all issuers, registries, wallets, and trust decisions disappear.

## Decision: external identity is optional evidence

Every member needs a cryptographic key so that MLS can authenticate group
operations. A member does not need a globally stable username, DID, GitHub
account, email, or phone number.

Admission determines whether a proposed session key may join. It can consider:

- GitHub control proof
- A verifiable presentation from a trusted issuer
- Possession of a secret capability
- A manual approval decision
- An out-of-band fingerprint comparison
- Boolean combinations of the above

The session key, rather than the external identity, is added to the encrypted
session.

## Common proof binding

Every admission method must bind its evidence to:

```text
invitation ID
invitation challenge
proposed session member public key
intended verifier or realm
issue time
expiration time
protocol version
```

This prevents a valid proof captured for one invitation from being replayed to
admit a different key or join a different session.

The join request also needs its own replay identifier. The inviter records
consumption according to the invitation's one-use or bounded-multi-use policy.

## GitHub admission

### Recommended flow

1. The recipient creates or loads local device material and generates a fresh
   session member key.
2. The client starts a GitHub authorization-code flow with PKCE through the
   configured identity bridge.
3. The bridge resolves GitHub's stable numeric subject identifier and any
   explicitly requested organization or repository claims.
4. The bridge signs a short-lived attestation containing the common proof
   binding.
5. The client encrypts the attestation and MLS KeyPackage to the invitation
   key.
6. The inviter verifies the bridge signature, provider subject, policy match,
   challenge, audience, key binding, expiry, and replay state.
7. The UI presents the evidence and requires approval.

The bridge keeps OAuth tokens out of clients where practical and always keeps
them out of invitations, rendezvous infrastructure, peers, logs, and message
storage.

### Stable identifier versus display name

Policies target the provider's stable account identifier, not a mutable GitHub
login. The UI may display both:

```text
GitHub login: @bob
Provider subject: github:user:789012
Proof time: 2026-08-16T18:42:00Z
Expected account: match
```

The UI must say "proved control of this account" rather than "is definitely
this person."

### GitHub without an identity bridge

An advanced flow might verify a challenge using a signed commit, tag, or other
GitHub-visible proof. This reduces dependence on the Session Chat bridge but is
slower, remains GitHub-mediated, and introduces signature-policy complexity.
It is a research item, not an MVP requirement.

## Verifiable credentials and SSI

### Good uses

Credential admission is useful for:

- Organization, team, role, or qualification proofs
- Cross-realm admission without a shared GitHub integration
- User-controlled presentation of portable evidence
- Selective disclosure when the credential format actually supports it
- Replacing provider-specific policies with issuer-and-claim policies

The project should accept presentations through a standards-based boundary such
as OpenID for Verifiable Presentations rather than inventing a Session Chat
wallet protocol.

### Trust remains configured

A DID proves control of keys described by a DID method. It does not prove the
semantic truth of "I am Bob" or "I work for example.org." Credential policies
must configure:

- Trusted issuers or trust frameworks
- Accepted credential types and securing mechanisms
- Required claims and acceptable values
- Holder-binding requirements
- Expiration and status handling
- Audience, nonce, and session-key binding
- Whether manual approval is still required

Arbitrary self-issued credentials must not satisfy an organization-issued
membership policy.

### Privacy constraints

Stable DIDs, subject identifiers, credential identifiers, signing material,
issuer-specific metadata, and online status checks can correlate presentations.
Therefore:

- Do not place a global DID in every MLS credential or envelope.
- Prefer a fresh session member key and bind the presentation to it.
- Request only the claims required by the admission policy.
- Prefer local verification and privacy-preserving cached status information.
- Warn when a proof contains stable identifiers.
- Do not claim unlinkability merely because selective disclosure is available.
- Treat BBS unlinkable derived proofs as experimental until the standard and
  implementation ecosystem meet the project's maturity requirements.

For the first credential adapter, portable verified admission is the goal;
strong cross-session unlinkability is a later research goal.

### DIDs are not required

Verifiable credentials and presentations can use several identifier and proof
formats. Session Chat should not require every credential to expose a DID and
should not select a DID method before defining resolution, availability,
privacy, recovery, and trust requirements.

## Capability and anonymous admission

A secret-capability invitation contains sufficient entropy to resist guessing
and is distributed through a channel suitable to the participants' threat
model. The capability permits a join request; it need not grant automatic MLS
membership.

Recommended policy:

```text
AllOf(
  ValidSecretCapability,
  ExplicitInviterApproval
)
```

The recipient uses a fresh session member key and discloses no external
identity. Optional safety-number or QR comparison can authenticate the key over
another channel.

Anonymous public request links are substantially more exposed to spam and
resource exhaustion. They require bounded mailboxes, rate limits or anonymous
resource proofs, queue caps, expiration, and a deliberate abuse strategy.
Secret capability links should be the first anonymous mode.

## Policy model

Illustrative policy types:

```rust
enum AdmissionRule {
    GitHubSubject(String),
    Credential {
        trusted_issuers: Vec<IssuerId>,
        credential_type: String,
        claims: Vec<ClaimConstraint>,
    },
    SecretCapability,
    ManualApproval,
    OutOfBandFingerprint,
    AllOf(Vec<AdmissionRule>),
    AnyOf(Vec<AdmissionRule>),
}
```

Verification should return normalized evidence without erasing provenance:

```rust
struct VerifiedAdmission {
    session_public_key: PublicKey,
    assurance: AssuranceLevel,
    evidence_source: EvidenceSource,
    policy_claims: Vec<PolicyClaim>,
    display_claims: Vec<DisplayClaim>,
    verified_at: Timestamp,
    expires_at: Timestamp,
}
```

The UI must retain the difference between a provider attestation, an
issuer-signed credential, capability possession, and manual approval.

## Recovery and multi-device concerns

Device recovery and multi-device support are intentionally deferred because
they can undermine otherwise clear identity guarantees. Future designs must
answer:

- Whether device roots are recoverable or deliberately non-exportable
- How a recovered or new device is announced to existing contacts
- Whether external identity proof is sufficient to replace a device
- How key rotation appears in ongoing sessions
- How an organization revokes a credential without learning every presentation
- Whether multiple devices are separate MLS clients or share group state

Changing a session member key must always be visible as a new device or new
admission event; it must never be silently treated as continuity.
