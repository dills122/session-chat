# Identity and admission

Status: proposed, with credential-format research remaining open

## Terminology

Session Chat should avoid using "identity" for several different concepts.

- **Device root**: locally protected material used to establish continuity on a
  device. It is not automatically disclosed to peers.
- **Session member key**: the fresh MLS leaf signature public key authenticated
  by the exact KeyPackage proposed for one session.
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

Admission determines whether one exact proposed MLS KeyPackage may join. It can consider:

- GitHub control proof
- A verifiable presentation from a trusted issuer
- Possession of a secret capability
- A manual approval decision
- An out-of-band fingerprint comparison
- Boolean combinations of the above

The KeyPackage containing the session-scoped credential identity and leaf
signature key, rather than the external identity, is added to the encrypted
session.

## Common proof binding

Every admission method must bind its evidence to:

```text
invitation ID
invitation challenge
join request ID
canonical MLS KeyPackage reference
MLS protocol version and ciphersuite
session-scoped credential type and identity
MLS leaf signature public key
intended verifier or realm
issue time
expiration time
admission-proof protocol version
```

This prevents a valid proof captured for one invitation from being replayed to
admit a different KeyPackage, credential, signature key, or session. The
KeyPackage reference is the selected ciphersuite's RFC 9420 hash reference over
the canonical TLS-serialized KeyPackage; Session Chat does not define a second
hash representation.

The inviter verifies the KeyPackage signature, lifetime, version, ciphersuite,
credential, and extension policy, extracts the credential identity and leaf
signature key, and compares them with the proof before approval. The exact
verified KeyPackage/reference must be passed unchanged to MLS Add. See ADR 0009.

The inviter records the join-request replay identifier separately. A valid
request reserves locally issued invitation state; only the successful durable
membership transaction consumes it under ADR 0008.

The current `admission-capability` laboratory accepts HPKE-authenticated
provenance, retains the exact signed-invitation signature, validates and owns
the exact provider KeyPackage, compares the reference/credential/leaf tuple,
and reserves both request ID and nonce in bounded in-memory state. It binds that
value to the exact local v2 invitation reservation and consumes an explicit
simulated `Approve` or `Reject` decision. Only the approved one-shot value can
enter MLS preparation. Rejection, expiry, failed preparation, or abandonment
releases invitation and replay reservations; success applies MLS then consumes
the invitation. This is not human UI evidence and does not persist replay, MLS,
approval, or invitation state atomically.

For the local secret-capability profile accepted by ADR 0014, the intended
verifier is the exact invitation-scoped Ed25519 verifying key authenticated by
the signed invitation. Successful RFC 9180 PSK opening proves possession of the
high-entropy invitation capability for that exact context; it does not prove a
person, device, DNS name, or realm identity and does not itself approve or add
the member. Credential, GitHub, manual, and hosted-realm proofs may use new
verifier-context and proof versions rather than overloading those 32 bytes.

## GitHub admission

### Recommended flow

1. The recipient creates or loads local device material and generates a fresh
   session-scoped credential, leaf signature key, and MLS KeyPackage.
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

ADR 0014 requires production creation to obtain the capability from a reviewed
cryptographic generator. Fixed length and rejection of the reserved all-zero
value are structural checks, not evidence of entropy.

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
    invitation_id: InvitationId,
    invitation_challenge: JoinChallenge,
    join_request_id: JoinRequestId,
    intended_verifier: VerifierRealm,
    admission_proof_version: AdmissionProofVersion,
    proof_issued_at: Timestamp,
    proof_expires_at: Timestamp,
    // The exact parsed object verified above; not reconstructible from the ref.
    verified_key_package: ParsedVerifiedKeyPackage,
    key_package_ref: KeyPackageRef,
    mls_protocol_version: MlsProtocolVersion,
    mls_ciphersuite: MlsCiphersuite,
    credential_type: CredentialType,
    credential_identity: SessionCredentialId,
    leaf_signature_key: MlsSignaturePublicKey,
    assurance: AssuranceLevel,
    evidence_source: EvidenceSource,
    policy_claims: Vec<PolicyClaim>,
    display_claims: Vec<DisplayClaim>,
    verified_at: Timestamp,
}
```

`VerifiedAdmission` has private constructors, is opaque, does not implement
`Clone`, and is consumed once by the membership state machine. It owns both the
full admission context and the exact parsed KeyPackage that produced these
values. No API exposes a path to reconstruct, substitute, or separately pair a
KeyPackage after verification, and no membership API accepts an additional
KeyPackage or invitation/request context beside this value.

The inviter-owned registry supports provider-generated invitation v2 issue,
read-only descriptor validation, reservation, release, and consumption. The
capability adapter connects those transitions to its exact admission value and
simulated approval decision in memory. The future durable implementation must
still make approval/result, replay, MLS, invitation consumption, and Welcome
outbox state one recoverable transaction.

ADR 0015's shared `ApprovalContext` is display-only metadata for that decision.
It does not replace `VerifiedAdmission`, erase evidence provenance, or grant
membership authority; each concrete provider retains its original exact proof,
KeyPackage, and reservations through the one-shot membership operation.

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
