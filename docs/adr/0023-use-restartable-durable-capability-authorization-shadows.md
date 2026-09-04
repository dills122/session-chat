# ADR 0023: Use restartable durable capability-authorization shadows

Status: accepted and implemented at the SQLCipher storage boundary and in the
headless capability-admission composition

Date: 2026-09-03

## Context

The retained capability path keeps its verified KeyPackage, HPKE-open
provenance, replay reservation, invitation reservation, and approval authority
in memory until the inviter MLS transaction is staged. The SQLCipher laboratory
durably owns the later membership/outbox transaction, but a process loss before
that transaction begins erases the only record of pending replay and approval
state.

Reconstructing the provider's parsed KeyPackage or its one-shot membership
authority from durable identifiers would violate ADR 0009. Simply releasing the
invitation after restart is also incomplete: invitation v2 requires the exact
signed bearer descriptor and invitation-scoped HPKE private key to open another
request for that generation. A row containing only an invitation identifier,
signature, and request identifier cannot make the generation usable again.

Phase 1 needs restartable authorization and invitation state without claiming
that a pending approval or membership operation can resume after loss of its
live provider-owned value.

## Decision

Use one inviter-local durable owner for both active invitation generations and
non-authorizing capability-authorization shadows. The SQLCipher laboratory is
the first adapter, but these state and ownership rules are provider-neutral.

### Durable invitation opening context

Before an invitation descriptor is shared, one atomic issuance transition must
store:

- the exact canonical signed invitation v2, bounded by the protocol's 512-byte
  maximum; and
- the exact 32-byte invitation-scoped HPKE private key in an opaque,
  non-cloneable, non-formattable storage value.

Loading re-verifies the canonical invitation and signature, checks the exact
invitation ID/generation/HPKE public-key binding, and rejects expired,
unsupported, malformed, missing, or conflicting state. The one-time Ed25519
signing seed is not retained after issuance. The stored bearer invitation and
HPKE private key are secrets at rest and never enter logs, diagnostics,
transport metadata, or public evidence.

Every operation that restores the opening context, including authorization
reservation after an earlier successful load, repeats these checks inside its
write transaction. A malformed private key or failed invitation restoration
atomically changes the exact `Available` generation to `Unusable` and zeroes
the retained opening key before returning a coarse rejection.

An invitation generation may return from `Reserved` to `Available` after a
pre-membership restart only when this exact opening context reloads
successfully and remains unexpired. Otherwise the generation becomes
terminally `Unusable`; recovery must not advertise a false `Available` state or
generate replacement keys under the old generation.

### Durable authorization shadow

After all automated checks pass and the exact local invitation is reserved,
the durable owner stores one bounded shadow containing:

- exact invitation ID and generation signature;
- join-request ID and nonce;
- intended verifier and the complete non-secret ADR 0009 binding tuple;
- exact SHA-256 fingerprint of the canonical protected request;
- request and invitation expirations;
- a provider-generated nonzero authorization-attempt ID; and
- the current closed state and any exact membership transaction ID.

This shadow is a replay/conflict and recovery record only. It contains no
parsed KeyPackage, KeyPackage bytes, HPKE-open plaintext, bearer capability,
provider proof, invitation HPKE private key, MLS pending Commit, group secret,
or value that can authorize MLS Add. Display-only `ApprovalContext` data is
never treated as stronger authority.

The closed authorization states are:

```text
PendingApproval
  | explicit approve
  v
ApprovedPendingMembership
  | exact transaction ID recorded before membership storage may begin
  v
MembershipOutcomeUnknown
  | authorized membership write commits atomically
  +--> Committed
  `--> exact recovery proves no commit --> Abandoned

PendingApproval ----------> Rejected | Abandoned
ApprovedPendingMembership -> Abandoned
```

`ApprovedPendingMembership` records the simulated decision but still grants no
membership authority. A process restart in either pre-membership live state
atomically records `Abandoned`, retains replay state, and releases only the
matching invitation generation when its opening context remains valid.

Once membership storage may have begun, the provider-applied Add exposes its
non-forgeable binding only inside an inseparable stage-and-write operation tied
to the same group instance and state revision. Any intervening state-changing
provider operation invalidates that authority, and the storage callback must
run under the one-shot provider-write authority activated on its originating
thread. Before delegating to caller-supplied storage, an MLS-owned wrapper
records a domain-separated SHA-256 digest over the exact serialized group state
and ordered epoch insert/update records emitted by that callback. The durable
owner recomputes and matches that digest, preventing a safe delegating wrapper
from substituting state while retaining the thread authority. The authorized inviter write
rechecks its exact KeyPackage reference, credential identity, leaf key, group,
epoch, Welcome, attempt, transaction, invitation generation, request binding,
reserved opening context, and fresh monotonic elapsed time after acquiring the
database write lock. It then
atomically commits MLS state, the retained Welcome, `Committed`, and invitation
consumption. Exact recovery that wins the write lock first and proves no commit
records `Abandoned`, so a previously staged writer fails its commit-time check.
Known results and ambiguous post-commit results can be read idempotently in the
same open scope. A conflicting, malformed, or unavailable result remains
fail-closed in `MembershipOutcomeUnknown`; it never repeats MLS Add and never
releases the invitation.

Live `PendingApproval` and `ApprovedPendingMembership` handles both expose
explicit abandonment for known cancellation or failure. Legacy reservation and
inviter APIs reject any generation owned by the durable opening-context ledger.
Opening a store rejects terminal authorization rows that contradict their exact
opening, inviter result, or compatibility reservation.

Request ID, nonce, and request fingerprint remain reserved through the exact
invitation-generation expiry after rejection or abandonment. Expiry may
terminalize and compact those records only under a bounded policy; capacity
pressure never evicts a live or unexpired replay record. Restoring an older
database can still roll this state backward, so stale-snapshot rollback
resistance remains outside Phase 1.

The Phase 1 reference owner persists its policy with the store and accepts only
1 through 8 live invitation generations and 1 through 8 retained unexpired
authorization attempts. Reopen rejects a caller policy that differs from the
stored policy. When either bound is full, issue or reserve fails before partial
mutation; it does not evict a live generation or unexpired replay record.

## Consequences

- A restart cannot turn display metadata or identifiers into membership
  authority; pending provider-owned KeyPackages are deliberately abandoned.
- A different fresh request can use the same single-use invitation generation
  after safe abandonment only when the exact original opening context reloads.
- The durable store owns one invitation, replay, approval-result, membership,
  and Welcome-outbox history rather than splitting those ledgers.
- Active invitation secrets expand the SQLCipher laboratory's sensitive data
  surface and require bounds, migration, redaction, zeroization, expiry, and
  corruption tests.
- Phase 1 still makes no platform-vault, rollback-resistance, secure-deletion,
  human-approval UX, network, or production-durability claim.

## Alternatives considered

### Reconstruct a verified admission after restart

Rejected. KeyPackage references and approval metadata cannot recreate the exact
provider-parsed KeyPackage or its proof provenance without violating ADR 0009.

### Release the reservation without retaining invitation opening material

Rejected. The resulting generation would be labelled `Available` but could not
open a new protected request. Silent regeneration under the same generation
would break the signed HPKE binding.

### Persist the full pending admission value

Rejected for Phase 1. Serializing provider internals and live MLS authority
would enlarge the compatibility and secret surface and would obscure the safer
abandon-on-restart boundary.

### Erase replay state when a request is abandoned

Rejected. A captured request could be replayed after restart while the
invitation remains live. The bounded generation-expiry retention rule is the
Phase 1 tradeoff.
