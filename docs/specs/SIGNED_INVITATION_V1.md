# Spec: Signed capability invitation v1

Status: implemented in the Phase 1 protocol laboratory

## Objective

Add the first authenticated invitation boundary to the headless Rust protocol
laboratory. An inviter can sign one deterministic, expiring, single-use secret
capability invitation; a recipient can parse and authenticate it without
mutation; and the inviter-owned core can reserve, release, and consume local
state through the ADR 0008 lifecycle.

This slice proves invitation integrity, explicit signature-domain separation,
time-policy enforcement, local-issuance anchoring, and transition exclusivity.
It does not yet prove that admission validation or MLS membership actually
occurred before callers invoke the correspondingly named transition methods.

## Assumptions

1. The inviter signing key is fresh and invitation-scoped. The embedded public
   key proves only that one key signed the descriptor; authenticity still comes
   from the channel, later admission evidence, or an out-of-band fingerprint.
2. The descriptor is the Phase 1 secret-capability mode, so it intentionally
   contains a 32-byte bearer capability and must be shared through a secret
   channel. Targeted publicly postable invitations come later and must not use
   this schema as a bearer credential.
3. Callers supply cryptographically random key material, invitation IDs,
   challenges, and capabilities. This crate does not add an RNG or key-storage
   policy.
4. Expiration and allowed clock skew are acceptance policy, not transport
   behavior. The core receives an explicit current time and configurable
   maximum lifetime/skew so tests remain deterministic.
5. Descriptor validation is read-only. Only local issuance creates registry
   state. Reservation, release, and consumption are atomic within one `&mut`
   in-memory registry; durable cross-layer transactions are deferred.

## Tech stack

- Rust 1.97.1, edition 2024
- `minicbor` 2.3.0 for the restricted deterministic-CBOR profile in ADR 0005
- `ed25519-dalek` 3.0.0 with only `fast` and `zeroize` features
- `zeroize` 1.9.0 for capability and temporary signing-buffer cleanup
- `thiserror` 2.0.20 for non-secret library errors

## Wire contract

`SignedCapabilityInvitationV1` is a fixed 12-item CBOR array:

| Position | Field | Constraint |
| ---: | --- | --- |
| 0 | Protocol version | unsigned integer `1` |
| 1 | Object type | unsigned integer `2` |
| 2 | Signature suite | unsigned integer `1` (`Ed25519`) |
| 3 | Invitation ID | exactly 16 bytes, not all zero |
| 4 | Issued at | unsigned Unix time in seconds |
| 5 | Expires at | unsigned Unix time in seconds; greater than issued at |
| 6 | Admission mode | unsigned integer `1` (`SecretCapability`) |
| 7 | Use policy | unsigned integer `1` (`SingleUse`) |
| 8 | Join challenge | exactly 32 bytes, not all zero |
| 9 | Secret capability | exactly 32 bytes, not all zero |
| 10 | Inviter verifying key | exactly 32-byte Ed25519 public key |
| 11 | Signature | exactly 64-byte Ed25519 signature |

The complete object is limited to 512 bytes before CBOR parsing. Definite
lengths, shortest integers, exact field count and types, no trailing bytes, and
decode/re-encode equality are mandatory.

The signature input is the ASCII domain label
`session-chat/signed-invitation/v1` followed by a zero byte and then the
canonical 11-item array containing positions 0 through 10. Verification uses
`VerifyingKey::verify_strict`; no generic Ed25519 signature from another
Session Chat object is valid for this domain.

## Commands

```sh
cargo test -p session-protocol --test signed_invitation
cargo test -p session-core --test invitation_registry
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

## Project structure

```text
crates/session-protocol/       # signed wire schema, canonical codec, signature verification
crates/session-core/           # inviter-owned availability/reservation/consumption lifecycle
docs/specs/                    # executable feature contract
docs/adr/                      # signature-suite and domain-separation rationale
```

## Code style

Public types keep fields private, expose typed accessors, and return explicit
errors without including secret bytes:

```rust
let validated = registry.validate_descriptor(&encoded_invitation, now)?;
let reservation = registry.reserve_after_admission(&validated, request_id, now)?;
registry.consume_after_membership(reservation, now)?;
```

Secret-bearing types do not implement `Debug` or `Clone`. The owned
`SecretCapability`, temporary decoded capability array, canonical verification
buffer, and temporary signature inputs are zeroized on drop. The returned
canonical `Vec<u8>` intentionally contains the bearer capability; callers own
its storage, copying, transmission, and cleanup. Rust zeroization cannot promise
removal of allocator, OS, backup, or hardware copies. No `unsafe`, panics on
attacker input, wall-clock reads, network calls, or ambient global state are allowed.

## Testing strategy

- Commit one exact signed wire fixture generated from a deterministic test key.
- Prove round-trip parsing, strict signature verification, and every public
  accessor against that fixture.
- Tamper each signed class of field and prove authentication fails.
- Reject wrong lengths and CBOR types for every field, unknown
  versions/object-types/suites/modes/use policies, non-deterministic integers,
  indefinite arrays and every byte string, trailing bytes, oversized inputs,
  zero decoded IDs/challenges/capabilities, and distinct invalid or weak keys.
- Prove descriptor validation never mutates lifecycle state; only local issuance
  consumes capacity; substituted same-ID descriptors cannot reserve local state;
  one request owns a reservation; release permits retry; only a matching
  reservation can be consumed; and rejected input leaves state unchanged.
- Run the complete workspace formatting, Clippy, and test gates after each
  complete increment.

## Boundaries

- Always: authenticate without mutation; validate time before every transition;
  require local issuance before reservation; reserve only after admission and
  KeyPackage binding checks; consume only with membership; keep state bounded;
  keep errors and debug output secret-free; update the threat model and roadmap.
- Ask first: change the Phase 1 admission mode; add persistent replay state;
  expose a public network/deep-link API; select HPKE or MLS dependencies.
- Never: put this bearer invitation in an opaque transport envelope or log;
  treat its self-contained key as GitHub/person identity; derive keys from the
  capability; implement a custom signature primitive; silently accept unknown
  suites or policies.

## Success criteria

1. A stable canonical fixture authenticates with `ed25519-dalek` 3.0.0.
2. Any changed signed byte fails before state mutation.
3. Descriptor validation succeeds only when signature and configured time policy
   are valid and does not create, reserve, or consume local state.
4. A remotely supplied self-signed descriptor cannot occupy inviter lifecycle state.
5. A locally issued invitation permits one reservation at a time, release is
   retryable, and a successful membership transition consumes it once.
6. A same-ID descriptor with another valid signature cannot operate on local state.
7. Lifecycle memory cannot exceed its configured capacity and expired entries are pruned.
8. Existing opaque-envelope behavior remains unchanged and still rejects an
   invitation object type.
9. All workspace gates pass with the lockfile.

## Follow-on decisions and deferred questions

- ADR 0014 now resolves the HPKE suite, invitation encryption key, protected
  join-request schema, and capability proof construction for a new local-only
  invitation v2 contract. It does not change or implement this v1 schema.
- Persistent transactional replay state and rollback protection
- Bounded-multi-use invitations and revocation
- Targeted GitHub and credential invitation schemas
- Deep-link and URL-fragment representation
