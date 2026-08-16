# Spec: Signed capability invitation v1

Status: implemented in the Phase 1 protocol laboratory

## Objective

Add the first authenticated invitation boundary to the headless Rust protocol
laboratory. An inviter can sign one deterministic, expiring, single-use secret
capability invitation; a recipient can parse and authenticate it; and the core
can consume it once in bounded in-memory state.

This slice proves invitation integrity, explicit signature-domain separation,
time-policy enforcement, and replay rejection. It does not yet prove admission,
encrypt a join request, create an MLS group, or identify the inviter as a
GitHub account or real-world person.

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
5. One-time consumption is atomic within one `&mut` in-memory registry. Durable
   and concurrent replay state is deferred to the persistence slice.

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
crates/session-core/           # expiration policy and bounded one-time consumption
docs/specs/                    # executable feature contract
docs/adr/                      # signature-suite and domain-separation rationale
```

## Code style

Public types keep fields private, expose typed accessors, and return explicit
errors without including secret bytes:

```rust
let accepted = registry.accept(&encoded_invitation, now)?;
assert_eq!(accepted.invitation_id(), &expected_id);
```

Secret-bearing types do not implement `Debug`. Capability buffers and temporary
signature inputs are zeroized on drop. No `unsafe`, panics on attacker input,
wall-clock reads, network calls, or ambient global state are allowed.

## Testing strategy

- Commit one exact signed wire fixture generated from a deterministic test key.
- Prove round-trip parsing, strict signature verification, and every public
  accessor against that fixture.
- Tamper each signed class of field and prove authentication fails.
- Reject wrong lengths, field counts/types, unknown versions/suites/modes/use
  policies, non-deterministic integers, indefinite lengths, trailing bytes,
  oversized inputs, zero IDs/challenges/capabilities, and invalid public keys.
- Prove expiration boundary, future-issued policy, maximum lifetime, duplicate
  consumption, same-ID replay under another valid signature, capacity bounds,
  expired-entry pruning, and no state mutation on rejected input.
- Run the complete workspace formatting, Clippy, and test gates after each
  complete increment.

## Boundaries

- Always: authenticate before consumption; validate time before mutation; keep
  replay state bounded; keep errors and debug output secret-free; update the
  threat model and roadmap with implemented versus deferred claims.
- Ask first: change the Phase 1 admission mode; add persistent replay state;
  expose a public network/deep-link API; select HPKE or MLS dependencies.
- Never: put this bearer invitation in an opaque transport envelope or log;
  treat its self-contained key as GitHub/person identity; derive keys from the
  capability; implement a custom signature primitive; silently accept unknown
  suites or policies.

## Success criteria

1. A stable canonical fixture authenticates with `ed25519-dalek` 3.0.0.
2. Any changed signed byte fails before state mutation.
3. An invitation is accepted only when its signature and configured time policy
   are valid.
4. The same invitation ID cannot be accepted twice while the invitation is
   valid, even when replayed in another validly signed descriptor.
5. Replay memory cannot exceed its configured capacity and expired entries are
   pruned.
6. Existing opaque-envelope behavior remains unchanged and still rejects an
   invitation object type.
7. All workspace gates pass with the lockfile.

## Deferred questions

- HPKE suite, invitation encryption key, and encrypted join-request schema
- Capability proof construction and binding to a proposed session member key
- Persistent transactional replay state and rollback protection
- Bounded-multi-use invitations and revocation
- Targeted GitHub and credential invitation schemas
- Deep-link and URL-fragment representation
