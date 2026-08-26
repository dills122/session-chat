# session-crypto-mls

Isolated Phase 1 adapter around the exact `mls-rs` and AWS-LC boundary selected
by ADR 0012.

It implements the provider-neutral established-session `MessageSession`
contract from ADR 0013. Applications using that contract do not import
`mls-rs` types or errors. The concrete API remains explicit for KeyPackage
validation, group creation/joining, membership transitions, and Welcome
ownership because those security semantics are not yet generalized across
multiple implementations.

This crate is a protocol laboratory. It does not provide durable storage,
rollback resistance, admission proof verification, a network transport, or a
production-security claim.

## Retained boundary

The adapter currently provides:

- MLS 1.0 with the exact `CURVE25519_AES128` ciphersuite and pinned reduced
  `mls-rs`/AWS-LC feature graph from ADR 0012;
- adapter-generated random 32-byte session credential identities and nonzero
  32-byte group identifiers supplied by the caller;
- a one-hour KeyPackage lifetime checked against caller-supplied time;
- a bounded external KeyPackage validator that returns a private, non-`Clone`
  value owning the exact validated message, reference, credential identity,
  and leaf signature key;
- in-memory two-member Add/Welcome, application-message, path-update, and
  removal transitions with explicit prepare/apply stages; and
- a versioned opaque durable-identity contract that creates once, reloads the
  same credential and AWS-LC signing key, and rejects a stored group whose local
  member does not match that reconstructed client; and
- coarse adapter errors that do not expose provider errors.

Untrusted serialized input is copied only after these outer bounds:

| Object | Maximum |
| --- | ---: |
| KeyPackage | 16 KiB |
| Welcome, Commit, or application wire message | 64 KiB |
| Application plaintext | 16 KiB |

Exact TLS decoding rejects trailing bytes. The Phase 1 policy accepts only
BasicCredential identities of the required length, no leaf or KeyPackage
extensions, no custom proposal capabilities, and at most two distinct members.
If an authenticated incoming Commit violates those roster invariants, the
local group instance fails closed and becomes unusable.

The selected upstream `BasicIdentityProvider` is only an MLS credential-format
mechanism here. It does not authenticate a person or implement Session Chat
admission. The separate capability adapter implements the current exact-key
admission proof and simulated approval path; external providers and human
approval UX remain unimplemented.

## Evidence and limits

Retained tests cover malformed, trailing, oversized, expired, replayed,
reordered, delayed, duplicate-identity, abandoned-pending-Commit, path-update,
third-member, and removal cases. A recording storage provider verifies that
create/prepare/apply cause no implicit group-state write and that an explicit
provider write causes one write.

The default client helper still uses process memory. The durable helper requires
a caller-owned identity store, inserts exactly one 141-byte version-1 record,
and has a separate load-only path that never generates a replacement. The
record binds MLS 1.0, the selected ciphersuite, the pinned AWS-LC representation,
the 32-byte BasicCredential identity, 32-byte signing public key, and 64-byte
signing secret; malformed, unknown, absent, conflicting, and key-mismatched
records fail closed. The separate SQLCipher laboratory owns this record and the
MLS group/KeyPackage stores. This crate does not itself coordinate invitation,
replay, approval, outbox, or KeyPackage-deletion transactions. Remote
acknowledgement must not gate or roll back the inviter's committed membership.
An exact committed identity-v1 hex fixture uses RFC 8032 test-only Ed25519
material and proves the expected credential/public key can reload and sign a
KeyPackage accepted by the independent validation boundary.
Cross-implementation fixtures, crash/rollback recovery, old-secret deletion,
platform coverage, fuzzing, and an independent review of the exact
`mls-rs`/AWS-LC boundary remain release gates.
