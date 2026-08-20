# session-crypto-mls

Isolated Phase 1 adapter around the exact `mls-rs` and AWS-LC boundary selected
by ADR 0012.

This crate is a protocol laboratory. It does not provide durable storage,
rollback resistance, admission proof verification, a network transport, or a
production-security claim.

## Retained boundary

The adapter currently provides:

- MLS 1.0 with the exact `CURVE25519_AES128` ciphersuite and pinned reduced
  `mls-rs`/AWS-LC feature graph from ADR 0012;
- nonzero 32-byte session credential and group identifiers;
- a one-hour KeyPackage lifetime checked against caller-supplied time;
- a bounded external KeyPackage validator that returns a private, non-`Clone`
  value owning the exact validated message, reference, credential identity,
  and leaf signature key;
- in-memory two-member Add/Welcome, application-message, path-update, and
  removal transitions with explicit prepare/apply stages; and
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
admission. ADR 0009's admission proof and approval layer remains unimplemented.

## Evidence and limits

Retained tests cover malformed, trailing, oversized, expired, replayed,
reordered, delayed, duplicate-identity, abandoned-pending-Commit, path-update,
third-member, and removal cases. A recording storage provider verifies that
create/prepare/apply cause no implicit group-state write and that an explicit
provider write causes one write.

All state is still process memory. The crate deliberately exposes no durable
write API: a future storage adapter must atomically coordinate MLS state,
joining-client KeyPackage deletion, invitation consumption, replay and approval
state, and the encrypted Welcome outbox. Cross-implementation fixtures,
crash/rollback recovery, old-secret deletion, platform coverage, fuzzing, and
an independent review of the exact `mls-rs`/AWS-LC boundary remain release
gates.
