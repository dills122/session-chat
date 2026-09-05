# Session Chat HPKE join protection

`session-crypto-hpke` implements the provider-neutral, one-shot RFC 9180 PSK
operation selected by ADR 0014 for the local capability join profile.

The public boundary accepts only typed `session-protocol` invitation and join
objects. It constructs the fixed PSK identifier, HPKE `info`, and canonical
outer AAD internally; callers cannot choose a mode, suite, domain, or raw
context. The object-safe trait permits a client composition root to select a
compiled implementation without leaking provider types or switching an
in-flight operation. The first concrete adapter uses the pinned AWS-LC-backed
`mls-rs` provider. Its invitation private-key wrapper is non-`Clone`,
non-`Debug`, and zeroizes on drop.

The same provider boundary can generate a complete invitation-v2 context. It
uses the selected AWS-LC CSPRNG for the invitation ID, challenge, bearer
capability, encryption-key ID, and Ed25519 signing seed, and generates the HPKE
keypair through the existing provider operation. Callers provide only the issue
and expiration times. A dedicated sink projects the canonical invitation and
an ephemeral private-key view into protected storage without a generic callback
return path. Restore consumes an opaque, non-cloneable, zeroizing key transfer
object and accepts only an exact canonical signed invitation whose stored
X25519 private key derives the public key authenticated by that invitation;
oversized, malformed, or mismatched parts fail through the same coarse error
surface.

Successful open returns a privately constructed, non-`Clone`, non-`Debug`
`OpenedCapabilityJoinRequest`. The later admission boundary can therefore
require proof that the request passed this exact cryptographic operation instead
of accepting an ordinary locally constructed request value.

Retained evidence includes:

- the official RFC 9180 PSK known-answer vector for X25519, HKDF-SHA256, and
  AES-128-GCM;
- an AWS-LC-produced ciphertext opened by the independent `hpke` crate, which
  is a dev-only oracle rather than a runtime dependency;
- two complete generated invitations with independent random fields, canonical
  authentication, and a working seal/open round trip;
- a close/reload protected-storage-sink round trip plus malformed, oversized, and
  wrong-private-key rejection;
- exact canonical inner round trips; and
- rejection of wrong keys, changed signed context, mismatched inner bindings,
  and tampered encapsulation, ciphertext, or outer AAD fields through one
  coarse public error.

This crate does not enforce realm time policy, track replay, approve admission,
reserve or consume an invitation, validate an MLS KeyPackage, mutate MLS state,
operate a mailbox, or provide durable key storage.
Successful open proves PSK possession for the exact cryptographic context only;
the later admission state machine must enforce the remaining policy before any
mutation.
