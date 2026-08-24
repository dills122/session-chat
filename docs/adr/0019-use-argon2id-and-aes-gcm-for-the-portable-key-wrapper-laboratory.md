# ADR 0019: Use Argon2id and AES-GCM for the portable key-wrapper laboratory

Status: accepted for a bounded conformance laboratory; production baseline unselected

Date: 2026-08-24

## Context

ADRs 0016 and 0017 leave the durable database key outside the database, while
ADR 0018 requires one common macOS, Windows, and Linux key-protection workflow
before native enhancements may be considered implemented. The leading portable
candidate derives a key-encryption key (KEK) from a user passphrase and uses it
to wrap a random database or session key.

This construction has materially weaker properties than a proven device-bound
protector with fresh user presence. Anyone who copies the wrapped-key record can
attempt passphrase guesses offline. Argon2id increases the cost of those guesses
but cannot create passphrase entropy, bind the record to a device, or prevent a
captured older record from being restored.

## Decision

Adopt one exact construction only for a bounded, non-production conformance
adapter:

- RustCrypto `argon2` 0.5.3, default features disabled, with only its `zeroize`
  feature enabled; the standard-library adapter allocates its own block memory;
- Argon2id v1.3 deriving a 32-byte KEK from a non-empty passphrase of at most
  1,024 bytes;
- one fixed measurement profile: `m=65,536 KiB`, `t=3`, and `p=4`;
- one fresh 16-byte random salt for each wrapping operation;
- AWS-LC 1.16.3 AES-256-GCM with one fresh 12-byte random nonce;
- one fresh random 32-byte wrapped key; and
- one fixed 102-byte version-1 record with no extension or trailing-data path.

The 102-byte record is:

| Offset | Length | Field |
| ---: | ---: | --- |
| 0 | 8 | fixed Session Chat magic `SCVKWRP\0` |
| 8 | 2 | object version `1` |
| 10 | 2 | Argon2 profile identifier `1` |
| 12 | 2 | AEAD suite identifier `1` |
| 14 | 4 | Argon2 memory cost in KiB |
| 18 | 4 | Argon2 time cost |
| 22 | 4 | Argon2 parallelism |
| 26 | 16 | salt |
| 42 | 12 | nonce |
| 54 | 48 | encrypted 32-byte key and 16-byte authentication tag |

All integers use big-endian byte order. The AEAD additional authenticated data
is the exact `session-chat/portable-wrapped-session-key/v1\0` domain separator,
the exact 54-byte public prefix through the nonce, and the caller-supplied
expected `SessionId`. The session identifier is deliberately not stored in the
record. Opening the same bytes for another expected session must fail
authentication.

The parser accepts only the exact record length, magic, version, profile, suite,
and fixed parameter tuple. It rejects all unsupported values before starting
Argon2 or allocating parameter-controlled work. Salt, nonce, and wrapped-key
generation use provider randomness and fail closed if randomness fails. Wrong
passphrases, authentication failure, cross-session substitution, and malformed
records expose only coarse public failure categories.

AES-256-GCM is selected over AES-256-GCM-SIV for this laboratory because the
pinned provider has the stronger retained AES-GCM verification inventory. This
is not a nonce-misuse-resistance claim: salt and nonce freshness remain mandatory.

## Evidence and limits

- **Documented fact:** RFC 9106 specifies Argon2id, test vectors, memory-wiping
  guidance, and a 64 MiB memory-constrained profile. The selected tuple is a
  measurement starting point, not a final production parameter.
  [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)
- **Documented fact:** RustCrypto `argon2` 0.5.3 implements Argon2id and exposes
  caller-supplied memory for password hashing.
  [`argon2` 0.5.3 documentation](https://docs.rs/crate/argon2/0.5.3) and
  [upstream source](https://github.com/RustCrypto/password-hashes/tree/master/argon2)
- **Source observation:** the implementation disables default features and
  enables only `zeroize`. It must explicitly own the Argon2 block memory as
  `Zeroizing<Vec<Block>>`; the convenience
  allocator does not establish wiping of the entire allocation.
- **Unknown:** no primary-source independent audit specifically covering
  RustCrypto `argon2` 0.5.3 was found. Repository review and RFC vectors are not
  a substitute for such an audit.
- **Documented fact:** the pinned AWS-LC Rust provider exposes AES-256-GCM and a
  randomized-nonce API.
  [AWS-LC 1.16.3 AEAD API](https://docs.rs/aws-lc-rs/1.16.3/aws_lc_rs/aead/)
- **Documented fact:** AWS-LC publishes a partial AES-256-GCM verification
  inventory for named configurations. It does not prove this complete Rust
  wrapper composition or its AAD handling.
  [AWS-LC verification inventory](https://github.com/awslabs/aws-lc-verification)
- **Source observation:** the pinned native AEAD context cleanup does not
  establish cleansing of every native key-schedule allocation.

Passphrases, the KEK, caller-supplied Argon2 block memory, decrypt buffers, and
temporary plaintext use zeroizing Rust owners where their libraries permit it.
Secret-bearing values omit `Clone`, `Debug`, and `Display`. These are
best-effort process-memory measures, not secure-memory or secure-deletion
guarantees; registers, allocator copies, swap, crash dumps, UI controls, and OS
snapshots remain outside that claim.

The synchronous Argon2 0.5.3 path has no preemptive cancellation hook. A caller
may invalidate the vault generation and discard a late result, but Argon2 work
already in progress continues through completion and cleanup. The adapter must
bound passphrase bytes before starting the KDF; a later product caller must also
bound concurrent operations. Neither may claim that `p=4` means four-way
execution.

## Consequences

- The same closed record and conformance fixtures can be tested on Linux,
  macOS, and Windows without an OS-specific identifier in the contract.
- A copied record permits unlimited offline guessing. Product UX, passphrase
  policy, measured latency and memory, and an offline-guessing cost model remain
  required gates.
- Rewrapping under a new passphrase does not revoke a captured older record and
  does not establish rollback resistance.
- The adapter does not satisfy `DeviceBound` or `FreshUserPresence`; later
  native protectors must report those properties independently.
- This decision adds no SQLCipher wiring, recovery, rekey transaction, rollback
  anchor, device binding, user presence, secure deletion, UI, or production
  storage claim.
- ADR 0020 now permits only the deterministic lifecycle model to use an
  exact-session protector backed by this construction. The protector owns the
  wrapped record, consumes one passphrase credential per attempt, shares a
  nonzero concurrency limit, and returns a generation-bound candidate result.
- No durable or product path may use this construction until three-OS
  measurements, dependency review, desktop credential acquisition, production
  scheduling/isolation, atomic persistence and key handoff, rollback policy,
  and independent boundary review are complete.

## Alternatives

### AES-256-GCM-SIV

Deferred. Its nonce-misuse resistance is attractive, but the pinned provider's
retained implementation evidence is smaller. It remains a candidate if later
review changes the evidence balance.

### Native platform protector first

Rejected by ADR 0018. Native Keychain, Windows, and Secret Service adapters may
be stronger optional modes only after the portable contract and three-OS gate.

### Use the passphrase-derived value as the database key

Rejected. The passphrase derives only a KEK; the wrapped database or session key
is random provider output.

### Call the portable baseline production-ready

Rejected. The conformance laboratory intentionally leaves unresolved the
operational, persistence, rollback, recovery, endpoint, and UX boundaries that
would be required for such a claim.
