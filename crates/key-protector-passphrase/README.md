# key-protector-passphrase

`key-protector-passphrase` is a bounded, non-production conformance adapter for
the portable key-wrapping candidate selected for laboratory work by ADR 0019.
It derives a 32-byte key-encryption key with exact RustCrypto Argon2id v1.3 and
uses the repository's pinned AWS-LC AES-256-GCM implementation to wrap one
fresh random 32-byte session key.

Version 1 fixes the Argon2 measurement profile at 65,536 KiB, three passes,
and four lanes. It uses a fresh 16-byte salt and 12-byte AEAD nonce. These are
RFC 9106's memory-constrained starting parameters, not a final performance or
production-security selection.

The canonical record is exactly 102 bytes:

| Offset | Length | Field |
| ---: | ---: | --- |
| 0 | 8 | `SCVKWRP\0` magic |
| 8 | 2 | big-endian object version `1` |
| 10 | 2 | big-endian Argon2 profile `1` |
| 12 | 2 | big-endian AES-256-GCM suite `1` |
| 14 | 4 | big-endian memory cost `65,536` KiB |
| 18 | 4 | big-endian time cost `3` |
| 22 | 4 | big-endian lane count `4` |
| 26 | 16 | random Argon2 salt |
| 42 | 12 | random AEAD nonce |
| 54 | 48 | encrypted 32-byte key and 16-byte tag |

AEAD additional data is the fixed Session Chat domain, the exact 54-byte
public prefix, and the caller-supplied expected `SessionId`. The session ID is
not stored in the wrapper. Substitution into another session therefore fails
authentication, while the persisted object avoids adding that identifier.

The adapter owns raw passphrase bytes without Unicode normalization, rejects
empty or over-1,024-byte inputs before KDF work, uses a fallible fixed-size
Argon2 allocation, and keeps the passphrase, KEK, Argon2 blocks, plaintext key,
and temporary ciphertext/plaintext buffers in zeroizing owners where their
Rust types permit it. It returns one coarse public rejection for malformed
input, wrong context or passphrase, randomness failure, or authentication
failure.

The exact-session `PortablePassphraseKeyProtector` now implements the
provider-neutral lifecycle boundary. It owns only the wrapped record; each
unlock consumes a separately supplied one-shot passphrase credential through
`session-storage`'s bounded work/result contract. Cancellation before provider
work preserves an unacquired credential, while cancellation or expiry after
Argon2 starts discards the eventual key result. Argon2 itself remains
non-preemptible.

This crate is not connected to `storage-sqlcipher` and does not provide a
desktop passphrase UI, password-quality enforcement, recovery, rekey
persistence, rollback resistance, device binding, fresh user presence, backup
exclusion, memory locking, secure deletion, or production storage. A copied
record permits offline passphrase guesses. Best-effort zeroization does not
establish removal from registers, allocator copies, native provider state,
swap, crash dumps, or OS snapshots.

```sh
cargo test -p key-protector-passphrase --all-features --locked --offline
cargo clippy -p key-protector-passphrase --all-targets --all-features --locked --offline -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc -p key-protector-passphrase --all-features --no-deps --locked --offline
```
