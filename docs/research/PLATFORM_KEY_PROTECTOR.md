# Platform key-protector decision packet

Status: bounded portable conformance adapter selected; production baseline and
native enhancements unselected

Reviewed: 2026-08-24

## Decision question

What key-protection baseline can one Session Chat local app provide on macOS,
Windows, and Linux without letting one native API shape the core vault?

## Executive conclusion

No uniform operating-system keychain claim is supported. ADR 0018 therefore
withdraws the macOS-first implementation order. Keep one provider-neutral
capability contract, select and prove one portable baseline on macOS, Windows,
and Linux first, and only then add native enhancements behind that boundary.

Windows DPAPI is a candidate for a weaker user/profile protection mode, not
fresh user presence. Linux Secret Service behavior is implementation-defined
at the item, collection, and cross-application unlock boundaries, so it must
report measured semantics and cannot claim device binding or a fresh prompt by
default. A generic Rust keyring facade is useful integration prior art but is
not the security-policy boundary.

ADR 0019 selects the passphrase candidate only for a bounded conformance
laboratory. Exact RustCrypto `argon2` 0.5.3 derives a 32-byte KEK with Argon2id
v1.3 and one fixed measurement profile (`m=65,536 KiB`, `t=3`, `p=4`). Exact
AWS-LC 1.16.3 AES-256-GCM then wraps one random 32-byte vault/database key with
a 16-byte random salt and 12-byte random nonce. The fixed authenticated record
is bound to a caller-supplied expected `SessionId`.

This does not select the production portable baseline. Parameter measurement,
offline-guessing exposure, credential acquisition, cancellation, recovery,
rekey and rollback behavior, secret-memory limits, atomic database-key handoff,
and cross-platform UX still need retained evidence. No SQLCipher or product path
uses the adapter.

## Evidence

- **Documented fact:** Apple says the device-only passcode accessibility class
  is unavailable without a passcode, is not synchronized through iCloud
  Keychain, and is not restored to another device. Its `userPresence` access
  control requires biometry or device passcode.
  [Apple keychain accessibility](https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility)
  and [user presence](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence).
- **Documented fact:** Windows `CryptProtectData` normally binds decryption to
  the same user credentials and computer. Machine scope permits any user on
  that computer. The API does not itself establish a fresh Windows Hello or
  biometric prompt.
  [Microsoft DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata).
- **Documented fact:** Secret Service may unlock a collection rather than one
  item, may share another application's unlocked state, and may relock at any
  time. Clients must handle those races.
  [Secret Service locking](https://specifications.freedesktop.org/secret-service/latest/unlocking.html).
- **Documented fact:** the Rust `keyring` project recommends that applications
  requiring control over concrete stores use `keyring-core` plus explicitly
  selected store modules instead of the all-in-one facade.
  [keyring API guidance](https://docs.rs/keyring/latest/keyring/).
- **Documented fact:** RFC 9106 specifies Argon2id, test vectors, parameter
  selection, memory wiping guidance, and a 64 MiB memory-constrained profile.
  These are inputs to measurement, not automatically suitable application
  parameters.
  [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html).
- **Documented fact:** RustCrypto `argon2` 0.5.3 implements Argon2id and exposes
  caller-provided memory through `hash_password_into_with_memory`.
  [`argon2` 0.5.3](https://docs.rs/crate/argon2/0.5.3) and
  [upstream source](https://github.com/RustCrypto/password-hashes/tree/master/argon2).
- **Source observation:** the exact dependency disables default features and
  enables only `zeroize`. The Session Chat adapter must explicitly own the
  Argon2 blocks as `Zeroizing<Vec<Block>>`; the convenience allocation path
  does not establish wiping of the whole allocation.
- **Unknown:** no primary-source independent audit specifically covering
  RustCrypto `argon2` 0.5.3 was found. RFC vectors and repository review do not
  fill that evidence gap.
- **Documented fact:** AWS-LC 1.16.3 exposes AES-256-GCM and randomized nonce
  handling. Its published verification inventory covers only named AES-GCM
  paths and configurations, not the complete Rust wrapper or AAD composition.
  [AWS-LC AEAD API](https://docs.rs/aws-lc-rs/1.16.3/aws_lc_rs/aead/) and
  [verification inventory](https://github.com/awslabs/aws-lc-verification).
- **Source observation:** pinned native AEAD context cleanup does not establish
  cleansing of every native key-schedule allocation.
- **Documented fact:** Rust lists hosted-tool Tier 1 targets for 64-bit macOS,
  Windows MSVC, and GNU Linux. This supports a common Rust-core build gate but
  does not prove native UI, credential-store, or packaging behavior.
  [Rust platform support](https://doc.rust-lang.org/rustc/platform-support.html).
- **Documented fact:** GitHub provides hosted `ubuntu-24.04`, `macos-15`, and
  `windows-2025` runner labels. These are the pinned first matrix representatives
  and remain mutable hosted images rather than reproducible-build evidence.
  [GitHub-hosted runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
- **Observation:** `session-storage` now reports key-storage, device-binding,
  user-presence, and backup dimensions independently. A policy requiring
  `DeviceBound` or `FreshUserPresence` rejects the deterministic protector
  before unsealing.

## Option comparison

| Option | Cross-platform baseline | Main limitation | Status |
| --- | --- | --- | --- |
| Passphrase-derived KEK wrapping a random vault key | Same design can run on all three families | Offline guessing, parameter tuning, recovery, rollback, cancellation, and memory handling | Selected only for bounded conformance laboratory by ADR 0019 |
| Native credential store on each family | Same interface, different factual guarantees | No uniform device-binding, prompting, backup, or availability semantics | Optional enhancement after baseline |
| One generic keyring facade as policy | Superficially portable | Backend selection hides the exact security properties policy needs | Rejected |
| macOS native adapter first | Strong fresh-presence candidate on one family | Allows one platform to shape the contract and leaves parity unproved | Withdrawn by ADR 0018 |

## Decision consequences

1. The core admits only reviewed, compiled adapters and validates their factual
   capabilities before key retrieval.
2. ADR 0019 fixes one closed 102-byte version-1 record for conformance: an
   authenticated 54-byte public prefix and 48-byte ciphertext/tag, bound to an
   out-of-band expected `SessionId`. Unknown versions, suites, profiles,
   parameters, lengths, and trailing bytes fail before KDF work.
3. The fixed profile is an RFC 9106 measurement starting point, not a final
   performance parameter. The same conformance fixtures and measurements must
   pass on Linux, macOS, and Windows before any baseline implementation claim.
4. Passphrases, KEKs, caller-owned Argon2 memory, and temporary plaintext use
   best-effort zeroizing Rust owners, but native key-schedule cleanup, registers,
   swap, dumps, UI copies, and OS snapshots remain unproved.
5. The synchronous Argon2 operation has no preemptive cancellation. A lifecycle
   may reject a late result by generation, but work already started continues
   until completion and cleanup. The current deterministic `session-storage`
   test rechecks the deadline after provider return; that is result-discard
   evidence only, not KDF cancellation or production scheduling evidence.
6. macOS Keychain remains a later enhanced-mode candidate because official APIs
   express device-only and fresh-prompt properties.
7. Windows needs a separate Windows Hello/CNG investigation before offering a
   fresh-presence mode; DPAPI alone may support only a weaker named mode.
8. Linux must identify and test the concrete Secret Service implementation and
   unlock-sharing behavior. Unsupported semantics fail closed.
9. No platform or portable adapter is selected for production until credential
   acquisition, atomic SQLCipher key handoff, lifecycle cancellation/result
   discard, rekey, rollback, recovery, offline-guessing UX, three-OS measurement,
   screen-lock, biometric-change, backup, entitlement, signing, and headless-CI
   behavior has retained evidence.
