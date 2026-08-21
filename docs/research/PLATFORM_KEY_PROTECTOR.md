# Platform key-protector decision packet

Status: adapter capability contract implemented; cross-platform gate accepted,
portable baseline not yet selected

Reviewed: 2026-08-20

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

A user passphrase deriving a key-encryption key with a reviewed Argon2id
implementation, then wrapping a random vault/database key with a reviewed AEAD,
is the leading portable candidate. It is not selected yet: parameter tuning,
offline-guessing exposure, recovery, rekey, secret-memory handling, and
cross-platform UX need retained evidence before an ADR can adopt it.

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
| Passphrase-derived KEK wrapping a random vault key | Same design can run on all three families | Offline guessing, parameter tuning, recovery, and memory handling | Next bounded spike |
| Native credential store on each family | Same interface, different factual guarantees | No uniform device-binding, prompting, backup, or availability semantics | Optional enhancement after baseline |
| One generic keyring facade as policy | Superficially portable | Backend selection hides the exact security properties policy needs | Rejected |
| macOS native adapter first | Strong fresh-presence candidate on one family | Allows one platform to shape the contract and leaves parity unproved | Withdrawn by ADR 0018 |

## Decision consequences

1. The core admits only reviewed, compiled adapters and validates their factual
   capabilities before key retrieval.
2. The next spike must implement the portable candidate contract and the same
   conformance fixtures on Linux, macOS, and Windows; no native adapter lands
   first as a product increment.
3. macOS Keychain remains a later enhanced-mode candidate because official APIs
   express device-only and fresh-prompt properties.
4. Windows needs a separate Windows Hello/CNG investigation before offering a
   fresh-presence mode; DPAPI alone may support only a weaker named mode.
5. Linux must identify and test the concrete Secret Service implementation and
   unlock-sharing behavior. Unsupported semantics fail closed.
6. No platform adapter is selected for production until native lifecycle,
   cancellation, screen-lock, biometric-change, backup, entitlement, signing,
   and headless-CI behavior has retained evidence.
