# Platform key-protector decision packet

Status: adapter capability contract implemented; first native probe selected,
no production platform adapter implemented

Reviewed: 2026-08-20

## Decision question

Can one cross-platform “keychain” adapter truthfully satisfy Session Chat's
device-bound and fresh-user-presence vault modes?

## Executive conclusion

No uniform claim is supported. Keep one provider-neutral capability contract,
but implement and assess native adapters separately. Select macOS Keychain
Services as the first `FreshUserPresence` probe using
`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` plus `userPresence`.

Windows DPAPI is a candidate for a weaker user/profile protection mode, not
fresh user presence. Linux Secret Service behavior is implementation-defined
at the item, collection, and cross-application unlock boundaries, so it must
report measured semantics and cannot claim device binding or a fresh prompt by
default. A generic Rust keyring facade is useful integration prior art but is
not the security-policy boundary.

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
- **Observation:** `session-storage` now reports key-storage, device-binding,
  user-presence, and backup dimensions independently. A policy requiring
  `DeviceBound` or `FreshUserPresence` rejects the deterministic protector
  before unsealing.

## Decision consequences

1. The core admits only reviewed, compiled adapters and validates their factual
   capabilities before key retrieval.
2. macOS is the first native probe because official APIs express the exact
   device-only plus fresh-prompt combination.
3. Windows needs a separate Windows Hello/CNG investigation before offering a
   fresh-presence mode; DPAPI alone may support only a weaker named mode.
4. Linux must identify and test the concrete Secret Service implementation and
   unlock-sharing behavior. Unsupported semantics fail closed.
5. No platform adapter is selected for production until native lifecycle,
   cancellation, screen-lock, biometric-change, backup, entitlement, signing,
   and headless-CI behavior has retained evidence.
