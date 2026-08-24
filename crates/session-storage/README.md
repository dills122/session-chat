# session-storage

`session-storage` defines the current sealed-vault and bounded opaque-inbox
contracts. Its first implementation is a deterministic in-memory conformance
model for:

- `Sealed -> Unlocking -> Open(session) -> Relocking -> Sealed` transitions;
- linear vault-instance/session/generation-bound unlock completions that reject
  stale, foreign-owner, relock, and import ABA;
- provider work prepared outside the lifecycle owner, with a nonzero shared
  concurrency bound and no internal queue;
- exact-session one-shot credential acquisition that fails before provider work
  when the request was cancelled or the selected protection is insufficient;
- immediate sealing on explicit lock, timeout, screen lock, sleep, logout, or
  process-exit events;
- rejection of decrypt, signing, admission, receive-capability read,
  acknowledgement, rotation, and MLS mutation before privileged work runs;
- canonical pre-bounded opaque-envelope append in every vault state; and
- open-generation-bound local import without granting remote acknowledgement.

The deterministic clock and key protector are test providers. The protector
retains an unwrapped fixture key in memory and provides no at-rest or
user-presence evidence. The orchestration model invalidates queued work and
discards results that return after cancellation, replacement, or deadline; it
does not preempt provider work already running.

This crate does not provide encrypted persistence, SQLCipher integration,
platform keychain or secure-hardware protection, a production inbox, durable
transactions, rollback resistance, crash recovery, rekey, backup, deletion, or
cryptographic-erasure guarantees.

```sh
cargo test -p session-storage --all-features --locked --offline
cargo clippy -p session-storage --all-targets --all-features --locked --offline -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc -p session-storage --all-features --no-deps --locked --offline
```
