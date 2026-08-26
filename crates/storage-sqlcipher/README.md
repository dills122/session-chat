# storage-sqlcipher

`storage-sqlcipher` is the first file-backed encrypted persistence adapter for
the Session Chat protocol laboratory. It uses exact `rusqlite` 0.40.1 with
bundled SQLCipher 4.14.0, vendored OpenSSL, and an externally supplied nonzero
32-byte raw key. The vendored provider removes the Windows dependency on an
ambient `OPENSSL_DIR`; it does not make the resulting binaries reproducible.
The adapter retains SQLCipher's default memory policy: cryptographic allocations
are locked and sanitized, while the optional process-wide wiping of every SQLite
allocation remains disabled.

Retained tests exercise the real `session-crypto-mls` storage path on the
required Linux, macOS, and Windows CI runners and prove that:

- the inviter's MLS snapshot, invitation consumption, replay/approval result,
  and pending encrypted Welcome commit or roll back together;
- the joiner's joined MLS state and deletion of its exact one-time KeyPackage
  commit or roll back together across the two upstream storage calls;
- ambiguous post-commit results recover idempotently without repeating MLS;
- committed inviter and joiner results survive close and reopen;
- a wrong key is rejected and the closed database omits fixture plaintext and
  the normal SQLite header; and
- SQLCipher's page-HMAC integrity check succeeds for retained fixtures.

Schema version 2 now makes the same database the sole Welcome-outbox owner. It
persists one nonzero store identity, exact canonical Welcome and LocalV1
endpoint bytes, delivery state, bounded attempts, monotonic lease generation,
opaque lease identity, lease expiry, and the per-row attempt ceiling so restart
cannot reinterpret committed work. Schema metadata is bound to SQLite's
application `user_version`, migration takes an exclusive transaction, and each
open reads back the retained rollback-journal and synchronization settings.
`SqlCipherStorage` implements the
coordinator's `WelcomeOutboxPort` with one immediate SQL transaction per lease,
accepted result, or failed result. Explicit schema-v1 fixtures prove atomic
migration of valid pending work and rollback of invalid legacy delivery
material. Close/reopen tests cover old-open-scope, stale, and foreign leases,
expiry, exhaustion,
and byte-identical retry after an unrecorded remote acceptance without repeating
the retained MLS epoch or reopening invitation state.

The retained capability-composition test now drives a fresh HPKE-protected
request through exact capability admission, simulated explicit approval, and
the real MLS Add. Admission returns a one-shot durability-pending result: an
ambiguous SQL commit is recovered by transaction ID before the in-memory
invitation shadow is finalized. After close/reopen, the sole-owner coordinator
delivers the canonical Welcome once and the original joiner enters the exact
two-member group; replaying the protected request remains rejected.

This adapter is durability-laboratory evidence, not production storage. It has
no platform keychain integration, rollback anchor, disk-full or power-loss
evidence, rekey/backup/deletion policy, full durable-client identity recovery,
or secure-erasure guarantee. Hosted-runner evidence is not a production
packaging or broader hardware/OS compatibility claim.

```sh
cargo test -p storage-sqlcipher --all-features --locked --offline
cargo clippy -p storage-sqlcipher --all-targets --all-features --locked --offline -- -D warnings
```
