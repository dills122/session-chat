# storage-sqlcipher

`storage-sqlcipher` is the first file-backed encrypted persistence adapter for
the Session Chat protocol laboratory. It uses exact `rusqlite` 0.40.1 with
bundled SQLCipher 4.14.0, vendored OpenSSL, and an externally supplied nonzero
32-byte raw key. The vendored provider removes the Windows dependency on an
ambient `OPENSSL_DIR`; it does not make the resulting binaries reproducible.
Because that bundled provider owns process-global activation state, the adapter
serializes all native SQLCipher calls across open stores, including connection
setup and teardown. This is a correctness boundary, not a concurrent-throughput
claim.

Retained tests exercise the real `session-crypto-mls` storage path and prove on
the tested macOS host that:

- the inviter's MLS snapshot, invitation consumption, replay/approval result,
  and pending encrypted Welcome commit or roll back together;
- the joiner's joined MLS state and deletion of its exact one-time KeyPackage
  commit or roll back together across the two upstream storage calls;
- ambiguous post-commit results recover idempotently without repeating MLS;
- committed inviter and joiner results survive close and reopen;
- a wrong key is rejected and the closed database omits fixture plaintext and
  the normal SQLite header; and
- SQLCipher's page-HMAC integrity check succeeds for retained fixtures; and
- concurrent store handles cannot race the process-global provider lifecycle.

This adapter is durability-laboratory evidence, not production storage. It has
no platform keychain integration, rollback anchor, cross-platform build/fault
evidence, disk-full or power-loss evidence, migration/rekey/backup/deletion
policy, durable outbox leasing, or secure-erasure guarantee.

```sh
cargo test -p storage-sqlcipher --all-features --locked --offline
cargo clippy -p storage-sqlcipher --all-targets --all-features --locked --offline -- -D warnings
```
