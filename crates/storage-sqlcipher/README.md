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

Schema version 3 retains the version-2 sole Welcome-outbox owner and adds one
opaque versioned MLS client-identity record. Version 4 binds that record to one
exact nonzero 32-byte group identifier. The MLS adapter creates it once through a secret
type with no `Clone`, `Debug`, or `Display`, reloads the same credential and
signing key after close/reopen only for the bound group, and verifies that the
loaded group's local member has the same credential and signing public key.
Missing, malformed, replacement, cross-group, or mismatched identity state
fails closed. Version 5 adds a bounded invitation-opening context that commits
the exact canonical signed invitation and matching invitation-scoped X25519
private key before publication. Reload re-authenticates the invitation, proves
the private/public-key binding, and terminalizes expired or invalid context
without returning it as available. The same schema retains bounded,
non-authorizing request shadows through `Pending`, `Approved`,
`OutcomeUnknown`, `Committed`, `Rejected`, and `Abandoned` states. Typed
one-shot handles bind transitions to the exact store, attempt, invitation
generation, and membership transaction. The authorized inviter write rechecks
that binding after acquiring the database write lock and consumes a
provider-created `CommittedAdditionStorageBinding` whose exact KeyPackage
reference, credential identity, leaf key, group, epoch transition, and Welcome
must match the retained authorization and inviter transaction. The MLS adapter
exposes that binding only inside an inseparable stage-and-write operation tied
to the exact group instance and state revision. The actual callback must also
carry the one-shot authority activated by that provider operation on its
originating thread and match the MLS-owned digest of its exact serialized group
state and ordered epoch records, while commit-time expiry uses staging time
advanced by fresh monotonic elapsed time. It then
atomically commits MLS state, the Welcome outbox, `Committed`, and invitation consumption. A
concurrent recovery that first proves non-commit fences the staged writer;
known success, known pre-commit failure, and ambiguous post-commit results can
be finalized in the same open scope. Restart abandons pre-membership work, while
outcome-unknown recovery releases the invitation only after reconciling the
exact durable membership transaction. Replay identifiers remain
retained through the invitation expiry, and the persisted 1-through-8 owner
limits cannot be reinterpreted on reopen. The outbox portion
persists one nonzero store identity, exact canonical Welcome and LocalV1
endpoint bytes, delivery state, bounded attempts, monotonic lease generation,
opaque lease identity, lease expiry, and the per-row attempt ceiling so restart
cannot reinterpret committed work. Schema metadata is bound to SQLite's
application `user_version`; the v1-to-v2, v2-to-v3, v3-to-v4, and v4-to-v5 migrations take
exclusive transactions, and v4-to-v5 persists the caller-selected bounded
authorization policy inside that transaction. A frozen schema-v2 fixture preserves leased, delivered,
and attempts-exhausted outbox rows plus the store identity through v5, while a
forced migration conflict proves that versions and rows roll back intact. A
frozen schema-v3 transition proves that a real legacy identity/group pair stays
reloadable when exactly one structurally valid nonzero group identifier exists;
the migration does not decode provider-owned MLS state, which the MLS reload
boundary still rejects when malformed. Ambiguous binding rolls back at version
3. Each open reads back the retained rollback-journal and synchronization settings.
Migration from versions 1 and 2 intentionally leaves the new identity table
empty because those databases never retained enough material to reconstruct the
same client; callers must not generate a replacement and attach it to an old group.
`SqlCipherStorage` implements the
coordinator's `WelcomeOutboxPort` with one immediate SQL transaction per lease,
accepted result, or failed result. Explicit schema-v1, schema-v2, and schema-v3 fixtures
prove atomic migration of valid retained work and rollback of invalid or
conflicting migration state. Close/reopen tests cover old-open-scope, stale,
and foreign leases,
expiry, exhaustion,
and byte-identical retry after an unrecorded remote acceptance without repeating
the retained MLS epoch or reopening invitation state.

Schema validation also rejects terminal authorization rows that contradict the
opening-context, exact inviter-result, or compatibility-reservation state.
Legacy reservations and inviter writes cannot claim a generation present in the
durable opening-context ledger, even before an authorization attempt exists.

The retained capability-composition tests now drive a fresh HPKE-protected
request through exact capability admission, simulated explicit approval, the
durable authorization owner, and the real MLS Add. Invitation opening context
commits before publication; pending and approved requests survive only as
non-authorizing shadows. An ambiguous SQL commit is recovered by the exact
authorization-attempt and transaction IDs before the provider's in-memory
shadows are settled. After close/reopen, the sole-owner coordinator delivers
the canonical Welcome once and the original joiner enters the exact two-member
group; replaying the protected request remains rejected by durable state. A
separate restart test abandons lost approved provider authority, retains replay,
reloads the exact opening generation, and permits a different fresh request.
Both `sessionctl` paths use the same durable owner.

This adapter is durability-laboratory evidence, not production storage. It has
no platform keychain integration, rollback anchor, disk-full or power-loss
evidence, rekey/backup/deletion policy, independent-process client runner,
or secure-erasure guarantee. Its exact identity/group close-reopen test is not
process-kill, rollback, or platform-vault evidence. Hosted-runner evidence is not a production
packaging or broader hardware/OS compatibility claim.

```sh
cargo test -p storage-sqlcipher --all-features --locked --offline
cargo clippy -p storage-sqlcipher --all-targets --all-features --locked --offline -- -D warnings
```
