# SQLCipher inviter-store compatibility spike

Status: disposable compatibility experiment; not production storage

This isolated crate evaluates the exact stop conditions in
`docs/research/INVITER_STORAGE_ENGINE.md`. Production workspace crates do not
depend on it, and its independent lockfile records the native dependency graph
under evaluation.

The spike must not be used to claim product durability, rollback resistance,
or client-vault security. Its retained evidence is limited to the exact tested
platform, dependency graph, database configuration, and fault cases.
