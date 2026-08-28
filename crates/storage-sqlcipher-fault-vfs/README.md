# storage-sqlcipher-fault-vfs

Publish-disabled test support for the Session Chat L2 storage-fault suite.
It registers one non-default SQLite VFS named
`session-chat-storage-fault-v1`, delegates to the process default VFS, and
retains only bounded, secret-free operation evidence.

Retained integration tests prove non-default registration, ordinary-connection
bypass, explicitly named reachability, exact SQLite result codes, bounded pause
behavior with fail-closed premature release, closed role/ordinal validation,
optional-service forwarding, and fail-closed null or missing callback slots. The
crate is a root-workspace member so the common Rust matrix exercises it on
Linux, macOS, and Windows.

This crate is not production storage, a durability guarantee, a filesystem
model, or power-loss evidence. The adapter affects only connections that name
it explicitly.
