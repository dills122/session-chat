# storage-sqlcipher-fault-vfs

Publish-disabled test support for the Session Chat L2 storage-fault suite.
It registers one non-default SQLite VFS named
`session-chat-storage-fault-v1`, delegates to the process default VFS, and
retains only bounded, secret-free operation evidence.

This crate is not production storage, a durability guarantee, a filesystem
model, or power-loss evidence. The adapter affects only connections that name
it explicitly.
