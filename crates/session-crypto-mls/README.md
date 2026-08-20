# session-crypto-mls

Isolated Phase 1 adapter around the exact `mls-rs` and AWS-LC boundary selected
by ADR 0012.

This crate is a protocol laboratory. It does not provide durable storage,
rollback resistance, admission proof verification, a network transport, or a
production-security claim.
