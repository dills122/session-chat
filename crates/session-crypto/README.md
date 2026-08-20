# session-crypto

Provider-neutral application contract for one already-established Session Chat
message session.

The crate deliberately contains no cryptographic implementation and no provider
factory. It defines bounded opaque protected messages, redacted message events,
coarse errors, and the object-safe `MessageSession` interface. A client may
select an allowlisted implementation for a newly created session at its trusted
composition root. It must not silently replace the implementation for an active
session.

`session-crypto-mls` is the only implementation currently retained. Admission,
membership creation and joining, durable storage, migration, transport, and
provider discovery are outside this narrow interface. Adding another backend
requires its own reviewed dependency boundary and the same conformance,
malformed-input, lifecycle, persistence, and interoperability evidence; merely
implementing the Rust trait is not security evidence.
