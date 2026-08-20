# Session Chat capability admission

`admission-capability` implements the first automated admission boundary for
ADR 0014's local secret-capability profile.

The verifier accepts only an `OpenedCapabilityJoinRequest` privately produced
by the HPKE PSK adapter. It independently validates the request's exact MLS
KeyPackage through the pinned MLS provider, compares the canonical reference,
`BasicCredential` identity, and leaf signature key, and returns a private,
non-`Clone`, non-`Debug` `VerifiedCapabilityAdmission`. That value owns both
the HPKE proof provenance and the parsed provider object.

Replay reservations bind the invitation ID, challenge, encryption key ID,
intended verifier, request ID, and nonce. Request IDs and nonces are single-use
within one invitation generation, while a freshly reissued generation is
independent. Request lifetime and retained state are bounded. Rejection cannot
evict a live reservation, and a monotonic reservation ID prevents a stale
release from deleting a replacement reservation.

The state is single-process and in memory. This crate does not implement manual
approval, invitation reservation or consumption, MLS Add, durable replay
protection, a Welcome outbox, mailbox behavior, or transport.
