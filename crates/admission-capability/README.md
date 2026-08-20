# Session Chat capability admission

`admission-capability` implements the first automated admission boundary for
ADR 0014's local secret-capability profile.

The verifier accepts only an `OpenedCapabilityJoinRequest` privately produced
by the HPKE PSK adapter. It independently validates the request's exact MLS
KeyPackage through the pinned MLS provider, compares the canonical reference,
`BasicCredential` identity, and leaf signature key, and returns a private,
non-`Clone`, non-`Debug` `VerifiedCapabilityAdmission`. That value owns both
the HPKE proof provenance and the parsed provider object. The verifier can move
that exact object directly into the MLS prepare/apply boundary. It never hands
callers a byte string or reference that could be paired with a replacement
KeyPackage.

Before MLS preparation, the verifier rechecks that the one-shot value owns an
exact reservation in that verifier instance. A value from an unrelated
verifier cannot mutate MLS state.

Replay reservations bind the invitation ID, challenge, encryption key ID,
intended verifier, request ID, and nonce. Request IDs and nonces are single-use
within one invitation generation, while a freshly reissued generation is
independent. Request lifetime and retained state are bounded. Rejection cannot
evict a live reservation, and a monotonic reservation ID prevents a stale
release from deleting a replacement reservation.

Rejected or expired preparation releases replay state. Dropping a prepared Add
clears both the MLS pending Commit and its replay reservation; applying it keeps
the replay reservation through request expiry.

The state is single-process and in memory. This crate does not implement manual
approval, invitation reservation or consumption, durable replay protection, an
atomic membership transaction, a Welcome outbox, mailbox behavior, or transport.
