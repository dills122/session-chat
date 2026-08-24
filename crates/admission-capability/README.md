# Session Chat capability admission

`admission-capability` implements the in-memory admission and explicit simulated
approval boundary for ADR 0014's local secret-capability profile.

Pending requests implement ADR 0015's provider-neutral `PendingAdmission`
observation seam. The returned approval context contains only redacted,
non-authorizing metadata; the capability adapter retains its original exact
proof, KeyPackage, and reservation authorities. The shared approval decision
therefore does not create a detachable or reconstructible membership token.

The verifier accepts only an `OpenedCapabilityJoinRequest` privately produced
by the HPKE PSK adapter. It independently validates the request's exact MLS
KeyPackage through the pinned MLS provider, compares the canonical reference,
`BasicCredential` identity, and leaf signature key, and returns a private,
non-`Clone`, non-`Debug` `VerifiedCapabilityAdmission`. That value owns both
the HPKE proof provenance, exact signed-invitation signature, and parsed
provider object. It never hands callers a byte string or reference that could
be paired with a replacement KeyPackage.

After automated verification, `reserve_v2_for_approval` binds the full HPKE
generation and exact invitation signature to the locally issued v2 record.
`decide_v2` consumes one explicit `Approve` or `Reject` input. Only the returned
approved one-shot value is accepted by `prepare_approved_add`; the former direct
verified-to-MLS public path no longer exists. A value from an unrelated verifier
cannot mutate invitation or MLS state.

Replay reservations bind the invitation ID, challenge, encryption key ID,
intended verifier, request ID, and nonce. Request IDs and nonces are single-use
within one invitation generation, while a freshly reissued generation is
independent. Request lifetime and retained state are bounded. Rejection cannot
evict a live reservation, and a monotonic reservation ID prevents a stale
release from deleting a replacement reservation.

Explicit rejection, request expiry, failed MLS preparation, or dropping a
prepared Add releases invitation and replay reservations and clears any pending
MLS Commit. Apply requires a fresh caller-supplied time and rechecks request,
response-endpoint, and invitation expiry before MLS mutation. Successful apply
advances MLS, consumes
the exact invitation in memory, and keeps replay state through request expiry.
Provider contradiction after MLS apply preserves the remaining authorities
fail-closed.

The state is single-process and in memory. `Approve` is a simulated headless
decision, not evidence of a human UI action. The apply/consume sequence is not
durable or crash-atomic. The committed result carries only the authenticated
deposit endpoint beside its MLS outputs, and a retained integration test
delivers the encrypted Welcome through the right-specific local mailbox. Durable
replay protection, the ADR 0008 membership transaction and Welcome outbox, and
network transport remain unimplemented.
