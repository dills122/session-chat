# Transport receive cursor and mailbox lifecycle research

Status: research recommendation; no persisted cursor or lifecycle implemented

Date: 2026-08-25

## Recommendation

Use an opaque provider cursor plus owner-store binding metadata and a
non-reused mailbox generation. Never make the cursor authority, never let the
protocol core parse it, and never let provider cursor state become the sole
durable receive checkpoint.

The owner store should atomically retain canonical envelopes, durable dedup
outcomes, exact acknowledgement intents, and the next opaque cursor before any
remote acknowledgement. The protected provider side retains routes,
capabilities, provider receipt handles, native offsets/revisions, retention
state, and provider-state epoch.

Every cursor must be bound to the exact profile, binding/configuration
fingerprint, mailbox continuity ID, generation, receive scope, cursor schema,
provider-state epoch, and expiry. It may overlap or replay earlier results but
cannot move the owner checkpoint backwards or authorize receive/acknowledge.

This follows established opaque-continuation behavior: [Google AIP-158](https://google.aip.dev/158)
requires request-bound opaque tokens and independent authorization;
[IMAP UIDVALIDITY](https://www.rfc-editor.org/rfc/rfc9051.html#section-2.3.1.1)
binds stable message identity to a mailbox generation; and
[Microsoft Graph delta](https://learn.microsoft.com/en-gb/graph/delta-query-overview)
uses opaque snapshot state that can require explicit resynchronization.

## Crash ordering

1. Validate separate receive authority and exact cursor binding.
2. Obtain one bounded provider page.
3. Atomically store envelopes, dedup outcomes, exact acknowledgement intents,
   and a compare-and-swap cursor advance.
4. Acknowledge only after the owner transaction commits.

Before commit, replay from the prior cursor is safe through durable dedup. After
commit but before acknowledgement, durable exact intents recover. Ambiguous
acknowledgement retries use only the same bounded ID set while the generation
remains eligible. `cursor=None` is valid only for a new generation or explicit
bounded resynchronization; `InvalidCursor` never silently falls back to it.

## Rotation

Use a compare-and-swap lifecycle:

```text
Active(g) -> Preparing(g+1) -> Draining(g,g+1) -> Active(g+1) -> Retired(g)
```

The transition consumes one rotation right, compares the exact predecessor,
uses a unique rotation ID, issues fresh independent rights, and never reuses a
generation. Routine rotation may drain the predecessor under a bound;
compromise rotation immediately retires it and accepts possible loss.

## Explicit limitations

- The current memory profile correctly rejects every cursor.
- No durable receive-state store, binder, lifecycle trait, provider epoch, or
  rollback-resistant generation anchor exists.
- A restored local database cannot detect its own rollback without provider or
  external monotonic evidence.
- No network provider or acknowledgement-handle policy is selected.

Task 7 should add manifest declarations for cursor schema, persistence/epoch,
generation, rotation/drain, and acknowledgement scope. Task 8 should add a
separate receive-state owner port; sender-side Welcome outbox state does not
belong in that port.
