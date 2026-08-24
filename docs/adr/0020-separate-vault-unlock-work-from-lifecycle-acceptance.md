# ADR 0020: Separate vault unlock work from lifecycle acceptance

Status: accepted; bounded deterministic orchestration implemented

Date: 2026-08-24

## Context

ADR 0016's first model called a protector while `complete_unlock` held the
vault lifecycle owner. That shape could reject a key after a provider advanced
past the deadline, but it did not model a worker that operates independently
of lock, sleep, logout, or replacement events. ADR 0019 additionally requires
one-shot passphrase acquisition and a process-wide bound before expensive
Argon2 work can enter any later product path.

The provider must never decide whether its returned key is still authorized.
The lifecycle owner must never retain an ambient passphrase merely to make a
synchronous trait convenient.

## Decision

Separate unlock into three linear stages:

```text
vault begin -> bounded credential/protector preparation -> vault acceptance
```

- `SessionVaultModel::begin_unlock` issues a non-cloneable request bound to one
  process-local vault instance, exact `SessionId`, monotonically increasing
  lifecycle generation, and minimum factual protection policy.
- The vault instance exposes no forgeable identifier. Request and completion
  values share private process-local ownership identity, so another vault with
  the same session and numeric generation cannot supply a valid completion.
- One shared `UnlockWorkLimiter` has a nonzero maximum and no internal queue.
  Saturation fails before credential acquisition or secret-bearing provider
  work. A linear permit releases its slot on every return and unwind path.
- `UnlockCredentialSource` yields one provider-specific credential for one
  exact session. `OneShotUnlockCredential` cannot be cloned or displayed,
  rejects a foreign session without consuming its value, and releases its
  value at most once.
- `SessionKeyProtector` consumes that credential. It reports factual
  capabilities before secret-bearing work, and a request below policy fails
  before acquiring the credential.
- The vault keeps a shared active unlock generation. Explicit lock, expiry
  polling, or replacement invalidates it. Preparation checks it before
  reserving work, before acquiring a credential, and again before provider
  entry. Cancellation observed at those points prevents the provider call.
- A provider already running cannot be preempted by this contract. Its returned
  key is carried only in a non-cloneable completion and is zeroized when the
  lifecycle rejects the vault instance, session, generation, deadline, or
  policy.
- Provider and credential errors cross the lifecycle boundary only as coarse
  vault errors. No credential, wrapped record, raw key, or provider detail is
  added to logs or generic metadata.

`key-protector-passphrase` implements this boundary for the fixed ADR 0019
record. Its protector owns one expected-session wrapped record and receives a
fresh `PortablePassphrase` for each attempt. It does not retain the passphrase,
open SQLCipher, or establish a production credential-input path.

## Retained evidence

Deterministic tests cover:

- current exact completion success;
- foreign-vault and stale-generation rejection without disturbing the current
  generation;
- explicit cancellation before work without credential consumption or
  provider entry;
- cancellation after preparation and completion after deadline without reopen;
- capability-policy rejection before credential or provider work;
- concurrency saturation before credential or provider work;
- exact-session, one-time credential acquisition; and
- correct portable passphrase unlock plus coarse wrong-passphrase failure.

## Limits and required next gates

This is process-local state-machine evidence. It does not provide an async
runtime, worker pool, OS process isolation, secure UI/IPC credential capture,
preemptive KDF cancellation, rate policy across processes, encrypted durable
state, SQLCipher key handoff, recovery, rollback resistance, or secure deletion.

Before a durable or product path uses the portable protector, complete the
remaining ADR 0019 gates: representative three-OS latency and peak-memory
measurements, desktop credential acquisition, production scheduling and
isolation, atomic wrapped-record/database-key persistence and handoff, rekey,
recovery, rollback policy, offline-guessing UX, and independent review.

## Alternatives

### Keep the protector inside the lifecycle model

Rejected. It prevents the lifecycle owner from independently processing lock
events while expensive or interactive provider work runs and hides the result
acceptance boundary.

### Store a passphrase inside the protector

Rejected. It creates ambient reusable secret state and obscures which attempt
consumes which credential.

### Add an async runtime and cancellable worker pool now

Deferred. The selected Argon2 API has no preemptive cancellation hook, and no
desktop runtime or scheduler has been selected. The provider-neutral linear
contract and deterministic adverse-race evidence are the smallest retained
foundation for that later decision.
