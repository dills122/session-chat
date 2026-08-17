## Scope

- [ ] The change is one bounded behavior, contract, test, documentation, or tooling increment.
- [ ] Unrelated formatting, generated files, and dependency churn are excluded.

## Security and protocol contracts

- [ ] I classified every changed claim as implemented, accepted-but-unimplemented, proposed, or deferred.
- [ ] Serialized or state-machine changes include compatibility fixtures and malformed/boundary tests.
- [ ] Security-boundary changes include the applicable expired, replayed, duplicated, reordered, unauthorized, rollback, and resource-exhaustion tests.
- [ ] Admission changes bind the exact KeyPackage, credential identity, and leaf key; transport changes preserve right-specific authority and private-mode no-downgrade.
- [ ] A consequential security or protocol decision updates its ADR and the threat model.
- [ ] No plaintext, key, bearer capability, provider token, or stable external identity was added to envelopes, logs, fixtures, or CI artifacts.

## Verification

List exact local commands and results, including anything that could not run:

```text

```

## Remaining risk

Describe unimplemented preconditions, follow-up research, and stop conditions. Use “none” only when that is evidence-backed.
