# Testing And Quality Gates

Testing must protect protocol behavior, security invariants, serialized contracts,
and adapter boundaries.

## Default Expectations

- Add or update focused tests for every behavior change.
- Cover malformed, missing, oversized, expired, replayed, duplicated, reordered,
  unauthorized, and rollback inputs where applicable.
- Keep fixtures small, explicit, deterministic, and free of real secrets.
- Treat captured wire objects and persisted state as evidence: assert that they
  contain no plaintext, group key material, bearer capability, or provider token.
- Use live services only in explicitly named integration suites.

## Before Finishing Work

Run the smallest reliable command that validates the changed area:

- Invitation-provider spike: `node --test spikes/sealed-invitation-provider/test/provider.test.mjs`
- AI Central link tooling: `node --test scripts/setup-codex-links.test.mjs`
- Rust formatting: `cargo fmt --check`
- Rust lint: `cargo clippy --workspace --all-targets -- -D warnings`
- Rust tests: `cargo test --workspace`
- Documentation hygiene: `git diff --check`

If a command cannot run locally, document why and the risk that remains.

## Quality Gates

- No known failing tests or new warnings are introduced.
- No unrelated formatting, generated artifact, or lockfile churn is included.
- Public contracts and fixtures change with behavior.
- Security-boundary changes include positive, negative, and adversarial tests.
- Membership tests prove new members cannot read past epochs and removed members
  cannot read future epochs.
- Persistence tests prove restore correctness and reject stale-state rollback.
- Transport tests operate on opaque envelopes and exercise loss, duplication,
  reordering, replay, and bounded-resource failure.
- Docs and ADRs reflect changes to setup, commands, protocol, or security claims.
