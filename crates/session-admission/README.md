# Session Chat admission contract

`session-admission` defines the provider-neutral approval seam used by the
headless composition root and later user interfaces.

`ApprovalContext` contains only the verified method, invitation ID, request ID,
canonical MLS KeyPackage reference, and request expiration needed to present
one decision. It contains no proof, bearer capability, parsed KeyPackage,
reservation token, or membership authority. Its identifiers and KeyPackage
reference are redacted from `Debug` output.

`PendingAdmission` is object-safe, but it exposes only that display context.
The concrete admission provider continues to own its non-cloneable verified
evidence and exact parsed KeyPackage until its approved value is consumed by
membership preparation. `ApprovalDecision` is input to that concrete flow; a
copied context or decision grants no authority by itself.

This crate does not verify an admission proof, implement approval policy,
authorize MLS membership, dynamically load providers, or provide durable
approval state.

## Verification

```sh
cargo test -p session-admission --all-features --locked --offline
cargo clippy -p session-admission --all-targets --all-features --locked --offline -- -D warnings
```
