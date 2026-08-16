# Rust Steering

## Scope And Enforcement

Use this guidance for Rust crates and workspaces under `{{RUST_ROOT}}`.

Repository-specific instructions and closer-scoped steering take precedence. Replace every
placeholder before enforcing this file.

The words **must**, **do not**, and **never** describe default requirements. Exceptions require a
documented reason, narrow scope, and a regression guard. Do not relax compiler, lint, test, safety,
or supply-chain gates merely to make a change pass.

## Toolchain, Cargo, And Reproducibility

- Declare the Rust edition and supported toolchain or MSRV explicitly.
- Pin repository development toolchains with `rust-toolchain.toml` when reproducibility requires it.
- CI must verify the declared MSRV for libraries that promise one and a current supported toolchain.
- Commit `Cargo.lock` for applications, binaries, and top-level workspaces. CI must use `--locked` or
  `--frozen` where network access is intentionally disabled.
- Centralize shared package metadata, dependencies, and lints in workspace tables and explicitly
  inherit them in members.
- Use the resolver appropriate to the declared edition and workspace policy.
- Do not use wildcard versions, unpinned Git revisions, mutable branches, or undocumented path
  overrides in release builds.
- Keep build scripts and procedural macros deterministic. Declare rerun inputs and do not perform
  hidden network access.
- Treat generated sources as outputs: change their source or generator, regenerate, and verify drift.

## Formatting, Lints, And Documentation

- `cargo fmt --check` must pass for all project-owned Rust source.
- `cargo clippy --workspace --all-targets` must pass with warnings denied.
- Enable `clippy::all`; consider `clippy::pedantic` deliberately. Never enable the entire
  `clippy::restriction` group—select individual restriction lints with documented intent.
- Configure workspace lints in `Cargo.toml` so local and CI behavior match.
- Lint allowances must be narrow and include a reason. Do not add crate-wide `allow` attributes to
  land a feature.
- Public items must have useful rustdoc when the crate exposes a supported API.
- Documentation examples must compile as doctests unless explicitly marked otherwise with a reason.
- Remove dead code and obsolete feature gates; do not retain commented-out implementations.

## Modules, Visibility, And DRY

- Keep module responsibilities cohesive and dependency direction explicit.
- Keep exports narrow. Default cross-module implementation details to `pub(crate)` and local details
  to private visibility.
- Do not expose dependency types, mutable internals, or synchronization primitives through a public
  API without making them part of the intentional compatibility contract.
- Avoid catch-all `utils`, `helpers`, or `common` modules with unrelated behavior.
- Separate pure computation and policy from I/O, serialization, persistence, UI, FFI, and runtime
  adapters.
- Reuse an existing parser, codec, validator, retry loop, client, or error mapping before adding a
  parallel implementation.
- Extract shared code when behavior and invariants are genuinely identical and copies could drift;
  do not add a generic abstraction solely to remove similar syntax.
- Remove obsolete implementations after migration. One behavior must have one authoritative path.
- Keep macros small and inspectable. Prefer functions and traits when compile-time generation adds no
  concrete value.

## Ownership And API Design

- Express ownership honestly. Do not add cloning, reference counting, interior mutability, or global
  state merely to bypass a design problem.
- Avoid unnecessary `clone`, `to_owned`, allocation, and collection materialization in hot or repeated
  paths; keep them when they make non-hot ownership clearer.
- Use newtypes for identifiers, units, validated values, or capabilities when they prevent invalid
  combinations.
- Use enums for closed states and make impossible states unrepresentable where doing so remains clear.
- Mark important returned values `#[must_use]` or use a type already carrying that contract.
- Implement standard conversion and borrowing traits consistently; do not invent parallel conversion
  naming when `From`, `TryFrom`, `AsRef`, or `Borrow` expresses the contract.
- Avoid panicking index operations when bounds are not proven. Prefer checked access at untrusted or
  data-dependent boundaries.
- Keep public trait bounds and generic parameters no broader than required.
- Review public API changes for SemVer compatibility, including feature and trait-implementation
  changes that may break downstream code.

## Errors And Failure Semantics

- Return `Result` for recoverable failure and `Option` only for expected absence.
- Use structured error types with stable variants at library boundaries and preserve error sources.
- Add context at boundaries where it helps diagnose the failed operation without exposing secrets.
- Do not use strings as programmatic error classifications.
- `unwrap`, `expect`, `panic!`, `todo!`, and `unimplemented!` are prohibited in production paths that
  can be reached through input, I/O, configuration, concurrency, or ordinary runtime state.
- A remaining panic must represent a locally proven invariant and include enough context to audit the
  proof. Tests may use panic assertions deliberately.
- Do not silently discard `Result`, partial-write, close, flush, join, or shutdown failures.
- Keep internal rich errors until the adapter responsible for mapping them to a stable external form.

## Unsafe Rust, FFI, And Native Boundaries

- Forbid unsafe code by default with the repository lint policy.
- If unsafe code is required, keep each block minimal and place a `SAFETY:` comment immediately next
  to it explaining every invariant used to discharge the proof obligation.
- Enable `unsafe_op_in_unsafe_fn`; an unsafe function body is not an implicit justification.
- Every `unsafe fn` and unsafe trait must document its caller or implementer obligations in a
  `# Safety` section.
- Wrap FFI behind a small safe API that validates pointers, lengths, ownership, lifetimes, threading,
  encodings, and error conventions.
- Use explicit `repr` attributes only where an external layout contract requires them and test that
  contract on supported targets.
- Do not unwind across FFI boundaries unless the ABI explicitly supports it and the behavior is
  tested.
- Unsafe changes require targeted tests and, when applicable, Miri, sanitizer, or platform-specific
  validation.

## Untrusted Input And Resource Bounds

- Validate lengths, ranges, encodings, variants, and structural limits before indexing, allocating,
  recursing, converting, or mutating durable state.
- Use checked arithmetic when overflow changes correctness or safety; use saturating/wrapping
  arithmetic only when that behavior is the documented contract.
- Bound payloads, decoded output, recursion, decompression ratios, redirects, retries, queues,
  collections, tasks, and process output.
- Reject malformed or oversized input deterministically. Do not silently truncate semantic data.
- Treat partial reads/writes, interrupted operations, unknown variants, and invalid encodings as
  normal failure cases to test.
- Normalize and constrain filesystem paths when input can influence them.
- Keep secrets out of errors, debug output, traces, fixtures, and serialized snapshots.
- Avoid deserializing directly into privileged or side-effecting types; validate before use.

## Concurrency, Async, And I/O

- Do not introduce or replace an async runtime incidentally.
- Every spawned task or thread must have a lifecycle owner, failure policy, and shutdown behavior.
- Bound task creation, worker pools, channels, retries, and buffered work.
- Keep blocking work off async executors through the runtime's documented blocking boundary.
- Do not hold synchronous lock guards across `.await`.
- Prefer message passing, ownership transfer, or immutable snapshots over shared mutable state when
  they simplify correctness.
- Treat cancellation as a normal path and make cleanup safe if a future is dropped at any await point.
- Apply explicit timeouts to external I/O and make retry safety and backoff observable.
- Never add `unsafe impl Send` or `unsafe impl Sync` without a documented proof and concurrency tests.
- Close files, sockets, child processes, temporary data, and runtime handles on every exit path.

## Dependencies, Features, And Supply Chain

- Add a crate only after checking the standard library and existing workspace dependencies.
- Keep default features intentional and dependency features minimal.
- Cargo features must be additive and safe to combine. Avoid mutually exclusive features; if they
  cannot be avoided, detect invalid combinations at compile time and test them.
- Review build dependencies and procedural macros as executable code with host access.
- Commit manifest and lock changes together and inspect duplicate versions and feature activation
  with `cargo tree` when dependency shape changes.
- Run the repository's vulnerability, license, and source-policy checks in CI.
- Do not suppress an advisory without a scoped rationale, affected-version analysis, owner, and
  review/removal condition.

## Performance And Efficiency

- Measure performance-sensitive changes with representative benchmarks and inputs.
- Choose algorithms and data structures with bounded, understood time and memory behavior.
- Avoid repeated allocation, copying, parsing, hashing, and lock acquisition in measured hot paths.
- Stream or iterate over large data instead of collecting it eagerly when ownership permits.
- Preallocate only from trusted or bounded size information.
- Caches must define keys, invalidation, synchronization, and memory bounds.
- Preserve clarity unless profiling demonstrates that a less direct implementation is necessary.

## Testing And Quality Gates

- Add focused unit tests for behavior, edge cases, failure paths, and every fixed defect.
- Test malformed, truncated, oversized, boundary, and overflow inputs for parsers and decoders.
- Add integration tests for filesystem, process, network, database, runtime, and FFI boundaries used
  by the crate.
- Public crates must run doctests and compatibility checks appropriate to their support policy.
- Test default features, no-default-features where supported, all features, and important feature
  combinations. Test supported target and MSRV matrices where promised.
- Use property tests or fuzzing for complex parsers, codecs, state machines, and invariant-heavy code.
- Unsafe code requires targeted invariant tests and applicable dynamic tooling.
- Keep default tests deterministic and independent of live network services.
- Formatting, compilation, Clippy, tests, docs, and supply-chain checks must run in CI with no new
  warnings.

## Verification

Run the smallest relevant checks first, then the complete gate:

```sh
{{RUST_FORMAT_COMMAND}}
{{RUST_CLIPPY_COMMAND}}
{{RUST_TEST_COMMAND}}
{{RUST_FEATURE_CHECK_COMMAND}}
{{RUST_DOC_COMMAND}}
{{RUST_DEPENDENCY_AUDIT_COMMAND}}
{{RUST_MSRV_COMMAND}}
```

Report exact commands and results. If a check cannot run, state why and what risk remains.
