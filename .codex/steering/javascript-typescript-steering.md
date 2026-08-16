# JavaScript And TypeScript Steering

## Scope And Enforcement

Use this guidance for JavaScript and TypeScript under `{{JAVASCRIPT_TYPESCRIPT_ROOT}}`.

Repository-specific instructions and closer-scoped steering take precedence. Replace every
placeholder before enforcing this file.

The words **must**, **do not**, and **never** describe default requirements. An exception requires a
documented reason, the narrowest possible scope, and a test or other guard against regression. Do
not weaken compiler, lint, test, or security gates merely to make a change pass.

## Runtime, Modules, And Reproducibility

- Pin the supported runtime and package-manager versions in repository-owned configuration.
- Use exactly one package manager for a dependency graph and commit its lockfile.
- CI must use the package manager's frozen or immutable install mode; it must not rewrite locks.
- Declare the module system explicitly. New modules must use ESM unless an existing compatibility
  boundary requires CommonJS.
- Use `import` and `export`; isolate unavoidable `require()` or `module.exports` interop.
- Use explicit relative file extensions where the runtime's native ESM resolver requires them.
- Use `node:` specifiers for Node built-ins and URL-aware APIs for module-relative paths.
- Keep module initialization free of hidden network, process, filesystem, timer, and registration
  side effects. Expose explicit startup and shutdown functions instead.
- Do not rely on experimental runtime behavior without an explicit project decision and CI coverage.

## TypeScript Safety

For TypeScript projects:

- Enable `strict` and keep it enabled.
- Enable `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`,
  `useUnknownInCatchVariables`, and `noImplicitOverride` unless a documented migration blocks one.
- New code must not introduce `any`. Use `unknown` and narrow it, or define the real type.
- Do not use `@ts-ignore`. A narrowly scoped `@ts-expect-error` must explain the expected diagnostic
  and link to a removal condition when it is not a permanent compatibility test.
- Avoid non-null assertions and unchecked type assertions. Prove the invariant with control flow,
  validation, or a small assertion function.
- Validate external data at runtime; TypeScript types do not validate JSON, environment variables,
  storage, messages, HTTP input, or JavaScript callers.
- Use discriminated unions for closed variants and exhaustive checks that fail compilation when a
  case is missed.
- Use primitive types such as `string` and `number`, not boxed `String` or `Number` types.
- Keep declaration output and runtime exports aligned for published packages.

JavaScript-only projects must enable the repository's static analysis and use JSDoc types where they
materially improve public contracts or complex data flow.

## Design, Cohesion, And DRY

- Keep modules cohesive and named for their responsibility. Do not create catch-all `utils`,
  `helpers`, or `common` modules that accumulate unrelated behavior.
- Separate pure transformation and decision logic from I/O and framework adapters.
- Keep CLI, route, event, and worker entrypoints thin: parse, validate, invoke, map, and report.
- Default to `const`. Limit mutation to the smallest owner and do not mutate caller-owned inputs.
- Prefer explicit data flow over hidden globals, service locators, monkey patching, or import-time
  registries.
- Reuse an existing implementation before adding another parser, validator, serializer, retry loop,
  or configuration loader.
- Extract shared code when the behavior and invariants are genuinely the same and duplicated copies
  could drift. Do not create an abstraction solely to remove similar-looking syntax.
- Delete obsolete paths after a migration; do not keep two authoritative implementations.
- Keep functions readable and single-purpose. Split code before nested control flow, parameter lists,
  or mixed responsibilities make behavior difficult to test.

## Errors And Control Flow

- Throw `Error` instances, not strings or arbitrary values.
- Preserve the original failure with `cause` when translating errors.
- Use stable error classes, codes, or discriminants at programmatic boundaries. Do not branch on
  human-readable error messages.
- Catch only errors that can be handled, enriched, or translated at that layer; otherwise propagate.
- Treat caught values as `unknown` and narrow them before use.
- Do not swallow promise rejections, stream errors, callback errors, or `EventEmitter` error events.
- Keep expected absence distinct from failure; do not return ambiguous `null`, `undefined`, or empty
  collections for unrelated error cases.
- Error messages and logs must not disclose secrets, credentials, tokens, or unnecessary sensitive
  input.

## Async Work And Resource Ownership

- Every promise must be awaited, returned, explicitly aggregated, or deliberately detached with
  documented error handling and lifecycle ownership.
- Thread `AbortSignal` or the project's cancellation primitive through cancellable I/O and long work.
- Bound concurrency, queues, retries, response sizes, and buffered data.
- Apply explicit timeouts to external I/O. Retries must be bounded, observable, and limited to
  operations that are safe to repeat.
- Respect stream backpressure; do not buffer an unbounded input merely for convenience.
- Remove listeners, clear timers, close handles, and terminate child processes on success, failure,
  cancellation, and shutdown.
- Do not use synchronous filesystem, crypto, compression, or child-process APIs on latency-sensitive
  event-loop paths.
- Avoid sequential `await` when operations are independent, but do not replace it with unbounded
  `Promise.all` over attacker-controlled or arbitrarily large collections.

## Security Boundaries

- Treat network data, files, environment variables, command-line arguments, storage, and dependency
  output as untrusted until validated for type, size, range, encoding, and allowed values.
- Never use `eval`, `new Function`, string-built module loading, or string-built shell commands with
  untrusted or variable input.
- Invoke child processes with an executable and argument array; avoid a shell unless shell syntax is
  the explicit requirement.
- Normalize and constrain filesystem paths before access when input can influence them.
- Prevent prototype-pollution paths when merging or assigning untrusted object keys.
- Use context-appropriate escaping for HTML, SQL, URLs, headers, and shell arguments; one encoding is
  not interchangeable with another.
- Keep secrets out of source, client bundles, logs, exceptions, snapshots, and test fixtures.
- Review dependency install scripts, native addons, loaders, and code-generation tools as executable
  supply-chain code.

## Dependencies And Public APIs

- Add a dependency only after checking the platform, standard library, and existing dependency graph.
- Do not use floating, wildcard, unpinned Git, or mutable URL dependencies.
- Commit manifest and lockfile changes together and review transitive changes.
- Keep runtime dependencies separate from build, development, test, and peer dependencies.
- Keep exports narrow. Published packages must define intentional entrypoints and must not require
  consumers to deep-import implementation files.
- Treat exported types, function signatures, error contracts, serialized formats, and package
  entrypoints as compatibility surfaces.
- Make breaking changes explicit, versioned, documented, and covered by migration tests or fixtures.
- Do not expose mutable internal state through public objects or collections.

## Performance And Efficiency

- Measure before and after performance-sensitive changes with representative inputs.
- Prefer algorithms and data structures with bounded, understood cost over clever micro-optimizations.
- Avoid repeated parsing, serialization, regular-expression compilation, and full-collection copies
  in hot paths.
- Stream or page large data and enforce size limits before allocation.
- Caches must have explicit keys, invalidation, and memory bounds; an unbounded map is not a cache.
- Preserve readability unless measurement demonstrates that a less direct implementation is needed.

## Testing And Quality Gates

- Add focused tests for behavior, edge cases, failure paths, and each fixed defect.
- Test external-data validation with malformed, missing, oversized, and boundary values.
- Test asynchronous cancellation, timeout, rejection, cleanup, and concurrency limits.
- Test public exports and declarations for libraries; test CLI exit codes and streams for CLIs.
- Keep unit tests deterministic and isolated. Live services belong only in explicit integration or
  end-to-end suites.
- Type checking, linting, formatting, tests, and builds must run in CI with no new warnings.
- Lint suppressions must be local and justified. Do not disable rules for an entire project to land a
  feature.
- TypeScript projects should use type-aware linting when supported by their toolchain.

## Verification

Run the smallest relevant checks first, then the complete gate:

```sh
{{JS_TS_FORMAT_COMMAND}}
{{JS_TS_LINT_COMMAND}}
{{JS_TS_TYPECHECK_COMMAND}}
{{JS_TS_TEST_COMMAND}}
{{JS_TS_BUILD_COMMAND}}
{{JS_TS_DEPENDENCY_AUDIT_COMMAND}}
```

Report exact commands and results. If a check cannot run, state why and what risk remains.
