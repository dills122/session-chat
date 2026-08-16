# Shell And Repository Scripting Steering

## Scope And Enforcement

Use this guidance for reusable automation under `{{SCRIPTS_ROOT}}`, including CI, container, VM,
hook, bootstrap, release, and developer scripts.

Repository-specific instructions and closer-scoped steering take precedence. Replace every
placeholder before enforcing this file.

The words **must**, **do not**, and **never** describe default requirements. Exceptions require a
documented portability or platform need, narrow scope, and representative tests.

## Shell Choice And Portability

- Shared cross-machine automation must use POSIX `sh` unless a concrete required feature justifies a
  different interpreter.
- The shebang must name the actual required interpreter. Do not write Bash syntax under `/bin/sh`.
- Bash-, Zsh-, or Fish-specific scripts must declare their minimum supported version and remain
  isolated from POSIX entrypoints.
- POSIX scripts must not use arrays, `[[ ... ]]`, process substitution, here-strings, `pipefail`,
  Bash-only parameter expansion, or other undeclared extensions.
- Treat BusyBox/Alpine utilities as the baseline when the script runs in minimal containers.
- Avoid GNU-only flags unless the supported platform contract guarantees them or a capability check
  selects a portable fallback.
- Set locale explicitly when parsing or sorting behavior depends on it.
- Do not parse human-oriented command output when a stable machine-readable interface exists.

## Structure, Interfaces, And DRY

- Keep scripts small, single-purpose, deterministic, and composable.
- Put reusable logic in functions or a sourced library with a narrow documented interface.
- Keep Make/package/CI targets as thin stable wrappers around versioned scripts where practical.
- Parse options with `getopts` or a small explicit loop and reject unknown or missing arguments.
- Document required arguments, environment variables, files, tools, outputs, and exit codes.
- Use stdout for requested data and stderr for diagnostics so callers can compose the script safely.
- Preserve established command names and exit semantics unless the change explicitly migrates them.
- Reuse existing repository commands before duplicating build, test, release, or environment logic.
- Extract shared behavior when copies could drift; do not create a generic shell framework for a
  handful of simple commands.
- Remove obsolete scripts and wrappers once callers have migrated.

## Expansion, Arguments, And Command Execution

- Quote parameter expansions, command substitutions, and paths unless splitting or globbing is the
  explicit, reviewed intent.
- Forward argument lists with `"$@"`, never unquoted `$@` or `$*`.
- Use `$(...)`, not backticks.
- Use `case` for string dispatch, `[` for POSIX tests, and `command -v` for dependency checks.
- Separate declaration from command substitution when the command's status matters; declarations can
  mask failures.
- Never use `eval` for data, arguments, or configuration.
- Do not construct commands in strings. In POSIX shell, build argument lists with functions and
  `set --`; in Bash, use arrays.
- Place `--` before untrusted path operands when the utility supports it.
- Avoid implicit current-directory assumptions; resolve repository-relative paths from the script's
  documented location.

## Failure Handling

- Exit nonzero on failure and emit an actionable diagnostic naming the failed operation.
- Use `set -u` when the script is written to handle optional parameters explicitly.
- Use `set -e` only with full understanding of its exceptions in conditions, functions, pipelines,
  and subshells. Do not rely on it as the sole error-handling strategy.
- Check critical commands explicitly, especially inside functions, conditionals, pipelines, cleanup,
  and retry logic.
- POSIX pipelines report the last command's status. Avoid pipelines where an earlier failure must be
  observed, or restructure them through files/FIFOs and explicit checks.
- Capture a status immediately when needed; do not overwrite it with logging or cleanup commands.
- Retry only transient operations, with a bounded attempt count, backoff, and final failure.
- Do not hide failures with unconditional `|| true`; handle the expected status narrowly.

## Temporary Data, Cleanup, And Concurrency

- Create temporary files and directories with a secure repository-supported helper; never predict a
  name in a shared directory.
- Set a restrictive `umask` before creating sensitive temporary data.
- Register cleanup immediately after acquiring a temporary file, lock, mount, or background process.
- Trap the signals the script can safely handle and preserve the original exit status during cleanup.
- Quote trap bodies so values expand at execution time when that is the intended behavior.
- Do not delete through empty variables, broad globs, unresolved substitutions, or unvalidated paths.
- Validate a destructive target's resolved path and ownership immediately before mutation.
- Use an atomic operation or documented lock when concurrent invocations can modify shared state.
- Write replaceable outputs to a temporary file and rename atomically when the filesystem contract
  permits it.
- Wait for child processes and propagate their failures; do not leave orphaned background work.

## Security Boundaries

- Treat arguments, environment variables, filenames, repository content, network responses, and tool
  output as untrusted data.
- Validate allowed values, lengths, formats, and resolved paths before use.
- Never interpolate untrusted data into shell syntax, regular expressions, `sed` programs, SQL, or
  remote command strings without a purpose-specific safe interface.
- Prefer an executable plus argument vector over `sh -c` or `bash -c`.
- Keep secrets out of command lines, tracing, process listings, logs, temporary filenames, and error
  output.
- Disable tracing around secrets and restore it only when safe.
- Downloaded code or artifacts must be authenticated or checksum-verified before execution.
- Do not source configuration files unless they are trusted executable shell code. Parse data formats
  as data.
- Drop privileges or use the narrowest available credentials for privileged steps.

## Efficiency And Maintainability

- Prefer one invocation over per-line process spawning when a standard tool can safely process the
  whole input.
- Do not optimize into dense `awk`, `sed`, or shell expressions that are harder to verify than a
  clear script or a more suitable language.
- Stream large inputs and avoid storing unbounded content in variables.
- Bound loops, retries, queues, and parallel jobs.
- Use a non-shell language when structured data, complex concurrency, substantial state, or growing
  business logic makes shell error-prone.
- Keep output concise and stable; machine consumers must not depend on decorative log text.

## Testing And Quality Gates

- Parse every script with each declared interpreter.
- Run ShellCheck for the declared dialect and fail CI on new findings.
- Use formatter output consistently when the repository has selected a shell formatter.
- Test success, invalid input, missing dependencies, command failure, interruption, cleanup, and
  idempotent reruns.
- Test paths containing spaces, glob characters, leading hyphens, newlines where supported, and empty
  values.
- Run shared scripts in representative minimal containers and supported operating systems.
- Test destructive operations against temporary fixtures, never developer or production data.
- Do not suppress ShellCheck globally. A local directive must explain why the warning is safe.

## Verification

Run the smallest relevant checks first, then the complete gate:

```sh
{{SHELL_SYNTAX_COMMAND}}
{{SHELL_LINT_COMMAND}}
{{SHELL_FORMAT_CHECK_COMMAND}}
{{SCRIPT_TEST_COMMAND}}
{{SCRIPT_PORTABILITY_COMMAND}}
```

Report exact commands and platform coverage. If a check cannot run, state why and what risk remains.
