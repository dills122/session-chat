# ADR 0028: Authenticate L2 evidence and own test artifacts

Status: accepted

Candidate redaction semantics are superseded by
[ADR 0030](0030-demote-l2-redaction-until-capture-is-owned.md). Candidate v3
keeps external attestation and artifact ownership while marking complete
capture unproved and redaction unverified.

## Context

Security findings #316 and #317 showed that the L2 public promotion API mistook
process environment and tool output for hosted provenance, and hashed a new
caller-supplied executable after the experiment. Finding #318 showed that the
workflow-reference checker skipped Docker pins and valid YAML representations.
Finding #319 showed that SQLCipher tests wrote into predictable shared temporary
paths, including a symlink-following tamper-copy write.

## Decision

This decision retired unsigned `promote_v1`: it always rejects with an
external-attestation requirement. Its original local collection format was
`l2-evidence-candidate-v2`, explicitly marked `provenance=self-reported` and
`publication=requires-external-attestation`. Git cleanliness, compiler output,
runner labels and GitHub environment values remain diagnostic assertions;
neither PATH-selected Git nor a caller-selected compiler is a trust root.
The new version prevents consumers from interpreting candidates as the old
public format. Internal observation v1 formats and product protocols do not
change.

Before launching an L2 executable, copy bounded bytes into an exclusively
created private directory and execute that snapshot. Capture SHA-256 before
execution, retain separate verifier, producer/controller, and optional Welcome
fault-driver identities, reject source replacement, and require identical
identities between baselines and cases and throughout each aggregate. Candidate
construction can only render those retained digests and rejects a supplied
replacement binary. SQLCipher return-code drivers run in the identified
controller; the Welcome engine driver additionally has its own executable.
These identities bind bytes, not a claim that the bytes are trustworthy.

A trusted non-PR CI run collects bounded candidates, fails if Cargo or candidate
parsing fails, and attests the exact JSON bundle with a full-commit
pinned GitHub provenance action. Uploaded candidates from PR runs are unsigned.
Consumers must use `scripts/verify-l2-evidence.mjs` with an independently chosen
expected source commit and approved absolute GitHub CLI path/content digest.
The consumer checks and boundedly reads each opened file handle, then executes
a private snapshot of the digest-approved CLI bytes. Path replacement between
inspection and use cannot substitute the candidate or verifier; file growth
cannot bypass the read bound.
The CLI verifies the signature and artifact digest using GitHub/Sigstore trust
roots, exact repository and signer workflow, expected source digest, GitHub OIDC
issuer and hosted-runner policy. The additional policy checks use verified
certificate fields to bind the run/attempt, workflow digest and reference,
repository and source commit to the exact candidate bytes. Locally supplied
verification JSON is never an input to the executable verification entrypoint.
The signed subject includes all binary, matrix and observation digests.

This authenticates a statement from the reviewed workflow; it does not prove
that a compromised builder told the truth. The consumer must review/trust the
expected source/workflow revision and its tool bootstrap. Compiler strings,
cleanliness, OS-image labels and semantic test results remain builder assertions,
not independently reproducible-build or hardware attestations. GitHub CLI's
own installed bytes and the consumer account/OS remain trusted.

Workflow policy accepts a deliberately bounded YAML subset: ordinary block and
flow mappings, single/double quoted keys and values (including decoded escapes),
and block scalars for scripts. It inspects every decoded `uses` key. Remote
actions/reusable workflows require full 40-hex commits; Docker actions require
`@sha256:` and exactly 64 lowercase hex digits. Expressions, aliases, tags,
explicit/complex keys and multiline action references fail closed. Unsupported
syntax must be rewritten into the supported subset; it is never skipped.
This preserves dependency-free Node tooling.

Repository evidence manifests use a second strict dependency-free grammar:
blank lines, comments, credential-free HTTPS sources, and canonical
forward-slash paths beneath the declared repository evidence roots. The policy
checker walks each path component without following links, requires a regular
file, and verifies canonical containment under both repository and selected
top-level evidence root. Dot segments, platform-specific separators, NTFS
alternate streams, absolute paths, unknown prose, missing targets, links, and
directories reject. Existing inventory headings are comments. The collection
digest continues to bind exact
manifest bytes; the recorded Git revision, rather than duplicated per-file
hashes, binds repository evidence content.

Core and retained spike SQLCipher tests share the publish-disabled
`scripts/test-private-dir` fixture owner. It uses 256 random bits from the OS,
exclusive creation, Unix mode 0700 at creation, or a Windows protected owner-only
inheritable DACL supplied to CreateDirectoryW. Database and SQLite sidecars live
inside that directory. New tamper copies use exclusive file creation. A retained
directory identity prevents cleanup from following a replacement root.
The Windows native calls and allocator-paired security descriptor are confined
to the test helper; ordinary product packages do not depend on it. Checked L2
executable snapshots use the same owner.

## Evidence and limits

Negative tests cover original mutable workflow spellings, quoted/flow/escaped
keys, hidden sibling keys after scripts, binary substitution and replacement,
mixed executable identities, retired promotion, wrong verified certificate or
subject fields, private-directory collisions, prepositioned links, exclusive
writes and sidecar cleanup. The v2 JSON fixture is synthetic and explicitly
unsigned; post-verification policy tests do not claim to exercise signatures.
Live hosted signing/verification and Windows/macOS/Linux results must be retained
for the exact revision before advancing portable provenance claims.

Private directories protect against other accounts within OS access-control
and temporary-parent assumptions. They do not protect from malicious same-account
processes, administrators, a compromised kernel or arbitrary replacement of a
parent directory. No product storage, network or cryptographic wire contract
changes, and no power-loss, rollback resistance or production-readiness claim
is added.

References: [GitHub CLI attestation verification](https://cli.github.com/manual/gh_attestation_verify)
and [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).
