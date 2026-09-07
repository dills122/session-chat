# ADR 0030: Demote L2 redaction until capture is owned

Status: accepted

## Context

Security finding #323 showed that candidate v2 accepted five caller-selected
byte slices as stdout, stderr, diagnostics, control frames, and retained
artifacts. The redaction gate scanned only those supplied slices before
emitting `redaction=pass`. A caller could omit a surface or pass empty bytes;
external attestation would authenticate the resulting overbroad claim without
proving capture completeness.

Existing L2 case runners still scan their known verifier, control, transcript,
artifact, canary, and actual-secret values. That evidence supports a bounded
case-surface secret-scan claim, not a complete process and artifact capture
claim.

## Decision

Retire candidate v2 and its public caller-supplied channel inventory. Every
`candidate_v2` entry point fails with `L2 complete capture required`.

Candidate v3 preserves recovery-matrix, cleanup, execution-identity, artifact,
and external-attestation fields, but emits the narrower tuple:

- `secret_scan=pass`
- `capture_completeness=unproven`
- `redaction=unverified`

Current parsing and external verification accept only
`protocol=l2-evidence-candidate-v3`. Frozen v3 and v2 fixtures retain the
current contract and negative compatibility case. Hosted attestation can authenticate exact v3
bytes and their workflow origin; it cannot upgrade capture completeness or
redaction.

Full `redaction=pass` requires one future runner to own and close every stdout,
stderr, diagnostic, control-frame, and artifact stream, bind an exact surface
inventory and digests, and scan the actual secret catalog before serialization.

## Consequences

CI may continue collecting and attesting v3 recovery candidates. Consumers can
use them as per-revision atomicity and provenance evidence, while complete
redaction remains unproved. Product and wire protocols do not change.

The candidate format changes incompatibly from v2 to v3. Callers no longer
construct an `L2EvidenceChannels` value or choose promotion surfaces.

## Evidence and limits

Tests reject v2, retire every v2 promotion entry point, prove the arbitrary
channel constructor is unavailable, require the exact v3 demotion fields, and
reject a canary in the serialized internal observation. Existing private-runner
tests retain actual-secret and per-surface canary rejection.

This decision does not prove complete capture, absence of secrets from omitted
or independently retained streams, production durability, or trustworthy
hosted builders.

This ADR supersedes ADR 0028 only for candidate redaction semantics. ADR 0028
continues to govern executable/artifact ownership and external attestation.
