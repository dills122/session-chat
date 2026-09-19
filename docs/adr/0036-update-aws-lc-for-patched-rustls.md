# ADR 0036: Update AWS-LC to use patched rustls

Status: accepted for the Phase 1 laboratory; three-OS CI evidence required

Date: 2026-09-18

## Context

The master lockfile held `rustls` 0.23.43. RustSec published
[RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html) on
2026-09-14: rustls 0.23.13 through 0.23.44 can accept TLS 1.3 handshake
messages across an encryption-level boundary. The fixed release is 0.23.45.
The scheduled dependency-policy job first rejected the unchanged master graph
on 2026-09-15; the aggregate Gate then failed as designed.

`rustls` 0.23.45 requires `aws-lc-rs` 1.18 or later when the AWS-LC TLS backend
is enabled. Session Chat pins `aws-lc-rs` 1.16.3 for its MLS, HPKE, portable
key-wrapper, and FastV1 laboratory graph. The latest published
`mls-rs-crypto-awslc` 0.25.0 also pins `aws-lc-rs` 1.16.3 and `aws-lc-sys`
0.40.0 exactly. Cargo cannot resolve that provider alongside the fixed rustls
release and the project's AWS-LC backend selection.

## Decision

Pin `rustls` 0.23.45, `aws-lc-rs` 1.18.1, and `aws-lc-sys` 0.45.0 in the
locked graph. Retain `mls-rs-crypto-awslc` 0.25.0 with a local crates.io patch:
copy the published package, preserve its source and test files byte-for-byte,
and change only its two AWS-LC dependency pins. Include upstream license texts
and a source checksum in the local patch directory.

Keep the existing non-FIPS AWS-LC provider for MLS and Iroh FastV1. Do not
ignore the advisory, weaken cargo-deny, change TLS backend, or claim the patched
provider has an upstream release or independent audit. The patch is limited to
this laboratory graph and needs the existing three-OS CI gate before its
cross-platform behavior is treated as retained evidence.

## Consequences and limits

- The dependency policy rejects the vulnerable rustls version without an
  advisory exception. Existing MLS ownership, HPKE cross-provider, wrapped-key
  byte fixture, and FastV1 tests must continue to pass.
- Upgrading AWS-LC's native library changes the implementation beneath several
  cryptographic boundaries. Passing fixtures and API tests do not establish
  equivalent side-channel, secure-deletion, FIPS, or production properties.
- No wire format, ciphersuite, admission, transport profile, or stored-record
  contract is intentionally changed. Any observed change in those contracts
  requires separate fixtures, negative tests, and review.
- The local patch is a maintenance burden. Remove it when an upstream provider
  release supports the fixed rustls graph, after locked policy, API, fixture,
  and Linux/macOS/Windows checks pass. Do not silently broaden the patch to
  other provider changes.
- The unrelated Windows L2 output timeout seen on 2026-09-14 remains an
  intermittent test/runner observation. Later master runs passed that job; no
  storage or recovery property is inferred from the timeout.
