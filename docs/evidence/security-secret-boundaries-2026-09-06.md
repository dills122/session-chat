# Security secret-boundary tranche evidence

Date: 2026-09-06

Scope: Deep Security Scan findings 1, 2, 7, 10, and 13, independently validated
against the current source before implementation. The original scan is analysis,
not authority. No other scan findings were selected for this tranche.

Outcome: all five changes implemented and verified locally on macOS arm64.
Portable verification remains blocked pending the changed revision's Linux and
Windows CI results. This record does not advance the Phase 1 completion revision
or claim OS isolation, production key custody, or human approval UX.

## Findings, fixes and regression evidence

| Finding | Validated path and enforcement | Evidence that the trigger no longer reproduces |
| --- | --- | --- |
| 1, high: L1 key exposure | Alice wrote its raw SQLCipher key to shared `alice/resume.state` while the same-account forwarder ran. All normal/hostile restart paths now route one fixed secret frame over an anonymous pipe inherited only by Alice/inspector roles; same-process compositions move the zeroizing state directly. There is no file fallback. | `alice_restart_key_is_absent_from_service_visible_files_and_diagnostics` captures only a disposable test key and scans the complete service-visible filesystem and child diagnostics after initialization, then proves a fresh Alice successfully reloads and completes the lifecycle. The pipe parser rejects truncated, wrong-magic, zero-key, and trailing input; closed input rejects even with an old resume file present. |
| 2, high: dirty AI Central execution | HEAD equality previously permitted mutable installer/helpers/catalog/skills. The wrapper compares all tracked bytes with pinned Git blobs before copying verified buffers into a retained snapshot, omits extra files, and refreshes recognized old skill links. | Real Git fixtures reject dirty installer/catalog/skill bytes, staged or assume-unchanged changes, symlink trees and source symlinks before invocation or pin recording. Source edits do not affect snapshot skills. Actual pinned installer preview and apply passed in temporary checkouts; both skill directories migrated away from an old unreviewed checkout. |
| 7, medium: public bearer guidance | The complete signed invitation serializes the capability and the scripted L1 path automatically approves a valid request. Transport guidance previously offered public publication without distinguishing modes. | Guidance now requires authenticated confidential transfer of current v1/v2 invitations; host output discloses simulated automatic approval and absence of intended-person verification. The two-terminal test checks these disclosures and still completes the flow. Existing unauthenticated network-probe tests prove the host does not send the invitation. |
| 10, medium: plaintext Debug | Concrete MLS `IncomingMessage::Application(Vec<u8>)` derived Debug despite the safer provider-neutral wrapper. | Manual Debug retains variant/length only. Tests cover ordinary, pretty, nested Result, empty and non-UTF8 payloads, control variants, and a real decrypted message. |
| 13, medium: envelope Debug | Derived Debug exposed ciphertext, expiry and envelope IDs; `ReceivedEnvelope` also exposed delivery IDs. | Both types redact every field in ordinary, pretty and nested formatting. Explicit byte access, equality, cloning, canonical fixtures and protocol decoding remain intact. |

Finding 7 intentionally does not add a human decision UI or alter the laboratory's
simulated approval contract. It fixes distribution guidance and executable host
disclosure; a leaked bearer invitation still grants its intended capability.
Future targeted public invitations are explicitly unimplemented.

## Ordered validation

Run from the repository root with pinned Rust 1.97.1 and Node 22.22.1.

Focused syntax/build and regression gates, all passing on the final code:

```sh
node --check scripts/setup-codex-links.mjs
cargo check -p sessionctl --all-targets --all-features --locked --offline
node --test scripts/setup-codex-links.test.mjs scripts/check-repository.test.mjs
cargo test -p session-protocol -p session-transport -p session-crypto-mls --locked --offline
cargo test -p sessionctl --all-features --lib --test l1_process --test two_terminal --test network_loopback --locked --offline
```

Results: 21 Node tests; 174 protocol/transport/MLS tests including doctests;
46 focused sessionctl tests. The real reviewed AI Central revision
`57e37b043b4366c395434cb534c243b599d158d1` additionally passed preview and apply
inside temporary targets. This did not change the developer's checkout or pin.

Area/workspace gates, all passing locally:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo test --workspace --all-features --locked --offline
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked --offline
cargo deny --all-features --locked check
node --test spikes/sealed-invitation-provider/test/provider.test.mjs
node scripts/check-repository.mjs
git diff --check
```

Workspace result: 571 passed, 0 failed, 2 ignored public-network operator tests.
The separate provider-spike suite passed. Cargo deny passed with existing
repository exceptions/warnings unchanged. Dependencies and wire formats did not
change; no dependency fetch or fixture migration was needed.

## Failures, review and remaining limits

- Initial compile checks identified a missing explicit key-buffer type and two
  test assertion type mismatches; these were corrected before passing gates.
- The network-restricted sandbox caused the existing direct-loopback test to
  fail with `EndpointUnavailable`. The same focused command and full workspace
  suite passed outside that sandbox with local endpoint binding available.
- Cargo deny initially could not lock its advisory cache on a read-only path.
  The unchanged command passed with cache access and advisory update access.
- The developer's AI Central HEAD differed from the repository pin. The wrapper
  correctly rejected that preview. An isolated local clone checked out at the
  unchanged reviewed pin passed actual preview/apply; no pin was relaxed.
- A fresh read-only security investigator and one fresh candidate reviewer were
  used. The reviewer found a missing snapshot Git-ignore rule and old-checkout
  skill links surviving a source-location change. Both were independently
  confirmed, corrected and covered by regression tests. The actual pinned
  installer also verified the old-checkout correction in both skill directories.
- Linux and Windows CI were not run from this local task. The existing common
  matrix includes the new Rust tests and now also runs the AI Central Node
  source/link suite with repository-pinned Node. The real shell-installer execution test
  is Unix-only; portable Node source-validation and link tests remain enabled.
- Anonymous pipes remove the shared-file key leak. They do not sandbox hostile
  code running as the same OS account, prevent process-memory/handle inspection,
  or isolate the separate filesystem bearer-invitation channel. OS-enforced
  isolation across all supported platforms is still required before running
  genuinely untrusted local service code.
- Verified snapshots do not protect against same-account artifact replacement,
  compromised local tools, or an incorrectly approved commit. Existing unrelated
  user skills remain outside the AI Central pin guarantee.
