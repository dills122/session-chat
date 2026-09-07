# ADR 0027: Bound experimental ingress before session ownership

Status: accepted; laboratory hardening, not a production availability claim

Date: 2026-09-06

## Context

An ordered frame link can remain byte-aligned while its request/response
exchange becomes desynchronized. A control failure after sending a complete
request leaves an unread response. Separately, binding a one-shot host to the
first transport-authenticated peer gives that peer session availability control
before it proves any invitation or mailbox authority. Fixed request counts do
not prove completion if denied operations count toward them.

The filesystem and Node simulators have the same ingress requirement: reject
objects with unbounded work or unintended authority before handing them to the
one-shot protocol owner or retaining them.

## Decision

- The Iroh delivery client marks the entire exchange incomplete before starting
  its send. Any error or dropped future leaves that client unusable; only a
  completely received and decoded response permits another exchange. Preflight
  rejection remains reusable. An ambiguous remote commit still requires exact
  idempotency reconciliation; failure does not assert non-commit.
- An accepting endpoint remains available across rejected connections. The two
  public host harnesses allow at most 32 candidates under one five-minute
  handoff deadline. Each candidate gets at most two seconds for handshake and
  stream opening, then two seconds for its first bounded frame. Rejection
  closes that connection without shutting down the listening endpoint.
- The network session's Alice owner opens the existing HPKE-protected first
  request against the exact issued invitation before committing to that peer.
  A capacity-one in-process channel carries candidates to that owner. Rejected
  frames do not enter Alice's one-shot filesystem channel or mutate admission
  state. After an accepted request, the existing full KeyPackage, admission,
  simulated approval, MLS and durable transaction checks remain authoritative.
  There is no new wire prelude, bearer export, or custom authentication scheme.
- The Fast evidence host uses a separately named authenticated serving method.
  Each counted operation must first pass its exact mailbox/right authorization.
  Authorized semantic outcomes, including the conformance case's expected
  idempotency conflict, still count. A denied request closes that candidate and
  cannot produce completion. The generic bounded request server continues to
  support tests that deliberately exercise denied responses. Later operations
  retain the thirty-second bound, with the host's overall deadline still active.
- L1 creates Unix root and channel directories with mode 0700 atomically,
  independent of umask; files remain 0600. Root validation rejects links and
  group/world-accessible Unix directories. Windows retains its inherited ACL
  baseline; Unix modes are not Windows ACL or hostile-process isolation evidence.
  Operators must use a trusted parent directory on every platform.
- L1 channels, marker and provenance files use the shared bounded regular-file
  reader. Links and special files are rejected before reads; Unix uses
  nonblocking/no-follow opens and checks device/inode after opening. Windows
  opens the reparse point itself and rejects reparse attributes. Both platforms
  recheck regular-file type and size. Anonymous-pipe state handoff remains a
  separate, controller-supervised boundary. These checks do not guarantee a
  deadline on an unresponsive filesystem or prevent malicious same-account
  mutation of regular files.
- Node spike envelopes share a descriptor-safe, closed-schema normalizer at
  mailbox deposit and direct recipient opening. Fixed encoded lengths precede
  regex, decoding, key import and cryptography. Only normalized fields are
  retained. Directory/attestor verification bounds claims and signature widths
  before canonicalization; bounded JSON snapshots reject accessors, cycles,
  excessive depth and excessive entries before cloning or serialization.
  The in-process object API is not a byte parser: a future transport must enforce
  a byte ceiling before JSON parsing. JavaScript own-key introspection itself
  remains proportional to an already materialized object's property count;
  fixed fields are checked first and descriptor tables are not cloned. Proxies that execute arbitrary JavaScript
  are not treated as remotely supplied data.

## Consequences

No Rust wire version, HPKE context, MLS operation, transport profile, fallback
policy, or architecture dependency direction changes. The existing generated
Node v1 envelopes remain compatible; previously ignored extra properties and
noncanonical encodings now fail closed.

A finite adversarial stream can still exhaust the candidate ceiling or handoff
deadline. A holder of genuine bearer authority can still disrupt the experiment.
These are bounded online-only laboratory workflows, without production abuse
control, offline delivery, durable mailbox recovery, anonymity, or OS sandbox
claims. Common tests belong to the existing Linux/macOS/Windows CI gate; local
macOS evidence alone cannot establish the other platforms' result.
