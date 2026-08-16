# V1-to-v2 evidence brief

## Scope

- Project: Session Chat
- Range: initial prototype in 2021 through v1 retirement in 2026
- Question: why the default branch stopped carrying the web prototype
- Audience: future maintainers and agents; repository-public facts only

## One-sentence journey

Session Chat progressed from a server-authoritative web chat prototype to a
security-first protocol project after repository review showed that TLS, JWTs,
one-use links, and Redis rooms could not provide the intended end-to-end or
identity-independent guarantees.

## Timeline

| Date/version | Event or observation | Evidence | Confidence | Why it matters |
| --- | --- | --- | --- | --- |
| 2021-08 | Backend, Redis rooms, Docker, and frontend foundations appeared | commits `c52858f`, `45fa218`, `498c5fc` | direct | Establishes the original web-service architecture |
| 2021-09 | Client crypto was removed in favor of TLS | commit `0058397` | direct | Marks the trust decision v2 later reverses |
| 2023-12 | The repository and dependencies were revived and the shared SDK was introduced | commits `a534102`, `8a50759`, `5cf17a5` | direct | Shows the maintenance cost and contract consolidation effort |
| 2024-01 | One-use participant-link and Redis room behavior was expanded | commits `9e8f07f`, `1900cd6`, `7b328ef` | direct | Provides the invitation and session UX lessons retained today |
| 2024-11 | Redis metadata and notification behavior were refined | PR-era commits ending in `cf02b6b` and `c2fb403` | direct | Represents the final meaningful v1 behavior |
| 2026-03 | A security review triggered a rearchitecture plan | commit `525751f` | direct | Records the first explicit pivot away from the old model |
| 2026-08 | The v2 architecture, threat model, and invitation-provider spike landed | merge commit `98178d9`, PR #246 | direct | Establishes the new design baseline and `legacy-v1` snapshot |
| 2026-08 | The bounded deterministic-CBOR protocol envelope landed | merge commit `7e4353c`, PR #247 | direct | Provides the first retained v2 implementation slice |
| 2026-08 | V1 was removed from the default branch | ADR 0006 and its implementation PR | direct once merged | Ends dual-stack maintenance while preserving recovery evidence |

## Evidence ledger

| Claim candidate | Source | Type | Supports | Does not prove | Sensitivity |
| --- | --- | --- | --- | --- | --- |
| V1 was not end-to-end encrypted | archived `MessageFormat`, `ChatGateway`, and `CryptoService`; current threat model | direct | Server received and rebroadcast plaintext | Whether every historical deployment used valid TLS | public |
| Invitations were deterministic and effectively one-use after join | archived link-generation and Redis services | direct | Hash construction and deletion on successful join | Guaranteed expiry, unguessability, or recipient authentication | public |
| The simple two-person journey remains useful | archived create/login/chat components | inference | Concrete UI flow and prompts | User validation or production usability | public |
| V1 accumulated substantial maintenance overhead | dependency-upgrade history and Rush/Docker configuration | direct | Repeated upgrade and CI work | Exact future maintenance cost | public |
| V2 has a stronger architecture baseline | v2 docs and ADRs 0001–0005 | direct | Explicit layer separation and invariants | A production-secure implementation | public |
| Removing v1 reduces current repository attack and dependency surface | retirement diff | inference | Fewer runtime paths and manifests remain | Removal of historical GitHub alerts or risk in unimplemented v2 | public |

## Turning points

- Starting assumption: a TLS-protected web chat with server-issued tokens and
  temporary-looking rooms could support the product direction.
- Friction: the server still read content, controlled membership, and carried a
  large aging web dependency and deployment surface.
- Abandoned approach: incrementally reinterpret JWT, Socket.IO, Redis, and
  deterministic link hashes as a secure v2 protocol.
- Decision: separate security, admission, rendezvous, and transport; begin with
  a headless Rust protocol laboratory.
- Supported result: the repository now has a bounded opaque wire envelope and
  negative parser tests, plus a complete design and threat-model baseline.
- Remaining boundary: invitation signing, encrypted join, replay state, MLS,
  persistence, transports, and clients are not yet implemented.

## Contradictions and gaps

- Historical README language called the chat secure, while the code and later
  threat model establish only a server-trusted TLS/JWT design.
- The Redis repository exposed an expiry operation, but active room and link
  creation did not call it.
- Commit history proves implementation activity, not active users, production
  deployments, or user research. No such claims should be inferred.
- The first v2 envelope proves deterministic opaque framing, not encryption or
  a complete secure conversation.

## Publication and privacy review

- Do not publish historical private keys, generated certificates, tokens, or
  local environment values; none are reproduced here.
- Dependency vulnerabilities should be described as historical exposure unless
  rechecked against the tagged snapshot at publication time.
- Avoid naming contributors beyond information they have already chosen to make
  public in repository history.

## Story candidates

1. **From “TLS is enough” to client-owned session keys.** The strongest evidence
   is commit `0058397`, the archived plaintext message path, and the v2 threat
   model. The boundary is architecture and learning, not a shipped secure app.
2. **Delete the prototype, preserve the evidence.** The opening is the decision
   to use a tag plus compact artifacts instead of a live `legacy/` tree. The
   boundary is repository simplification, not user migration.
3. **Build the envelope before the transport.** ADR 0005 and PR #247 demonstrate
   why bounded canonical objects precede GitHub, SSI, mailbox, or mixnet work.

## Handoff

For future retrospectives, use “server-authoritative v1 prototype” and
“capability-first v2 protocol laboratory.” Cite `legacy-v1`, ADRs 0004–0006,
PRs #246–#247, and the current tests. Do not call v2 production-ready or imply
that v1 had end-to-end encryption.
