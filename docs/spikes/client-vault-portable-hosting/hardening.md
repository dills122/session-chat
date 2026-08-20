# Security Hardening Review: Client vault and portable realm hosting

## Evidence Basis

This review combines the current Session Chat v2 contracts with primary platform,
storage, container, TLS, discovery, and database documentation inventoried in
[`evidence-manifest.txt`](evidence-manifest.txt). It is a design product: the
repository still has no desktop client, encrypted storage adapter, production
service, or deployable realm.

The two opportunities belong together. A replaceable host is safe only if the
host never becomes a recovery holder for client secrets, and a sealed client is
useful only if it can receive bounded opaque work without unlocking its MLS and
capability state.

## Constraints

- Preserve client-owned MLS keys and the separation among admission, rendezvous,
  transport, and session state.
- Keep Phase 1 headless, in-memory, capability-only, and free of deployed service
  dependencies.
- Do not select the desktop shell, encrypted database, or production deployment
  dependency through a research spike.
- Keep multi-device synchronization, account recovery, federation, and strong
  anonymity claims deferred.
- Treat all performance, resource, restore, and platform-prompt effects as
  unmeasured until the proposed experiments run.

## Opportunity Portfolio

| Opportunity | Evidence | Options | Recommendation | Proposal |
| --- | --- | --- | --- | --- |
| Seal client secret state outside active use | Local-storage threat boundary, MLS persistence, and platform unlock semantics (`V001`–`V008`) | Whole-store wrapping; session-scoped sealed vault; portable recovery wrapper | Spike the session-scoped sealed vault; retain whole-store wrapping as fallback and defer recovery | [Client state vault](proposals/client-state-vault.md) |
| Make realms replaceable without content trust | Realm/transport contracts and portable deployment primitives (`H001`–`H010`) | Compose appliance; signed portable appliance; split operators | Build toward a signed portable appliance in two increments; defer split operation | [Portable realm hosting](proposals/portable-realm-hosting.md) |

## Recommendation Summary

I recommend a locked-mode client that can append only bounded opaque envelopes,
with user presence unsealing a narrow Rust-owned vault and only the selected
session’s keys. This directly reduces the useful-secret window while preserving
offline receipt. It does not claim to defeat malware once a session is open.

For hosting, I recommend a one-host Compose appliance whose identity is a
client-pinned, offline-root-signed realm descriptor rather than merely a DNS
name. Routine services receive role keys only; active session endpoints rotate
through member-authenticated state. This allows another operator or machine to
restore or replace infrastructure without acquiring content authority or
silently impersonating a lost realm.

## Next Decisions

1. Approve or revise Option 2 in each proposal as the target for bounded
   implementation experiments.
2. Decide whether the first client experiment targets macOS only or requires
   simultaneous macOS, Windows, and Linux protector evidence.
3. Define the hosting experiment’s recovery objectives: acceptable opaque-mail
   loss, restore-time target, and whether the initial descriptor requires an
   offline-root recovery bundle.
4. Record selected storage and realm-descriptor contracts in ADRs only after the
   experiments satisfy their stop conditions.
