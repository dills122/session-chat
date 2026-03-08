# Session Chat Dependency Upgrade Plan

This document describes the recommended package upgrade path for the repository, with special focus on the Angular frontend and its compatibility constraints.

## Executive Summary

The frontend is currently on Angular 16.2.x. That is not ancient, but it is old enough that upgrading is justified. The larger problem is that the frontend still carries older tooling and config patterns:

- Protractor-based e2e setup
- Karma Istanbul coverage reporter
- deprecated dev-server flags
- hardcoded websocket endpoint configuration
- older Angular workspace conventions

The recommended target is:

- Angular 20.x
- Nebular 16.x
- `ngx-socket-io` 4.9.x
- Socket.IO 4.8.x alignment across frontend and backend

This is the safest modern target because it keeps the current UI stack viable while landing on a supported Angular major.

## Current State

### Frontend

From [apps/chat-frontend/package.json](/Users/dsteele/repos/session-chat/apps/chat-frontend/package.json):

- Angular framework packages: `16.2.12`
- Angular CLI/build tooling: `16.2.x`
- TypeScript: `5.1.6`
- RxJS: `7.8.1`
- Nebular: `12.0.0`
- `ngx-socket-io`: `4.5.1`
- Protractor: `7.0.0`
- Karma-based test stack still present

### Backend

From [apps/chat-backend/package.json](/Users/dsteele/repos/session-chat/apps/chat-backend/package.json):

- NestJS 10.x
- Socket.IO server `4.5.1`
- Redis 4.7.0

### Monorepo Tooling

From [rush.json](/Users/dsteele/repos/session-chat/rush.json):

- Rush `5.62.4`
- pnpm `7.33.6`
- Node support range still set to `>=16`

Local runtime currently reports Node `22.21.1`, which is fine for modern Angular, but the repo metadata has not been updated to reflect current supported engines.

## Recommended Target Versions

### Frontend target

- Angular: `20.2.x` or `20.3.x`
- Angular CLI/devkit/compiler-cli: same Angular major and minor
- TypeScript: Angular 20 supported range
- RxJS: keep `7.8.x`
- Nebular: `16.x`
- `ngx-socket-io`: `4.9.x`
- Socket.IO server/client: `4.8.1` compatible line

### Why not Angular 21 first

Nebular’s release history indicates:

- Nebular 13 -> Angular 17
- Nebular 14 -> Angular 18
- Nebular 15 -> Angular 19
- Nebular 16 -> Angular 20

That makes Angular 20 the cleanest target if Nebular remains part of the stack.

### Why not stay on Angular 16

Angular 16 is outside active support, and the ecosystem around it keeps moving:

- library peer dependency ranges move forward
- update tooling assumptions move forward
- older test and builder conventions create more friction over time

## Compatibility Notes

### Angular compatibility

Angular’s official version compatibility table shows:

- Angular 16.2 supports Node `^16.14 || ^18.10`, TypeScript `>=4.9.3 <5.2.0`
- Angular 20.2 and 20.3 support Node `^20.19 || ^22.12 || ^24`, TypeScript `>=5.8.0 <6.0.0`, RxJS `^6.5.3 || ^7.4.0`

This means the current frontend TypeScript version is too old for Angular 20 and must move as part of the upgrade.

### Nebular compatibility

Nebular’s release history indicates:

- v13.0.0 updated to Angular 17
- v14.0.0 updated to Angular 18
- v15.0.0 updated to Angular 19
- v16.0.0 updated to Angular 20

This is the main reason to target Angular 20 rather than Angular 21.

### `ngx-socket-io` compatibility

The package’s published compatibility table indicates:

- v4.5.0 -> Angular 16.x
- v4.6.1 -> Angular 17.x
- v4.7.0 -> Angular 18.x
- v4.8.1 -> Angular 19.x
- v4.9.0 -> Angular 20.x

It also states the expected Socket.IO server version for Angular 20 support is `4.8.1`.

That means the backend Socket.IO package should be upgraded in the same program.

## Repo-Specific Upgrade Risks

### 1. Protractor e2e is dead weight

The repo still uses Protractor in [apps/chat-frontend/e2e/protractor.conf.js](/Users/dsteele/repos/session-chat/apps/chat-frontend/e2e/protractor.conf.js). It should be treated as removal work, not something to preserve.

Recommendation:

- remove Protractor from the mainline upgrade path
- either replace later with Playwright or pause frontend e2e until the auth/session redesign stabilizes

### 2. Legacy Angular CLI serve flag

[apps/chat-frontend/package.json](/Users/dsteele/repos/session-chat/apps/chat-frontend/package.json) still uses:

- `ng serve --host 0.0.0.0 --disable-host-check`

`--disable-host-check` is a legacy dev-server flag and should be removed during upgrade preparation.

### 3. Legacy Karma coverage plugin

[apps/chat-frontend/karma.conf.js](/Users/dsteele/repos/session-chat/apps/chat-frontend/karma.conf.js) uses `karma-coverage-istanbul-reporter`, which is older than the current Angular CLI defaults.

Recommendation:

- migrate to the maintained coverage path expected by modern Angular/Karma tooling

### 4. Hardcoded socket endpoint

[apps/chat-frontend/src/app/app.module.ts](/Users/dsteele/repos/session-chat/apps/chat-frontend/src/app/app.module.ts) hardcodes `localhost:3001/chat`.

That is a deployment problem and an upgrade problem.

Recommendation:

- move socket URL and namespace to environment config before or during the Angular upgrade

### 5. Nebular constrains Angular major adoption

If Nebular stalls again after Angular 20, the next Angular major may require:

- waiting for Nebular
- forcing unsupported peers
- or replacing Nebular entirely

For that reason, avoid over-investing in Nebular-specific patterns during the upgrade.

## Recommended Upgrade Sequence

### Phase 1: Baseline cleanup before major bumps

1. Make runtime config environment-driven.
2. Remove `--disable-host-check`.
3. Remove or quarantine Protractor.
4. Ensure the frontend builds cleanly on current main before version bumps.

### Phase 2: Angular 16 -> 17

1. Update Angular core, CLI, devkit, and compiler-cli to 17.
2. Upgrade Nebular to 13.
3. Upgrade `ngx-socket-io` to the Angular 17-compatible line.
4. Raise TypeScript into Angular 17’s supported range.
5. Fix any builder, lint, and test fallout.

### Phase 3: Angular 17 -> 18

1. Update Angular packages to 18.
2. Upgrade Nebular to 14.
3. Upgrade `ngx-socket-io` to 4.7.x.
4. Align Socket.IO packages.
5. Rebuild and fix regressions.

### Phase 4: Angular 18 -> 19

1. Update Angular packages to 19.
2. Upgrade Nebular to 15.
3. Upgrade `ngx-socket-io` to 4.8.x.
4. Rebuild and fix regressions.

### Phase 5: Angular 19 -> 20

1. Update Angular packages to 20.
2. Upgrade Nebular to 16.
3. Upgrade `ngx-socket-io` to 4.9.x.
4. Upgrade backend Socket.IO to the 4.8.x line for compatibility.
5. Raise TypeScript to Angular 20’s supported range.
6. Rebuild and fix regressions.

### Why do this in hops

Angular majors are designed to be upgraded one major at a time. That keeps migration schematics and breaking changes manageable, especially in a workspace that still contains legacy tooling.

## Package Buckets

### Bucket A: Frontend framework

- `@angular/*`
- `@angular-devkit/build-angular`
- `@angular/cli`
- `@angular/compiler-cli`
- `@schematics/angular`
- `zone.js`
- `typescript`

### Bucket B: Angular-adjacent libraries

- `@nebular/theme`
- `@nebular/eva-icons`
- `ngx-socket-io`
- `@auth0/angular-jwt`

### Bucket C: Frontend test and lint tooling

- `karma*`
- `jasmine*`
- `protractor`
- `@angular-eslint/*`
- `@typescript-eslint/*`
- `eslint`

### Bucket D: Realtime/backend alignment

- `socket.io`
- `@socket.io/*`
- frontend socket wrapper compatibility

### Bucket E: Monorepo/tooling

- Rush
- pnpm version pinned by Rush
- Node engine declarations

## Suggested Work Items

### UPG-001: Establish supported target matrix

- Decide Angular 20 as the frontend target major
- Decide whether Nebular stays
- Decide whether Protractor is removed immediately

### UPG-002: Clean frontend runtime config

- move socket URL to environment config
- remove deprecated dev-server options

### UPG-003: Remove Protractor from the active path

- delete unused Protractor scripts and config if not replacing immediately
- or replace with Playwright in a later dedicated task

### UPG-004: Angular hop 16 -> 17

- framework, CLI, TypeScript, and Angular ESLint compatibility

### UPG-005: Angular hop 17 -> 18

- framework, Nebular, and socket wrapper compatibility

### UPG-006: Angular hop 18 -> 19

- framework, Nebular, and socket wrapper compatibility

### UPG-007: Angular hop 19 -> 20

- framework, Nebular, and socket wrapper compatibility

### UPG-008: Align Socket.IO server and client stack

- backend `socket.io`
- `@socket.io/redis-adapter`
- frontend socket wrapper compatibility

### UPG-009: Refresh frontend test tooling

- modernize Karma setup or replace with a lighter strategy

### UPG-010: Refresh Rush and Node metadata

- raise supported Node range
- consider Rush and pnpm refresh after app packages stabilize

## Recommended First Sprint For Upgrades

If package upgrades start now, the first sprint should contain only:

- UPG-001
- UPG-002
- UPG-003
- UPG-004

That keeps the first delivery small enough to recover from migration fallout without mixing several major framework jumps into one review.

## Recommendation For This Repo

Do not try to upgrade every package in one shot.

The safest execution order is:

1. frontend and runtime cleanup
2. Angular major hops to 20
3. Nebular and socket wrapper alignment at each hop
4. backend Socket.IO alignment
5. test and lint cleanup
6. Rush and repo-wide tooling refresh

That sequence minimizes the chance of creating a repo that is neither runnable nor easy to debug.

## Sources

- Angular version compatibility: [angular.dev/reference/versions](https://angular.dev/reference/versions)
- Angular update guidance: [angular.dev/update](https://angular.dev/update)
- Angular standalone migration: [angular.dev/reference/migrations/standalone](https://angular.dev/reference/migrations/standalone)
- Angular build system migration: [angular.dev/tools/cli/build-system-migration](https://angular.dev/tools/cli/build-system-migration)
- Nebular releases: [github.com/akveo/nebular/releases](https://github.com/akveo/nebular/releases)
- `ngx-socket-io` compatibility table: [npmjs.com/package/ngx-socket-io](https://www.npmjs.com/package/ngx-socket-io/v/4.9.0/)
