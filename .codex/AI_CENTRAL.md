# AI Central integration

Status: refreshed on 2026-08-24

Session Chat commits its repository-specific instructions, selected steering,
AI Central revision pin, and link-management script. The large skill catalog is
not committed. It is recreated as local symlinks from a developer-owned AI
Central checkout.

This matches the repository-managed link pattern used by the other projects:
Git stores the reproducible setup and reviewed revision, while each machine owns
the absolute filesystem targets of its generated links.

## Installed source

- Remote: `https://github.com/dills122/ai-central.git`
- Reviewed revision: `57e37b043b4366c395434cb534c243b599d158d1`
- Profiles: `base,javascript-typescript,shell-scripting,rust`
- Skill bundles: `all`
- Installation: committed steering copies and ignored local skill links

The JavaScript/TypeScript and shell profiles cover retained repository tooling
and the invitation-provider spike. The Rust profile covers the v2 protocol
laboratory. Angular and frontend-design steering were retired with v1.
The full skill catalog includes the Technical Writing bundle:
`technical-blog-writer`, `project-story-miner`, and `humanizer`.

## Repository-owned files

- `AGENTS.md`
- `.codex/AI_CENTRAL.md`
- `.codex/ai-central-pin.json`
- `.codex/steering/*.md`
- `scripts/setup-codex-links.mjs`
- `scripts/setup-codex-links.test.mjs`

Generated `.agents/skills/` and `.codex/skills/` links are excluded through the
shared `.gitignore`, not a developer-specific Git exclude. No machine-specific
AI Central path is stored in the Git tree.

## Source discovery and pinning

Set `AI_CENTRAL_HOME` to either the AI Central repository root or its `templates`
directory. When it is unset, the setup script defaults to `~/.ai-central`.

The script refuses to create links unless the checkout commit matches
`.codex/ai-central-pin.json`. After deliberately reviewing a new AI Central
revision, record it with:

```sh
node scripts/setup-codex-links.mjs --record-pin
```

Commit the pin change together with any reviewed steering updates.

## Refresh

Preview the exact AI Central setup:

```sh
node scripts/setup-codex-links.mjs --dry-run
```

Apply it:

```sh
node scripts/setup-codex-links.mjs
```

The wrapper invokes AI Central's maintained non-overwriting installer with the
profiles and full skill bundle recorded above. It preserves repository-owned
steering and creates only missing local skill links.

## Verification

```sh
node --test scripts/setup-codex-links.test.mjs
node scripts/setup-codex-links.mjs --dry-run
```

Then verify that every `.agents/skills/` entry is a symlink whose target contains
`SKILL.md`, every `.codex/skills/` compatibility link resolves, and neither
generated directory appears in `git status`.
