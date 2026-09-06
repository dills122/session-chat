# AI Central integration

Status: refreshed on 2026-08-24

Session Chat commits its repository-specific instructions, selected steering,
AI Central revision pin, and link-management script. The large skill catalog is
not committed. It is recreated as local symlinks into a verified snapshot of a developer-owned
AI Central checkout.

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
`.codex/ai-central-pin.json` and every tracked regular file matches its Git blob.
It rejects dirty installer, helper, catalog or skill bytes (including changes
hidden by assume-unchanged), staged differences, source symlinks and unsupported
Git tree types. Untracked and ignored files never enter the snapshot. It copies
only the verified buffers into a fresh ignored `.agents/ai-central-snapshots/`
directory and executes the installer there. Applied snapshots remain available
as skill-link targets; dry-run snapshots are removed. Existing managed links
into the source checkout or older snapshots are refreshed to the new snapshot.
User-owned files and unrelated links are preserved. Pin recording performs the
same tracked-content checks. These controls isolate setup from mutable source
content; they do not sandbox a malicious process running under the same account
or authenticate the human review of the selected commit. After deliberately reviewing a new AI Central
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
steering, refreshes existing managed skill links, and creates missing links.
Keep snapshots while any installed link references them. Snapshot files are
read-only to reduce accidental modification; same-account tampering remains
outside this guarantee.

## Verification

```sh
node --test scripts/setup-codex-links.test.mjs
node scripts/setup-codex-links.mjs --dry-run
```

Then verify that every `.agents/skills/` entry is a symlink whose target contains
`SKILL.md`, every `.codex/skills/` compatibility link resolves, and neither
generated directory appears in `git status`.
