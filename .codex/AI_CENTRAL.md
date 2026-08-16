# AI Central integration

Status: installed locally on 2026-08-16

Session Chat uses the developer-owned shared checkout at
`/Users/dsteele/.ai-central`. Skill directories use link mode so their contents
are not duplicated into this repository. Selected steering is committed as
ordinary Markdown so it remains portable, reviewable, and compatible with the
repository's formatting hooks.

## Installed source

- Remote: `https://github.com/dills122/ai-central.git`
- Revision: `1d4e91025a9379e0a741adb4f29faa41e9e51438`
- Profiles: `base,javascript-typescript,angular,shell-scripting,frontend-design,rust`
- Skill bundles: `all`
- Mode: linked skills with committed steering copies

The TypeScript, Angular, shell, and frontend profiles cover the legacy workspace.
The Rust profile covers the planned v2 protocol laboratory.

## Ownership

Track and review these project-owned files:

- `AGENTS.md`
- `.codex/AI_CENTRAL.md`
- `.codex/steering/repository-steering.md`
- `.codex/steering/testing-quality-gates-steering.md`
- `.codex/steering/angular-steering.md`
- `.codex/steering/frontend-design-steering.md`
- `.codex/steering/javascript-typescript-steering.md`
- `.codex/steering/rust-steering.md`
- `.codex/steering/shell-scripting-steering.md`

The following are symlinks into the shared checkout and are intentionally visible
to Git:

- `.agents/skills/`
- `.codex/skills/`

Do not edit linked skills through this repository; change the shared AI Central
source deliberately and review its effect across consuming repositories.
Committing a symlink records its target, not the linked skill contents, so the
skill catalog does not add its full size to this repository. A checkout on a
machine without the recorded AI Central source path will have unresolved skill
links until its AI Central integration is recreated for that machine.

## Refresh

First inspect the shared checkout's status and revision. Do not pull, switch, or
reset it implicitly. Preview the refresh:

```sh
/Users/dsteele/.ai-central/scripts/setup-ai-context.sh \
  /Users/dsteele/repos/session-chat \
  --yes --mode link \
  --profiles base,javascript-typescript,angular,shell-scripting,frontend-design,rust \
  --bundles all --dry-run
```

Apply the same selection by removing `--dry-run`. The installer is
non-overwriting: it preserves the committed steering files above and refreshes
only missing skill links. Review upstream steering changes separately before
copying them into this repository. Use `--sync` only after reviewing deselected
managed links.

## Verification

From `/Users/dsteele/.ai-central`, run:

```sh
./scripts/check.sh
```

Then verify that every entry in `.agents/skills/` is a link whose target contains
`SKILL.md`, every `.codex/skills/` compatibility link resolves, selected steering
is an ordinary file, and `git status --short --untracked-files=all` exposes the
skill links as repository content.
