import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import { promisify } from 'node:util';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  buildSetupArguments,
  createVerifiedSnapshot,
  readVerifiedTree,
  refreshManagedLinks,
  runInstaller,
  recordCurrentPin,
  evaluatePin,
  parseArguments,
  resolveAiCentralRoot
} from './setup-codex-links.mjs';

test('resolves an AI Central root or templates path without a machine-specific default', () => {
  const root = path.join(path.sep, 'tmp', 'ai-central');
  assert.equal(resolveAiCentralRoot(root), root);
  assert.equal(resolveAiCentralRoot(path.join(root, 'templates')), root);
  assert.equal(resolveAiCentralRoot(), path.join(os.homedir(), '.ai-central'));
});

test('builds the pinned full-catalog link-mode setup command', () => {
  const argumentsToPass = buildSetupArguments('/tmp/session-chat', true);
  assert.deepEqual(argumentsToPass.slice(0, 4), ['/tmp/session-chat', '--yes', '--mode', 'link']);
  assert.equal(argumentsToPass.at(-1), '--dry-run');
  assert.equal(argumentsToPass[argumentsToPass.indexOf('--bundles') + 1], 'all');
  assert.match(argumentsToPass[argumentsToPass.indexOf('--profiles') + 1], /javascript-typescript/);
  assert.match(argumentsToPass[argumentsToPass.indexOf('--profiles') + 1], /rust/);
  assert.doesNotMatch(argumentsToPass[argumentsToPass.indexOf('--profiles') + 1], /angular/);
});

test('rejects incompatible or unknown options', () => {
  assert.deepEqual(parseArguments(['--dry-run']), {
    dryRun: true,
    recordPin: false
  });
  assert.throws(() => parseArguments(['--dry-run', '--record-pin']), /cannot be combined/);
  assert.throws(() => parseArguments(['--unknown']), /Unknown option/);
});

test('classifies reviewed AI Central revisions', () => {
  assert.equal(evaluatePin({}, 'abc'), 'missing');
  assert.equal(evaluatePin({ expectedCommit: 'abc' }, 'def'), 'mismatch');
  assert.equal(evaluatePin({ expectedCommit: 'abc' }, 'abc'), 'match');
});

// Real Git trees exercise the boundary rather than mocking HEAD equality.
const exec = promisify(execFile);

async function fixture(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'session-ai-pin-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const source = path.join(root, 'source');
  await fs.mkdir(path.join(source, 'scripts'), { recursive: true });
  await fs.mkdir(path.join(source, 'templates', 'skills', 'example'), { recursive: true });
  await fs.writeFile(path.join(source, 'scripts', 'setup-ai-context.sh'), '#!/bin/sh\necho reviewed\n');
  await fs.writeFile(path.join(source, 'templates', 'catalog.json'), '{}\n');
  await fs.writeFile(path.join(source, 'templates', 'skills', 'example', 'SKILL.md'), 'Reviewed skill\n');
  const git = (...args) => exec('git', ['-C', source, ...args]);
  await git('init');
  await git('add', '.');
  await git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '-m', 'fixture');
  const { stdout } = await git('rev-parse', 'HEAD');
  return { source, root, git, commit: stdout.trim() };
}

for (const file of ['scripts/setup-ai-context.sh', 'templates/catalog.json', 'templates/skills/example/SKILL.md']) {
  test(`rejects dirty pinned bytes in ${file}`, async (t) => {
    const f = await fixture(t);
    await fs.writeFile(path.join(f.source, file), 'unreviewed marker');
    await assert.rejects(createVerifiedSnapshot(f.source, f.commit, path.join(f.root, 'snapshots')), /differs/);
    await assert.rejects(fs.access(path.join(f.root, 'snapshots')));
  });
}

test('rejects staged and assume-unchanged modifications at the pin', async (t) => {
  const f = await fixture(t);
  const file = path.join(f.source, 'templates/catalog.json');
  await fs.writeFile(file, 'staged');
  await f.git('add', '.');
  await fs.writeFile(file, '{}\n');
  await assert.rejects(readVerifiedTree(f.source, f.commit), /index differs/);
  await f.git('reset', '--hard', f.commit);
  await f.git('update-index', '--assume-unchanged', 'templates/catalog.json');
  await fs.writeFile(file, 'hidden dirty');
  await assert.rejects(readVerifiedTree(f.source, f.commit), /working-tree content differs/);
});

test('snapshot omits untracked helpers and survives later source mutation', async (t) => {
  const f = await fixture(t);
  await fs.writeFile(path.join(f.source, 'scripts', 'injected.sh'), 'unreviewed executable');
  const snapshot = await createVerifiedSnapshot(f.source, f.commit, path.join(f.root, 'snapshots'));
  await assert.rejects(fs.access(path.join(snapshot, 'scripts', 'injected.sh')));
  await fs.writeFile(path.join(f.source, 'templates', 'skills', 'example', 'SKILL.md'), 'changed later');
  assert.equal(await fs.readFile(path.join(snapshot, 'templates', 'skills', 'example', 'SKILL.md'), 'utf8'), 'Reviewed skill\n');
  assert.equal(await fs.readFile(path.join(snapshot, 'scripts', 'setup-ai-context.sh'), 'utf8'), '#!/bin/sh\necho reviewed\n');
});

test('rejects source directory symlink substitution', async (t) => {
  const f = await fixture(t);
  const templates = path.join(f.source, 'templates');
  const moved = path.join(f.root, 'outside');
  await fs.rename(templates, moved);
  await fs.symlink(moved, templates, process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(readVerifiedTree(f.source, f.commit), /regular files and directories/);
});


test('refreshes existing checkout links while preserving user skills and dry-run', async (t) => {
  const f = await fixture(t);
  const target = path.join(f.root, 'target');
  const links = path.join(target, '.agents', 'skills');
  await fs.mkdir(links, { recursive: true });
  await fs.mkdir(path.join(links, 'user-skill'));
  const link = path.join(links, 'example');
  const original = path.join(f.source, 'templates', 'skills', 'example');
  await fs.symlink(original, link, process.platform === 'win32' ? 'junction' : 'dir');
  const snapshot = await createVerifiedSnapshot(f.source, f.commit, path.join(target, '.agents', 'ai-central-snapshots'));
  await refreshManagedLinks(target, f.source, snapshot, true);
  assert.equal(await fs.realpath(link), await fs.realpath(original));
  await refreshManagedLinks(target, f.source, snapshot, false);
  assert.equal(await fs.realpath(link), await fs.realpath(path.join(snapshot, 'templates', 'skills', 'example')));
  assert.ok((await fs.lstat(path.join(links, 'user-skill'))).isDirectory());
  await fs.writeFile(path.join(original, 'SKILL.md'), 'malicious subsequent edit');
  assert.equal(await fs.readFile(path.join(link, 'SKILL.md'), 'utf8'), 'Reviewed skill\n');
});


test('installer rejects dirty code before execution in apply and preview modes', async (t) => {
  const f = await fixture(t);
  const target = path.join(f.root, 'target');
  await fs.mkdir(target);
  await fs.writeFile(path.join(f.source, 'scripts', 'setup-ai-context.sh'), '#!/bin/sh\ntouch "$1/executed"\n');
  for (const dryRun of [false, true]) {
    await assert.rejects(runInstaller(f.source, dryRun, target, { expectedCommit: f.commit }), /differs/);
    await assert.rejects(fs.access(path.join(target, 'executed')));
  }
  await assert.rejects(runInstaller(f.source, false, target, { expectedCommit: '0'.repeat(40) }), /does not match/);
});

test('reviewed shell installer executes from snapshot and preview removes it', { skip: process.platform === 'win32' }, async (t) => {
  const f = await fixture(t);
  const script = path.join(f.source, 'scripts', 'setup-ai-context.sh');
  await fs.writeFile(script, '#!/bin/sh\nprintf "%s" "$0" > "$1/executed"\n');
  await fs.chmod(script, 0o755);
  await f.git('add', '.');
  await f.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '-m', 'executable fixture');
  const { stdout } = await f.git('rev-parse', 'HEAD');
  const target = path.join(f.root, 'target');
  await fs.mkdir(target);
  await runInstaller(f.source, true, target, { expectedCommit: stdout.trim() });
  const executed = await fs.readFile(path.join(target, 'executed'), 'utf8');
  assert.ok(executed.startsWith(path.join(target, '.agents', 'ai-central-snapshots')));
  await assert.rejects(fs.access(executed));
  await runInstaller(f.source, false, target, { expectedCommit: stdout.trim() });
  await fs.access(await fs.readFile(path.join(target, 'executed'), 'utf8'));
});


test('pin recording rejects dirty content without overwriting the previous pin', async (t) => {
  const f = await fixture(t);
  const pin = path.join(f.root, 'pin.json');
  await recordCurrentPin(f.source, pin);
  const previous = await fs.readFile(pin, 'utf8');
  assert.equal(JSON.parse(previous).expectedCommit, f.commit);
  await fs.writeFile(path.join(f.source, 'templates', 'catalog.json'), 'unreviewed');
  await assert.rejects(recordCurrentPin(f.source, pin), /differs/);
  assert.equal(await fs.readFile(pin, 'utf8'), previous);
});

test('rejects symlink objects even when committed at the selected pin', async (t) => {
  const f = await fixture(t);
  const { stdout } = await f.git('ls-files', '--stage', 'templates/catalog.json');
  const hash = stdout.split(' ')[1];
  await f.git('update-index', '--add', '--cacheinfo', `120000,${hash},escape`);
  await f.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '-m', 'symlink fixture');
  const { stdout: commit } = await f.git('rev-parse', 'HEAD');
  await assert.rejects(readVerifiedTree(f.source, commit.trim()), /only regular files/);
});

test('refreshes a managed link when AI_CENTRAL_HOME is a directory alias', async (t) => {
  const f = await fixture(t);
  const alias = path.join(f.root, 'source-alias');
  await fs.symlink(f.source, alias, process.platform === 'win32' ? 'junction' : 'dir');
  const target = path.join(f.root, 'target');
  const link = path.join(target, '.agents', 'skills', 'example');
  await fs.mkdir(path.dirname(link), { recursive: true });
  await fs.symlink(path.join(f.source, 'templates', 'skills', 'example'), link, process.platform === 'win32' ? 'junction' : 'dir');
  const snapshot = await createVerifiedSnapshot(alias, f.commit, path.join(target, '.agents', 'ai-central-snapshots'));
  await refreshManagedLinks(target, alias, snapshot, false);
  assert.equal(await fs.realpath(link), await fs.realpath(path.join(snapshot, 'templates', 'skills', 'example')));
});

test('retained snapshots stay out of Git under the repository ignore policy', async (t) => {
  const f = await fixture(t);
  const ignore = await fs.readFile(new URL('../.gitignore', import.meta.url));
  await fs.writeFile(path.join(f.source, '.gitignore'), ignore);
  const { stdout } = await f.git('check-ignore', '--no-index', '.agents/ai-central-snapshots/reviewed/templates/skills/example/SKILL.md');
  assert.match(stdout, /ai-central-snapshots/);
});

test('switching AI Central checkouts replaces previously managed mutable links', async (t) => {
  const f = await fixture(t);
  const oldSkill = path.join(f.root, 'old-source', 'templates', 'skills', 'example');
  await fs.mkdir(oldSkill, { recursive: true });
  await fs.writeFile(path.join(oldSkill, 'SKILL.md'), 'unreviewed old checkout');
  const target = path.join(f.root, 'target');
  const link = path.join(target, '.agents', 'skills', 'example');
  await fs.mkdir(path.dirname(link), { recursive: true });
  await fs.symlink(oldSkill, link, process.platform === 'win32' ? 'junction' : 'dir');
  const snapshot = await createVerifiedSnapshot(f.source, f.commit, path.join(target, '.agents', 'ai-central-snapshots'));
  await refreshManagedLinks(target, f.source, snapshot, false);
  assert.equal(await fs.readFile(path.join(link, 'SKILL.md'), 'utf8'), 'Reviewed skill\n');
  assert.equal(await fs.realpath(link), await fs.realpath(path.join(snapshot, 'templates', 'skills', 'example')));
});
