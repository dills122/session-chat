#!/usr/bin/env node

import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, '..');
const pinPath = path.join(repositoryRoot, '.codex', 'ai-central-pin.json');
const isEntrypoint = Boolean(process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href);

const profiles = 'base,javascript-typescript,shell-scripting,rust';

export function usage() {
  return `Usage: node scripts/setup-codex-links.mjs [--dry-run] [--record-pin]

Recreates ignored local skill links with AI Central's maintained installer.

Environment:
  AI_CENTRAL_HOME  Path to ai-central or ai-central/templates.
                   Defaults to ~/.ai-central.

Options:
  --dry-run        Preview the installer changes without writing links.
  --record-pin     Record the current AI Central commit after review.
  --help           Show this help.`;
}

export function parseArguments(argumentsToParse) {
  const allowed = new Set(['--dry-run', '--record-pin']);
  const unknown = argumentsToParse.filter((argument) => argument !== '--' && !allowed.has(argument));

  if (unknown.length > 0) {
    throw new Error(`Unknown option: ${unknown[0]}`);
  }

  const dryRun = argumentsToParse.includes('--dry-run');
  const recordPin = argumentsToParse.includes('--record-pin');
  if (dryRun && recordPin) {
    throw new Error('--dry-run and --record-pin cannot be combined');
  }

  return { dryRun, recordPin };
}

export function resolveAiCentralRoot(input) {
  const absolute = path.resolve(input ?? path.join(os.homedir(), '.ai-central'));
  return path.basename(absolute) === 'templates' ? path.dirname(absolute) : absolute;
}

export function buildSetupArguments(targetRoot, dryRun = false) {
  const setupArguments = [targetRoot, '--yes', '--mode', 'link', '--profiles', profiles, '--bundles', 'all'];

  if (dryRun) {
    setupArguments.push('--dry-run');
  }

  return setupArguments;
}

export function evaluatePin(pin, currentCommit) {
  if (!pin?.expectedCommit) {
    return 'missing';
  }
  return pin.expectedCommit === currentCommit ? 'match' : 'mismatch';
}

async function readPin() {
  return JSON.parse(await fs.readFile(pinPath, 'utf8'));
}

async function resolveCurrentCommit(aiCentralRoot) {
  const { stdout } = await git(aiCentralRoot, ['rev-parse', 'HEAD']);
  return stdout.trim();
}

// Git metadata selects objects; it must not redirect this probe to another repo
// or substitute replace-ref objects. No filters, hooks or checkout code run.
function git(aiCentralRoot, argumentsToPass) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_')));
  env.GIT_NO_REPLACE_OBJECTS = '1';
  return execFileAsync('git', ['-C', aiCentralRoot, '-c', 'core.fsmonitor=false', ...argumentsToPass], {
    env, maxBuffer: 4 * 1024 * 1024, timeout: 30_000
  });
}

export async function readVerifiedTree(aiCentralRoot, commit) {
  if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error('Invalid AI Central commit');
  const { stdout } = await git(aiCentralRoot, ['ls-tree', '-rz', '--full-tree', commit]);
  const entries = stdout.split('\0').filter(Boolean);
  if (entries.length === 0 || entries.length > 4096) throw new Error('AI Central tree size rejected');
  const files = [];
  let total = 0;
  for (const entry of entries) {
    const match = /^(100644|100755) blob ([0-9a-f]{40})\t(.+)$/s.exec(entry);
    if (!match) throw new Error('AI Central tree must contain only regular files');
    const [, mode, expectedHash, relativePath] = match;
    const components = relativePath.split('/');
    if (components.some((part) => !part || part === '.' || part === '..' || /[\\:\x00-\x1f]/.test(part))) {
      throw new Error('AI Central tree path rejected');
    }
    let source = aiCentralRoot;
    for (const [index, component] of components.entries()) {
      source = path.join(source, component);
      const info = await fs.lstat(source);
      if (info.isSymbolicLink() || (index < components.length - 1 ? !info.isDirectory() : !info.isFile())) {
        throw new Error('AI Central source must contain only regular files and directories');
      }
      if (index === components.length - 1 && info.size > 4 * 1024 * 1024) {
        throw new Error('AI Central file size rejected');
      }
    }
    const bytes = await fs.readFile(source);
    total += bytes.length;
    if (bytes.length > 4 * 1024 * 1024 || total > 32 * 1024 * 1024) throw new Error('AI Central source size rejected');
    const actualHash = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
    if (actualHash !== expectedHash) throw new Error('AI Central working-tree content differs from the reviewed commit');
    files.push({ relativePath, mode, bytes });
  }
  // Catch staged changes even when the working file has been restored to HEAD.
  const { stdout: staged } = await git(aiCentralRoot, ['diff-index', '--cached', '--name-only', commit, '--']);
  if (staged) throw new Error('AI Central index differs from the reviewed commit');
  return files;
}

export async function createVerifiedSnapshot(aiCentralRoot, commit, snapshotParent) {
  // Validate all bytes before any installer can run. Copy these exact buffers,
  // never reopen the mutable source after verification. Extra files are omitted.
  const files = await readVerifiedTree(aiCentralRoot, commit);
  await fs.mkdir(snapshotParent, { recursive: true });
  const snapshot = await fs.mkdtemp(path.join(snapshotParent, `${commit}-`));
  try {
    for (const { relativePath, mode, bytes } of files) {
      const destination = path.join(snapshot, relativePath);
      await fs.mkdir(path.dirname(destination), { recursive: true });
      await fs.writeFile(destination, bytes, { flag: 'wx', mode: mode === '100755' ? 0o500 : 0o400 });
    }
    return snapshot;
  } catch (error) {
    await fs.rm(snapshot, { recursive: true, force: true });
    throw error;
  }
}

export async function refreshManagedLinks(targetRoot, aiCentralRoot, snapshot, dryRun) {
  const sourceRoot = await fs.realpath(aiCentralRoot);
  const snapshots = await fs.realpath(path.join(targetRoot, '.agents', 'ai-central-snapshots'));
  for (const directory of ['.agents/skills', '.codex/skills']) {
    const linkDirectory = path.join(targetRoot, directory);
    let entries;
    try { entries = await fs.readdir(linkDirectory, { withFileTypes: true }); }
    catch (error) { if (error.code === 'ENOENT') continue; throw error; }
    for (const entry of entries) {
      if (!entry.isSymbolicLink()) continue;
      const link = path.join(linkDirectory, entry.name);
      const lexicalTarget = path.resolve(linkDirectory, await fs.readlink(link));
      const compatibilityTarget = path.relative(path.join(targetRoot, '.agents', 'skills'), lexicalTarget);
      if (directory === '.codex/skills' && !path.isAbsolute(compatibilityTarget)
          && !compatibilityTarget.split(path.sep).includes('..')) continue;
      // Resolve source aliases (for example ~/.ai-central -> another checkout).
      // Preserve unresolved unrelated links; managed missing replacements reject.
      const oldTarget = await fs.realpath(lexicalTarget).catch(() => lexicalTarget);
      let relativeTarget = path.relative(sourceRoot, oldTarget);
      const priorSnapshot = path.relative(snapshots, oldTarget).split(path.sep);
      if (/^[0-9a-f]{40}-[^/\\]+$/.test(priorSnapshot[0])) {
        relativeTarget = priorSnapshot.slice(1).join(path.sep);
      }
      if (path.isAbsolute(relativeTarget) || relativeTarget.split(path.sep).includes('..')) {
        // Older installs may come from another AI_CENTRAL_HOME. Recognize the
        // maintained template layout and require a reviewed replacement below;
        // never silently keep a formerly managed link into a mutable checkout.
        const marker = `${path.sep}templates${path.sep}skills${path.sep}`;
        const markerIndex = oldTarget.lastIndexOf(marker);
        if (markerIndex < 0) continue;
        relativeTarget = oldTarget.slice(markerIndex + 1);
      }
      // Only managed reusable templates; preserve user files and compatibility
      // links pointing to .agents/skills. Missing reviewed replacements fail closed.
      if (!relativeTarget.startsWith(`templates${path.sep}`)) continue;
      const replacement = path.join(snapshot, relativeTarget);
      await fs.access(path.join(replacement, 'SKILL.md'));
      if (dryRun) {
        process.stdout.write(`Would refresh managed skill: ${entry.name}\n`);
      } else {
        await fs.unlink(link);
        await fs.symlink(replacement, link, process.platform === 'win32' ? 'junction' : 'dir');
      }
    }
  }
}

export async function recordCurrentPin(aiCentralRoot, destinationPinPath = pinPath) {
  const currentCommit = await resolveCurrentCommit(aiCentralRoot);
  await readVerifiedTree(aiCentralRoot, currentCommit);
  const payload = {
    expectedCommit: currentCommit,
    note: 'Reviewed AI Central revision required by scripts/setup-codex-links.mjs.'
  };
  await fs.writeFile(destinationPinPath, `${JSON.stringify(payload, null, 2)}\n`);
  process.stdout.write(`Recorded AI Central pin: ${currentCommit}\n`);
}

export async function runInstaller(aiCentralRoot, dryRun, targetRoot = repositoryRoot, reviewedPin) {
  const currentCommit = await resolveCurrentCommit(aiCentralRoot);
  const pin = reviewedPin ?? await readPin();
  const pinStatus = evaluatePin(pin, currentCommit);

  if (pinStatus !== 'match') {
    throw new Error(
      `AI Central commit ${currentCommit} does not match the reviewed pin ` +
        `${pin.expectedCommit ?? 'none'}. Review the checkout, then run ` +
        '`node scripts/setup-codex-links.mjs --record-pin`.'
    );
  }

  const snapshot = await createVerifiedSnapshot(
    aiCentralRoot, currentCommit, path.join(targetRoot, '.agents', 'ai-central-snapshots')
  );
  // Keep applied snapshots: installed skill links must continue to reference
  // verified bytes, not the original mutable checkout. Dry-run leaves no links.
  try {
    const setupScript = path.join(snapshot, 'scripts', 'setup-ai-context.sh');
    await fs.access(setupScript);
    await fs.access(path.join(snapshot, 'templates', 'catalog.json'));
    await refreshManagedLinks(targetRoot, aiCentralRoot, snapshot, dryRun);
    await new Promise((resolve, reject) => {
      const child = execFile(setupScript, buildSetupArguments(targetRoot, dryRun), { cwd: snapshot });

      child.stdout.pipe(process.stdout);
      child.stderr.pipe(process.stderr);
      child.once('error', reject);
      child.once('exit', (code, signal) => {
        if (signal) {
          reject(new Error(`AI Central setup terminated by ${signal}`));
        } else if (code !== 0) {
          reject(new Error(`AI Central setup exited with status ${code}`));
        } else {
          resolve();
        }
      });
    });
  } finally {
    if (dryRun) await fs.rm(snapshot, { recursive: true, force: true });
  }
}

async function main() {
  if (process.argv.includes('--help') || process.argv.includes('-h')) {
    process.stdout.write(`${usage()}\n`);
    return;
  }

  const options = parseArguments(process.argv.slice(2));
  const aiCentralRoot = resolveAiCentralRoot(process.env.AI_CENTRAL_HOME);

  if (options.recordPin) {
    await recordCurrentPin(aiCentralRoot);
    return;
  }

  await runInstaller(aiCentralRoot, options.dryRun);
}

if (isEntrypoint) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
