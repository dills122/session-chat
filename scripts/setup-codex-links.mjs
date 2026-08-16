#!/usr/bin/env node

import { execFile } from 'node:child_process';
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
  const { stdout } = await execFileAsync('git', ['-C', aiCentralRoot, 'rev-parse', 'HEAD']);
  return stdout.trim();
}

async function recordCurrentPin(aiCentralRoot) {
  const currentCommit = await resolveCurrentCommit(aiCentralRoot);
  const payload = {
    expectedCommit: currentCommit,
    note: 'Reviewed AI Central revision required by scripts/setup-codex-links.mjs.'
  };
  await fs.writeFile(pinPath, `${JSON.stringify(payload, null, 2)}\n`);
  process.stdout.write(`Recorded AI Central pin: ${currentCommit}\n`);
}

async function runInstaller(aiCentralRoot, dryRun) {
  const setupScript = path.join(aiCentralRoot, 'scripts', 'setup-ai-context.sh');
  const catalog = path.join(aiCentralRoot, 'templates', 'catalog.json');

  await fs.access(setupScript);
  await fs.access(catalog);

  const currentCommit = await resolveCurrentCommit(aiCentralRoot);
  const pin = await readPin();
  const pinStatus = evaluatePin(pin, currentCommit);

  if (pinStatus !== 'match') {
    throw new Error(
      `AI Central commit ${currentCommit} does not match the reviewed pin ` +
        `${pin.expectedCommit ?? 'none'}. Review the checkout, then run ` +
        '`node scripts/setup-codex-links.mjs --record-pin`.'
    );
  }

  await new Promise((resolve, reject) => {
    const child = execFile(setupScript, buildSetupArguments(repositoryRoot, dryRun), { cwd: aiCentralRoot });

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
