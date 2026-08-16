import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  buildSetupArguments,
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
