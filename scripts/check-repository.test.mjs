import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { checkRepository } from './check-repository.mjs';

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'session-chat-policy-'));
  mkdirSync(join(root, 'docs'), { recursive: true });
  return root;
}

test('accepts valid local links, JSON, evidence, and immutable actions', (context) => {
  const root = fixture();
  context.after(() => rmSync(root, { force: true, recursive: true }));
  mkdirSync(join(root, '.github', 'workflows'), { recursive: true });
  writeFileSync(join(root, 'docs', 'target.md'), '# Target\n');
  writeFileSync(join(root, 'docs', 'index.md'), '[target](target.md#target)\n');
  writeFileSync(join(root, 'docs', 'data.json'), '{"ok":true}\n');
  writeFileSync(join(root, 'docs', 'evidence-manifest.txt'), 'docs/target.md\n');
  writeFileSync(
    join(root, '.github', 'workflows', 'ci.yml'),
    'steps:\n  - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n',
  );

  assert.deepEqual(checkRepository(root).failures, []);
});

test('rejects missing links, local paths, malformed JSON, and mutable actions', (context) => {
  const root = fixture();
  context.after(() => rmSync(root, { force: true, recursive: true }));
  mkdirSync(join(root, '.github', 'workflows'), { recursive: true });
  writeFileSync(join(root, 'docs', 'index.md'), '[missing](missing.md)\n`/Users/example/project`\n');
  writeFileSync(join(root, 'docs', 'data.json'), '{nope}\n');
  writeFileSync(join(root, '.github', 'workflows', 'ci.yml'), 'steps:\n  - uses: actions/checkout@v7\n');

  const messages = checkRepository(root).failures.join('\n');
  assert.match(messages, /missing link target/);
  assert.match(messages, /developer-local/);
  assert.match(messages, /invalid JSON/);
  assert.match(messages, /not pinned to a full commit/);
});

test('rejects stale evidence digests and unresolved steering placeholders', (context) => {
  const root = fixture();
  context.after(() => rmSync(root, { force: true, recursive: true }));
  mkdirSync(join(root, 'docs', 'spike'), { recursive: true });
  mkdirSync(join(root, '.codex', 'steering'), { recursive: true });
  writeFileSync(join(root, 'docs', 'spike', 'evidence-manifest.txt'), 'docs/index.md\n');
  writeFileSync(
    join(root, 'docs', 'spike', 'hardening.json'),
    '{"sourceEvidence":{"collectionSha256":"deadbeef"}}\n',
  );
  writeFileSync(join(root, '.codex', 'steering', 'rust.md'), '{{RUST_TEST_COMMAND}}\n');

  const messages = checkRepository(root).failures.join('\n');
  assert.match(messages, /collectionSha256 does not match/);
  assert.match(messages, /unresolved template placeholder/);
});
