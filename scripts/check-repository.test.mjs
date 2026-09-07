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

const COMMIT = '0123456789abcdef0123456789abcdef01234567';
const DIGEST = 'a'.repeat(64);
for (const extension of ['yml', 'yaml']) {
  for (const reference of [
    'docker://alpine:latest', 'docker://registry.example:5000/team/image:1.2.3',
    'docker://image', `DOCKER://image:latest@${COMMIT}`, `docker://image@sha256:${DIGEST.slice(1)}`,
    `docker://image@sha256:${DIGEST}garbage`, 'actions/checkout@v7',
    'owner/repo/.github/workflows/reuse.yml@main', '${{ inputs.action }}',
  ]) {
    for (const encode of [
      value => `jobs:\n  nested:\n    steps:\n      - uses: ${value}\n`,
      value => `steps: [{ uses: '${value}' }]\n`,
      value => `jobs: { nested: { "uses": "${value}" } }\n`,
      value => `steps: [{ "\\u0075ses": '${value}' }]\n`,
    ]) {
      test(`rejects mutable/ambiguous ${extension} reference ${encode(reference)}`, context => {
        const root = fixture();
        context.after(() => rmSync(root, { force: true, recursive: true }));
        mkdirSync(join(root, '.github/workflows'), { recursive: true });
        writeFileSync(join(root, `.github/workflows/ci.${extension}`), encode(reference));
        assert.ok(checkRepository(root).failures.length > 0);
      });
    }
  }
}
for (const contents of [
  `steps: [{uses: actions/checkout@${COMMIT}}]\n`,
  `jobs: { reuse: { 'uses': 'owner/repo/.github/workflows/ci.yaml@${COMMIT}' } }\n`,
  `steps:\n  - "\\u0075ses": "docker://registry.example:5000/team/image:tag@sha256:${DIGEST}" # pinned\n`,
  `steps:\n  - run: |\n      uses: docker://not-yaml:latest\n      echo 'uses: mutable@latest'\n  - uses: ./local/action\n`,
]) {
  test(`accepts supported immutable workflow ${contents}`, context => {
    const root = fixture();
    context.after(() => rmSync(root, { force: true, recursive: true }));
    mkdirSync(join(root, '.github/workflows'), { recursive: true });
    writeFileSync(join(root, '.github/workflows/ci.yml'), contents);
    assert.deepEqual(checkRepository(root).failures, []);
  });
}
for (const contents of [
  'steps:\n - uses: >-\n     docker://alpine:latest\n',
  'steps:\n - uses:\n     docker://alpine:latest\n',
  'steps:\n - ? uses\n   : docker://alpine:latest\n',
  'steps:\n - uses: &action docker://alpine:latest\n',
  'steps:\n - uses: *action\n',
  'steps:\n - !!str uses: docker://alpine:latest\n',
  'steps:\n - "us\\\n     es": docker://alpine:latest\n',
]) {
  test(`rejects unsupported workflow representation ${contents}`, context => {
    const root = fixture();
    context.after(() => rmSync(root, { force: true, recursive: true }));
    mkdirSync(join(root, '.github/workflows'), { recursive: true });
    writeFileSync(join(root, '.github/workflows/ci.yml'), contents);
    assert.ok(checkRepository(root).failures.length > 0);
  });
}

test('block scalar in compact sequence cannot hide a sibling uses key', context => {
  const root = fixture();
  context.after(() => rmSync(root, { force: true, recursive: true }));
  mkdirSync(join(root, '.github/workflows'), { recursive: true });
  writeFileSync(join(root, '.github/workflows/ci.yml'), 'steps:\n  - run: |\n      echo ok\n    uses: docker://alpine:latest\n');
  assert.ok(checkRepository(root).failures.length > 0);
});
