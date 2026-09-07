import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, sep } from 'node:path';
import test from 'node:test';

import { checkRepository } from './check-repository.mjs';

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'session-chat-policy-'));
  mkdirSync(join(root, 'docs'), { recursive: true });
  return root;
}

function portable(path) {
  return path.split(sep).join('/');
}

const PHASE_ONE_CRITERIA = `# ADR 0004

<!-- phase1-acceptance-criteria:start -->
- \`P1-STATE-CRASH-ATOMICITY\` — crash-atomic restore
- \`P1-STATE-STALE-SNAPSHOT\` — stale-snapshot rollback resistance
<!-- phase1-acceptance-criteria:end -->
`;

function phaseOneLedger(rows, status = 'complete') {
  return `# Phase 1 closeout

Status: ${status}

<!-- phase1-acceptance-ledger:start -->
| Criterion ID | Disposition | Evidence or superseding ADR |
| --- | --- | --- |
${rows.join('\n')}
<!-- phase1-acceptance-ledger:end -->
`;
}

function writePhaseOneAcceptance(root, rows, status) {
  mkdirSync(join(root, 'docs', 'adr'), { recursive: true });
  mkdirSync(join(root, 'docs', 'evidence'), { recursive: true });
  writeFileSync(join(root, 'docs', 'adr', '0004-phase-one.md'), PHASE_ONE_CRITERIA);
  writeFileSync(join(root, 'docs', 'adr', '0029-split.md'), '# ADR 0029\n');
  writeFileSync(join(root, 'docs', 'evidence', 'retained.md'), '# Retained evidence\n');
  writeFileSync(
    join(root, 'docs', 'evidence', 'phase1-closeout.md'),
    phaseOneLedger(rows, status),
  );
}

const CRASH_PASSED =
  '| `P1-STATE-CRASH-ATOMICITY` | passed | [evidence](retained.md) |';
const STALE_SUPERSEDED =
  '| `P1-STATE-STALE-SNAPSHOT` | superseded | [ADR 0029](../adr/0029-split.md) |';

test('accepts an exact complete Phase 1 acceptance ledger', (context) => {
  const root = fixture();
  context.after(() => rmSync(root, { force: true, recursive: true }));
  writePhaseOneAcceptance(root, [CRASH_PASSED, STALE_SUPERSEDED]);

  assert.deepEqual(checkRepository(root).failures, []);
});

test('rejects invalid Phase 1 acceptance-ledger mappings', () => {
  const cases = [
    {
      name: 'missing criterion',
      rows: [CRASH_PASSED],
      expected: /missing criterion P1-STATE-STALE-SNAPSHOT/,
    },
    {
      name: 'duplicate criterion',
      rows: [CRASH_PASSED, CRASH_PASSED, STALE_SUPERSEDED],
      expected: /duplicate criterion P1-STATE-CRASH-ATOMICITY/,
    },
    {
      name: 'passed without evidence',
      rows: ['| `P1-STATE-CRASH-ATOMICITY` | passed | none |', STALE_SUPERSEDED],
      expected: /passed criterion P1-STATE-CRASH-ATOMICITY requires retained evidence link/,
    },
    {
      name: 'passed with anchor instead of retained file',
      rows: ['| `P1-STATE-CRASH-ATOMICITY` | passed | [anchor](#only) |', STALE_SUPERSEDED],
      expected: /passed criterion P1-STATE-CRASH-ATOMICITY requires retained evidence link/,
    },
    {
      name: 'passed with external URL instead of retained file',
      rows: [
        '| `P1-STATE-CRASH-ATOMICITY` | passed | [external](https://example.com) |',
        STALE_SUPERSEDED,
      ],
      expected: /passed criterion P1-STATE-CRASH-ATOMICITY requires retained evidence link/,
    },
    {
      name: 'superseded without ADR',
      rows: [CRASH_PASSED, '| `P1-STATE-STALE-SNAPSHOT` | superseded | none |'],
      expected: /superseded criterion P1-STATE-STALE-SNAPSHOT requires ADR link/,
    },
    {
      name: 'complete with incomplete criterion',
      rows: [
        CRASH_PASSED,
        '| `P1-STATE-STALE-SNAPSHOT` | incomplete | [backlog](retained.md) |',
      ],
      expected: /complete ledger contains incomplete criterion P1-STATE-STALE-SNAPSHOT/,
    },
    {
      name: 'unrecognized visual table row',
      rows: [CRASH_PASSED, STALE_SUPERSEDED, '| P1-UNKNOWN | passed | [evidence](retained.md) |'],
      expected: /malformed acceptance row \| P1-UNKNOWN/,
    },
  ];

  for (const fixtureCase of cases) {
    const root = fixture();
    try {
      writePhaseOneAcceptance(root, fixtureCase.rows);
      assert.match(
        checkRepository(root).failures.join('\n'),
        fixtureCase.expected,
        fixtureCase.name,
      );
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  }
});

test('rejects duplicate Phase 1 acceptance marker blocks', (context) => {
  const root = fixture();
  context.after(() => rmSync(root, { force: true, recursive: true }));
  writePhaseOneAcceptance(root, [CRASH_PASSED, STALE_SUPERSEDED]);
  writeFileSync(
    join(root, 'docs', 'evidence', 'phase1-closeout.md'),
    `${phaseOneLedger([CRASH_PASSED, STALE_SUPERSEDED])}\n<!-- phase1-acceptance-ledger:start -->\n<!-- phase1-acceptance-ledger:end -->\n`,
  );

  assert.match(
    checkRepository(root).failures.join('\n'),
    /missing Phase 1 acceptance ledger block/,
  );
});

const CURRENT_CLAIMS = [
  {
    id: 'hpke_join',
    state: 'implemented_laboratory',
    evidence: ['crates/session-crypto-hpke/tests/capability_join_protection.rs'],
    limitations: ['no_human_approval_ux', 'no_production_readiness'],
    surfaces: [
      'docs/INDEPENDENT_AUDIT_BRIEF.md',
      'site/src/pages/security.astro',
      'site/CONTENT_DUMP.md',
    ],
  },
  {
    id: 'durable_authorization',
    state: 'implemented_laboratory',
    evidence: [
      'apps/sessionctl/tests/l1_process.rs',
      'crates/storage-sqlcipher/tests/durable_authorization.rs',
    ],
    limitations: [
      'no_platform_key_custody',
      'no_stale_snapshot_rollback_resistance',
      'no_secure_deletion',
      'no_production_readiness',
    ],
    surfaces: [
      'docs/INDEPENDENT_AUDIT_BRIEF.md',
      'site/src/pages/security.astro',
      'site/src/pages/architecture.astro',
      'site/src/pages/project.astro',
      'site/CONTENT_DUMP.md',
    ],
  },
  {
    id: 'fast_v1_delivery',
    state: 'implemented_experimental',
    evidence: [
      'crates/transport-iroh/tests/conformance.rs',
      'docs/evidence/transport-iroh-fast.md',
    ],
    limitations: [
      'no_offline_delivery',
      'no_durable_mailbox',
      'no_anonymity',
      'no_production_readiness',
    ],
    surfaces: [
      'docs/INDEPENDENT_AUDIT_BRIEF.md',
      'docs/ROADMAP_V2.md',
      'site/src/pages/index.astro',
      'site/src/pages/security.astro',
      'site/src/pages/architecture.astro',
      'site/src/pages/project.astro',
      'site/CONTENT_DUMP.md',
    ],
  },
];

function currentClaimMarkers(claims = CURRENT_CLAIMS) {
  return claims.map((claim) => `current-claim:${claim.id}=${claim.state}`).join('\n');
}

function writeCurrentImplementationFixture(root) {
  mkdirSync(join(root, 'apps', 'sessionctl'), { recursive: true });
  writeFileSync(join(root, 'Cargo.toml'), '[workspace]\nmembers = ["apps/sessionctl"]\n');
  writeFileSync(
    join(root, 'apps', 'sessionctl', 'Cargo.toml'),
    '[package]\nname = "sessionctl"\n[dependencies]\ntransport-iroh = { path = "../../crates/transport-iroh" }\n',
  );
  mkdirSync(join(root, 'apps', 'sessionctl', 'src'), { recursive: true });
  writeFileSync(
    join(root, 'apps', 'sessionctl', 'src', 'fast_adapter.rs'),
    'IrohFastEndpoint::bind_public().await;\n',
  );
  mkdirSync(join(root, 'crates', 'transport-iroh', 'src'), { recursive: true });
  writeFileSync(
    join(root, 'crates', 'transport-iroh', 'src', 'adapter.rs'),
    'impl EnvelopeDelivery for IrohFastDelivery {}\n',
  );
  writeFileSync(
    join(root, 'crates', 'transport-iroh', 'src', 'lib.rs'),
    'pub async fn bind_public() {}\n',
  );
  for (const claim of CURRENT_CLAIMS) {
    for (const evidence of claim.evidence) {
      const path = join(root, evidence);
      mkdirSync(join(path, '..'), { recursive: true });
      writeFileSync(path, '# Evidence\n');
    }
  }
  writeFileSync(
    join(root, 'docs', 'current-implementation.json'),
    `${JSON.stringify({ schemaVersion: 1, claims: CURRENT_CLAIMS }, null, 2)}\n`,
  );

  const surfaces = new Set(CURRENT_CLAIMS.flatMap((claim) => claim.surfaces));
  for (const surface of surfaces) {
    const path = join(root, surface);
    mkdirSync(join(path, '..'), { recursive: true });
    const claims = CURRENT_CLAIMS.filter((claim) => claim.surfaces.includes(surface));
    writeFileSync(
      path,
      `${currentClaimMarkers(claims)}\ntransport-iroh experimental connected FastV1. Not production; not an offline or durable mailbox; not anonymous; no platform key custody, rollback resistance, or secure deletion.\n`,
    );
  }
}

test('accepts one bounded current-implementation claim ledger', (context) => {
  const root = fixture();
  context.after(() => rmSync(root, { force: true, recursive: true }));
  writeCurrentImplementationFixture(root);

  assert.deepEqual(checkRepository(root).failures, []);
});

test('rejects contradictory current implementation claims and stale projections', () => {
  const cases = [
    ['HPKE has not been selected.', /hpke_join contradicts implemented_laboratory/],
    [
      'Approval/replay shadows are still process memory.',
      /durable_authorization contradicts implemented_laboratory/,
    ],
    [
      'The adapter is not an EnvelopeDelivery provider.',
      /fast_v1_delivery contradicts implemented_experimental/,
    ],
    ['There is no network adapter.', /fast_v1_delivery contradicts implemented_experimental/],
  ];

  for (const [contradiction, expected] of cases) {
    const root = fixture();
    try {
      writeCurrentImplementationFixture(root);
      writeFileSync(
        join(root, 'docs', 'INDEPENDENT_AUDIT_BRIEF.md'),
        `${currentClaimMarkers()}\n${contradiction}\n`,
      );
      assert.match(checkRepository(root).failures.join('\n'), expected);
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  }
});

test('requires immutable revision qualification for historical contrary claims', (context) => {
  const root = fixture();
  context.after(() => rmSync(root, { force: true, recursive: true }));
  writeCurrentImplementationFixture(root);
  const auditBrief = join(root, 'docs', 'INDEPENDENT_AUDIT_BRIEF.md');
  writeFileSync(auditBrief, `${currentClaimMarkers()}\nHistorical: no network transport.\n`);
  assert.match(
    checkRepository(root).failures.join('\n'),
    /fast_v1_delivery contradicts implemented_experimental/,
  );

  writeFileSync(
    auditBrief,
    `${currentClaimMarkers()}\nHistorical at revision ${'a'.repeat(40)}: no network transport. Current implementation has no network transport.\n`,
  );
  assert.match(
    checkRepository(root).failures.join('\n'),
    /fast_v1_delivery contradicts implemented_experimental/,
  );

  writeFileSync(
    auditBrief,
    `${currentClaimMarkers()}\nEvidence digest ${'a'.repeat(40)}. There is no network transport.\n`,
  );
  assert.match(
    checkRepository(root).failures.join('\n'),
    /fast_v1_delivery contradicts implemented_experimental/,
  );

  writeFileSync(
    auditBrief,
    `${currentClaimMarkers()}\nHistorical at revision ${'a'.repeat(40)}: no network transport.\n`,
  );
  assert.deepEqual(checkRepository(root).failures, []);
});

test('binds current claims to exact evidence and connected implementation', () => {
  const cases = [
    ['evidence', 'docs/INDEPENDENT_AUDIT_BRIEF.md'],
    ['implementation', 'crates/transport-iroh/src/adapter.rs'],
    ['implementation', 'crates/transport-iroh/src/lib.rs'],
    ['implementation', 'apps/sessionctl/src/fast_adapter.rs'],
    ['implementation', 'apps/sessionctl/Cargo.toml'],
  ];

  for (const [kind, target] of cases) {
    const root = fixture();
    try {
      writeCurrentImplementationFixture(root);
      if (kind === 'evidence') {
        const ledgerPath = join(root, 'docs', 'current-implementation.json');
        const ledger = JSON.parse(readFileSync(ledgerPath, 'utf8'));
        ledger.claims[0].evidence = [target];
        writeFileSync(ledgerPath, `${JSON.stringify(ledger, null, 2)}\n`);
      } else {
        writeFileSync(join(root, target), 'removed\n');
      }
      assert.match(
        checkRepository(root).failures.join('\n'),
        /incorrect evidence set|missing connected FastV1 implementation/,
      );
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  }
});

test('requires one exact current-claim marker per declared surface', () => {
  const fastMarker = 'current-claim:fast_v1_delivery=implemented_experimental';
  const cases = [
    `${fastMarker}\n${fastMarker}\n`,
    `${fastMarker}\ncurrent-claim:fast_v1_delivery=implemented_laboratory\n`,
    `${fastMarker}\ncurrent-claim:unknown=implemented_experimental\n`,
  ];

  for (const markers of cases) {
    const root = fixture();
    try {
      writeCurrentImplementationFixture(root);
      writeFileSync(
        join(root, 'docs', 'ROADMAP_V2.md'),
        `${markers}transport-iroh experimental connected FastV1.\n`,
      );
      assert.match(
        checkRepository(root).failures.join('\n'),
        /invalid current-claim markers/,
      );
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  }
});

test('requires generated claims and experimental transport inventory', () => {
  const root = fixture();
  try {
    writeCurrentImplementationFixture(root);
    writeFileSync(
      join(root, 'site', 'CONTENT_DUMP.md'),
      currentClaimMarkers().replace('current-claim:fast_v1_delivery=implemented_experimental', ''),
    );
    assert.match(
      checkRepository(root).failures.join('\n'),
      /site\/CONTENT_DUMP\.md: invalid current-claim markers/,
    );

    writeCurrentImplementationFixture(root);
    writeFileSync(join(root, 'site', 'src', 'pages', 'architecture.astro'), currentClaimMarkers());
    assert.match(
      checkRepository(root).failures.join('\n'),
      /site\/src\/pages\/architecture\.astro: missing experimental transport-iroh inventory/,
    );
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

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

test('accepts the explicit evidence-manifest line grammar', (context) => {
  const root = fixture();
  context.after(() => rmSync(root, { force: true, recursive: true }));
  writeFileSync(join(root, 'docs', 'target.md'), '# Target\n');
  writeFileSync(
    join(root, 'docs', 'evidence-manifest.txt'),
    '# Repository evidence\n\ndocs/target.md\n\nhttps://example.com/specification\n',
  );

  assert.deepEqual(checkRepository(root).failures, []);
});

test('does not inspect ignored nested development worktrees', (context) => {
  const root = fixture();
  context.after(() => rmSync(root, { force: true, recursive: true }));
  const worktree = join(root, '.claude', 'worktrees', 'local', 'docs');
  mkdirSync(worktree, { recursive: true });
  writeFileSync(join(worktree, 'evidence-manifest.txt'), 'arbitrary stale prose\n');

  assert.deepEqual(checkRepository(root).failures, []);
});

test('rejects traversing, symlinked, non-file, and malformed evidence entries', (context) => {
  const root = fixture();
  const outside = mkdtempSync(join(tmpdir(), 'session-chat-policy-outside-'));
  context.after(() => rmSync(root, { force: true, recursive: true }));
  context.after(() => rmSync(outside, { force: true, recursive: true }));
  const outsideFile = join(outside, 'outside.md');
  writeFileSync(outsideFile, '# Outside\n');
  writeFileSync(join(root, 'docs', 'target.md'), '# Target\n');
  writeFileSync(join(root, 'docs', 'target.md:stream'), '# Not Git-portable\n');
  mkdirSync(join(root, 'docs', 'directory'));
  symlinkSync(outsideFile, join(root, 'docs', 'file-link.md'));
  symlinkSync(outside, join(root, 'docs', 'directory-link'), 'dir');

  const badLines = [
    'docs/../docs/target.md',
    `docs/${portable(relative(join(root, 'docs'), outsideFile))}`,
    'docs/file-link.md',
    'docs/directory-link/outside.md',
    'docs/directory',
    outsideFile,
    'docs\\target.md',
    'C:\\outside.md',
    'docs/target.md:stream',
    'arbitrary prose',
    ' docs/target.md',
  ];
  writeFileSync(
    join(root, 'docs', 'evidence-manifest.txt'),
    `${badLines.join('\n')}\n`,
  );

  const messages = checkRepository(root).failures.join('\n');
  for (const line of badLines) {
    assert.ok(messages.includes(line), `missing rejection for ${line}:\n${messages}`);
  }
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
