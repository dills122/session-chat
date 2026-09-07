import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';

import {
  COVERAGE_POLICY,
  evaluateCoverageReport,
  integrationTestTargets,
} from './check-rust-coverage.mjs';

function metric(covered, count) {
  return {
    count,
    covered,
    notcovered: count - covered,
    percent: count === 0 ? 0 : (covered * 100) / count,
  };
}

function file(root, path, { functions, lines, regions }) {
  return {
    filename: join(root, path),
    summary: {
      branches: metric(0, 0),
      functions: metric(...functions),
      lines: metric(...lines),
      mcdc: metric(0, 0),
      regions: metric(...regions),
    },
  };
}

function report(files, { functions, lines, regions }, version = '0.9.0') {
  return {
    cargo_llvm_cov: { version },
    data: [
      {
        files,
        totals: {
          branches: metric(0, 0),
          functions: metric(...functions),
          lines: metric(...lines),
          mcdc: metric(0, 0),
          regions: metric(...regions),
        },
      },
    ],
    type: 'llvm.coverage.json.export',
    version: '3.1.0',
  };
}

const policy = {
  cargoLlvmCovVersion: '0.9.0',
  components: {
    alpha: 'crates/alpha/src/',
    client: 'apps/client/src/',
  },
  minimumComponentLines: 90,
  componentLineRatchets: { client: 78 },
  minimumWorkspaceFunctions: 80,
  minimumWorkspaceLines: 90,
  minimumWorkspaceRegions: 85,
  nonInstrumentedSources: [],
};

const APPROVED_NON_INSTRUMENTED_SOURCES = [
  'apps/sessionctl/src/l2_process.rs',
  'apps/sessionctl/src/l2_process/evidence.rs',
  'apps/sessionctl/src/l2_process/execution.rs',
  'apps/sessionctl/src/l2_process/welcome.rs',
  'apps/sessionctl/src/l2_process/welcome_io.rs',
  'crates/storage-sqlcipher-fault-vfs/src/lib.rs',
  'crates/storage-sqlcipher/src/fault_testing.rs',
  'crates/transport-conformance/src/lib.rs',
];

test('coverage policy and documentation retain one exact threshold and allowance set', () => {
  assert.deepEqual(
    {
      componentLines: COVERAGE_POLICY.minimumComponentLines,
      workspaceFunctions: COVERAGE_POLICY.minimumWorkspaceFunctions,
      workspaceLines: COVERAGE_POLICY.minimumWorkspaceLines,
      workspaceRegions: COVERAGE_POLICY.minimumWorkspaceRegions,
    },
    {
      componentLines: 90,
      workspaceFunctions: 85.64,
      workspaceLines: 92.23,
      workspaceRegions: 88,
    },
  );
  assert.deepEqual(COVERAGE_POLICY.nonInstrumentedSources, APPROVED_NON_INSTRUMENTED_SOURCES);

  const secureDevelopment = readFileSync(
    new URL('../docs/SECURE_DEVELOPMENT.md', import.meta.url),
    'utf8',
  );
  const coverageRow = secureDevelopment
    .split('\n')
    .find((line) => line.startsWith('| Rust production coverage |'));
  assert.equal(
    coverageRow,
    `| Rust production coverage | Pinned source-based driver; integration-target production measurement; ${COVERAGE_POLICY.minimumWorkspaceLines.toFixed(2)}% workspace lines, ${COVERAGE_POLICY.minimumWorkspaceRegions.toFixed(2)}% regions, ${COVERAGE_POLICY.minimumWorkspaceFunctions.toFixed(2)}% functions, and ${COVERAGE_POLICY.minimumComponentLines}% lines for every vital library component |`,
  );

  const coveragePolicy = readFileSync(new URL('../docs/CODE_COVERAGE.md', import.meta.url), 'utf8');
  const canonicalThresholdSentence = `CI retains stable floors at ${COVERAGE_POLICY.minimumWorkspaceLines.toFixed(2)}% workspace lines, ${COVERAGE_POLICY.minimumWorkspaceRegions.toFixed(2)}% regions, ${COVERAGE_POLICY.minimumWorkspaceFunctions.toFixed(2)}% functions, and ${COVERAGE_POLICY.minimumComponentLines}% lines for each vital component.`;
  assert.ok(
    coveragePolicy.replaceAll(/\s+/g, ' ').includes(canonicalThresholdSentence),
    'CODE_COVERAGE.md must contain executable threshold tuple',
  );
  const allowanceBlock = coveragePolicy.match(
    /<!-- coverage-policy:non-instrumented-sources:start -->([\s\S]*?)<!-- coverage-policy:non-instrumented-sources:end -->/,
  );
  assert.ok(allowanceBlock, 'CODE_COVERAGE.md must delimit canonical allowance set');
  const documentedAllowances = [...allowanceBlock[1].matchAll(/^- `([^`]+)`$/gm)].map(
    (match) => match[1],
  );
  assert.deepEqual(documentedAllowances, APPROVED_NON_INSTRUMENTED_SOURCES);
});

test('workspace region floor rejects immediately below and accepts exact or higher reports', () => {
  const root = '/workspace';
  const regionPolicy = {
    ...policy,
    minimumWorkspaceRegions: COVERAGE_POLICY.minimumWorkspaceRegions,
  };
  const exactRegionBasisPoints = Math.round(COVERAGE_POLICY.minimumWorkspaceRegions * 100);
  const files = [
    file(root, 'crates/alpha/src/lib.rs', {
      functions: [1, 1],
      lines: [100, 100],
      regions: [88, 100],
    }),
    file(root, 'apps/client/src/main.rs', {
      functions: [1, 1],
      lines: [100, 100],
      regions: [88, 100],
    }),
  ];

  for (const [covered, accepted] of [
    [exactRegionBasisPoints - 1, false],
    [exactRegionBasisPoints, true],
    [8852, true],
  ]) {
    const result = evaluateCoverageReport(
      report(files, { functions: [100, 100], lines: [100, 100], regions: [covered, 10000] }),
      root,
      regionPolicy,
    );
    assert.equal(
      result.failures.some((failure) => failure.startsWith('workspace region coverage')),
      !accepted,
      `${covered / 100}% region report`,
    );
  }
});

test('ordinary production coverage explicitly excludes checked-cfg fault modules', () => {
  for (const source of [
    'apps/sessionctl/src/l2_process.rs',
    'apps/sessionctl/src/l2_process/evidence.rs',
    'crates/storage-sqlcipher/src/fault_testing.rs',
  ]) {
    assert.ok(COVERAGE_POLICY.nonInstrumentedSources.includes(source), source);
  }
});

test('measures the fault VFS and allows only its declaration-only crate root', () => {
  assert.equal(
    COVERAGE_POLICY.components['storage-sqlcipher-fault-vfs'],
    'crates/storage-sqlcipher-fault-vfs/src/',
  );
  assert.ok(
    COVERAGE_POLICY.nonInstrumentedSources.includes(
      'crates/storage-sqlcipher-fault-vfs/src/lib.rs',
    ),
  );
});

test('aggregates every production source file and accepts exact thresholds', () => {
  const root = '/workspace';
  const input = report(
    [
      file(root, 'crates/alpha/src/lib.rs', {
        functions: [4, 5],
        lines: [9, 10],
        regions: [17, 20],
      }),
      file(root, 'crates/alpha/src/state.rs', {
        functions: [4, 5],
        lines: [9, 10],
        regions: [17, 20],
      }),
      file(root, 'apps/client/src/main.rs', {
        functions: [1, 1],
        lines: [9, 10],
        regions: [9, 10],
      }),
    ],
    { functions: [9, 11], lines: [27, 30], regions: [43, 50] },
  );

  const result = evaluateCoverageReport(input, root, policy);

  assert.deepEqual(result.failures, []);
  assert.equal(result.components.alpha.lines.covered, 18);
  assert.equal(result.components.alpha.lines.count, 20);
  assert.equal(result.components.client.lines.percent, 90);
});

test('rejects component, workspace ratchet, and tool-version regressions', () => {
  const root = '/workspace';
  const input = report(
    [
      file(root, 'crates/alpha/src/lib.rs', {
        functions: [8, 10],
        lines: [89, 100],
        regions: [85, 100],
      }),
      file(root, 'apps/client/src/main.rs', {
        functions: [1, 1],
        lines: [9, 10],
        regions: [9, 10],
      }),
    ],
    { functions: [79, 100], lines: [899, 1000], regions: [849, 1000] },
    '0.8.7',
  );

  const messages = evaluateCoverageReport(input, root, policy).failures.join('\n');

  assert.match(messages, /expected cargo-llvm-cov 0\.9\.0, received 0\.8\.7/);
  assert.match(messages, /alpha line coverage 89\.00% is below 90\.00%/);
  assert.match(messages, /workspace line coverage 89\.90% is below 90\.00%/);
  assert.match(messages, /workspace region coverage 84\.90% is below 85\.00%/);
  assert.match(messages, /workspace function coverage 79\.00% is below 80\.00%/);
});

test('rejects missing components and unmatched production source', () => {
  const root = '/workspace';
  const input = report(
    [
      file(root, 'crates/alpha/src/lib.rs', {
        functions: [1, 1],
        lines: [10, 10],
        regions: [10, 10],
      }),
      file(root, 'crates/unlisted/src/lib.rs', {
        functions: [1, 1],
        lines: [10, 10],
        regions: [10, 10],
      }),
    ],
    { functions: [2, 2], lines: [20, 20], regions: [20, 20] },
  );

  const messages = evaluateCoverageReport(input, root, policy).failures.join('\n');

  assert.match(messages, /coverage report is missing production component client/);
  assert.match(messages, /production source is not assigned to a coverage component: crates\/unlisted\/src\/lib\.rs/);
});

test('accepts only an existing non-instrumented source allowance and rejects stale allowances', () => {
  const root = '/workspace';
  const input = report(
    [
      file(root, 'crates/alpha/src/state.rs', {
        functions: [1, 1],
        lines: [10, 10],
        regions: [10, 10],
      }),
      file(root, 'apps/client/src/main.rs', {
        functions: [1, 1],
        lines: [10, 10],
        regions: [10, 10],
      }),
    ],
    { functions: [2, 2], lines: [20, 20], regions: [20, 20] },
  );
  const allowedPolicy = {
    ...policy,
    nonInstrumentedSources: ['crates/alpha/src/lib.rs'],
  };

  const accepted = evaluateCoverageReport(input, root, allowedPolicy, [
    'apps/client/src/main.rs',
    'crates/alpha/src/lib.rs',
    'crates/alpha/src/state.rs',
  ]);
  assert.deepEqual(accepted.failures, []);

  const stale = evaluateCoverageReport(input, root, allowedPolicy, [
    'apps/client/src/main.rs',
    'crates/alpha/src/state.rs',
  ]).failures.join('\n');
  assert.match(stale, /non-instrumented source allowance does not exist/);
});

test('selects only integration-test targets in stable package and target order', () => {
  const metadata = {
    packages: [
      {
        name: 'zeta',
        targets: [
          { kind: ['bin'], name: 'zeta' },
          { kind: ['test'], name: 'flow' },
        ],
      },
      {
        name: 'alpha',
        targets: [
          { kind: ['test'], name: 'state' },
          { kind: ['lib'], name: 'alpha' },
          { kind: ['test'], name: 'bounds' },
        ],
      },
    ],
  };

  assert.deepEqual(integrationTestTargets(metadata), [
    { package: 'alpha', test: 'bounds' },
    { package: 'alpha', test: 'state' },
    { package: 'zeta', test: 'flow' },
  ]);
});
