import assert from 'node:assert/strict';
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

test('ordinary production coverage explicitly excludes the checked-cfg fault module', () => {
  assert.ok(
    COVERAGE_POLICY.nonInstrumentedSources.includes(
      'crates/storage-sqlcipher/src/fault_testing.rs',
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
