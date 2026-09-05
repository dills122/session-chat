import { readFileSync, readdirSync, rmSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const COVERAGE_POLICY = Object.freeze({
  cargoLlvmCovVersion: '0.9.0',
  components: Object.freeze({
    'admission-capability': 'crates/admission-capability/src/',
    'key-protector-passphrase': 'crates/key-protector-passphrase/src/',
    'session-admission': 'crates/session-admission/src/',
    'session-core': 'crates/session-core/src/',
    'session-crypto': 'crates/session-crypto/src/',
    'session-crypto-hpke': 'crates/session-crypto-hpke/src/',
    'session-crypto-mls': 'crates/session-crypto-mls/src/',
    'session-inviter-transaction': 'crates/session-inviter-transaction/src/',
    'session-protocol': 'crates/session-protocol/src/',
    'session-storage': 'crates/session-storage/src/',
    'session-transport': 'crates/session-transport/src/',
    sessionctl: 'apps/sessionctl/src/',
    'storage-sqlcipher': 'crates/storage-sqlcipher/src/',
    'storage-sqlcipher-fault-vfs': 'crates/storage-sqlcipher-fault-vfs/src/',
    'transport-conformance': 'crates/transport-conformance/src/',
    'transport-iroh': 'crates/transport-iroh/src/',
    'transport-memory': 'crates/transport-memory/src/',
  }),
  minimumComponentLines: 90,
  componentLineRatchets: Object.freeze({ sessionctl: 90 }),
  minimumWorkspaceFunctions: 85.64,
  minimumWorkspaceLines: 92.23,
  minimumWorkspaceRegions: 88,
  nonInstrumentedSources: Object.freeze([
    'apps/sessionctl/src/l2_process.rs',
    'apps/sessionctl/src/l2_process/evidence.rs',
    'crates/storage-sqlcipher-fault-vfs/src/lib.rs',
    'crates/storage-sqlcipher/src/fault_testing.rs',
    'crates/transport-conformance/src/lib.rs',
  ]),
});

const PRODUCTION_SOURCE = /^(?:apps|crates)\/[^/]+\/src\/.*\.rs$/;
const METRICS = ['functions', 'lines', 'regions'];

function normalize(path) {
  return path.split(sep).join('/');
}

function emptyMetric() {
  return { count: 0, covered: 0, notcovered: 0, percent: 0 };
}

function addMetric(target, source) {
  target.count += source.count;
  target.covered += source.covered;
  target.notcovered = target.count - target.covered;
  target.percent = target.count === 0 ? 0 : (target.covered * 100) / target.count;
}

function emptySummary() {
  return Object.fromEntries(METRICS.map((metric) => [metric, emptyMetric()]));
}

function formatPercent(value) {
  return `${value.toFixed(2)}%`;
}

function belowThreshold(failures, label, metric, minimum) {
  if (metric.percent + Number.EPSILON < minimum) {
    failures.push(`${label} ${formatPercent(metric.percent)} is below ${formatPercent(minimum)}`);
  }
}

function coverageData(report) {
  if (report?.type !== 'llvm.coverage.json.export' || report?.data?.length !== 1) {
    throw new Error('coverage report must contain exactly one LLVM coverage export');
  }
  return report.data[0];
}

export function evaluateCoverageReport(report, root, policy = COVERAGE_POLICY, sourceFiles = []) {
  const failures = [];
  const data = coverageData(report);
  const componentEntries = Object.entries(policy.components);
  const components = Object.fromEntries(componentEntries.map(([name]) => [name, emptySummary()]));
  const reportedProductionSources = new Set();
  const nonInstrumentedSources = new Set(policy.nonInstrumentedSources ?? []);
  const knownSources = new Set(sourceFiles);

  if (report.cargo_llvm_cov?.version !== policy.cargoLlvmCovVersion) {
    failures.push(
      `expected cargo-llvm-cov ${policy.cargoLlvmCovVersion}, received ${report.cargo_llvm_cov?.version ?? 'unknown'}`,
    );
  }

  for (const file of data.files ?? []) {
    const repositoryPath = normalize(relative(root, file.filename));
    if (!PRODUCTION_SOURCE.test(repositoryPath)) continue;
    reportedProductionSources.add(repositoryPath);

    const matches = componentEntries.filter(([, prefix]) => repositoryPath.startsWith(prefix));
    if (matches.length !== 1) {
      failures.push(`production source is not assigned to a coverage component: ${repositoryPath}`);
      continue;
    }

    const [componentName] = matches[0];
    for (const metric of METRICS) addMetric(components[componentName][metric], file.summary[metric]);
  }

  for (const repositoryPath of sourceFiles) {
    if (
      PRODUCTION_SOURCE.test(repositoryPath) &&
      !reportedProductionSources.has(repositoryPath) &&
      !nonInstrumentedSources.has(repositoryPath)
    ) {
      failures.push(`production source is missing from the coverage report: ${repositoryPath}`);
    }
  }

  for (const repositoryPath of nonInstrumentedSources) {
    if (!knownSources.has(repositoryPath)) {
      failures.push(`non-instrumented source allowance does not exist: ${repositoryPath}`);
    } else if (reportedProductionSources.has(repositoryPath)) {
      failures.push(`non-instrumented source allowance is stale: ${repositoryPath}`);
    }
  }

  for (const [name, summary] of Object.entries(components)) {
    if (summary.lines.count === 0) {
      failures.push(`coverage report is missing production component ${name}`);
      continue;
    }
    const minimumLines = policy.componentLineRatchets?.[name] ?? policy.minimumComponentLines;
    belowThreshold(failures, `${name} line coverage`, summary.lines, minimumLines);
  }

  const workspace = data.totals;
  belowThreshold(
    failures,
    'workspace line coverage',
    workspace.lines,
    policy.minimumWorkspaceLines,
  );
  belowThreshold(
    failures,
    'workspace region coverage',
    workspace.regions,
    policy.minimumWorkspaceRegions,
  );
  belowThreshold(
    failures,
    'workspace function coverage',
    workspace.functions,
    policy.minimumWorkspaceFunctions,
  );

  return { components, failures, workspace };
}

function collectRustSources(root) {
  const sources = [];

  function visit(directory) {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile() && entry.name.endsWith('.rs')) {
        sources.push(normalize(relative(root, path)));
      }
    }
  }

  for (const topLevel of ['apps', 'crates']) visit(join(root, topLevel));
  return sources;
}

function verifyInstalledVersion(root, expectedVersion) {
  const result = spawnSync('cargo', ['llvm-cov', '--version'], {
    cwd: root,
    encoding: 'utf8',
  });
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || 'cargo llvm-cov --version failed');
  }
  const actual = result.stdout.trim();
  if (actual !== `cargo-llvm-cov ${expectedVersion}`) {
    throw new Error(`expected cargo-llvm-cov ${expectedVersion}, received ${actual || 'no version'}`);
  }
}

export function integrationTestTargets(metadata) {
  return metadata.packages
    .flatMap((packageMetadata) =>
      packageMetadata.targets
        .filter((target) => target.kind.includes('test'))
        .map((target) => ({ package: packageMetadata.name, test: target.name })),
    )
    .sort((left, right) =>
      left.package.localeCompare(right.package) || left.test.localeCompare(right.test),
    );
}

function runInherited(root, arguments_) {
  const result = spawnSync('cargo', arguments_, { cwd: root, stdio: 'inherit' });
  return result.status ?? 1;
}

function readCargoMetadata(root) {
  const result = spawnSync(
    'cargo',
    ['metadata', '--no-deps', '--format-version', '1', '--locked', '--offline'],
    { cwd: root, encoding: 'utf8' },
  );
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || 'cargo metadata failed');
  }
  return JSON.parse(result.stdout);
}

function printSummary(result) {
  console.log('Component line coverage:');
  for (const [name, summary] of Object.entries(result.components)) {
    console.log(
      `  ${name.padEnd(29)} ${formatPercent(summary.lines.percent).padStart(7)} ` +
        `(${summary.lines.covered}/${summary.lines.count})`,
    );
  }
  console.log(
    `Workspace: lines ${formatPercent(result.workspace.lines.percent)}, ` +
      `regions ${formatPercent(result.workspace.regions.percent)}, ` +
      `functions ${formatPercent(result.workspace.functions.percent)}`,
  );
}

export function runCoverageGate(root) {
  verifyInstalledVersion(root, COVERAGE_POLICY.cargoLlvmCovVersion);
  const temporaryDirectory = mkdtempSync(join(tmpdir(), 'session-chat-coverage-'));
  const reportPath = join(temporaryDirectory, 'coverage.json');

  try {
    if (runInherited(root, ['llvm-cov', 'clean', '--workspace']) !== 0) return 1;
    for (const target of integrationTestTargets(readCargoMetadata(root))) {
      const status = runInherited(root, [
        'llvm-cov',
        '--no-report',
        '--no-cfg-coverage',
        '--all-features',
        '--locked',
        '--offline',
        '--quiet',
        '--package',
        target.package,
        '--test',
        target.test,
      ]);
      if (status !== 0) return status;
    }
    const reportStatus = runInherited(root, [
      'llvm-cov',
      'report',
      '--json',
      '--output-path',
      reportPath,
    ]);
    if (reportStatus !== 0) return reportStatus;

    const report = JSON.parse(readFileSync(reportPath, 'utf8'));
    const evaluation = evaluateCoverageReport(report, root, COVERAGE_POLICY, collectRustSources(root));
    printSummary(evaluation);
    if (evaluation.failures.length > 0) {
      for (const failure of evaluation.failures) console.error(`coverage gate: ${failure}`);
      return 1;
    }
    return 0;
  } finally {
    rmSync(temporaryDirectory, { force: true, recursive: true });
  }
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : undefined;
if (invokedPath === fileURLToPath(import.meta.url)) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  try {
    process.exitCode = runCoverageGate(root);
  } catch (error) {
    console.error(`coverage gate: ${error.message}`);
    process.exitCode = 1;
  }
}
