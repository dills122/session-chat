import { createHash } from 'node:crypto';
import { existsSync, lstatSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import { dirname, extname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const SKIPPED_DIRECTORIES = new Set(['.git', '.agents', 'node_modules', 'target']);
const LOCAL_MACHINE_PATH = /(?:file:\/\/|\/Users\/|\/home\/[A-Za-z0-9_.-]+\/|[A-Za-z]:\\Users\\)/;
const MARKDOWN_LINK = /!?\[[^\]]*\]\(([^)]+)\)/g;
import { workflowUses } from './workflow-uses.mjs';
const FULL_COMMIT = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$/;
const EVIDENCE_ROOTS = new Set(['apps', 'crates', 'docs', 'scripts', 'spikes']);

function normalize(relativePath) {
  return relativePath.split(sep).join('/');
}

function shouldSkip(relativePath, entryName) {
  if (SKIPPED_DIRECTORIES.has(entryName)) return true;
  const repositoryPath = normalize(relativePath);
  return repositoryPath === '.codex/skills' || repositoryPath === '.claude/worktrees';
}

export function collectFiles(root) {
  const files = [];

  function visit(directory) {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      const relativePath = relative(root, path);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (!shouldSkip(relativePath, entry.name)) visit(path);
      } else if (entry.isFile()) {
        files.push(path);
      }
    }
  }

  visit(root);
  return files;
}

function linkTarget(rawTarget) {
  const trimmed = rawTarget.trim();
  if (trimmed.startsWith('<')) {
    const end = trimmed.indexOf('>');
    return end === -1 ? trimmed : trimmed.slice(1, end);
  }
  return trimmed.split(/\s+/, 1)[0];
}

function checkMarkdown(root, path, failures) {
  const contents = readFileSync(path, 'utf8');
  const repositoryPath = normalize(relative(root, path));

  if (LOCAL_MACHINE_PATH.test(contents)) {
    failures.push(`${repositoryPath}: contains a developer-local or file:// path`);
  }

  for (const match of contents.matchAll(MARKDOWN_LINK)) {
    const target = linkTarget(match[1]);
    if (!target || target.startsWith('#')) continue;
    if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(target)) continue;

    const withoutFragment = target.split('#', 1)[0].split('?', 1)[0];
    if (!withoutFragment) continue;

    let decoded;
    try {
      decoded = decodeURIComponent(withoutFragment);
    } catch {
      failures.push(`${repositoryPath}: malformed link target ${target}`);
      continue;
    }

    if (isAbsolute(decoded)) {
      failures.push(`${repositoryPath}: repository link must be relative: ${target}`);
      continue;
    }

    const resolved = resolve(dirname(path), decoded);
    const rootPrefix = `${resolve(root)}${sep}`;
    if (resolved !== resolve(root) && !resolved.startsWith(rootPrefix)) {
      failures.push(`${repositoryPath}: link escapes repository: ${target}`);
    } else if (!existsSync(resolved)) {
      failures.push(`${repositoryPath}: missing link target ${target}`);
    }
  }
}

function checkJson(root, path, failures) {
  const repositoryPath = normalize(relative(root, path));
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    failures.push(`${repositoryPath}: invalid JSON: ${error.message}`);
    return;
  }

  if (repositoryPath.endsWith('/hardening.json') && parsed?.sourceEvidence?.collectionSha256) {
    const manifestPath = join(dirname(path), 'evidence-manifest.txt');
    if (!existsSync(manifestPath)) {
      failures.push(`${repositoryPath}: collection digest has no sibling evidence-manifest.txt`);
      return;
    }
    const digest = createHash('sha256').update(readFileSync(manifestPath)).digest('hex');
    if (digest !== parsed.sourceEvidence.collectionSha256) {
      failures.push(`${repositoryPath}: collectionSha256 does not match evidence-manifest.txt`);
    }
  }
}

function checkEvidenceManifest(root, path, failures) {
  const repositoryPath = normalize(relative(root, path));
  const canonicalRoot = realpathSync(root);
  for (const line of readFileSync(path, 'utf8').split(/\r?\n/)) {
    if (line === '' || line === '#' || line.startsWith('# ')) continue;
    if (line.trim() !== line) {
      failures.push(`${repositoryPath}: invalid evidence entry ${line}: surrounding whitespace`);
      continue;
    }
    if (line.startsWith('https://')) {
      try {
        const source = new URL(line);
        if (source.protocol === 'https:' && source.hostname && !source.username && !source.password) {
          continue;
        }
      } catch {
        // Fall through to one stable policy error.
      }
      failures.push(`${repositoryPath}: invalid external evidence URL ${line}`);
      continue;
    }
    if (isAbsolute(line) || line.includes('\\') || line.includes(':')) {
      failures.push(`${repositoryPath}: invalid repository evidence path ${line}`);
      continue;
    }

    const parts = line.split('/');
    if (!EVIDENCE_ROOTS.has(parts[0]) || parts.some(part => !part || part === '.' || part === '..')) {
      failures.push(`${repositoryPath}: invalid repository evidence path ${line}`);
      continue;
    }

    let target = canonicalRoot;
    let metadata;
    try {
      for (const part of parts) {
        target = join(target, part);
        metadata = lstatSync(target);
        if (metadata.isSymbolicLink()) {
          throw new Error('symbolic link');
        }
      }
    } catch (error) {
      const reason = error.message === 'symbolic link' ? 'symbolic link' : 'missing path';
      failures.push(`${repositoryPath}: invalid repository evidence ${line}: ${reason}`);
      continue;
    }

    const allowedRoot = join(canonicalRoot, parts[0]);
    let canonicalTarget;
    try {
      canonicalTarget = realpathSync(target);
    } catch {
      failures.push(`${repositoryPath}: invalid repository evidence ${line}: unresolved path`);
      continue;
    }
    const allowedRelative = relative(allowedRoot, canonicalTarget);
    const contained = allowedRelative === ''
      || (!isAbsolute(allowedRelative) && allowedRelative !== '..' && !allowedRelative.startsWith(`..${sep}`));
    if (!contained || !metadata.isFile()) {
      const reason = contained ? 'not a regular file' : 'outside allowed evidence root';
      failures.push(`${repositoryPath}: invalid repository evidence ${line}: ${reason}`);
    }
  }
}

function checkWorkflow(root, path, failures) {
  const contents = readFileSync(path, 'utf8');
  const repositoryPath = normalize(relative(root, path));
  try {
    for (const action of workflowUses(contents)) {
      if (/^\.\/[A-Za-z0-9_./-]+$/.test(action) && !action.split('/').includes('..')) continue;
      if (action.startsWith('docker://')) {
        if (!/^docker:\/\/[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}$/.test(action)) {
          failures.push(`${repositoryPath}: container action is not pinned to a SHA-256 digest`);
        }
      } else if (!FULL_COMMIT.test(action)) {
        failures.push(`${repositoryPath}: action is not pinned to a full commit: ${action}`);
      }
    }
  } catch (error) {
    failures.push(`${repositoryPath}: ${error.message}`);
  }
}

function markedBlock(contents, startMarker, endMarker) {
  if (contents.split(startMarker).length !== 2 || contents.split(endMarker).length !== 2) {
    return undefined;
  }
  const start = contents.indexOf(startMarker);
  const end = contents.indexOf(endMarker);
  if (start === -1 || end === -1 || end <= start) return undefined;
  return contents.slice(start + startMarker.length, end);
}

function retainedRepositoryFile(root, sourcePath, evidence) {
  const match = evidence.match(/\[[^\]]+\]\(([^)]+)\)/);
  if (!match) return undefined;
  const target = linkTarget(match[1]);
  if (!target || target.startsWith('#') || /^[A-Za-z][A-Za-z0-9+.-]*:/.test(target)) {
    return undefined;
  }
  const withoutFragment = target.split('#', 1)[0].split('?', 1)[0];
  let decoded;
  try {
    decoded = decodeURIComponent(withoutFragment);
  } catch {
    return undefined;
  }
  if (!decoded || isAbsolute(decoded)) return undefined;
  const resolved = resolve(dirname(sourcePath), decoded);
  const canonicalRoot = realpathSync(root);
  let metadata;
  let canonicalTarget;
  try {
    metadata = lstatSync(resolved);
    canonicalTarget = realpathSync(resolved);
  } catch {
    return undefined;
  }
  const relativeTarget = relative(canonicalRoot, canonicalTarget);
  if (
    metadata.isSymbolicLink()
    || !metadata.isFile()
    || isAbsolute(relativeTarget)
    || relativeTarget === '..'
    || relativeTarget.startsWith(`..${sep}`)
  ) {
    return undefined;
  }
  return normalize(relativeTarget);
}

function checkPhaseOneAcceptance(root, failures) {
  const adrRoot = join(root, 'docs', 'adr');
  const closeoutPath = join(root, 'docs', 'evidence', 'phase1-closeout.md');
  const adrCandidates = existsSync(adrRoot)
    ? readdirSync(adrRoot).filter((name) => /^0004-.*\.md$/.test(name))
    : [];
  if (adrCandidates.length === 0 && !existsSync(closeoutPath)) return;
  if (adrCandidates.length !== 1) {
    failures.push('docs/adr: Phase 1 acceptance policy requires exactly one ADR 0004 file');
    return;
  }
  if (!existsSync(closeoutPath)) {
    failures.push('docs/evidence/phase1-closeout.md: missing Phase 1 acceptance ledger');
    return;
  }

  const adrPath = join(adrRoot, adrCandidates[0]);
  const criteriaBlock = markedBlock(
    readFileSync(adrPath, 'utf8'),
    '<!-- phase1-acceptance-criteria:start -->',
    '<!-- phase1-acceptance-criteria:end -->',
  );
  if (criteriaBlock === undefined) {
    failures.push(`${normalize(relative(root, adrPath))}: missing Phase 1 acceptance criteria block`);
    return;
  }
  const criteria = new Set();
  for (const line of criteriaBlock.split(/\r?\n/).filter(Boolean)) {
    const match = line.match(/^- `([A-Z][A-Z0-9-]+)` — .+$/);
    if (!match) {
      failures.push(`${normalize(relative(root, adrPath))}: malformed Phase 1 criterion ${line}`);
      continue;
    }
    if (criteria.has(match[1])) {
      failures.push(`${normalize(relative(root, adrPath))}: duplicate criterion ${match[1]}`);
    }
    criteria.add(match[1]);
  }

  const closeout = readFileSync(closeoutPath, 'utf8');
  const ledgerBlock = markedBlock(
    closeout,
    '<!-- phase1-acceptance-ledger:start -->',
    '<!-- phase1-acceptance-ledger:end -->',
  );
  if (ledgerBlock === undefined) {
    failures.push('docs/evidence/phase1-closeout.md: missing Phase 1 acceptance ledger block');
    return;
  }
  const status = closeout.match(/^Status: (.+)$/m)?.[1] ?? '';
  const complete = /\bcomplete\b/.test(status);
  const ledger = new Map();
  const lines = ledgerBlock.split(/\r?\n/).filter(Boolean);
  const rows = [];
  for (const line of lines) {
    if (
      line === '| Criterion ID | Disposition | Evidence or superseding ADR |'
      || line === '| --- | --- | --- |'
    ) {
      continue;
    }
    if (!line.startsWith('| `')) {
      failures.push(`docs/evidence/phase1-closeout.md: malformed acceptance row ${line}`);
      continue;
    }
    rows.push(line);
  }
  for (const row of rows) {
    const match = row.match(
      /^\| `([A-Z][A-Z0-9-]+)` \| (passed|superseded|incomplete) \| (.+) \|$/,
    );
    if (!match) {
      failures.push(`docs/evidence/phase1-closeout.md: malformed acceptance row ${row}`);
      continue;
    }
    const [, criterion, disposition, evidence] = match;
    if (ledger.has(criterion)) {
      failures.push(`docs/evidence/phase1-closeout.md: duplicate criterion ${criterion}`);
      continue;
    }
    ledger.set(criterion, disposition);
    const evidencePath = retainedRepositoryFile(root, closeoutPath, evidence);
    if (disposition === 'passed' && evidencePath === undefined) {
      failures.push(
        `docs/evidence/phase1-closeout.md: passed criterion ${criterion} requires retained evidence link`,
      );
    }
    if (
      disposition === 'superseded'
      && (evidencePath === undefined || !/^docs\/adr\/\d{4}-[^/]+\.md$/.test(evidencePath))
    ) {
      failures.push(
        `docs/evidence/phase1-closeout.md: superseded criterion ${criterion} requires ADR link`,
      );
    }
    if (complete && disposition === 'incomplete') {
      failures.push(
        `docs/evidence/phase1-closeout.md: complete ledger contains incomplete criterion ${criterion}`,
      );
    }
  }
  for (const criterion of criteria) {
    if (!ledger.has(criterion)) {
      failures.push(`docs/evidence/phase1-closeout.md: missing criterion ${criterion}`);
    }
  }
  for (const criterion of ledger.keys()) {
    if (!criteria.has(criterion)) {
      failures.push(`docs/evidence/phase1-closeout.md: unknown criterion ${criterion}`);
    }
  }
}

export function checkRepository(root) {
  const failures = [];
  const files = collectFiles(root);
  let markdownCount = 0;
  let jsonCount = 0;

  for (const path of files) {
    const repositoryPath = normalize(relative(root, path));
    if (extname(path) === '.md') {
      markdownCount += 1;
      checkMarkdown(root, path, failures);
    }
    if (extname(path) === '.json') {
      jsonCount += 1;
      checkJson(root, path, failures);
    }
    if (path.endsWith('evidence-manifest.txt')) checkEvidenceManifest(root, path, failures);
    if (/^\.github\/workflows\/.*\.ya?ml$/.test(repositoryPath)) {
      checkWorkflow(root, path, failures);
    }
  }

  checkPhaseOneAcceptance(root, failures);

  const steeringRoot = join(root, '.codex', 'steering');
  if (existsSync(steeringRoot)) {
    for (const path of collectFiles(steeringRoot)) {
      if (/\{\{[^}]+\}\}/.test(readFileSync(path, 'utf8'))) {
        failures.push(`${normalize(relative(root, path))}: contains an unresolved template placeholder`);
      }
    }
  }

  return { failures, jsonCount, markdownCount };
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : undefined;
if (invokedPath === fileURLToPath(import.meta.url)) {
  const root = resolve(process.argv[2] ?? '.');
  const result = checkRepository(root);
  if (result.failures.length > 0) {
    for (const failure of result.failures) console.error(failure);
    process.exitCode = 1;
  } else {
    console.log(`Repository policy passed (${result.markdownCount} Markdown, ${result.jsonCount} JSON files).`);
  }
}
