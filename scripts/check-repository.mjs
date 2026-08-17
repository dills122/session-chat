import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, extname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const SKIPPED_DIRECTORIES = new Set(['.git', '.agents', 'node_modules', 'target']);
const LOCAL_MACHINE_PATH = /(?:file:\/\/|\/Users\/|\/home\/[A-Za-z0-9_.-]+\/|[A-Za-z]:\\Users\\)/;
const MARKDOWN_LINK = /!?\[[^\]]*\]\(([^)]+)\)/g;
const ACTION_USE = /^\s*(?:-\s+)?uses:\s*([^\s#]+)(?:\s+#.*)?$/gm;
const FULL_COMMIT = /^[^@]+@[0-9a-f]{40}$/;

function normalize(relativePath) {
  return relativePath.split(sep).join('/');
}

function shouldSkip(relativePath, entryName) {
  if (SKIPPED_DIRECTORIES.has(entryName)) return true;
  return normalize(relativePath) === '.codex/skills';
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
  for (const line of readFileSync(path, 'utf8').split(/\r?\n/)) {
    if (!/^(?:apps|crates|docs|scripts|spikes)\//.test(line)) continue;
    if (!existsSync(resolve(root, line))) {
      failures.push(`${repositoryPath}: missing repository evidence ${line}`);
    }
  }
}

function checkWorkflow(root, path, failures) {
  const contents = readFileSync(path, 'utf8');
  const repositoryPath = normalize(relative(root, path));
  for (const match of contents.matchAll(ACTION_USE)) {
    const action = match[1];
    if (action.startsWith('./') || action.startsWith('docker://')) continue;
    if (!FULL_COMMIT.test(action)) {
      failures.push(`${repositoryPath}: action is not pinned to a full commit: ${action}`);
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
