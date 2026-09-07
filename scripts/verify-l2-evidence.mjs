import { execFileSync } from 'node:child_process';
import { closeSync, constants, fstatSync, mkdtempSync, openSync, readSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { matchVerifiedAttestation, parseCandidate, REPOSITORY, sha256, WORKFLOW } from './l2-candidate.mjs';

// Inspect and read one opened object, with a read-time bound even if it grows.
// Where supported, no-follow/nonblocking flags also reject links and FIFOs.
export function readBoundedRegularFile(path, maximum) {
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > maximum) throw new Error('file type or size bound');
    const chunks = [];
    let length = 0;
    for (;;) {
      const chunk = Buffer.alloc(Math.min(64 * 1024, maximum + 1 - length));
      const count = readSync(fd, chunk, 0, chunk.length, null);
      if (!count) return Buffer.concat(chunks, length);
      length += count;
      if (length > maximum) throw new Error('file read bound');
      chunks.push(chunk.subarray(0, count));
    }
  } finally {
    closeSync(fd);
  }
}

// The verifier path/digest and expected revision are consumer trust policy,
// supplied independently of the downloaded candidate and its environment.
export function verifyCandidate(candidate, expectedCommit, ghPath, ghDigest) {
  if (!/^[0-9a-f]{40}$/.test(expectedCommit) || !isAbsolute(ghPath) || !/^[0-9a-f]{64}$/.test(ghDigest)) throw new Error('explicit verifier trust policy required');
  const verifierBytes = readBoundedRegularFile(ghPath, 256 * 1024 * 1024);
  if (sha256(verifierBytes) !== ghDigest) throw new Error('untrusted GitHub verifier');
  const bytes = readBoundedRegularFile(candidate, 32 * 1024 * 1024);
  const records = parseCandidate(bytes);
  const directory = mkdtempSync(join(tmpdir(), 'session-chat-attestation-'));
  const snapshot = join(directory, 'candidate.json');
  const verifier = join(directory, 'gh.exe');
  try {
    writeFileSync(snapshot, bytes, { flag: 'wx', mode: 0o600 });
    // Execute exactly the approved bytes, even if the source path is replaced.
    writeFileSync(verifier, verifierBytes, { flag: 'wx', mode: 0o500 });
    // No PATH git, RUSTC, GITHUB_*, RUNNER_*, token override, custom root, or
    // downloaded JSON can stand in for verification by the trusted executable.
    const env = Object.fromEntries(['HOME', 'USERPROFILE', 'SystemRoot', 'SYSTEMROOT', 'TEMP', 'TMP'].filter(key => process.env[key]).map(key => [key, process.env[key]]));
    const output = execFileSync(verifier, ['attestation', 'verify', snapshot, '--repo', REPOSITORY, '--signer-workflow', WORKFLOW, '--source-digest', expectedCommit, '--deny-self-hosted-runners', '--cert-oidc-issuer', 'https://token.actions.githubusercontent.com', '--predicate-type', 'https://slsa.dev/provenance/v1', '--format', 'json'], { env, encoding: 'utf8', timeout: 60_000, maxBuffer: 4 * 1024 * 1024 });
    return matchVerifiedAttestation(JSON.parse(output), bytes, records, expectedCommit);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [candidate, commit, ghPath, ghDigest] = process.argv.slice(2);
  console.log(JSON.stringify(verifyCandidate(candidate, commit, ghPath, ghDigest)));
}
