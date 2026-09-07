import { execFileSync } from 'node:child_process';
import { lstatSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { matchVerifiedAttestation, parseCandidate, REPOSITORY, sha256, WORKFLOW } from './l2-candidate.mjs';

// The verifier path/digest and expected revision are consumer trust policy,
// supplied independently of the downloaded candidate and its environment.
export function verifyCandidate(candidate, expectedCommit, ghPath, ghDigest) {
  if (!/^[0-9a-f]{40}$/.test(expectedCommit) || !isAbsolute(ghPath) || !/^[0-9a-f]{64}$/.test(ghDigest)) throw new Error('explicit verifier trust policy required');
  if (!lstatSync(ghPath).isFile() || sha256(readFileSync(ghPath)) !== ghDigest) throw new Error('untrusted GitHub verifier');
  if (!lstatSync(candidate).isFile() || lstatSync(candidate).size > 32 * 1024 * 1024) throw new Error('candidate file bound');
  const bytes = readFileSync(candidate);
  const records = parseCandidate(bytes);
  const directory = mkdtempSync(join(tmpdir(), 'session-chat-attestation-'));
  const snapshot = join(directory, 'candidate.json');
  try {
    writeFileSync(snapshot, bytes, { flag: 'wx', mode: 0o600 });
    // No PATH git, RUSTC, GITHUB_*, RUNNER_*, token override, custom root, or
    // downloaded JSON can stand in for verification by the trusted executable.
    const env = Object.fromEntries(['HOME', 'USERPROFILE', 'SystemRoot', 'SYSTEMROOT', 'TEMP', 'TMP'].filter(key => process.env[key]).map(key => [key, process.env[key]]));
    const output = execFileSync(ghPath, ['attestation', 'verify', snapshot, '--repo', REPOSITORY, '--signer-workflow', WORKFLOW, '--source-digest', expectedCommit, '--deny-self-hosted-runners', '--cert-oidc-issuer', 'https://token.actions.githubusercontent.com', '--predicate-type', 'https://slsa.dev/provenance/v1', '--format', 'json'], { env, encoding: 'utf8', timeout: 60_000, maxBuffer: 4 * 1024 * 1024 });
    return matchVerifiedAttestation(JSON.parse(output), bytes, records, expectedCommit);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [candidate, commit, ghPath, ghDigest] = process.argv.slice(2);
  console.log(JSON.stringify(verifyCandidate(candidate, commit, ghPath, ghDigest)));
}
