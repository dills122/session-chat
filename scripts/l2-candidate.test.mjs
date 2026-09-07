import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { parseCandidate, matchVerifiedAttestation, sha256 } from './l2-candidate.mjs';
import { verifyCandidate } from './verify-l2-evidence.mjs';
const bytes = readFileSync(new URL('./fixtures/l2-candidate-v2.json', import.meta.url));
const commit = '1'.repeat(40);
function verifiedResult() {
  return [{ verificationResult: {
    signature: { certificate: {
      issuer: 'https://token.actions.githubusercontent.com',
      sourceRepositoryURI: 'https://github.com/dills122/session-chat',
      sourceRepositoryDigest: commit,
      buildSignerURI: 'https://github.com/dills122/session-chat/.github/workflows/ci.yml@refs/heads/master',
      buildSignerDigest: commit,
      runnerEnvironment: 'github-hosted',
      runInvocationURI: 'https://github.com/dills122/session-chat/actions/runs/123/attempts/1',
    } },
    statement: { predicateType: 'https://slsa.dev/provenance/v1', subject: [{ digest: { sha256: sha256(bytes) } }] },
  } }];
}
test('frozen v2 candidate remains explicitly unverified and requires external verification', () => {
  const records = parseCandidate(bytes);
  assert.equal(records[0].provenance, 'self-reported');
  assert.throws(() => matchVerifiedAttestation([], bytes, records, commit));
  // This is only the post-cryptographic-verification policy fixture. It is not
  // a signed attestation and is never accepted by the external CLI entrypoint.
  assert.equal(matchVerifiedAttestation(verifiedResult(), bytes, records, commit).candidate_sha256, sha256(bytes));
});
for (const field of ['issuer', 'sourceRepositoryURI', 'sourceRepositoryDigest', 'buildSignerURI', 'buildSignerDigest', 'runnerEnvironment', 'runInvocationURI']) {
  test(`rejects a verified statement with wrong certificate ${field}`, () => {
    const result = verifiedResult();
    result[0].verificationResult.signature.certificate[field] = 'forged';
    assert.throws(() => matchVerifiedAttestation(result, bytes, parseCandidate(bytes), commit));
  });
}
test('rejects changed subject, manifest, run, revision, binary, legacy schema and mixed matrices', () => {
  const records = parseCandidate(bytes);
  const result = verifiedResult();
  result[0].verificationResult.statement.subject[0].digest.sha256 = 'f'.repeat(64);
  assert.throws(() => matchVerifiedAttestation(result, bytes, records, commit));
  assert.throws(() => matchVerifiedAttestation(verifiedResult(), bytes, records, '2'.repeat(40)));
  for (const [before, after] of [['github_run_id=123', 'github_run_id=124'], ['producer_binary_sha256=' + 'b'.repeat(64), 'producer_binary_sha256=' + 'c'.repeat(64)]]) {
    const changed = Buffer.from(bytes.toString().replace(before, after));
    assert.throws(() => matchVerifiedAttestation(verifiedResult(), changed, parseCandidate(changed), commit));
  }
  assert.throws(() => parseCandidate(Buffer.from(bytes.toString().replace('l2-evidence-candidate-v2', 'l2-evidence-v1'))));
  const values = JSON.parse(bytes);
  assert.throws(() => parseCandidate(Buffer.from(JSON.stringify([values[0], values[0]]))));
});
test('a spoofed environment or fake git/RUSTC cannot replace an approved external verifier', context => {
  const directory = mkdtempSync(join(tmpdir(), 'l2-verifier-test-'));
  context.after(() => rmSync(directory, { recursive: true, force: true }));
  const fake = join(directory, 'gh');
  writeFileSync(fake, '#!/bin/sh\necho counterfeit\n', { mode: 0o700 });
  const candidate = join(directory, 'candidate.json');
  writeFileSync(candidate, bytes);
  // The candidate cannot select its own trust root, even when tool output and
  // every environment diagnostic are forged; digest mismatch precedes spawn.
  assert.throws(() => verifyCandidate(candidate, commit, fake, '0'.repeat(64)), /untrusted GitHub verifier/);
});
