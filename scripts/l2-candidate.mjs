import { createHash } from 'node:crypto';

export const REPOSITORY = 'dills122/session-chat';
export const WORKFLOW = `${REPOSITORY}/.github/workflows/ci.yml`;
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const HEX = /^[0-9a-f]{64}$/;
const FIELDS = `version protocol provenance publication record scenario result coverage sweep storage_scenario case_index case_count schedule_seed case_id target_kind checkpoint file_role operation fault_mode target_ordinal last_fully_explored_ordinal expected_state observed_state sqlite_primary_code sqlite_extended_code transaction_result commit dirty toolchain rustc_release rustc_commit rustc_host rustc_sha256 lock_sha256 platform runner_image github_run_id github_run_attempt github_workflow_sha github_workflow_ref github_repository github_event_name runner_os runner_arch runner_environment sqlcipher_version sqlite_version test_binary_sha256 verifier_binary_sha256 producer_binary_sha256 fault_driver_binary_sha256 baseline_artifact_sha256 post_recovery_artifact_sha256 matrix_sha256 internal_observation_sha256 frame_bytes frame_wait_ms child_wait_ms maximum_application_checkpoints maximum_artifact_bytes integrity schema semantic_oracle exact_retry secret_scan capture_completeness redaction child_cleanup handle_cleanup lease_cleanup directory_cleanup cleanup`.split(' ');

// Structural validation is NOT authentication. Only verify-l2-evidence may
// classify these bytes after the external signature verifier succeeds.
export function parseCandidate(bytes) {
  if (bytes.length > 32 * 1024 * 1024) throw new Error('candidate bound');
  const records = JSON.parse(bytes.toString('utf8'));
  if (!Array.isArray(records) || !records.length || records.length > 16384) throw new Error('candidate records');
  const parsed = records.map(record => {
    if (typeof record !== 'string' || record.length > 4096 || !record.endsWith('\n')) throw new Error('candidate record bound');
    const fields = Object.create(null);
    for (const line of record.slice(0, -1).split('\n')) {
      const at = line.indexOf('=');
      const key = line.slice(0, at), value = line.slice(at + 1);
      if (at < 1 || !FIELDS.includes(key) || Object.hasOwn(fields, key) || !/^[\x20-\x7e]+$/.test(value)) throw new Error('candidate field');
      fields[key] = value;
    }
    if (Object.keys(fields).length !== FIELDS.length || fields.version !== '4' || fields.protocol !== 'l2-evidence-candidate-v4'
      || fields.provenance !== 'self-reported' || fields.publication !== 'requires-external-attestation'
      || fields.result !== 'pass' || fields.coverage !== 'complete' || fields.dirty !== 'false'
      || fields.secret_scan !== 'pass' || fields.capture_completeness !== 'unproven'
      || fields.redaction !== 'unverified'
      || fields.github_repository !== REPOSITORY || !/^[0-9a-f]{40}$/.test(fields.commit)
      || !/^[0-9]+$/.test(fields.github_run_id) || !/^[0-9]+$/.test(fields.github_run_attempt)
      || !fields.github_workflow_ref.startsWith(`${WORKFLOW}@refs/`)) throw new Error('candidate contract');
    for (const key of FIELDS.filter(key => key.endsWith('_sha256'))) {
      if (key === 'fault_driver_binary_sha256' && fields[key] === 'none') continue;
      if (!HEX.test(fields[key])) throw new Error('candidate digest');
    }
    if (fields.test_binary_sha256 !== (fields.fault_driver_binary_sha256 === 'none' ? fields.verifier_binary_sha256 : fields.fault_driver_binary_sha256)) throw new Error('candidate binary roles');
    return fields;
  });
  const first = parsed[0];
  for (const record of parsed) {
    for (const key of ['commit', 'toolchain', 'rustc_release', 'rustc_commit', 'rustc_host', 'rustc_sha256', 'lock_sha256', 'github_run_id', 'github_run_attempt', 'github_workflow_sha', 'github_workflow_ref', 'platform', 'runner_image', 'producer_binary_sha256', 'verifier_binary_sha256']) {
      if (record[key] !== first[key]) throw new Error('mixed candidate provenance');
    }
  }
  const matrices = Map.groupBy(parsed, record => `${record.sweep}/${record.storage_scenario}`);
  for (const matrix of matrices.values()) {
    const keys = new Set();
    matrix.forEach((record, index) => {
      if (record.case_index !== String(index) || record.case_count !== String(matrix.length) || keys.has(record.case_id)
        || record.matrix_sha256 !== matrix[0].matrix_sha256 || record.fault_driver_binary_sha256 !== matrix[0].fault_driver_binary_sha256) throw new Error('candidate matrix');
      keys.add(record.case_id);
    });
  }
  return parsed;
}

// Input MUST be the output of a successful trusted `gh attestation verify`,
// never user-supplied JSON. Additional claims are bound to certificate fields,
// not the workflow-controllable statement predicate.
export function matchVerifiedAttestation(results, bytes, records, expectedCommit) {
  const first = records[0];
  if (first.commit !== expectedCommit) throw new Error('unexpected evidence revision');
  const subject = sha256(bytes);
  const invocation = `https://github.com/${REPOSITORY}/actions/runs/${first.github_run_id}/attempts/${first.github_run_attempt}`;
  if (!Array.isArray(results) || !results.some(result => {
    const verified = result.verificationResult;
    const cert = verified?.signature?.certificate;
    return cert?.issuer === 'https://token.actions.githubusercontent.com'
      && cert.sourceRepositoryURI === `https://github.com/${REPOSITORY}`
      && cert.sourceRepositoryDigest === expectedCommit
      && cert.buildSignerURI === `https://github.com/${first.github_workflow_ref}`
      && cert.buildSignerDigest === first.github_workflow_sha
      && cert.runnerEnvironment === 'github-hosted'
      && cert.runInvocationURI === invocation
      && verified.statement?.predicateType === 'https://slsa.dev/provenance/v1'
      && verified.statement.subject?.some(item => item.digest?.sha256 === subject);
  })) throw new Error('no attestation binds this candidate to the expected hosted run');
  return { provenance: 'github-attested', repository: REPOSITORY, commit: expectedCommit, invocation, candidate_sha256: subject, cases: records.length };
}
