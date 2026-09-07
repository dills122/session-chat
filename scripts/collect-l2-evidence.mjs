import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseCandidate } from './l2-candidate.mjs';

const suite = process.argv[2];
if (!['l2_outbox_crash_restart', 'l2_crash_restart_inviter', 'l2_crash_restart_joiner', 'l2_io_faults'].includes(suite)) throw new Error('unsupported L2 suite');
const output = execFileSync('cargo', ['test', '-p', 'sessionctl', '--test', suite, '--locked', '--offline', '--', '--nocapture', '--test-threads=1'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 45 * 60 * 1000 });
const records = [...output.matchAll(/L2_CANDIDATE_BEGIN\r?\n([\s\S]*?)L2_CANDIDATE_END/g)].map(match => match[1].replaceAll('\r\n', '\n'));
const bytes = Buffer.from(JSON.stringify(records));
parseCandidate(bytes);
const directory = resolve('target/l2-candidates');
mkdirSync(directory, { recursive: true });
writeFileSync(resolve(directory, `${suite}.json`), bytes, { flag: 'wx', mode: 0o600 });
console.log(`Retained ${records.length} unsigned ${suite} candidates; external attestation is required.`);
