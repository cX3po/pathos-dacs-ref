/**
 * verify CLI edge cases — Codex M2 round-8/9 notes
 *
 * Tests by spawning the CLI as a child process so we exercise exit codes,
 * argument parsing, and the unhandled-error path end-to-end.
 *
 * No network — uses --bundle-file with deliberately bad input.
 */

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { writeFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';

const CLI = join(process.cwd(), 'src/cli/verify.ts');

function run(args: string[]): { code: number; stdout: string; stderr: string } {
  const result = spawnSync('npx', ['tsx', CLI, ...args], {
    encoding: 'utf-8',
    timeout: 30000,
  });
  return {
    code: result.status ?? -1,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

test('CLI: bad flag → exit 3 (usage error)', () => {
  const r = run(['--bogus-flag']);
  assert.equal(r.code, 3);
  assert.match(r.stderr, /Error:/);
});

test('CLI: no source flag → exit 3 (usage error)', () => {
  const r = run([]);
  assert.equal(r.code, 3);
});

test('CLI: --help → exit 0 + USAGE on stdout', () => {
  const r = run(['--help']);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /pathos-dacs-verify/);
});

test('CLI: missing file → exit 2 (indeterminate, not usage)', () => {
  const r = run(['--bundle-file', '/nonexistent/file.json', '--offline', '--json']);
  assert.equal(r.code, 2);
});

test('CLI: malformed JSON file → exit 2 (indeterminate)', () => {
  const path = '/tmp/dacs-malformed-' + process.pid + '.json';
  writeFileSync(path, 'this is not valid json {{{');
  try {
    const r = run(['--bundle-file', path, '--offline', '--json']);
    assert.equal(r.code, 2);
  } finally {
    unlinkSync(path);
  }
});

test('CLI: --offline + valid bundle file → can pass without chain access', async () => {
  // Build the bundle inline in this process, then exec the CLI as a subprocess.
  const { generateKeypair, sign } = await import('../../src/lib/sign.js');
  const { DOMAIN_SEPARATORS } = await import('../../src/domain-sep.js');
  const { jcsCanonical, jcsHash } = await import('../../src/jcs.js');

  const { privKey, pubKey } = generateKeypair();
  const pubKeyHex = Array.from(pubKey, b => b.toString(16).padStart(2, '0')).join('');
  const unsigned = {
    v: 'dacs-5-bundle:0.1' as const,
    jobId: 'cli-test-001',
    role: 'buyer' as const,
    party: { v: 'dacs-1:0.1' as const, primary: { scheme: 'cci' as const, identifier: pubKeyHex }, claims: [], issuedAt: '2026-05-28T00:00:00Z', presentation: { kind: 'siwd' as const } },
    counterparty: { primary: { scheme: 'cci' as const, identifier: 'ff'.repeat(32) } },
    state: 'completed' as const,
    phases: [],
    finalisedAt: '2026-05-28T01:00:00Z',
  };
  const canonical = jcsCanonical(unsigned);
  const bundleHash = jcsHash(unsigned);
  const sig = sign(DOMAIN_SEPARATORS.BUNDLE, canonical, privKey, bundleHash);
  const signed = { ...unsigned, signature: Buffer.from(sig).toString('base64') };

  const path = '/tmp/dacs-cli-valid-' + process.pid + '.json';
  writeFileSync(path, JSON.stringify(signed));
  try {
    const r = run(['--bundle-file', path, '--offline', '--json']);
    assert.equal(r.code, 0, `expected exit 0 (pass), got ${r.code}\nstderr: ${r.stderr}\nstdout: ${r.stdout.slice(0, 500)}`);
  } finally {
    try { unlinkSync(path); } catch {}
  }
});
