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

test('CLI: v0.1 AttestationBundleV1 file → unanchored default = indeterminate (exit 2); --offline = pass (exit 0)', async () => {
  // Codex BLOCKER 1 regression: a real-key v0.1 bundle (bundleVersion:"1") routes to the v0.1
  // path. WITHOUT --offline the §10.4.2 two-sided lookup runs; an UNANCHORED local file (neither
  // party anchor on chain) is INDETERMINATE, not a default pass. WITH --offline the two-sided
  // lookup is skipped (caller-accepted scope) and the bundle passes structural+sig.
  const { sign } = await import('../../src/lib/sign.js');
  const { DOMAIN_SEPARATORS } = await import('../../src/domain-sep.js');
  const { bundleSignedScopeHashV1 } = await import('../../src/lib/bundle-signed-scope-v1.js');
  const { ed25519 } = await import('@noble/curves/ed25519');

  const hexOf = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  const mk = (fill: number) => { const priv = new Uint8Array(32).fill(fill); return { priv, pubHex: hexOf(ed25519.getPublicKey(priv)) }; };
  const buyer = mk(0x61), seller = mk(0x62);
  const unsigned = {
    bundleVersion: '1' as const, jobId: 'cli-v1-001', outcome: 'completed' as const, anchoredByRole: 'buyer' as const,
    listingRef: { listingId: 'lst-1', version: 1, contentHash: 'ab'.repeat(32) },
    parties: [
      { role: 'buyer' as const, bundleHash: 'aa'.repeat(32), primaryClaim: { scheme: 'cci' as const, identifier: buyer.pubHex } },
      { role: 'seller' as const, bundleHash: 'bb'.repeat(32), primaryClaim: { scheme: 'cci' as const, identifier: seller.pubHex } },
    ],
    phaseSummary: [{ index: 0, kind: 'vet-credentials', outcome: 'ok' as const }],
    vetRecords: [], settlementEvidence: [], recipeRegistryVersion: 1, railRegistryVersion: 1, finalisedAt: 1735689600000,
  };
  const bundleHash = bundleSignedScopeHashV1(unsigned);
  const enc = new TextEncoder();
  const sigOf = (k: { priv: Uint8Array; pubHex: string }) => ({
    party: { scheme: 'cci' as const, identifier: k.pubHex }, algorithm: 'ed25519' as const,
    value: Buffer.from(sign(DOMAIN_SEPARATORS.BUNDLE, enc.encode(bundleHash), k.priv)).toString('base64'),
  });
  const signed = { ...unsigned, signatures: [sigOf(buyer), sigOf(seller)] };

  const path = '/tmp/dacs-cli-v1-' + process.pid + '.json';
  writeFileSync(path, JSON.stringify(signed));
  try {
    // Default (no --offline): two-sided lookup attempted, bundle is not anchored → indeterminate (exit 2).
    const def = run(['--bundle-file', path, '--json', '--rpc', 'http://127.0.0.1:1/']);
    assert.equal(def.code, 2,
      `expected exit 2 (indeterminate — unanchored, NOT a default pass), got ${def.code}\nstderr: ${def.stderr}\nstdout: ${def.stdout.slice(0, 600)}`);
    const defJson = JSON.parse(def.stdout);
    assert.equal(defJson.decision, 'indeterminate');
    assert.ok(defJson.steps.some((s: { step: string }) => s.step === 'two-sided-anchoring'),
      'v0.1 default path MUST run the §10.4.2 two-sided-anchoring step');

    // With --offline: two-sided lookup skipped → structural+sig pass (exit 0).
    const off = run(['--bundle-file', path, '--offline', '--json']);
    assert.equal(off.code, 0, `expected exit 0 with --offline, got ${off.code}\nstderr: ${off.stderr}\nstdout: ${off.stdout.slice(0, 500)}`);
  } finally {
    try { unlinkSync(path); } catch {}
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
