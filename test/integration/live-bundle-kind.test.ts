import { test } from 'node:test';
import assert from 'node:assert/strict';
import { main, parameterHash, parseBundleKind, DacsTestnetRefusal, type DacsTestnetConfig } from '../../src/live/dacs-testnet-run.mjs';
import { createDryRunDependencies } from '../../src/live/testnet-run-fixtures.js';

const config = (overrides: Partial<DacsTestnetConfig> = {}): DacsTestnetConfig => ({
  jobId: 'kind-job', mode: 'dry-run', organ: 'nws_alerts', query: '35.2271,-80.8431',
  priceDem: '1', spendCapDem: 50, rpc: 'https://demosnode.discus.sh/', ...overrides,
});

test('the bundle kind is a session parameter: it changes the dry-run hash and anything else is a configuration refusal', () => {
  const base = parameterHash(config());
  assert.equal(base, parameterHash(config({ bundleKind: 'ebfab' })), 'the default form and the explicit default hash alike');
  assert.notEqual(base, parameterHash(config({ bundleKind: 'fab' })), 'the standard form is a different session');
  assert.equal(parseBundleKind('fab'), 'fab');
  assert.equal(parseBundleKind('ebfab'), 'ebfab');
  for (const junk of ['FAB', 'fault', '', 'ebfab ']) {
    assert.throws(() => parseBundleKind(junk), (error: unknown) => error instanceof DacsTestnetRefusal && error.code === 'config', junk);
  }
});

async function dryRunAnchoredBundles(env: NodeJS.ProcessEnv): Promise<Array<Record<string, unknown>>> {
  let state: Map<string, unknown> | undefined;
  const out = process.stdout.write.bind(process.stdout);
  process.stdout.write = (() => true) as typeof process.stdout.write;
  try {
    const exit = await main(['--dry-run', '--json'], env, (run) => {
      const deps = createDryRunDependencies(run);
      state = deps.fixtureState.byNative;
      return deps;
    });
    assert.equal(exit, 0);
  } finally {
    process.stdout.write = out;
  }
  return [...(state ?? new Map()).values()].filter((v): v is Record<string, unknown> =>
    typeof v === 'object' && v !== null && 'anchoredByRole' in (v as Record<string, unknown>));
}

test('DACS_BUNDLE_KIND=fab finalizes DACS-5 FaultAttestationBundle copies; the default stays the evidence-bound form', async () => {
  const standard = await dryRunAnchoredBundles({ DACS_BUNDLE_KIND: 'fab' });
  assert.ok(standard.length >= 2, 'buyer and seller copies are anchored');
  for (const bundle of standard) {
    assert.equal(bundle.faultBundleVersion, '1');
    assert.equal(bundle.evidenceBoundFaultBundleVersion, undefined);
    assert.equal(bundle.bundleVersion, undefined);
  }
  const additive = await dryRunAnchoredBundles({});
  assert.ok(additive.length >= 2);
  for (const bundle of additive) {
    assert.equal(bundle.evidenceBoundFaultBundleVersion, '1');
    assert.equal(bundle.faultBundleVersion, undefined);
  }
  // An unknown kind never reaches finalization: the CLI refuses at configuration (exit 2, typed refusal).
  const err = process.stderr.write.bind(process.stderr); const out = process.stdout.write.bind(process.stdout);
  const stderr: string[] = [];
  process.stderr.write = ((chunk: string | Uint8Array) => { stderr.push(String(chunk)); return true; }) as typeof process.stderr.write;
  process.stdout.write = (() => true) as typeof process.stdout.write;
  try {
    const exit = await main(['--dry-run', '--json'], { DACS_BUNDLE_KIND: 'fault' }, (run) => createDryRunDependencies(run));
    assert.equal(exit, 2);
  } finally {
    process.stderr.write = err; process.stdout.write = out;
  }
  assert.match(stderr.join(''), /"reason":"config"/);
});

// DACS-2 §7.5.2: an AttestationRef on the wire is exactly { anchor: { kind, locator }, contentHash, signer? }. The
// pinned dacs-sdk checks those keys exactly; LIVE attempt 7 (2026-09-06) was refused by it because our references
// carried a substrate name, a type and a producedAt. Every reference a finalized copy cites must be the spec form.
function citedRefs(bundle: Record<string, unknown>): Array<Record<string, unknown>> {
  const refs: Array<Record<string, unknown>> = [];
  if (bundle.agreementRef) refs.push(bundle.agreementRef as Record<string, unknown>);
  for (const k of ['vetRecords', 'settlementEvidence', 'amendments', 'ratingRefs']) for (const r of (bundle[k] as unknown[] | undefined) ?? []) refs.push(r as Record<string, unknown>);
  for (const ph of (bundle.phaseSummary as Array<Record<string, unknown>>) ?? []) if (ph.attestationRef) refs.push(ph.attestationRef as Record<string, unknown>);
  return refs;
}

test('every reference a finalized copy cites is the DACS-2 §7.5.2 wire form, in both bundle forms', async () => {
  for (const env of [{ DACS_BUNDLE_KIND: 'fab' }, {}]) {
    const copies = await dryRunAnchoredBundles(env);
    assert.ok(copies.length >= 2);
    let seen = 0;
    for (const copy of copies) {
      for (const ref of citedRefs(copy)) {
        seen++;
        const keys = Object.keys(ref).sort();
        assert.ok(keys.join(',') === 'anchor,contentHash' || keys.join(',') === 'anchor,contentHash,signer', `ref keys ${keys.join(',')}`);
        assert.deepEqual(Object.keys(ref.anchor as object).sort(), ['kind', 'locator']);
        assert.equal((ref.anchor as { kind: string }).kind, 'storage-program');
        assert.match(String(ref.contentHash), /^[0-9a-f]{64}$/);
      }
    }
    assert.ok(seen >= 4, `cited references seen: ${seen}`);
  }
});
