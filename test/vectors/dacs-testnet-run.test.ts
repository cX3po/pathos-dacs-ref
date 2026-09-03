import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  rollupColdVerifications,
  runDacsTestnetSession,
  type AgreementResult,
  type AnchoredEvidence,
  type ColdVerdict,
  type DacsTestnetConfig,
  type DacsTestnetDependencies,
  type DeliveryResult,
  type FinalizationResult,
  type PublishedListing,
} from '../../src/live/dacs-testnet-run.mjs';

const config: DacsTestnetConfig = { jobId: 'unit-job', mode: 'dry-run', organ: 'nws_alerts', query: 'fixture-query', priceDem: '1', spendCapDem: 50, rpc: 'https://example.invalid' };
const anchor = (logicalAddress: string, nativeAddress = `native-${logicalAddress}`) => ({ logicalAddress, nativeAddress, transactionRef: { kind: 'fixture', value: `tx-${logicalAddress}` }, writer: 'cci:writer', nonce: '1' });
const listing = { listing: { listingId: 'listing', listingVersion: 1 }, listingRef: { listingId: 'listing', version: 1, contentHash: 'aa'.repeat(32) }, anchor: anchor('listing') } as PublishedListing;
const agreement = { committed: { addresses: { agreement: { logical: 'agreement', native: 'native-agreement' }, commitment: { logical: 'commitment', native: 'native-commitment' } } }, commitmentRef: { anchor: { substrate: 'demos', locator: 'native-commitment' }, contentHash: 'bb'.repeat(32), type: 'finality-commitment', producedAt: new Date(0).toISOString() } } as AgreementResult;
const payment = { evidence: {}, evidenceRef: { anchor: { substrate: 'demos', locator: 'native-payment' }, contentHash: 'cc'.repeat(32), type: 'settlement-evidence', producedAt: new Date(0).toISOString(), signer: 'cci:writer' }, evidenceLogicalAddress: 'payment', evidenceAnchor: anchor('payment', 'native-payment') } as AnchoredEvidence;
const delivery = { ...payment, evidenceRef: { ...payment.evidenceRef, anchor: { substrate: 'demos', locator: 'native-delivery' } }, evidenceLogicalAddress: 'delivery', evidenceAnchor: anchor('delivery', 'native-delivery'), deliverableAnchor: anchor('deliverable', 'native-deliverable') } as DeliveryResult;
const finalization = { finalized: { scopeHash: 'dd'.repeat(32), bundles: { buyer: { address: { logical: 'buyer', native: 'native-buyer' } }, seller: { address: { logical: 'seller', native: 'native-seller' } } } }, session: {} } as FinalizationResult;

function fakeDeps(calls: string[], overrides: Partial<DacsTestnetDependencies> = {}): DacsTestnetDependencies {
  const step = <T>(name: string, value: T) => async () => { calls.push(name); return value; };
  return {
    capabilityPreflight: step('preflight', undefined), publishListing: step('listing', listing),
    vetListing: step('vet', { outcome: 'pass', detail: 'ok' } as ColdVerdict), emitAgreement: step('agreement', agreement),
    verifyAgreement: step('agreement-cold', { outcome: 'pass', detail: 'ok' } as ColdVerdict), settlePayment: step('payment', payment),
    deliver: step('delivery', delivery), finalize: step('finalization', finalization),
    verifyBundle: step('bundle-cold', { outcome: 'pass', detail: 'ok' } as ColdVerdict), ...overrides,
  };
}

test('orchestration executes in exact fail-closed order', async () => {
  const calls: string[] = [];
  const result = await runDacsTestnetSession(config, fakeDeps(calls));
  assert.deepEqual(calls, ['preflight', 'listing', 'vet', 'agreement', 'agreement-cold', 'payment', 'delivery', 'finalization', 'bundle-cold']);
  assert.equal(result.rollup, 'PASS');
  assert.deepEqual(result.phases.map(({ index, kind }) => [index, kind]), [[0, 'negotiate-fixed-price'], [1, 'commit-agreement'], [2, 'pay-dem'], [3, 'deliver-storage-program']]);
});

test('every failing stage stops all subsequent work', async () => {
  const stages = ['listing', 'vet', 'agreement', 'agreement-cold', 'payment', 'delivery', 'finalization', 'bundle-cold'] as const;
  const full = ['preflight', 'listing', 'vet', 'agreement', 'agreement-cold', 'payment', 'delivery', 'finalization', 'bundle-cold'];
  for (const stage of stages) {
    const calls: string[] = [];
    const overrides: Partial<DacsTestnetDependencies> = {};
    const method = ({ listing: 'publishListing', vet: 'vetListing', agreement: 'emitAgreement', 'agreement-cold': 'verifyAgreement', payment: 'settlePayment', delivery: 'deliver', finalization: 'finalize', 'bundle-cold': 'verifyBundle' } as const)[stage];
    (overrides as Record<string, unknown>)[method] = async () => {
      calls.push(stage);
      if (stage === 'vet' || stage === 'agreement-cold' || stage === 'bundle-cold') return { outcome: 'fail', detail: `${stage} refused` };
      throw new Error(`${stage} refused`);
    };
    const result = await runDacsTestnetSession(config, fakeDeps(calls, overrides));
    assert.deepEqual(calls, full.slice(0, full.indexOf(stage) + 1), stage);
    assert.notEqual(result.rollup, 'PASS', stage);
  }
});

test('cold-verifier rollup covers every fail/indeterminate combination', () => {
  const outcomes = ['pass', 'fail', 'indeterminate'] as const;
  for (const a of outcomes) for (const b of outcomes) {
    const actual = rollupColdVerifications({ outcome: a, detail: a }, { outcome: b, detail: b });
    const expected = a === 'fail' || b === 'fail' ? 'FAIL' : a === 'indeterminate' || b === 'indeterminate' ? 'INDETERMINATE' : 'PASS';
    assert.equal(actual, expected, `${a}/${b}`);
  }
});

test('finalizer receives complete SEB-3 logical/native/hash/writer bindings', async () => {
  const calls: string[] = [];
  const result = await runDacsTestnetSession(config, fakeDeps(calls, {
    async finalize(input) {
      calls.push('finalization');
      for (const evidence of [input.payment, input.delivery]) {
        assert.equal(evidence.evidenceRef.anchor.locator, evidence.evidenceAnchor.nativeAddress);
        assert.equal(evidence.evidenceAnchor.logicalAddress, evidence.evidenceLogicalAddress);
        assert.equal(evidence.evidenceRef.signer, evidence.evidenceAnchor.writer);
        assert.match(evidence.evidenceRef.contentHash, /^[0-9a-f]{64}$/);
      }
      return finalization;
    },
  }));
  assert.equal(result.rollup, 'PASS');
});

test('result JSON and error handling do not expose secret or environment values', async () => {
  const sentinel = 'twelve-secret-words-never-appear';
  const calls: string[] = [];
  const result = await runDacsTestnetSession(config, fakeDeps(calls, { async publishListing() { calls.push('listing'); throw new Error('listing refused'); } }));
  const encoded = JSON.stringify(result);
  assert.doesNotMatch(encoded, /mnemonic|private.?key|fixture.?seed/i);
  assert.ok(!encoded.includes(sentinel));
});

function spawn(args: string[], extraEnv: NodeJS.ProcessEnv = {}) {
  return spawnSync(process.execPath, ['--import', 'tsx', 'src/live/dacs-testnet-run.mts', ...args], {
    cwd: process.cwd(), encoding: 'utf8', env: { PATH: process.env.PATH, ...extraEnv }, timeout: 30_000,
  });
}

test('dry-run CLI is deterministic, passes both cold checks, and emits no key material', (t) => {
  const first = spawn(['--dry-run', '--job-id', 'fixture-job', '--json']);
  if (first.error && (first.error as NodeJS.ErrnoException).code === 'EPERM') { t.skip('sandbox refuses nested process creation'); return; }
  const second = spawn(['--dry-run', '--job-id', 'fixture-job', '--json']);
  assert.equal(first.status, 0, first.stderr);
  assert.equal(second.status, 0, second.stderr);
  assert.ok(first.stdout.trim(), `first stdout empty; stderr=${first.stderr}`);
  assert.ok(second.stdout.trim(), `second stdout empty; stderr=${second.stderr}`);
  const a = JSON.parse(first.stdout.trim()), b = JSON.parse(second.stdout.trim());
  assert.deepEqual(a.anchors, b.anchors);
  assert.equal(a.verification.agreement.outcome, 'pass');
  assert.equal(a.verification.bundle.outcome, 'pass');
  assert.equal(a.rollup, 'PASS');
  assert.doesNotMatch(first.stdout, /mnemonic|seed|private.?key/i);
});

test('LIVE without operator approval exits 2 and never prints environment values', (t) => {
  const sentinel = 'ENV-VALUE-MUST-NOT-APPEAR';
  const result = spawn(['--job-id', 'live-refusal', '--json'], { LIVE: '1', DEMOS_MNEMONIC: sentinel, DEMOS_SELLER_MNEMONIC: sentinel, GATEWAY_DRYRUN_HASH: sentinel });
  if (result.error && (result.error as NodeJS.ErrnoException).code === 'EPERM') { t.skip('sandbox refuses nested process creation'); return; }
  assert.equal(result.status, 2);
  assert.ok(!`${result.stdout}${result.stderr}`.includes(sentinel));
});
