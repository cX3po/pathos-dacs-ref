import { test } from 'node:test';
import assert from 'node:assert/strict';
import { jcsHashHex } from '../../src/jcs.js';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  createLiveDependencies, DacsTestnetRefusal, OrganDeliverableError, liveDeliverableSpec, organDeliverableFrom, parameterHash, requireOrganBridgeConfig, runDacsTestnetSession, runOrganBridge, supportedOrgans,
  type CoreReceiptProvider, type DacsTestnetConfig, type LiveSettlementSeams,
} from '../../src/live/dacs-testnet-run.mjs';
import { createDryRunDependencies } from '../../src/live/testnet-run-fixtures.js';

const run = { jobId: 'job-1', organ: 'nws_alerts', query: '35.2271,-80.8431' };
const NONCE = 'a3f9c2e1b7d4485f9e0c1122aa33bb44a3f9c2e1b7d4485f9e0c1122aa33bb44';
const good = {
  organ: 'nws_alerts',
  answer: { coverage: 'verified-empty', active: false, highest_band: 'none', count_band: 'zero', basis: 'supplied-feed verified zero active entries for the committed point' },
  input_commitment: 'd69a4d056724977733ef0fed80de356d3d8db03d66e9b32b344d92dca5c95e5e',
  commitment_scheme: 'hmac-sha256(nonce, sorted-json-record)',
  commitment_nonce: NONCE,
  fetched_at: '2026-09-06T01:07:55.459420+00:00',
};
const isDelivery = (e: unknown) => e instanceof OrganDeliverableError && !(e instanceof DacsTestnetRefusal);
const isConfig = (e: unknown) => e instanceof DacsTestnetRefusal && e.code === 'config';

test('a valid organ answer becomes the projected deliverable and the commitment nonce is never carried', () => {
  const d = organDeliverableFrom(JSON.stringify(good), run);
  assert.deepEqual(Object.keys(d).sort(), ['answer', 'commitment_scheme', 'fetched_at', 'input_commitment', 'jobId', 'organ', 'v']);
  assert.equal(d.v, 'pathos-organ-deliverable:0.1');
  assert.deepEqual(d.answer, good.answer);
  assert.ok(!JSON.stringify(d).includes(NONCE));
  assert.deepEqual(supportedOrgans(), ['nws_alerts']);
});

test('only the projected public answer fields are anchored; extra fields are dropped', () => {
  const d = organDeliverableFrom(JSON.stringify({ ...good, answer: { ...good.answer, raw_feed: ['secret event'], location: '35.2,-80.8' } }), run);
  assert.deepEqual(Object.keys(d.answer).sort(), ['active', 'basis', 'count_band', 'coverage', 'highest_band']);
});

test('the indeterminate-coverage answer shape is accepted as is', () => {
  const d = organDeliverableFrom(JSON.stringify({ ...good, answer: { coverage: 'indeterminate', active: null, basis: 'feed-not-applicable-or-unavailable' } }), run);
  assert.deepEqual(d.answer, { coverage: 'indeterminate', active: null, basis: 'feed-not-applicable-or-unavailable' });
});

const deliveryFailures: Array<[string, unknown]> = [
  ['not JSON', 'nope'],
  ['an array', [good]],
  ['error property present (string)', { ...good, error: 'engine failed' }],
  ['error property present (true)', { ...good, error: true }],
  ['error property present (null)', { ...good, error: null }],
  ['error property present (empty string)', { ...good, error: '' }],
  ['another organ', { ...good, organ: 'other' }],
  ['no answer', { ...good, answer: {} }],
  ['answer is a string', { ...good, answer: 'text' }],
  ['unknown coverage value', { ...good, answer: { ...good.answer, coverage: 'verified-secret-feed' } }],
  ['active is a string', { ...good, answer: { ...good.answer, active: 'yes' } }],
  ['band label is prose', { ...good, answer: { ...good.answer, highest_band: 'Tornado Warning issued for Mecklenburg' } }],
  ['bad commitment', { ...good, input_commitment: 'abc' }],
  ['no scheme', { ...good, commitment_scheme: '' }],
  ['bad timestamp', { ...good, fetched_at: 'yesterday' }],
  ['nonce missing', { ...good, commitment_nonce: undefined }],
  ['nonce null', { ...good, commitment_nonce: null }],
  ['nonce is an object', { ...good, commitment_nonce: { v: NONCE } }],
  ['nonce is not hex', { ...good, commitment_nonce: 'not"hex' }],
  ['nonce smuggled into a string value', { ...good, answer: { ...good.answer, basis: `basis ${NONCE}` } }],
];
for (const [name, payload] of deliveryFailures) {
  test(`organ output is a delivery failure, not a refusal: ${name}`, () => {
    const raw = typeof payload === 'string' ? payload : JSON.stringify(payload);
    assert.throws(() => organDeliverableFrom(raw, run), isDelivery);
  });
}

test('a nonce smuggled into an unknown answer key is dropped by the projection and never anchored', () => {
  const smuggled = { ...good, answer: { ...good.answer, [NONCE]: 'x' } };
  const d = organDeliverableFrom(JSON.stringify(smuggled), run);
  assert.ok(!(NONCE in d.answer));
  assert.ok(!JSON.stringify(d).includes(NONCE));
});

test('prototype-inherited names are not organs and cannot bypass the schema', () => {
  for (const organ of ['constructor', 'toString', '__proto__', 'hasOwnProperty']) {
    assert.throws(() => requireOrganBridgeConfig({ ORGAN_CLI: 'x.py' }, { organ }), isConfig, organ);
    assert.throws(() => organDeliverableFrom(JSON.stringify({ ...good, organ }), { jobId: 'j', organ }), isDelivery, organ);
  }
  // Inherited answer properties are not read: an answer object with only a prototype-shaped key is refused.
  assert.throws(() => organDeliverableFrom(JSON.stringify({ ...good, answer: { constructor: 'x' } }), run), isDelivery);
});

test('bridge configuration is a config refusal, checked without running anything, and the script must exist', () => {
  const present = () => true;
  assert.throws(() => requireOrganBridgeConfig({}, run, present), (e: unknown) => isConfig(e) && /ORGAN_CLI/.test((e as Error).message));
  assert.throws(() => requireOrganBridgeConfig({ ORGAN_CLI: ' x.py' }, run, present), isConfig);
  assert.throws(() => requireOrganBridgeConfig({ ORGAN_CLI: 'x.py' }, { organ: 'unknown_organ' }, present), isConfig);
  assert.throws(() => requireOrganBridgeConfig({ ORGAN_CLI: '/nonexistent/bridge.py' }, run), (e: unknown) => isConfig(e) && /existing file/.test((e as Error).message));
  assert.throws(() => requireOrganBridgeConfig({ ORGAN_CLI: 'x.py', AXIOM_PY: '/nonexistent/python3' }, run, (p) => p === 'x.py'), (e: unknown) => isConfig(e) && /interpreter/.test((e as Error).message));
  assert.deepEqual(requireOrganBridgeConfig({ ORGAN_CLI: 'x.py' }, run, present), { cli: 'x.py', py: 'python3' });
  assert.deepEqual(requireOrganBridgeConfig({ ORGAN_CLI: 'x.py', AXIOM_PY: '/venv/bin/python3' }, run, present), { cli: 'x.py', py: '/venv/bin/python3' });
});

test('the bridge is invoked with the configured interpreter, script, organ and query; only PATH and HOME reach it; timeout and buffer are bounded', async () => {
  const calls: Array<{ file: string; args: string[]; options: { timeout: number; maxBuffer: number; env: NodeJS.ProcessEnv } }> = [];
  const exec = async (file: string, args: string[], options: { timeout: number; maxBuffer: number; env: NodeJS.ProcessEnv }) => {
    calls.push({ file, args, options: { ...options, env: { ...options.env } } });
    return { stdout: JSON.stringify(good) };
  };
  const dir = mkdtempSync(join(tmpdir(), 'organ-bridge-'));
  const script = join(dir, 'organ_answer.py'); writeFileSync(script, '# placeholder for the existence check\n');
  const env = { ORGAN_CLI: script, AXIOM_PY: 'python3-from-path', PATH: '/usr/bin', HOME: '/home/x', DEMOS_MNEMONIC: 'SECRET-WORDS', GATEWAY_LIVE_APPROVED: '1' };
  const d = await runOrganBridge(env, run, exec);
  rmSync(dir, { recursive: true, force: true });
  assert.equal(d.organ, 'nws_alerts');
  assert.equal(calls[0]!.file, 'python3-from-path');
  assert.deepEqual(calls[0]!.args, [script, 'nws_alerts', '35.2271,-80.8431']);
  assert.deepEqual(calls[0]!.options.env, { PATH: '/usr/bin', HOME: '/home/x' });
  assert.equal(calls[0]!.options.timeout, 60_000);
  assert.equal(calls[0]!.options.maxBuffer, 1_048_576);
});

test('a bridge that fails at runtime is a delivery failure, not a config refusal', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'organ-bridge-'));
  try {
    const script = join(dir, 'x.py'); writeFileSync(script, '');
    const failing = async () => { throw new Error('exit 1'); };
    await assert.rejects(runOrganBridge({ ORGAN_CLI: script }, run, failing), isDelivery);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a real bridge script runs through the default executor and yields the deliverable', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'organ-bridge-'));
  try {
    const script = join(dir, 'bridge.js');
    writeFileSync(script, `const [organ, query] = process.argv.slice(2);\nprocess.stdout.write(JSON.stringify({ ...${JSON.stringify(good)}, organ, answer: { ...${JSON.stringify(good.answer)}, basis: 'query ' + query.length } }));\n`);
    const d = await runOrganBridge({ ORGAN_CLI: script, AXIOM_PY: process.execPath, PATH: process.env.PATH, HOME: process.env.HOME }, run);
    assert.equal(d.organ, 'nws_alerts');
    assert.equal(d.answer.basis, `query ${run.query.length}`);
    const missing = join(dir, 'missing.js');
    // At delivery time a vanished bridge is a delivery failure (the pre-payment check is requireOrganBridgeConfig at construction).
    await assert.rejects(runOrganBridge({ ORGAN_CLI: missing, AXIOM_PY: process.execPath, PATH: process.env.PATH, HOME: process.env.HOME }, run), isDelivery);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Coordinator coverage: configuration is refused before any phase; a runtime bridge failure after
// construction is a delivery-phase failure and anchors nothing.
const liveConfig: DacsTestnetConfig = { jobId: 'organ-live', mode: 'live', organ: 'nws_alerts', query: 'q', priceDem: '1', spendCapDem: 10, rpc: 'https://example.invalid', receiptProvider: 'demos-node' };
function fakeSeams(anchors: string[]): Partial<LiveSettlementSeams> {
  const claim = `did:demos:agent:${'11'.repeat(32)}`;
  const anchor = { logicalAddress: 'x', nativeAddress: 'stor-x', transactionRef: { kind: 'demos', value: 'tx' }, writer: claim, nonce: '1' };
  const handle = { address: 'wallet', rpc: liveConfig.rpc, demos: {} } as never;
  const gate = { authorize: async () => ({ verdict: 'PROCEED' as const, nowIso: new Date().toISOString() }), journalOutcome: async () => {}, beforeBroadcast: async () => {} };
  return {
    loadPolicy: async () => ({ network: 'testnet', rpcHosts: ['example.invalid'], perTransactionCapDem: '10', dailyCapDem: '20', killSwitchFile: '/tmp/no-kill' }),
    resolveJournalPath: async () => '/tmp/organ-test-pay.jsonl',
    readJournal: async () => [], killSwitchPresent: async () => false,
    authorizeTransfer: async () => ({ verdict: 'PROCEED', nowIso: new Date().toISOString() }),
    createJournal: async () => async () => {}, createOutcomeJournal: async () => async () => {},
    createAuthorizationGate: async () => gate,
    connect: async () => ({
      handles: { buyer: handle, seller: handle },
      signers: { buyer: { claim, sign: async () => new Uint8Array([1]) }, seller: { claim, sign: async () => new Uint8Array([1]) }, orchestrator: { claim, sign: async () => new Uint8Array([1]) } },
      anchor: async (request: { logicalAddress: string }) => { anchors.push(request.logicalAddress); return anchor; },
      fetchAnchored: async () => ({}),
    }),
    balance: async () => 100,
    preflight: async () => ({ verdict: 'PROCEED', estCostDem: 9, reasons: [] }),
  };
}
const provider: CoreReceiptProvider = { describe: () => ({ kind: 'core-5.1-receipts', provesFinality: true, source: 'test' }), async fetch() { return { outcome: 'indeterminate', detail: 'unused' }; } };

test('LIVE dependencies refuse at construction, before any phase, when ORGAN_CLI is missing', async () => {
  const anchors: string[] = [];
  const env = { GATEWAY_LIVE_APPROVED: '1', GATEWAY_DRYRUN_HASH: parameterHash(liveConfig), PATH: process.env.PATH, HOME: process.env.HOME };
  await assert.rejects(createLiveDependencies(liveConfig, env, provider, fakeSeams(anchors)), (e: unknown) => isConfig(e) && /ORGAN_CLI/.test((e as Error).message));
  assert.deepEqual(anchors, []);
});

test('with the bridge configured, a runtime bridge failure during deliver is a delivery failure that anchors nothing', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'organ-bridge-'));
  try {
    const script = join(dir, 'failing.js');
    writeFileSync(script, 'process.exit(3);\n');
    const anchors: string[] = [];
    const env = { GATEWAY_LIVE_APPROVED: '1', GATEWAY_DRYRUN_HASH: parameterHash(liveConfig), PATH: process.env.PATH, HOME: process.env.HOME, ORGAN_CLI: script, AXIOM_PY: process.execPath };
    const deps = await createLiveDependencies(liveConfig, env, provider, fakeSeams(anchors));
    await assert.rejects(deps.deliver({} as never, liveConfig), isDelivery);
    assert.deepEqual(anchors, []);
    // A configured path that does not exist is refused at construction, before any phase.
    await assert.rejects(createLiveDependencies(liveConfig, { ...env, ORGAN_CLI: join(dir, 'missing.js') }, provider, fakeSeams(anchors)), isConfig);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('with a working bridge, deliver anchors the projected deliverable and its evidence, never the nonce', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'organ-bridge-'));
  try {
    const script = join(dir, 'bridge.js');
    writeFileSync(script, `process.stdout.write(JSON.stringify(${JSON.stringify(good)}));\n`);
    const anchored: Array<{ logicalAddress: string; content: unknown }> = [];
    const seams = fakeSeams([]);
    const baseConnect = seams.connect!;
    seams.connect = async (...args: Parameters<NonNullable<LiveSettlementSeams['connect']>>) => {
      const wiring = await baseConnect(...args);
      return { ...wiring, anchor: async (request: { logicalAddress: string; content: unknown }) => { anchored.push(request); return { logicalAddress: request.logicalAddress, nativeAddress: 'stor-x', transactionRef: { kind: 'demos', value: 'tx' }, writer: `did:demos:agent:${'11'.repeat(32)}`, nonce: '1' }; } };
    };
    const env = { GATEWAY_LIVE_APPROVED: '1', GATEWAY_DRYRUN_HASH: parameterHash(liveConfig), PATH: process.env.PATH, HOME: process.env.HOME, ORGAN_CLI: script, AXIOM_PY: process.execPath };
    const deps = await createLiveDependencies(liveConfig, env, provider, seams);
    const delivery = await deps.deliver({} as never, liveConfig);
    assert.equal(anchored.length, 2);
    const deliverable = anchored[0]!.content as Record<string, unknown>;
    assert.equal(deliverable.v, 'pathos-organ-deliverable:0.1');
    assert.equal(deliverable.jobId, 'organ-live');
    assert.ok(!JSON.stringify(anchored).includes(NONCE));
    assert.equal(delivery.evidence.outcome, 'success');
    // The delivery evidence hashes exactly the anchored deliverable bytes.
    const { jcsHashHex } = await import('../../src/jcs.js');
    assert.equal((delivery.evidence as { deliverableContentHash?: string }).deliverableContentHash, jcsHashHex(deliverable));
    assert.equal(anchored[1]!.logicalAddress.includes('organ-live'), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('at session level, a bridge failure in deliver is recorded as a delivery FAIL with the earlier phases and anchors preserved', async () => {
  const cfg: DacsTestnetConfig = { jobId: 'session-fail', mode: 'dry-run', organ: 'nws_alerts', query: 'q', priceDem: '1', spendCapDem: 50, rpc: 'https://example.invalid' };
  const deps = createDryRunDependencies(cfg);
  deps.deliver = async () => { throw new OrganDeliverableError('organ bridge did not complete'); };
  const result = await runDacsTestnetSession(cfg, deps);
  assert.equal(result.rollup, 'FAIL');
  assert.deepEqual(result.phases.map((p) => [p.kind, p.outcome]), [['negotiate-fixed-price', 'PASS'], ['commit-agreement', 'PASS'], ['pay-dem', 'PASS'], ['deliver-storage-program', 'FAIL']]);
  assert.ok(result.anchors.paymentEvidence, 'payment evidence anchor is preserved');
  assert.ok(!('deliverable' in result.anchors));
});

test('the live listing deliverable spec carries the type and hash the agreement adapter requires, identically for listing and terms', () => {
  const spec = liveDeliverableSpec({ organ: 'nws_alerts' });
  assert.equal(spec.deliverableType, 'storage-program');
  assert.match(spec.hash, /^[0-9a-f]{64}$/);
  assert.deepEqual(liveDeliverableSpec({ organ: 'nws_alerts' }), spec);
  assert.notEqual(liveDeliverableSpec({ organ: 'other' }).hash, spec.hash);
});

// The live listing and agreement must pass the receipt-enforcing adapters, not only the fixtures. A fake
// receipt source fabricates finalized receipts from the anchors the fake wiring wrote, the way the dry-run
// fixtures do, so listing publication, vetting and agreement emission are exercised through the real adapters.
test('the live listing and agreement pass the agreement adapter with a fabricated finalized receipt source', async () => {
  const { jcsCanonical } = await import('../../src/jcs.js');
  const contents = new Map<string, unknown>();
  const anchorsWritten: Array<{ logicalAddress: string; nativeAddress: string; transactionRef: { kind: string; value: string }; writer: string; nonce: string }> = [];
  const claim = `did:demos:agent:${'22'.repeat(32)}`;
  const seams = fakeSeams([]);
  const baseConnect = seams.connect!;
  seams.connect = async (...args: Parameters<NonNullable<LiveSettlementSeams['connect']>>) => {
    const wiring = await baseConnect(...args);
    let ordinal = 0;
    return {
      ...wiring,
      signers: { buyer: { claim: `did:demos:agent:${'11'.repeat(32)}`, sign: async () => new Uint8Array(64) }, seller: { claim, sign: async () => new Uint8Array(64) }, orchestrator: { claim, sign: async () => new Uint8Array(64) } },
      anchor: async (request: { logicalAddress: string; content: unknown; contentHash: string }) => {
        const nativeAddress = `stor-${String(ordinal++).padStart(40, '0')}`;
        contents.set(nativeAddress, request.content); contents.set(request.logicalAddress, request.content);
        const result = { logicalAddress: request.logicalAddress, nativeAddress, transactionRef: { kind: 'demos', value: `tx-${nativeAddress}` }, writer: claim, nonce: String(ordinal) };
        anchorsWritten.push(result);
        return result;
      },
      fetchAnchored: async (address: string) => { if (!contents.has(address)) throw new Error('missing'); return structuredClone(contents.get(address)); },
    };
  };
  const receipts: CoreReceiptProvider = {
    describe: () => ({ kind: 'core-5.1-receipts', provesFinality: true, source: 'fabricated-for-test' }),
    async fetch(request) {
      const a = request.anchor ?? anchorsWritten.find((x) => x.logicalAddress === request.logicalAddress);
      if (!a) return { outcome: 'indeterminate', detail: 'no anchor' };
      const content = contents.get(a.nativeAddress);
      return {
        receiptVersion: '1', substrate: 'demos-fixture', finalityProfile: 'fixture-finalized', logicalAddress: request.logicalAddress, nativeAddress: a.nativeAddress,
        contentHash: request.contentHash, transactionRef: a.transactionRef, writer: a.writer, nonce: a.nonce, state: 'finalized', observationDisposition: 'established',
        observedAt: Date.now(), blockRef: { id: `block-${a.nativeAddress}`, height: '1', timestamp: Date.now() },
        evidence: { kind: 'stored-bytes-base64url', value: Buffer.from(jcsCanonical(content)).toString('base64url') },
      };
    },
  };
  const dir = mkdtempSync(join(tmpdir(), 'organ-bridge-'));
  try {
    const script = join(dir, 'bridge.js'); writeFileSync(script, `process.stdout.write(JSON.stringify(${JSON.stringify(good)}));\n`);
    const env = { GATEWAY_LIVE_APPROVED: '1', GATEWAY_DRYRUN_HASH: parameterHash(liveConfig), PATH: process.env.PATH, HOME: process.env.HOME, ORGAN_CLI: script, AXIOM_PY: process.execPath };
    const deps = await createLiveDependencies(liveConfig, env, receipts, seams);
    const published = await deps.publishListing(liveConfig);
    assert.equal(published.anchor.writer, claim);
    assert.deepEqual((published.listing.offering as Record<string, unknown>).deliverable, { kind: 'storage-program' }, 'DACS-1 listing carries a DeliverableSpec');
    // The listing signature is a stand-in here, so the vet reports it without throwing.
    const vet = await deps.vetListing(published, liveConfig);
    assert.ok(['pass', 'fail'].includes(vet.outcome));
    const agreement = await deps.emitAgreement(published, liveConfig);
    assert.ok(agreement.committed.commitmentHash.length === 64);
    assert.equal(anchorsWritten.length, 3, 'listing, agreement and commitment anchors');
    assert.deepEqual((agreement.committed.agreement.terms as unknown as Record<string, unknown>).deliverable, { deliverableType: 'storage-program', hash: jcsHashHex({ kind: 'storage-program' }) }, 'the agreement carries the DeliverableRef derived from the listing DeliverableSpec');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
