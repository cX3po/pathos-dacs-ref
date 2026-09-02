import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

import {
  createProofLedger,
  gateVerdictEntryFromCase,
  receiptEntryFromOutboundReceipt,
  type ReceiptEntry,
} from '../../src/adapters/demos/proof-ledger.js';
import type { DemosHandle } from '../../src/demos/connection.js';
import { planAppend } from '../../src/demos/receipt-ledger.js';
import { fromVerifyVerdict } from '../../src/demos/receipt-mappers.js';
import type { FetchResult } from '../../src/demos/storage.js';

const HASH = 'a'.repeat(64);
const outbound = {
  ts: 1_788_350_400,
  action: 'publish',
  target: 'cX3po/pathos-dacs-ref#47',
  content_sha256: HASH,
  verdict: 'APPROVED',
  verdict_code: 'GATE_OK',
  tier: 'T2',
};
const caseJson = {
  id: 'CASE-47',
  stage: 'approved',
  history: [{
    from: 'review', to: 'approved', by: 'policy-engine', gate: 'release', passed: true,
    ts: '2026-09-02T12:00:00.000Z', gate_output: { secret: true },
  }],
  intent: 'excluded',
};

test('outbound receipt projection has exactly the permitted keys', () => {
  const entry = receiptEntryFromOutboundReceipt({
    ...outbound,
    intent: 'do not anchor',
    checks: { token: 'do not anchor' },
    process_history: ['do not anchor'],
    mnemonic: 'do not anchor',
  });
  assert.deepEqual(entry, {
    kind: 'outbound-receipt',
    ref: 'publish:cX3po/pathos-dacs-ref#47',
    contentHash: HASH,
    outcome: 'APPROVED',
    at: '2026-09-02T12:00:00.000Z',
    detail: { tier: 'T2', verdictCode: 'GATE_OK' },
  });
  assert.deepEqual(Object.keys(entry), ['kind', 'ref', 'contentHash', 'outcome', 'at', 'detail']);
  assert.deepEqual(Object.keys(entry.detail ?? {}), ['tier', 'verdictCode']);
});

test('outbound receipt projection rejects missing and malformed fields', () => {
  assert.throws(() => receiptEntryFromOutboundReceipt(null), /JSON object/);
  assert.throws(() => receiptEntryFromOutboundReceipt({ ...outbound, action: '' }), /action/);
  assert.throws(() => receiptEntryFromOutboundReceipt({ ...outbound, ts: '1788350400' }), /timestamp/);
  assert.throws(() => receiptEntryFromOutboundReceipt({ ...outbound, content_sha256: 'abc' }), /64/);
  assert.throws(() => receiptEntryFromOutboundReceipt({ ...outbound, verdict_code: undefined }), /verdict_code/);
});

test('Case gate projection excludes gate output, intent, and actor identity from the entry', () => {
  const entry = gateVerdictEntryFromCase(caseJson, 0);
  assert.deepEqual(entry, {
    kind: 'gate-verdict',
    ref: 'CASE-47:approved',
    contentHash: '95e1c7a642306e75864e57f14567620a1d7b452e2199f858c20f72569005c6ed',
    outcome: 'PASS',
    at: '2026-09-02T12:00:00.000Z',
    detail: { from: 'review', to: 'approved', gate: 'release' },
  });
  assert.doesNotMatch(JSON.stringify(entry), /gate_output|intent|policy-engine|secret/);
});

test('Case gate content hash is deterministic across JSON member order', () => {
  const reordered = {
    history: [{
      ts: '2026-09-02T12:00:00.000Z', passed: true, gate: 'release', by: 'policy-engine',
      to: 'approved', from: 'review', gate_output: 'different and excluded',
    }],
    stage: 'approved', id: 'CASE-47', intent: 'also different',
  };
  assert.equal(
    gateVerdictEntryFromCase(reordered, 0).contentHash,
    gateVerdictEntryFromCase(caseJson, 0).contentHash,
  );
});

test('Case gate projection rejects malformed Case history', () => {
  assert.throws(() => gateVerdictEntryFromCase({ ...caseJson, stage: undefined }, 0), /stage/);
  assert.throws(() => gateVerdictEntryFromCase({ ...caseJson, history: [] }, 0), /missing/);
  assert.throws(() => gateVerdictEntryFromCase(caseJson, -1), /non-negative/);
  assert.throws(() => gateVerdictEntryFromCase({
    ...caseJson,
    history: [{ ...caseJson.history[0], passed: 'yes' }],
  }, 0), /boolean/);
});

async function harness(fetchOverride?: (rpc: string, address: string) => Promise<FetchResult | null>) {
  const owner = `0x${'1'.repeat(64)}`;
  let nonce = 0;
  const stored = new Map<string, FetchResult>();
  const names: string[] = [];
  const broadcasted: unknown[] = [];
  const handle = {
    address: owner,
    rpc: 'https://rpc.invalid/',
    demos: { async getAddressNonce() { return nonce; } },
  } as unknown as DemosHandle;
  let activeFetch = fetchOverride
    ?? (async (_rpc: string, address: string) => stored.get(address) ?? null);
  const fetchImpl = async (rpc: string, address: string) => activeFetch(rpc, address);
  const broadcastImpl = async (
    _handle: DemosHandle,
    rawPayload: unknown,
  ): Promise<{ txHash: string }> => {
    const payload = rawPayload as {
      storageAddress: string;
      programName: string;
      data: Record<string, unknown>;
    };
    broadcasted.push(rawPayload);
    names.push(payload.programName);
    nonce += 1;
    stored.set(payload.storageAddress, {
      storageAddress: payload.storageAddress,
      owner,
      data: payload.data,
      sizeBytes: JSON.stringify(payload.data).length,
      createdAt: '2026-09-02T12:00:00.000Z',
    });
    return { txHash: `tx-${nonce}` };
  };
  const ledger = await createProofLedger({
    handle, rpc: handle.rpc, ledgerName: 'proof', broadcastImpl, fetchAnchoredImpl: fetchImpl,
  });
  return {
    ledger,
    stored,
    names,
    broadcasted,
    handle,
    fetchImpl,
    broadcastImpl,
    setFetchImpl(next: typeof activeFetch) { activeFetch = next; },
  };
}

const firstEntry = receiptEntryFromOutboundReceipt(outbound);
const secondEntry = gateVerdictEntryFromCase(caseJson, 0);
const FIRST_STORAGE_ADDRESS = 'stor-2d49367303cedcbc4c62f6ab3392f4c392a232ea';
const FIRST_LEDGER = {
  ledgerVersion: '1',
  name: 'proof#1',
  entries: [{
    kind: 'outbound-receipt',
    ref: 'publish:cX3po/pathos-dacs-ref#47',
    contentHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    outcome: 'APPROVED',
    at: '2026-09-02T12:00:00.000Z',
    detail: { tier: 'T2', verdictCode: 'GATE_OK' },
  }],
};
const SECOND_LEDGER = {
  ledgerVersion: '1',
  name: 'proof#2',
  entries: [
    FIRST_LEDGER.entries[0],
    {
      kind: 'gate-verdict',
      ref: 'CASE-47:approved',
      contentHash: '95e1c7a642306e75864e57f14567620a1d7b452e2199f858c20f72569005c6ed',
      outcome: 'PASS',
      at: '2026-09-02T12:00:00.000Z',
      detail: {
        from: 'review',
        to: 'approved',
        gate: 'release',
        prev: FIRST_STORAGE_ADDRESS,
      },
    },
  ],
};
const FIRST_LEDGER_HASH = '57c46cb21ebf9c3024bc929b0dab749b00f48666b5ca76ad6dcd00e432c7ae6c';
const SECOND_LEDGER_HASH = 'e293f4f98887eebc195fd4f9447f331d1873a278a4ab560be026d29973bdaaba';

test('generic planAppend preserves mapper detail while skipping unsafe detail keys', async () => {
  const state = await harness();
  const knownAddress = 'stor-generic';
  const mapped = fromVerifyVerdict({
    decision: 'pass',
    jobId: 'job-123',
    steps: [],
    canonicalBundleHash: HASH,
    signersVerified: ['pk1', 'pk2'],
    attestationsVerified: 3,
    attestationsFailed: 0,
  }, '2026-09-02T12:00:00.000Z');
  Object.defineProperty(mapped.detail, '__proto__', { value: 'excluded', enumerable: true });
  Object.assign(mapped.detail!, { constructor: 'excluded', prototype: 'excluded' });
  state.stored.set(knownAddress, {
    storageAddress: knownAddress,
    owner: state.handle.address,
    data: { ledgerVersion: '1', name: 'generic', entries: [mapped] },
    sizeBytes: 0,
    createdAt: '2026-09-02T12:00:00.000Z',
  });
  const plan = await planAppend(state.handle, state.handle.rpc, 'generic', secondEntry, {
    knownAddress,
    fetchAnchoredImpl: state.fetchImpl,
  });
  const data = (plan.payload as { data: { entries: ReceiptEntry[] } }).data;
  assert.deepEqual(data.entries[0]?.detail, {
    signersVerified: 2,
    attestationsVerified: 3,
    attestationsFailed: 0,
  });
});

test('proof ledger creates immutable versions, links append, and reads entries in order', async () => {
  const { ledger, names, stored, broadcasted } = await harness();
  const createPlan = await ledger.plan(firstEntry);
  assert.equal(createPlan.op, 'create');
  assert.equal(createPlan.entryCount, 1);
  const first = await ledger.append(firstEntry);
  const appendPlan = await ledger.plan(secondEntry);
  assert.equal(appendPlan.op, 'create');
  assert.equal(appendPlan.entryCount, 2);
  const second = await ledger.append(secondEntry);
  const read = await ledger.read();
  assert.deepEqual(names, ['proof#1', 'proof#2']);
  assert.equal(second.entryCount, 2);
  assert.deepEqual(read.entries.map((entry) => entry.ref), [firstEntry.ref, secondEntry.ref]);
  assert.equal(read.entries[1]?.detail?.prev, first.storageAddress);
  assert.notEqual(second.storageAddress, first.storageAddress);
  assert.equal(first.storageAddress, FIRST_STORAGE_ADDRESS);
  const anchoredFirst = stored.get(first.storageAddress);
  const anchoredSecond = stored.get(second.storageAddress);
  assert.ok(anchoredFirst);
  assert.ok(anchoredSecond);
  assert.deepEqual(anchoredFirst.data, FIRST_LEDGER);
  assert.deepEqual(anchoredSecond.data, SECOND_LEDGER);
  assert.equal(first.contentHash, FIRST_LEDGER_HASH);
  assert.equal(second.contentHash, SECOND_LEDGER_HASH);
  assert.equal(
    (broadcasted[1] as { storageAddress: string }).storageAddress,
    second.storageAddress,
  );
});

test('proof ledger anchors only allow-listed entry fields and hashes those exact bytes', async () => {
  const { ledger, stored } = await harness();
  const entry = {
    ...firstEntry,
    intent: 'excluded',
    checks: { excluded: true },
    process_history: ['excluded'],
    gate_output: { excluded: true },
    mnemonic: 'excluded',
    names: ['excluded'],
    detail: { ...firstEntry.detail, excluded: true, by: 'policy-engine' },
  } as ReceiptEntry;
  const appended = await ledger.append(entry);
  const anchored = stored.get(appended.storageAddress);
  assert.ok(anchored);
  assert.deepEqual(anchored.data, FIRST_LEDGER);
  assert.equal(appended.contentHash, FIRST_LEDGER_HASH);
  assert.doesNotMatch(
    JSON.stringify(anchored.data),
    /intent|checks|process_history|gate_output|policy-engine|excluded|mnemonic|names/,
  );
});

test('proof ledger resumes a persisted head and creates the next linked version', async () => {
  const firstHarness = await harness();
  const first = await firstHarness.ledger.append(firstEntry);
  const callerAddress = `${first.storageAddress} `;
  const resumeFetch = async (rpc: string, address: string) => address === callerAddress
    ? firstHarness.fetchImpl(rpc, first.storageAddress)
    : firstHarness.fetchImpl(rpc, address);
  const resumed = await createProofLedger({
    handle: firstHarness.handle,
    rpc: firstHarness.handle.rpc,
    ledgerName: 'proof',
    head: { storageAddress: callerAddress },
    broadcastImpl: firstHarness.broadcastImpl,
    fetchAnchoredImpl: resumeFetch,
  });
  assert.equal((await resumed.verify()).outcome, 'pass');
  const plan = await resumed.plan(secondEntry);
  assert.equal(plan.entryCount, 2);
  assert.equal(
    ((plan.payload as { data: { entries: ReceiptEntry[] } }).data.entries[1]?.detail?.prev),
    FIRST_STORAGE_ADDRESS,
  );
  assert.deepEqual((plan.payload as { data: unknown }).data, SECOND_LEDGER);
  const second = await resumed.append(secondEntry);
  assert.equal(second.entryCount, 2);
  assert.deepEqual(firstHarness.stored.get(first.storageAddress)?.data, FIRST_LEDGER);
  assert.deepEqual(firstHarness.stored.get(second.storageAddress)?.data, SECOND_LEDGER);
  assert.equal(second.contentHash, SECOND_LEDGER_HASH);
});

test('proof ledger rejects absent and malformed persisted heads on construction', async () => {
  const base = await harness();
  await assert.rejects(createProofLedger({
    handle: base.handle,
    rpc: base.handle.rpc,
    ledgerName: 'proof',
    head: { storageAddress: 'stor-missing' },
    broadcastImpl: base.broadcastImpl,
    fetchAnchoredImpl: base.fetchImpl,
  }), /not readable/);
  base.stored.set('stor-malformed', {
    storageAddress: 'stor-malformed', owner: base.handle.address, data: { entries: [] },
    sizeBytes: 0, createdAt: '2026-09-02T12:00:00.000Z',
  });
  await assert.rejects(createProofLedger({
    handle: base.handle,
    rpc: base.handle.rpc,
    ledgerName: 'proof',
    head: { storageAddress: 'stor-malformed' },
    broadcastImpl: base.broadcastImpl,
    fetchAnchoredImpl: base.fetchImpl,
  }), /ledgerVersion/);
  base.stored.set('stor-other-name', {
    storageAddress: 'stor-other-name', owner: base.handle.address,
    data: { ...FIRST_LEDGER, name: 'other#1' },
    sizeBytes: 0, createdAt: '2026-09-02T12:00:00.000Z',
  });
  await assert.rejects(createProofLedger({
    handle: base.handle,
    rpc: base.handle.rpc,
    ledgerName: 'proof',
    head: { storageAddress: 'stor-other-name' },
    broadcastImpl: base.broadcastImpl,
    fetchAnchoredImpl: base.fetchImpl,
  }), /is other#1, not proof#1/);
  base.stored.set('stor-other-owner', {
    storageAddress: 'stor-other-owner', owner: `0x${'2'.repeat(64)}`,
    data: FIRST_LEDGER,
    sizeBytes: 0, createdAt: '2026-09-02T12:00:00.000Z',
  });
  await assert.rejects(createProofLedger({
    handle: base.handle,
    rpc: base.handle.rpc,
    ledgerName: 'proof',
    head: { storageAddress: 'stor-other-owner' },
    broadcastImpl: base.broadcastImpl,
    fetchAnchoredImpl: base.fetchImpl,
  }), /owner .* is not/);
});

test('proof ledger cold verification passes and fails after anchored data is tampered', async () => {
  const { ledger, stored } = await harness();
  const appended = await ledger.append(firstEntry);
  assert.equal((await ledger.verify()).outcome, 'pass');
  const anchored = stored.get(appended.storageAddress);
  assert.ok(anchored);
  anchored.data = { ...(anchored.data as Record<string, unknown>), name: 'tampered' };
  const result = await ledger.verify();
  assert.equal(result.outcome, 'fail');
  assert.match(result.detail, /hash mismatch/);
});

test('proof ledger refuses an oversized version before anchoring', async () => {
  const { ledger, names } = await harness();
  const huge: ReceiptEntry = { ...firstEntry, ref: 'x'.repeat(5_000_000) };
  const plan = await ledger.plan(huge);
  assert.equal(plan.withinSizeLimit, false);
  await assert.rejects(ledger.append(huge), /size limit/);
  assert.deepEqual(names, []);
});

test('proof ledger propagates RPC errors instead of treating them as absence', async () => {
  const transportFailure = async () => { throw new Error('RPC unavailable'); };
  const { ledger } = await harness(transportFailure);
  await assert.rejects(ledger.plan(firstEntry), /RPC unavailable/);
});

test('proof ledger verify propagates RPC errors after a successful append', async () => {
  const state = await harness();
  await state.ledger.append(firstEntry);
  state.setFetchImpl(async () => { throw new Error('RPC unavailable'); });
  await assert.rejects(state.ledger.verify(), /RPC unavailable/);
});

test('proof ledger dry-run CLI prints network-free plans for receipt and Case inputs', (t) => {
  const env: NodeJS.ProcessEnv = { ...process.env, LIVE: '' };
  delete env.NODE_TEST_CONTEXT;
  const run = spawnSync(process.execPath, [
    '--import', 'tsx', 'src/live/proof-ledger.mts', '--dry-run',
    '--fresh',
    '--receipt', 'test/fixtures/proof-ledger/outbound-receipt.json',
    '--case', 'test/fixtures/proof-ledger/case.json', '--event', '0',
  ], { cwd: process.cwd(), encoding: 'utf8', env });
  if ((run.error as NodeJS.ErrnoException | undefined)?.code === 'EPERM') {
    t.skip('sandbox forbids child-process creation from node:test');
    return;
  }
  assert.equal(run.status, 0, run.stderr);
  const output = JSON.parse(run.stdout) as { mode: string; plans: Array<Record<string, unknown>> };
  assert.equal(output.mode, 'dry-run');
  assert.equal(output.plans.length, 2);
  for (const plan of output.plans) {
    assert.deepEqual(Object.keys(plan), [
      'address', 'op', 'entryCount', 'sizeBytes', 'feeOS', 'withinSizeLimit',
    ]);
    assert.match(String(plan.address), /^stor-/);
    assert.equal(plan.op, 'create');
    assert.equal(plan.withinSizeLimit, true);
  }
  assert.deepEqual(output.plans.map((plan) => plan.entryCount), [1, 2]);
});

test('proof ledger live CLI fails closed without a mnemonic and prints no environment value', (t) => {
  const marker = 'ENV_VALUE_MUST_NOT_APPEAR';
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    LIVE: '1',
    DACS_ENV_PATH: '/tmp/proof-ledger-no-such-env-file',
    DEMOS_RPC: marker,
  };
  delete env.DEMOS_MNEMONIC;
  delete env.NODE_TEST_CONTEXT;
  const run = spawnSync(process.execPath, [
    '--import', 'tsx', 'src/live/proof-ledger.mts',
    '--fresh',
    '--receipt', 'test/fixtures/proof-ledger/outbound-receipt.json',
  ], { cwd: process.cwd(), encoding: 'utf8', env });
  if ((run.error as NodeJS.ErrnoException | undefined)?.code === 'EPERM') {
    t.skip('sandbox forbids child-process creation from node:test');
    return;
  }
  assert.notEqual(run.status, 0);
  assert.doesNotMatch(`${run.stdout}${run.stderr}`, new RegExp(marker));
  assert.deepEqual(JSON.parse(run.stderr), { ok: false, error: 'proof ledger command failed' });
});

test('an open or annotation Case event (no from or passed) is refused with a pointer to gate events', () => {
  const caseJson = JSON.parse(readFileSync(new URL('../fixtures/proof-ledger/case.json', import.meta.url), 'utf8'));
  const openEvent = { to: 'stated', by: 'claude-judge', gate: 'open', ts: '2026-09-02T12:00:00.000Z' };
  assert.throws(
    () => gateVerdictEntryFromCase({ ...caseJson, history: [openEvent, ...caseJson.history] }, 0),
    /not a gate-verdict event/,
  );
});
