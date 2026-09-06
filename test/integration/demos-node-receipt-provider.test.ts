import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sha256 } from '@noble/hashes/sha2';
import { nodeBlockNumber as payDemBlockNumber } from '../../src/adapters/dacs/pay-dem-demosdk.js';
import {
  consensusTimestampMs,
  createDefaultNodeCall,
  createDemosNodeReceiptProvider,
  DEMOS_NODE_FINALITY_PROFILE,
  nodeBlockNumber,
  type NodeCall,
} from '../../src/live/demos-node-receipt-provider.js';
import { createLiveAdapterWiring, DacsTestnetRefusal, main, parameterHash, selectReceiptProvider, withSessionAnchor, type DacsTestnetConfig } from '../../src/live/dacs-testnet-run.mjs';
import { jcsCanonical } from '../../src/jcs.js';
import { cciClaimForAddress } from '../../src/adapters/demos/identity.js';
import type { AnchorReceipt } from '../../src/types/bundle.js';

// Shapes recorded read-only from the public testnet node on 2026-09-05 (stor-34efb7e7…, tx e30c766e…, block 216982).
const OWNER = '0x6bb11b21d18ba9bb03c4c50085326da4d2192c0cfbb6b575cc42d6dcddc0cda2';
const TX = 'e30c766ed207b415d522a647627844eddfe107f06a867f52a91a9cf7e1a31e9e';
const OTHER_TX = '53ff3a57a472785c5f9937a97502b6a8ede11b3b8b5a2fad64e728c19f21740a';
const BLOCK_HASH = '7a65cb7174dddbd02fc9cd3063b5022cb52ba8b2e8b822aa1335b6a9c71aa5d8';
const NATIVE = 'stor-34efb7e7d37d866bda0fc50733084fe9fed41099';
const CONTENT = { v: 'dacs-ref-anchor:1', hello: 'world', n: 3 };
const CONTENT_HASH = Buffer.from(sha256(new Uint8Array(Buffer.from(jcsCanonical(CONTENT))))).toString('hex');

type Node = Record<string, unknown>;
type Observation = { outcome: 'indeterminate'; detail: string; observed?: Record<string, unknown> };
const asObservation = (value: unknown): Observation => {
  assert.ok(value && typeof value === 'object' && !('receiptVersion' in (value as object)), 'expected an observation, not a receipt');
  return value as Observation;
};
function nodeFixture(overrides: Partial<Record<'program' | 'tx' | 'status' | 'block', Node | null>> = {}): Node {
  const program: Node = { storageAddress: NATIVE, owner: OWNER, programName: 'dacs1:listing:test', encoding: 'json', data: CONTENT, sizeBytes: 648,
    createdAt: '2026-09-02T18:45:45.583Z', createdByTx: TX };
  const tx: Node = { hash: TX, status: 'confirmed', blockNumber: 216982,
    content: { type: 'storageProgram', from: OWNER, to: OWNER, nonce: 403, timestamp: 1788374737679 } };
  const status: Node = { state: 'included', blockNumber: 216982 };
  const block: Node = { id: 216983, number: 216982, hash: BLOCK_HASH, status: 'confirmed', proposer: 'e7f5aa5b',
    content: { ordered_transactions: [TX], timestamp: 1788374743, previousHash: 'prev' } };
  return { program, tx, status, block, ...overrides };
}

function nodeCallFor(fixture: Node, calls: string[] = []): NodeCall {
  return async (message, data) => {
    calls.push(message);
    switch (message) {
      case 'getStorageProgram': return fixture.program;
      case 'getTxByHash': return fixture.tx;
      case 'getTransactionStatus': return fixture.status;
      case 'getBlockByNumber': return fixture.block;
      default: throw new Error(`unexpected nodeCall ${message} ${JSON.stringify(data)}`);
    }
  };
}

const config = { rpc: 'https://demosnode.discus.sh/' };
const request = { logicalAddress: 'dacs1:listing:test', contentHash: CONTENT_HASH,
  anchor: { logicalAddress: 'dacs1:listing:test', nativeAddress: NATIVE, transactionRef: { kind: 'demos', value: TX }, writer: cciClaimForAddress(OWNER), nonce: '403' } };

test('describe declares a finality-proving CORE §5.1 source', () => {
  const provider = createDemosNodeReceiptProvider(config, { nodeCall: nodeCallFor(nodeFixture()) });
  assert.deepEqual(provider.describe(), { kind: 'core-5.1-receipts', provesFinality: true, source: 'demos-node-finalized-receipts' });
});

test('a confirmed transaction in a confirmed block yields a finalized, fully bound receipt', async () => {
  const calls: string[] = [];
  const provider = createDemosNodeReceiptProvider(config, { nodeCall: nodeCallFor(nodeFixture(), calls), now: () => 1_800_000_000_000 });
  const receipt = await provider.fetch(request) as AnchorReceipt;
  assert.equal(receipt.receiptVersion, '1');
  assert.equal(receipt.state, 'finalized');
  assert.equal(receipt.observationDisposition, 'established');
  assert.equal(receipt.finalityProfile, DEMOS_NODE_FINALITY_PROFILE);
  assert.equal(receipt.substrate, 'demos-node:demosnode.discus.sh');
  assert.equal(receipt.nativeAddress, NATIVE);
  assert.equal(receipt.logicalAddress, request.logicalAddress);
  assert.equal(receipt.contentHash, CONTENT_HASH);
  assert.deepEqual(receipt.transactionRef, { kind: 'demos', value: TX });
  assert.equal(receipt.writer, cciClaimForAddress(OWNER));
  assert.equal(receipt.nonce, '403');
  assert.deepEqual(receipt.blockRef, { id: BLOCK_HASH, height: '216982', timestamp: 1788374743000 });
  assert.equal(receipt.observedAt, 1_800_000_000_000);
  assert.equal(receipt.evidence.kind, 'stored-bytes-base64url');
  assert.equal(Buffer.from(receipt.evidence.value, 'base64url').toString('utf8'), Buffer.from(jcsCanonical(CONTENT)).toString('utf8'));
  assert.deepEqual(calls, ['getStorageProgram', 'getTxByHash', 'getTransactionStatus', 'getBlockByNumber']);
});

test('the receipt reports the bytes the node holds, not the caller expectation', async () => {
  const provider = createDemosNodeReceiptProvider(config, { nodeCall: nodeCallFor(nodeFixture()) });
  const receipt = await provider.fetch({ ...request, contentHash: 'ff'.repeat(32) }) as AnchorReceipt;
  assert.equal(receipt.state, 'finalized');
  assert.equal(receipt.contentHash, CONTENT_HASH);
});

test('a wrapped text anchor is unwrapped before hashing', async () => {
  const fixture = nodeFixture();
  (fixture.program as Node).data = { v: 'dacs-ref-text:1', text: 'plain text payload' };
  const provider = createDemosNodeReceiptProvider(config, { nodeCall: nodeCallFor(fixture) });
  const receipt = await provider.fetch(request) as AnchorReceipt;
  assert.equal(Buffer.from(receipt.evidence.value, 'base64url').toString('utf8'), JSON.stringify('plain text payload'));
});

test('an included transaction whose block is not confirmed stays included, never finalized', async () => {
  const fixture = nodeFixture();
  (fixture.block as Node).status = 'derived';
  const provider = createDemosNodeReceiptProvider(config, { nodeCall: nodeCallFor(fixture) });
  const receipt = await provider.fetch(request) as AnchorReceipt;
  assert.equal(receipt.state, 'included');
  const tx = nodeFixture(); (tx.tx as Node).status = 'included';
  const second = await createDemosNodeReceiptProvider(config, { nodeCall: nodeCallFor(tx) }).fetch(request) as AnchorReceipt;
  assert.equal(second.state, 'included');
});

test('the provider asks the node for exactly the selected address and refuses a substituted record', async () => {
  const args: Array<Record<string, unknown>> = [];
  const fixture = nodeFixture();
  const other = { ...(fixture.program as Node), storageAddress: 'stor-98a32a825771321642b3b9f913c5a414d04f57da' };
  const provider = createDemosNodeReceiptProvider(config, { nodeCall: async (message, data) => { args.push({ message, ...data }); return message === 'getStorageProgram' ? other : null; } });
  const result = asObservation(await provider.fetch(request));
  assert.deepEqual(args, [{ message: 'getStorageProgram', storageAddress: NATIVE }]);
  assert.equal(result.outcome, 'indeterminate');
  assert.match(result.detail, /different storage record/);
});

test('the logical address must be the node-recorded program name; a relabelled request is indeterminate', async () => {
  const provider = createDemosNodeReceiptProvider(config, { nodeCall: nodeCallFor(nodeFixture()) });
  const relabelled = asObservation(await provider.fetch({ ...request, logicalAddress: 'dacs1:listing:other', anchor: { ...request.anchor, logicalAddress: 'dacs1:listing:other' } }));
  assert.equal(relabelled.outcome, 'indeterminate');
  assert.match(relabelled.detail, /not named by the requested logical address/);
  // A caller pointing the anchor at another program is caught the same way.
  const fixture = nodeFixture(); (fixture.program as Node).programName = 'dacs1:listing:test';
  const tampered = asObservation(await provider.fetch({ ...request, anchor: { ...request.anchor, nativeAddress: 'stor-98a32a825771321642b3b9f913c5a414d04f57da' } }));
  assert.equal(tampered.outcome, 'indeterminate');
});

test('a cold read with only a logical name and no anchor is indeterminate, not a guess', async () => {
  const calls: string[] = [];
  const provider = createDemosNodeReceiptProvider(config, { nodeCall: nodeCallFor(nodeFixture(), calls) });
  const result = asObservation(await provider.fetch({ logicalAddress: 'dacs1:listing:test', contentHash: CONTENT_HASH }));
  assert.equal(result.outcome, 'indeterminate');
  assert.match(result.detail, /needs the anchor/);
  assert.deepEqual(calls, []);
  // A bare storage address as the logical name is read directly; the node's programName must still agree.
  const direct = asObservation(await provider.fetch({ logicalAddress: NATIVE, contentHash: CONTENT_HASH }));
  assert.equal(direct.outcome, 'indeterminate');
});

test('thrown node reads and malformed stored content become indeterminate with the observations so far', async () => {
  const failing = createDemosNodeReceiptProvider(config, { nodeCall: async (message) => { if (message === 'getTxByHash') throw new TypeError('fetch failed'); return nodeFixture().program; } });
  const result = asObservation(await failing.fetch(request));
  assert.equal(result.outcome, 'indeterminate');
  assert.match(result.detail, /node read failed \(TypeError\): fetch failed/);
  assert.equal(result.observed?.nativeAddress, NATIVE);
  assert.equal(result.observed?.writer, OWNER);
  const fixture = nodeFixture(); (fixture.program as Node).data = { n: Number.POSITIVE_INFINITY };
  const malformed = asObservation(await createDemosNodeReceiptProvider(config, { nodeCall: nodeCallFor(fixture) }).fetch(request));
  assert.equal(malformed.outcome, 'indeterminate');
  assert.match(malformed.detail, /node read failed/);
});

const indeterminateCases: Array<[string, (f: Node) => void, RegExp]> = [
  ['missing storage record', (f) => { f.program = null; }, /storage record unavailable/],
  ['storage record without creating transaction', (f) => { delete (f.program as Node).createdByTx; }, /creating transaction/],
  ['storage record without data', (f) => { (f.program as Node).data = null; }, /no data/],
  ['transaction unavailable', (f) => { f.tx = null; }, /transaction unavailable/],
  ['node returns another transaction', (f) => { (f.tx as Node).hash = OTHER_TX; }, /different transaction/],
  ['creating transaction is not a storage program', (f) => { ((f.tx as Node).content as Node).type = 'native'; }, /not a storage program/],
  ['signer differs from owner', (f) => { ((f.tx as Node).content as Node).from = '0xabc'; }, /signer differs/],
  ['nonce missing', (f) => { delete ((f.tx as Node).content as Node).nonce; }, /nonce/],
  ['status unavailable', (f) => { f.status = null; }, /status unavailable/],
  ['status failed', (f) => { (f.status as Node).state = 'failed'; }, /failed/],
  ['status and record disagree on block', (f) => { (f.status as Node).blockNumber = 1; }, /disagree/],
  ['not yet in a block', (f) => { delete (f.tx as Node).blockNumber; (f.status as Node).state = 'pending'; delete (f.status as Node).blockNumber; }, /not yet in a block/],
  ['block unavailable', (f) => { f.block = null; }, /block unavailable/],
  ['node returns another block', (f) => { (f.block as Node).number = 1; }, /different block/],
  ['block without hash', (f) => { delete (f.block as Node).hash; }, /no hash/],
  ['block does not list the transaction', (f) => { ((f.block as Node).content as Node).ordered_transactions = [OTHER_TX]; }, /does not list/],
  ['block without timestamp', (f) => { delete ((f.block as Node).content as Node).timestamp; }, /timestamp/],
  ['storage record without owner', (f) => { delete (f.program as Node).owner; }, /no owner/],
  ['unrecognised transaction state', (f) => { (f.status as Node).state = 'bogus'; }, /unrecognised transaction state/],
  ['status unknown', (f) => { (f.status as Node).state = 'unknown'; }, /unknown/],
  ['status pending', (f) => { (f.status as Node).state = 'pending'; }, /not yet in a block/],
  ['status without block number', (f) => { delete (f.status as Node).blockNumber; }, /disagree/],
  ['transaction record with a malformed block number string', (f) => { (f.tx as Node).blockNumber = '0x34f96'; }, /names no block/],
  ['transaction record with a signed block number string', (f) => { (f.tx as Node).blockNumber = '-216982'; }, /names no block/],
  ['negative nonce', (f) => { ((f.tx as Node).content as Node).nonce = -1; }, /nonce/],
  ['fractional nonce', (f) => { ((f.tx as Node).content as Node).nonce = 1.5; }, /nonce/],
  ['unrecognised transaction disposition', (f) => { (f.tx as Node).status = 'bogus'; }, /no recognised disposition/],
  ['missing transaction disposition', (f) => { delete (f.tx as Node).status; }, /no recognised disposition/],
  ['record pending while status says included', (f) => { (f.tx as Node).status = 'pending'; }, /disagree on inclusion/],
  ['non-string transaction disposition', (f) => { (f.tx as Node).status = 7; }, /no recognised disposition/],
  ['unsafe-integer nonce', (f) => { ((f.tx as Node).content as Node).nonce = Number.MAX_SAFE_INTEGER + 2; }, /nonce/],
  ['unrecognised block disposition', (f) => { (f.block as Node).status = 'bogus'; }, /unrecognised disposition/],
  ['fractional block timestamp', (f) => { ((f.block as Node).content as Node).timestamp = 1788374743.5; }, /timestamp/],
];
for (const [name, mutate, pattern] of indeterminateCases) {
  test(`indeterminate, never a receipt: ${name}`, async () => {
    const fixture = nodeFixture(); mutate(fixture);
    const provider = createDemosNodeReceiptProvider(config, { nodeCall: nodeCallFor(fixture) });
    const result = asObservation(await provider.fetch(request));
    assert.equal(result.outcome, 'indeterminate');
    assert.match(result.detail, pattern);
    assert.equal(result.observed?.nativeAddress, NATIVE);
  });
}

test('consensus timestamps in seconds become milliseconds; milliseconds pass through; nothing is rounded', () => {
  assert.equal(consensusTimestampMs(1788374743), 1788374743000);
  assert.equal(consensusTimestampMs(1788374737679), 1788374737679);
  assert.equal(consensusTimestampMs(1e12 - 1), (1e12 - 1) * 1000);
  assert.equal(consensusTimestampMs(1e12), 1e12);
  for (const bad of [0, -5, 0.0001, 1788374743.5, 1788374737679.25, Number.MAX_SAFE_INTEGER + 2, Number.POSITIVE_INFINITY, Number.NaN, '1788374743', null, undefined]) {
    assert.equal(consensusTimestampMs(bad), undefined, String(bad));
  }
});

test('the default node call speaks the nodeCall envelope and treats result 404 as missing', async () => {
  const seen: Array<{ url: string; body: unknown }> = [];
  const responses: unknown[] = [{ result: 200, response: { ok: true } }, { result: 404, response: null }, { result: 500, response: 'boom' }];
  const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
    seen.push({ url: String(url), body: JSON.parse(String(init?.body)) });
    return new Response(JSON.stringify(responses.shift()), { status: 200, headers: { 'Content-Type': 'application/json' } });
  }) as typeof fetch;
  const nodeCall = createDefaultNodeCall(config.rpc, fetchImpl);
  assert.deepEqual(await nodeCall('getStorageProgram', { storageAddress: NATIVE }), { ok: true });
  assert.equal(await nodeCall('getTxByHash', { hash: TX }), null);
  await assert.rejects(nodeCall('getBlockByNumber', { blockNumber: 1 }), /result=500/);
  assert.equal(seen[0]!.url, config.rpc);
  assert.deepEqual((seen[0]!.body as { method: string; params: Array<{ message: string; data: unknown }> }).params[0]!.message, 'getStorageProgram');
  const transport = createDefaultNodeCall(config.rpc, (async () => new Response('nope', { status: 502 })) as typeof fetch);
  await assert.rejects(transport('getStorageProgram', { storageAddress: NATIVE }), /HTTP 502/);
});

test('the provider performs only read-shaped node calls and leaves the environment unchanged', async () => {
  const calls: string[] = [];
  const provider = createDemosNodeReceiptProvider(config, { nodeCall: nodeCallFor(nodeFixture(), calls) });
  const before = JSON.stringify(Object.entries(process.env).sort());
  await provider.fetch(request);
  assert.equal(JSON.stringify(Object.entries(process.env).sort()), before, 'no mutation (reads are not instrumented here)');
  assert.deepEqual(calls, ['getStorageProgram', 'getTxByHash', 'getTransactionStatus', 'getBlockByNumber']);
});

test('a cold request is enriched with the anchor this session wrote; an explicit anchor wins; unknown names pass through', () => {
  const written = { logicalAddress: 'dacs1:listing:test', nativeAddress: NATIVE, transactionRef: { kind: 'demos', value: TX }, writer: cciClaimForAddress(OWNER), nonce: '403' };
  const wiring = { anchored: (name: string) => (name === 'dacs1:listing:test' ? written : undefined) };
  const cold = { logicalAddress: 'dacs1:listing:test', contentHash: CONTENT_HASH };
  assert.deepEqual(withSessionAnchor(cold, wiring), { ...cold, anchor: written });
  const explicit = { ...cold, anchor: { ...written, nativeAddress: 'stor-98a32a825771321642b3b9f913c5a414d04f57da' } };
  assert.equal(withSessionAnchor(explicit, wiring), explicit);
  const unknown = { logicalAddress: 'dacs1:listing:other', contentHash: CONTENT_HASH };
  assert.equal(withSessionAnchor(unknown, wiring), unknown);
  assert.equal(withSessionAnchor(unknown, {}), unknown);
});

const runConfig: DacsTestnetConfig = { jobId: 'unit-job', mode: 'live', organ: 'nws_alerts', query: 'fixture-query', priceDem: '1', spendCapDem: 50, rpc: 'https://example.invalid' };

test('selectReceiptProvider picks the finality-proving provider only by name', () => {
  assert.equal(selectReceiptProvider(runConfig).describe().provesFinality, false);
  assert.equal(selectReceiptProvider({ ...runConfig, receiptProvider: 'observer' }).describe().provesFinality, false);
  assert.equal(selectReceiptProvider({ ...runConfig, receiptProvider: 'demos-node' }).describe().provesFinality, true);
});

test('the receipt provider choice enters the parameter hash', () => {
  const observer = parameterHash(runConfig);
  assert.equal(parameterHash({ ...runConfig, receiptProvider: 'observer' }), observer);
  assert.notEqual(parameterHash({ ...runConfig, receiptProvider: 'demos-node' }), observer);
});

test('LIVE wiring checks the demos-node capability before any environment read, then refuses at credentials without leaking them', async () => {
  const sentinel = 'ENV-SENTINEL-MUST-STAY-PRIVATE';
  const events: string[] = [];
  const target: NodeJS.ProcessEnv = { DEMOS_MNEMONIC: sentinel, DEMOS_SELLER_MNEMONIC: sentinel, DACS_ENV_PATH: '/nonexistent/.env' };
  const env = new Proxy(target, { get(t, key, r) { if (typeof key === 'string') events.push(`env:${key}`); return Reflect.get(t, key, r); } });
  const real = selectReceiptProvider({ ...runConfig, receiptProvider: 'demos-node' });
  const provider = { describe: () => { events.push('describe'); return real.describe(); }, fetch: real.fetch.bind(real) };
  let caught: unknown;
  try { await createLiveAdapterWiring({ ...runConfig, receiptProvider: 'demos-node' }, env, provider); }
  catch (error) { caught = error; }
  assert.ok(caught instanceof Error);
  assert.ok(!(caught instanceof DacsTestnetRefusal && caught.code === 'capability'), 'capability must pass with demos-node');
  assert.ok(!caught.message.includes(sentinel));
  assert.equal(events[0], 'describe');
  assert.ok(events.slice(1).some((e) => e.startsWith('env:')), 'credentials are read only after the capability check');
  // The observer keeps refusing at capability and never reaches the environment.
  const before = events.length;
  await assert.rejects(createLiveAdapterWiring(runConfig, env), (error: unknown) => error instanceof DacsTestnetRefusal && error.code === 'capability');
  assert.equal(events.length, before);
});

test('CLI accepts --receipt-provider demos-node, rejects other values, and keeps the observer refusal by default', async () => {
  const writes: string[] = [];
  const original = process.stderr.write;
  process.stderr.write = ((chunk: string | Uint8Array) => { writes.push(String(chunk)); return true; }) as typeof process.stderr.write;
  try {
    assert.equal(await main(['--job-id', 'x', '--receipt-provider', 'bogus', '--json'], {}), 2);
    assert.match(writes.join(''), /"reason":"usage"/);
    writes.length = 0;
    // dry-run with the flag still runs on fixtures (the provider is a LIVE concern) and passes.
    assert.equal(await main(['--job-id', 'x', '--receipt-provider', 'demos-node', '--dry-run', '--json'], {}), 0);
  } finally {
    process.stderr.write = original;
  }
});

test('block numbers reported as decimal strings (observed on the node 2026-09-06) are accepted and compared numerically', async () => {
  const fixture = nodeFixture();
  (fixture.tx as Node).blockNumber = '216982';
  (fixture.status as Node).blockNumber = '216982';
  (fixture.block as Node).number = '216982';
  const receipt = await createDemosNodeReceiptProvider(config, { nodeCall: nodeCallFor(fixture) }).fetch(request) as AnchorReceipt;
  assert.equal(receipt.state, 'finalized');
  assert.equal(receipt.blockRef?.height, '216982');
  // Mixed shapes still agree; a genuinely different block still disagrees.
  const mixed = nodeFixture(); (mixed.status as Node).blockNumber = '216982';
  assert.equal(((await createDemosNodeReceiptProvider(config, { nodeCall: nodeCallFor(mixed) }).fetch(request)) as AnchorReceipt).state, 'finalized');
  const other = nodeFixture(); (other.status as Node).blockNumber = '216983';
  assert.equal(asObservation(await createDemosNodeReceiptProvider(config, { nodeCall: nodeCallFor(other) }).fetch(request)).outcome, 'indeterminate');
  // The block is requested by number whatever shape the node used to report it.
  const seen: unknown[] = [];
  const recording: NodeCall = async (message, data) => {
    if (message === 'getBlockByNumber') seen.push(data);
    return nodeCallFor(fixture)(message, data);
  };
  assert.equal(((await createDemosNodeReceiptProvider(config, { nodeCall: recording }).fetch(request)) as AnchorReceipt).state, 'finalized');
  assert.equal(seen.length, 1);
  assert.deepEqual(seen[0], { blockNumber: 216982 });
  // A block whose own number disagrees, as a string, is still not the requested block.
  const wrongBlock = nodeFixture(); (wrongBlock.block as Node).number = '216983';
  const wrong = asObservation(await createDemosNodeReceiptProvider(config, { nodeCall: nodeCallFor(wrongBlock) }).fetch(request));
  assert.equal(wrong.outcome, 'indeterminate');
  assert.match(wrong.detail, /different block/);
  // Both copies of the helper (provider and pay-dem parser) accept and reject the same inputs, including the safe-integer boundary.
  const table: Array<[unknown, number | undefined]> = [
    [244489, 244489], ['244489', 244489], ['0', 0], [0, 0],
    [Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER], [String(Number.MAX_SAFE_INTEGER), Number.MAX_SAFE_INTEGER],
    [Number.MAX_SAFE_INTEGER + 1, undefined], [String(Number.MAX_SAFE_INTEGER + 1), undefined],
    ['007', undefined], ['-1', undefined], [-1, undefined], ['1.5', undefined], [1.5, undefined], ['0x2a', undefined], ['1e5', undefined],
    ['', undefined], [' 42', undefined], [null, undefined], [undefined, undefined], [42n, undefined], ['99999999999999999999', undefined],
  ];
  for (const [raw, want] of table) {
    assert.equal(nodeBlockNumber(raw), want, `provider ${String(raw)}`);
    assert.equal(payDemBlockNumber(raw), want, `pay-dem ${String(raw)}`);
  }
});
