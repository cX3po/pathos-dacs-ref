import { test } from 'node:test';
import assert from 'node:assert/strict';
import { anchorFactsFromNode, AnchorFactsContradiction } from '../../src/demos/storage.js';

const NATIVE = 'stor-457c1ddf4d55e0d3206e1f5376f3876f301f3e3f';
const OWNER = '0x01e836295780008f15d46587e9c0b94d6ea1b2e8b4a3fd0c8d10ce6f7ec9e8a1';
const TX = '5a1ef2e16f7d37f8e85c7b8a3cd3cb9ab0573643127db353487be848f3fb6716';
// Shapes recorded read-only from the public testnet node on 2026-09-06 (the probe that found the two mismatches).
const program = { storageAddress: NATIVE, owner: OWNER, programName: 'dacs3:commit:debug', createdByTx: TX, data: { v: 1 } };
const tx = { hash: TX, status: 'confirmed', blockNumber: 244392, content: { type: 'storageProgram', from: OWNER, nonce: 34, timestamp: 1788662470000 } };

function fetchFor(responses: Record<string, unknown>, calls: string[] = []): typeof fetch {
  return (async (_url: string | URL | Request, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as { params: Array<{ message: string; data?: { storageAddress?: string } }> };
    const message = body.params[0]!.message; calls.push(message);
    let value = responses[message];
    // The anchor derives its own storage address; a program fixture answers under the address that was asked for.
    const asked = (body.params[0] as { data?: { storageAddress?: string } }).data?.storageAddress;
    if (message === 'getStorageProgram' && value && typeof value === 'object' && asked && (value as { storageAddress?: string }).storageAddress === NATIVE) value = { ...(value as object), storageAddress: asked };
    return new Response(JSON.stringify(value === undefined ? { result: 404, response: null } : { result: 200, response: value }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  }) as typeof fetch;
}

test('the node establishes the creating transaction and the nonce it carries', async () => {
  const calls: string[] = [];
  const facts = await anchorFactsFromNode('https://node.invalid/', NATIVE, { fetchImpl: fetchFor({ getStorageProgram: program, getTxByHash: tx }, calls) });
  assert.deepEqual(facts, { txHash: TX, nonce: '34', owner: OWNER });
  assert.deepEqual(calls, ['getStorageProgram', 'getTxByHash']);
});

const unavailable: Array<[string, Record<string, unknown>]> = [
  ['program missing', { getTxByHash: tx }],
  ['tx missing', { getStorageProgram: program }],
];
for (const [name, responses] of unavailable) {
  test(`facts are null when the record is not (yet) available: ${name}`, async () => {
    assert.equal(await anchorFactsFromNode('https://node.invalid/', NATIVE, { fetchImpl: fetchFor(responses) }), null);
  });
}
const contradictions: Array<[string, Record<string, unknown>]> = [
  ['program is another record', { getStorageProgram: { ...program, storageAddress: 'stor-other' }, getTxByHash: tx }],
  ['program without creating tx', { getStorageProgram: { ...program, createdByTx: undefined }, getTxByHash: tx }],
  ['creating tx not hex', { getStorageProgram: { ...program, createdByTx: '0xabc' }, getTxByHash: tx }],
  ['tx is another transaction', { getStorageProgram: program, getTxByHash: { ...tx, hash: 'ff'.repeat(32) } }],
  ['tx is not a storage program', { getStorageProgram: program, getTxByHash: { ...tx, content: { ...tx.content, type: 'native' } } }],
  ['tx signer is not the owner', { getStorageProgram: program, getTxByHash: { ...tx, content: { ...tx.content, from: '0xdead' } } }],
  ['nonce negative', { getStorageProgram: program, getTxByHash: { ...tx, content: { ...tx.content, nonce: -1 } } }],
  ['nonce fractional', { getStorageProgram: program, getTxByHash: { ...tx, content: { ...tx.content, nonce: 1.5 } } }],
  ['nonce missing', { getStorageProgram: program, getTxByHash: { ...tx, content: { type: 'storageProgram', from: OWNER } } }],
];
for (const [name, responses] of contradictions) {
  test(`a present but contradictory record throws, never null: ${name}`, async () => {
    await assert.rejects(anchorFactsFromNode('https://node.invalid/', NATIVE, { fetchImpl: fetchFor(responses) }), (e: unknown) => e instanceof AnchorFactsContradiction);
  });
}

test('a string nonce is accepted; a transport or RPC error propagates', async () => {
  const facts = await anchorFactsFromNode('https://node.invalid/', NATIVE, { fetchImpl: fetchFor({ getStorageProgram: program, getTxByHash: { ...tx, content: { ...tx.content, nonce: '34' } } }) });
  assert.equal(facts?.nonce, '34');
  const failing = (async () => new Response('nope', { status: 502 })) as typeof fetch;
  await assert.rejects(anchorFactsFromNode('https://node.invalid/', NATIVE, { fetchImpl: failing }), /HTTP 502/);
});

// anchor() itself, through a fake wallet: the signed transaction is the authority and the node read-back must agree.
import { anchor } from '../../src/demos/storage.js';
type FakeOpts = { signedHash?: string; signedNonce?: number; signedFrom?: string; broadcastHash?: string; state?: string; signed?: unknown };
function fakeHandle(o: FakeOpts = {}) {
  const calls: string[] = [];
  const counters = { broadcasts: 0 };
  const demos = {
    getAddressNonce: async () => 33,
    storagePrograms: { sign: async () => o.signed ?? ({ hash: o.signedHash ?? TX, content: { type: 'storageProgram', from: o.signedFrom ?? OWNER, nonce: o.signedNonce ?? 34 } }) },
    confirm: async (t: unknown) => t,
    broadcastAndWait: async () => { counters.broadcasts++; return { broadcast: { response: { hash: o.broadcastHash ?? '' } }, status: { state: o.state ?? 'included' } }; },
  };
  return { handle: { demos, address: OWNER, rpc: 'https://node.invalid/' } as never, calls, counters };
}
const okNode = { getStorageProgram: program, getTxByHash: tx };

test('anchor: empty broadcast hash, facts read back from the node, result carries the transaction and its nonce', async () => {
  const { handle } = fakeHandle();
  const calls: string[] = [];
  const result = await anchor(handle, 'dacs3:commit:x', { v: 1 }, { fetchImpl: fetchFor(okNode, calls), readBackAttempts: 1 });
  assert.equal(result.txHash, TX);
  assert.equal(result.nonce, '34');
  assert.deepEqual(calls, ['getStorageProgram', 'getTxByHash']);
});

test('anchor: a node record that names another transaction than the one this wallet signed is refused', async () => {
  const { handle } = fakeHandle({ signedHash: 'ee'.repeat(32) });
  await assert.rejects(anchor(handle, 'p', { v: 1 }, { fetchImpl: fetchFor(okNode), readBackAttempts: 1 }), /not the transaction this wallet signed/);
});

test('anchor: a node nonce that differs from the signed transaction is refused', async () => {
  const { handle } = fakeHandle({ signedNonce: 33 });
  await assert.rejects(anchor(handle, 'p', { v: 1 }, { fetchImpl: fetchFor(okNode), readBackAttempts: 1 }), /node records nonce 34, the signed transaction carried 33/);
});

test('anchor: a record owned by another wallet is refused even if internally consistent', async () => {
  const { handle } = fakeHandle();
  const other = '0x' + 'ab'.repeat(32);
  const node = { getStorageProgram: { ...program, owner: other }, getTxByHash: { ...tx, content: { ...tx.content, from: other } } };
  await assert.rejects(anchor(handle, 'p', { v: 1 }, { fetchImpl: fetchFor(node), readBackAttempts: 1 }), /not this wallet/);
});

test('anchor: a signed transaction from another wallet is refused before broadcast (zero broadcasts)', async () => {
  const f = fakeHandle({ signedFrom: '0x' + 'cd'.repeat(32) });
  await assert.rejects(anchor(f.handle, 'p', { v: 1 }, { fetchImpl: fetchFor(okNode), readBackAttempts: 1 }), /not this wallet/);
  assert.equal(f.counters.broadcasts, 0);
});

test('anchor: a signed transaction lacking hash, signer or nonce is refused before broadcast', async () => {
  for (const signed of [{ content: {} }, { hash: TX, content: { from: OWNER } }, { hash: TX, content: { nonce: 34 } }, { content: { from: OWNER, nonce: 34 } }, { hash: 'zz', content: { from: OWNER, nonce: 34 } }]) {
    const f = fakeHandle({ signed });
    await assert.rejects(anchor(f.handle, 'p', { v: 1 }, { fetchImpl: fetchFor(okNode), readBackAttempts: 1 }), /lacks a hash, signer or nonce/);
    assert.equal(f.counters.broadcasts, 0);
  }
});

test('anchor: a contradictory node record fails at once and is never retried', async () => {
  let programCalls = 0;
  const contradictory: typeof fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as { params: Array<{ message: string }> };
    if (body.params[0]!.message === 'getStorageProgram') { programCalls++; return new Response(JSON.stringify({ result: 200, response: { ...program, storageAddress: 'stor-other' } }), { status: 200 }); }
    return fetchFor(okNode)(url, init);
  }) as typeof fetch;
  const f = fakeHandle();
  await assert.rejects(anchor(f.handle, 'p', { v: 1 }, { fetchImpl: contradictory, readBackAttempts: 5, readBackDelayMs: 0 }), (e: unknown) => e instanceof AnchorFactsContradiction);
  assert.equal(programCalls, 1);
  assert.equal(f.counters.broadcasts, 1);
});

test('anchor: a broadcast hash that disagrees with the node is refused; an agreeing one passes', async () => {
  await assert.rejects(anchor(fakeHandle({ broadcastHash: 'ff'.repeat(32) }).handle, 'p', { v: 1 }, { fetchImpl: fetchFor(okNode), readBackAttempts: 1 }), /not the transaction this wallet signed|differs from the node/);
  const result = await anchor(fakeHandle({ broadcastHash: TX }).handle, 'p', { v: 1 }, { fetchImpl: fetchFor(okNode), readBackAttempts: 1 });
  assert.equal(result.txHash, TX);
});

test('anchor: a record that is not yet visible is retried, then fails closed when it never appears', async () => {
  let n = 0;
  const lateFetch: typeof fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    n++;
    const body = JSON.parse(String(init?.body)) as { params: Array<{ message: string }> };
    if (body.params[0]!.message === 'getStorageProgram' && n <= 2) return new Response(JSON.stringify({ result: 404, response: null }), { status: 200 });
    return fetchFor(okNode)(url, init);
  }) as typeof fetch;
  const f = fakeHandle();
  const result = await anchor(f.handle, 'p', { v: 1 }, { fetchImpl: lateFetch, readBackAttempts: 4, readBackDelayMs: 0 });
  assert.equal(result.txHash, TX);
  assert.equal(f.counters.broadcasts, 1, 'retries read back; they never rebroadcast');
  await assert.rejects(anchor(fakeHandle().handle, 'p', { v: 1 }, { fetchImpl: fetchFor({}), readBackAttempts: 2, readBackDelayMs: 0 }), /could not be read back from the node after 2 attempt/);
});

test('anchor: a transaction the node reports as not included is refused before any read-back', async () => {
  const calls: string[] = [];
  await assert.rejects(anchor(fakeHandle({ state: 'pending' }).handle, 'p', { v: 1 }, { fetchImpl: fetchFor(okNode, calls), readBackAttempts: 1 }), /not included/);
  assert.deepEqual(calls, []);
});
