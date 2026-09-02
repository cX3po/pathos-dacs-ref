import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { StorageProgram, type StorageProgramData } from '@kynesyslabs/demosdk/storage';
import {
  fetchAnchored,
  storedAnchorPayload,
  unwrapTextAnchor,
  verifyAnchor,
  wrapTextAnchor,
  type FetchResult,
} from '../../src/demos/storage.js';
import { fetchAddressFirst, resolveByName } from '../../src/live/anchor-naming.js';

const storageAddress = `stor-${'a'.repeat(64)}`;
const rpc = 'https://unused.invalid';
const owner = '0xowner';
const programName = 'wrapped-text-test';

function sdkResult(data: unknown): StorageProgramData {
  return {
    storageAddress,
    programName,
    owner,
    data,
    encoding: 'json',
    sizeBytes: StorageProgram.getDataSize(data as Record<string, unknown> | string, 'json'),
    createdAt: '2026-09-02T00:00:00.000Z',
  } as StorageProgramData;
}

function searchResponse(results: Array<Record<string, unknown>>, result = 200): Response {
  return new Response(JSON.stringify({ result, response: results }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

function addressResponse(response?: StorageProgramData, result = 200): Response {
  return new Response(JSON.stringify({ result, ...(response === undefined ? {} : { response }) }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

const searchItem = { storageAddress, owner, name: programName, data: 'must not be trusted' };

test('wrapped text survives node-style JSON serialization byte-exactly', () => {
  const values = ['', 'plain ASCII', '🌍 café 漢字',
    'quotes: " slash: \\ controls: \n\t\u0000',
    'a\uD800b', 'x'.repeat(250_000)];
  for (const value of values) {
    const round = JSON.parse(JSON.stringify(wrapTextAnchor(value)));
    assert.equal(unwrapTextAnchor(round), value);
    assert.equal(unwrapTextAnchor({ text: value, v: 'dacs-ref-text:1' }), value);
  }
});

test('unwrapTextAnchor rejects near-matches and extra fields', () => {
  assert.equal(unwrapTextAnchor({ text: 'not marked' }), null);
  assert.equal(unwrapTextAnchor({ v: 'wrong', text: 'value' }), null);
  assert.equal(unwrapTextAnchor({ v: 'dacs-ref-text:1', text: 1 }), null);
  assert.equal(unwrapTextAnchor({ v: 'dacs-ref-text:1', text: 'value', extra: true }), null);
  assert.equal(unwrapTextAnchor(JSON.stringify(wrapTextAnchor('text-shaped bytes'))), null);
  assert.equal(unwrapTextAnchor(null), null);
});

test('storedAnchorPayload wraps only JSON-encoded strings and size validation includes overhead', () => {
  const value = 'byte-exact';
  assert.deepEqual(storedAnchorPayload(value, 'json'), wrapTextAnchor(value));
  assert.equal(storedAnchorPayload(value, 'binary'), value);
  assert.equal(
    StorageProgram.validateSize(storedAnchorPayload('x'.repeat(1_048_545), 'json'), 'json'),
    false,
  );
});

test('fetchAnchored unwraps marked text and verifyAnchor hashes original encoded bytes', async () => {
  const original = 'byte-exact 🌍 " \\ \n';
  const envelope = JSON.parse(JSON.stringify(wrapTextAnchor(original)));
  const expected = createHash('sha256').update(new TextEncoder().encode(original)).digest('hex');
  const fetchImpl = async () => addressResponse(sdkResult(envelope));
  const fetched = await fetchAnchored(rpc, storageAddress, { fetchImpl });
  assert.equal(fetched?.data, original);
  assert.equal(fetched?.wrapped, true);
  const pass = await verifyAnchor(rpc, storageAddress, expected, {
    fetchAnchoredImpl: async () => fetchAnchored(rpc, storageAddress, { fetchImpl }),
  });
  assert.equal(pass.outcome, 'pass');

  const rawEnvelopeResult: FetchResult = {
    storageAddress, owner, data: envelope, sizeBytes: 1, createdAt: '2026-09-02T00:00:00.000Z',
  };
  const customPass = await verifyAnchor(rpc, storageAddress, expected, {
    fetchAnchoredImpl: async () => rawEnvelopeResult,
  });
  assert.equal(customPass.outcome, 'pass');
});

test('fetchAnchored preserves ordinary objects with a text field', async () => {
  const ordinary = { text: 'not marked', kind: 'artifact' };
  const result = await fetchAnchored(rpc, storageAddress, {
    fetchImpl: async () => addressResponse(sdkResult(ordinary)),
  });
  assert.deepEqual(result?.data, ordinary);
  assert.equal(result?.wrapped, undefined);
});

test('envelope object stored as JSON (not via wrapTextAnchor) is reserved and unwraps', async () => {
  const obj = { v: 'dacs-ref-text:1' as const, text: 'hello' };
  const result = await fetchAnchored(rpc, storageAddress, {
    fetchImpl: async () => addressResponse(sdkResult(obj)),
  });
  assert.equal(result?.data, 'hello');
  assert.equal(result?.wrapped, true);
});

test('resolveByName loads wrapped text by storage address and preserves objects', async () => {
  for (const [stored, expected, wrapped] of [
    [wrapTextAnchor('resolved text'), 'resolved text', true],
    [{ kind: 'object-anchor' }, { kind: 'object-anchor' }, undefined],
  ] as const) {
    const result = await resolveByName(rpc, owner, programName, {
      fetchImpl: async () => searchResponse([searchItem]),
      fetchAnchoredImpl: async (_rpc, address) => {
        assert.equal(address, storageAddress);
        return fetchAnchored(rpc, address, {
          fetchImpl: async () => addressResponse(sdkResult(stored)),
        });
      },
    });
    assert.deepEqual(result?.data, expected);
    assert.equal(result?.wrapped, wrapped);
  }
});

test('resolveByName retries bounded absence but defaults to one search', async () => {
  let retryCalls = 0;
  const retried = await resolveByName(rpc, owner, programName, {
    retries: 1,
    delayMs: 0,
    retryLog: () => undefined,
    fetchImpl: async () => searchResponse(++retryCalls === 2 ? [searchItem] : []),
    fetchAnchoredImpl: async () => fetchAnchored(rpc, storageAddress, {
      fetchImpl: async () => addressResponse(sdkResult(wrapTextAnchor('indexed'))),
    }),
  });
  assert.equal(retryCalls, 2);
  assert.equal(retried?.data, 'indexed');

  let noRetryCalls = 0;
  const absent = await resolveByName(rpc, owner, programName, {
    fetchImpl: async () => {
      noRetryCalls++;
      return searchResponse([]);
    },
  });
  assert.equal(absent, null);
  assert.equal(noRetryCalls, 1);
});

test('resolveByName RPC errors throw and are never reported as absence', async () => {
  await assert.rejects(
    resolveByName(rpc, owner, programName, {
      retries: 3,
      delayMs: 0,
      retryLog: () => assert.fail('RPC errors must not enter the absence retry path'),
      fetchImpl: async () => searchResponse([], 503),
    }),
    /RPC returned result=503/,
  );
});

test('gateway address-first helper uses a known storage locator without name search', async () => {
  let addressCalls = 0;
  let searchCalls = 0;
  const known: FetchResult = {
    storageAddress, owner, data: 'bundle', sizeBytes: 6, createdAt: '2026-09-02T00:00:00.000Z',
  };
  const result = await fetchAddressFirst(rpc, storageAddress, owner, programName, {
    fetchAnchoredImpl: async (_rpc, address) => {
      addressCalls++;
      assert.equal(address, storageAddress);
      return known;
    },
    fetchImpl: async () => {
      searchCalls++;
      return searchResponse([]);
    },
  });
  assert.equal(result, known);
  assert.equal(addressCalls, 1);
  assert.equal(searchCalls, 0);
});

test('address-read RPC errors throw without retry or address-first name fallback', async () => {
  let searchCalls = 0;
  await assert.rejects(
    fetchAddressFirst(rpc, storageAddress, owner, programName, {
      retries: 3,
      delayMs: 0,
      retryLog: () => assert.fail('address RPC errors must not enter the absence retry path'),
      fetchImpl: async (_input, init) => {
        const request = JSON.parse(String(init?.body)) as { params: Array<{ message: string }> };
        if (request.params[0]?.message === 'searchStoragePrograms') searchCalls++;
        return addressResponse(undefined, 503);
      },
    }),
    /getStorageProgram RPC returned result=503/,
  );
  assert.equal(searchCalls, 0);
});

test('a matching search row propagates an address-read RPC error without retry', async () => {
  let retryCalls = 0;
  await assert.rejects(
    resolveByName(rpc, owner, programName, {
      retries: 3,
      delayMs: 0,
      retryLog: () => assert.fail('address RPC errors must not enter the absence retry path'),
      fetchImpl: async (_input, init) => {
        const request = JSON.parse(String(init?.body)) as { params: Array<{ message: string }> };
        if (request.params[0]?.message === 'searchStoragePrograms') {
          retryCalls++;
          return searchResponse([searchItem]);
        }
        return addressResponse(undefined, 503);
      },
    }),
    /getStorageProgram RPC returned result=503/,
  );
  assert.equal(retryCalls, 1);
});

test('a matching search row with an honestly empty address body may retry', async () => {
  let searchCalls = 0;
  let addressCalls = 0;
  let retryCalls = 0;
  const result = await resolveByName(rpc, owner, programName, {
    retries: 1,
    delayMs: 0,
    retryLog: () => retryCalls++,
    fetchImpl: async (_input, init) => {
      const request = JSON.parse(String(init?.body)) as { params: Array<{ message: string }> };
      if (request.params[0]?.message === 'searchStoragePrograms') {
        searchCalls++;
        return searchResponse([searchItem]);
      }
      addressCalls++;
      return addressResponse();
    },
  });
  assert.equal(result, null);
  assert.equal(searchCalls, 2);
  assert.equal(addressCalls, 2);
  assert.equal(retryCalls, 1);
});

test('an HTTP 404 on the address read is a transport error, not absence', async () => {
  let searchCalls = 0;
  await assert.rejects(
    fetchAddressFirst(rpc, storageAddress, owner, programName, {
      retries: 3,
      delayMs: 0,
      retryLog: () => assert.fail('an HTTP 404 must not enter the absence retry path'),
      fetchImpl: async (_input, init) => {
        const request = JSON.parse(String(init?.body)) as { params: Array<{ message: string }> };
        if (request.params[0]?.message === 'searchStoragePrograms') searchCalls++;
        return new Response('', { status: 404 });
      },
    }),
    /getStorageProgram HTTP 404/,
  );
  assert.equal(searchCalls, 0);
});

test('an envelope result 404 on the address read is honest absence and may fall back to name search', async () => {
  let searchCalls = 0;
  const result = await fetchAddressFirst(rpc, storageAddress, owner, programName, {
    retries: 0,
    delayMs: 0,
    fetchImpl: async (_input, init) => {
      const request = JSON.parse(String(init?.body)) as { params: Array<{ message: string }> };
      if (request.params[0]?.message === 'searchStoragePrograms') { searchCalls++; return searchResponse([]); }
      return new Response(JSON.stringify({ result: 404, response: null }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    },
  });
  assert.equal(result, null);
  assert.equal(searchCalls, 1);
});
