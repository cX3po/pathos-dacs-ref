/**
 * Demos bridge layer — UNIT tests (mocked fetch, no network)
 *
 * Covers parts of src/demos/dahr.ts that exercise:
 *   - stub-mode AttestationRef shape (§7.5.2 conformance)
 *   - dahr-stub: prefix honest-scope marker
 *   - contentHash = sha256(raw response bytes) — consistent with verifyAnchor()
 *
 * No network calls. Deterministic. Codex re-review #2: the previous version
 * of this file called fetch() against api.gleif.org; that's now in the
 * integration suite. Here we install a globalThis.fetch mock for each test.
 */

import { test, after } from 'node:test';
import { strict as assert } from 'node:assert';
import { dahrFetch } from '../../src/demos/index.js';
import { sha256 } from '@noble/hashes/sha2';

const realFetch = globalThis.fetch;

/** Build a deterministic fake Response for a given body string + content-type. */
function fakeFetch(body: string, status = 200, contentType = 'application/vnd.api+json') {
  return async (_url: string | URL | Request, _init?: RequestInit): Promise<Response> => {
    const bytes = new TextEncoder().encode(body);
    return new Response(bytes, {
      status,
      headers: { 'content-type': contentType },
    });
  };
}

after(() => {
  globalThis.fetch = realFetch;
});

test('DAHR stub mode — attestation.type has dahr-stub: prefix even with --recipe set', async () => {
  globalThis.fetch = fakeFetch('{"data":{"id":"TESTLEI","attributes":{}}}');
  const result = await dahrFetch(undefined, 'https://api.gleif.org/api/v1/lei-records/TESTLEI', {
    skipAnchor: true,
    recipe: 'gleif-cbp:1',
  });
  assert.match(result.attestation.type, /^dahr-stub:/,
    'v0.2 stub mode MUST mark attestation.type with dahr-stub: prefix so a high-stakes verifier can refuse');
  assert.equal(result.attestation.type, 'dahr-stub:gleif-cbp:1');
});

test('DAHR contentHash MUST equal sha256 of raw response bytes (Codex review #3 fix)', async () => {
  const body = '{"data":{"id":"DETERMINISTIC","attributes":{"entity":{"legalName":{"name":"Test"}}}}}';
  globalThis.fetch = fakeFetch(body);
  const expectedHash = sha256(new TextEncoder().encode(body));
  const expectedHashHex = Array.from(expectedHash, (b) => b.toString(16).padStart(2, '0')).join('');

  const result = await dahrFetch(undefined, 'https://api.gleif.org/api/v1/lei-records/DETERMINISTIC', {
    skipAnchor: true,
    recipe: 'gleif-cbp:1',
  });
  assert.equal(result.attestation.contentHash, expectedHashHex,
    'contentHash must equal sha256(raw response bytes); verifyAnchor() recomputes the same hash from the anchored data');
});

test('DAHR stub mode — locator follows stor-stub-<contentHashPrefix> pattern', async () => {
  globalThis.fetch = fakeFetch('{"x":1}');
  const result = await dahrFetch(undefined, 'https://api.gleif.org/api/v1/lei-records/X', {
    skipAnchor: true,
    recipe: 'gleif-cbp:1',
  });
  assert.match(result.attestation.anchor.locator, /^stor-stub-[0-9a-f]{32}$/);
  assert.equal(
    result.attestation.anchor.locator,
    `stor-stub-${result.attestation.contentHash.slice(0, 32)}`,
  );
});

test('DAHR — binary content-types are refused in v0.2 (UTF-8 only)', async () => {
  globalThis.fetch = fakeFetch('binary-blob-bytes', 200, 'application/x-protobuf');
  await assert.rejects(
    async () => {
      await dahrFetch(undefined, 'https://api.gleif.org/api/v1/binary', { skipAnchor: true });
    },
    /DAHR v0.2 supports text\/JSON\/XML responses only/,
    'binary responses should be refused with a clear v0.3 roadmap pointer'
  );
});

test('dahrFetch — handle=undefined + skipAnchor:false (default) THROWS (Codex round 6 #3 regression test)', async () => {
  globalThis.fetch = fakeFetch('{"x":1}');
  await assert.rejects(
    async () => {
      await dahrFetch(undefined, 'https://api.gleif.org/api/v1/lei-records/X', {
        // No skipAnchor — should refuse rather than silently downgrade to stub
        recipe: 'gleif-cbp:1',
      });
    },
    /handle is undefined but skipAnchor is not true/,
    'must refuse silent stub-mode downgrade when caller intent is ambiguous'
  );
});

test('DAHR — 404 from upstream still produces a well-formed AttestationRef', async () => {
  globalThis.fetch = fakeFetch('{"errors":[{"detail":"not found"}]}', 404);
  const result = await dahrFetch(undefined, 'https://api.gleif.org/api/v1/lei-records/MISSING', {
    skipAnchor: true,
    recipe: 'gleif-cbp:1',
  });
  assert.equal(result.responseStatus, 404);
  assert.match(result.attestation.contentHash, /^[0-9a-f]{64}$/);
  assert.equal(result.attestation.type, 'dahr-stub:gleif-cbp:1');
});
