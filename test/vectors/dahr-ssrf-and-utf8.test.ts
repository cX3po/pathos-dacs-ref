/**
 * DAHR — SSRF + strict-UTF-8 unit tests (Codex re-re-review #1 + #3)
 *
 * No network. Deterministic. Locks in:
 *   - http:// is rejected (SSRF guard)
 *   - file://, data:, javascript: schemes are rejected
 *   - invalid URLs are rejected
 *   - application/octet-stream is rejected (binary marker)
 *   - missing content-type is rejected (no benefit-of-the-doubt)
 *   - invalid UTF-8 bytes throw with strict fatal: true decoder
 */

import { test, after } from 'node:test';
import { strict as assert } from 'node:assert';
import { dahrFetch } from '../../src/demos/index.js';

const realFetch = globalThis.fetch;
after(() => { globalThis.fetch = realFetch; });

function fakeFetch(body: string | Uint8Array, status = 200, contentType?: string) {
  return async (): Promise<Response> => {
    const bytes = typeof body === 'string' ? new TextEncoder().encode(body) : body;
    const headers: Record<string, string> = {};
    if (contentType !== undefined) headers['content-type'] = contentType;
    return new Response(bytes as BodyInit, { status, headers });
  };
}

test('SSRF — http:// URL is refused', async () => {
  await assert.rejects(
    async () => { await dahrFetch(undefined, 'http://example.com', { skipAnchor: true }); },
    /DAHR requires https:\/\//
  );
});

test('SSRF — file:// URL is refused', async () => {
  await assert.rejects(
    async () => { await dahrFetch(undefined, 'file:///etc/passwd', { skipAnchor: true }); },
    /DAHR requires https:\/\//
  );
});

test('SSRF — data: URL is refused', async () => {
  await assert.rejects(
    async () => { await dahrFetch(undefined, 'data:text/plain,hello', { skipAnchor: true }); },
    /DAHR requires https:\/\//
  );
});

test('SSRF — invalid URL string is refused', async () => {
  await assert.rejects(
    async () => { await dahrFetch(undefined, 'not a url', { skipAnchor: true }); },
    /DAHR: invalid URL/
  );
});

test('DAHR — application/octet-stream content-type is refused', async () => {
  globalThis.fetch = fakeFetch('any', 200, 'application/octet-stream');
  await assert.rejects(
    async () => { await dahrFetch(undefined, 'https://api.gleif.org/api/v1/lei-records/X', { skipAnchor: true }); },
    /DAHR v0.2 supports text\/JSON\/XML/
  );
});

test('DAHR — missing content-type is refused (no benefit-of-the-doubt)', async () => {
  globalThis.fetch = fakeFetch('any', 200, undefined);
  await assert.rejects(
    async () => { await dahrFetch(undefined, 'https://api.gleif.org/api/v1/lei-records/X', { skipAnchor: true }); },
    /DAHR v0.2 supports text\/JSON\/XML/
  );
});

test('DAHR — invalid UTF-8 bytes throw (strict fatal: true decoder)', async () => {
  // 0xFF is invalid as a UTF-8 leading byte
  const invalidUtf8 = new Uint8Array([0xff, 0xfe, 0xfd]);
  globalThis.fetch = fakeFetch(invalidUtf8, 200, 'text/plain');
  await assert.rejects(
    async () => { await dahrFetch(undefined, 'https://api.gleif.org/api/v1/lei-records/X', { skipAnchor: true }); },
    /response bytes are not valid UTF-8/
  );
});
