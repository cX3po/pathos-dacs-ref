/**
 * DAHR hostname allowlist — SSRF defense layer 2 (Codex round 4 #2)
 *
 * Locks in:
 *   - 127.0.0.1, localhost, RFC1918, link-local addresses (https://) all rejected
 *   - api.gleif.org (the wired DACS-2 recipe) allowed
 *   - example.com allowed ONLY when DACS_TEST_NETWORK=1 (test-fixture host)
 */

import { test, after, beforeEach } from 'node:test';
import { strict as assert } from 'node:assert';
import { dahrFetch } from '../../src/demos/index.js';
import { isAllowedHost, assertAllowedHost, DAHR_HOST_ALLOWLIST } from '../../src/demos/dahr-allowlist.js';

const realFetch = globalThis.fetch;
after(() => { globalThis.fetch = realFetch; });

const realTestNet = process.env.DACS_TEST_NETWORK;
beforeEach(() => {
  if (realTestNet === undefined) delete process.env.DACS_TEST_NETWORK;
  else process.env.DACS_TEST_NETWORK = realTestNet;
});

test('allowlist — api.gleif.org is allowed (the wired DACS-2 recipe host)', () => {
  assert.equal(isAllowedHost('api.gleif.org'), true);
});

test('allowlist — case-insensitive match', () => {
  assert.equal(isAllowedHost('API.GLEIF.ORG'), true);
  assert.equal(isAllowedHost('Api.Gleif.Org'), true);
});

test('allowlist — 127.0.0.1 is REJECTED (no SSRF via loopback)', () => {
  assert.equal(isAllowedHost('127.0.0.1'), false);
  assert.throws(() => assertAllowedHost('127.0.0.1'), /not on the allowlist/);
});

test('allowlist — localhost is REJECTED', () => {
  assert.equal(isAllowedHost('localhost'), false);
});

test('allowlist — RFC1918 private IP rejected', () => {
  assert.equal(isAllowedHost('10.0.0.1'), false);
  assert.equal(isAllowedHost('192.168.1.1'), false);
  assert.equal(isAllowedHost('172.16.0.1'), false);
});

test('allowlist — link-local (cloud metadata) rejected', () => {
  // 169.254.169.254 — AWS/Azure/GCP metadata endpoint
  assert.equal(isAllowedHost('169.254.169.254'), false);
});

test('allowlist — IPv6 loopback rejected', () => {
  assert.equal(isAllowedHost('::1'), false);
});

test('allowlist — example.com allowed only when DACS_TEST_NETWORK=1', () => {
  delete process.env.DACS_TEST_NETWORK;
  assert.equal(isAllowedHost('example.com'), false);
  process.env.DACS_TEST_NETWORK = '1';
  assert.equal(isAllowedHost('example.com'), true);
});

test('dahrFetch — https://127.0.0.1 is refused with allowlist error', async () => {
  globalThis.fetch = async () => new Response('{"x":1}', { status: 200, headers: { 'content-type': 'application/json' } });
  await assert.rejects(
    async () => { await dahrFetch(undefined, 'https://127.0.0.1/x', { skipAnchor: true }); },
    /not on the allowlist/
  );
});

test('dahrFetch — https://169.254.169.254 (metadata endpoint) is refused', async () => {
  globalThis.fetch = async () => new Response('{"x":1}', { status: 200, headers: { 'content-type': 'application/json' } });
  await assert.rejects(
    async () => { await dahrFetch(undefined, 'https://169.254.169.254/latest/meta-data/', { skipAnchor: true }); },
    /not on the allowlist/
  );
});

test('allowlist is the right size for v0.2 scope', () => {
  // Sanity check — keep this number visible so review catches scope creep.
  // v0.2 only wires the GLEIF recipe, so the production allowlist is exactly api.gleif.org.
  // Adding a new host requires bumping this assertion in the same commit that wires the recipe.
  assert.equal(DAHR_HOST_ALLOWLIST.length, 1,
    'v0.2 allowlist should contain exactly 1 production host: api.gleif.org');
  assert.equal(DAHR_HOST_ALLOWLIST[0], 'api.gleif.org');
});
