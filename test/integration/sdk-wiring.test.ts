/**
 * Integration tests — Demos SDK wiring
 *
 * ALL tests here make live network calls. They are SKIPPED by default unless
 * an explicit opt-in env var is set:
 *   - DACS_LIVE_NETWORK=1  → enables network-only tests (e.g. live GLEIF reads)
 *   - DEMOS_MNEMONIC=...   → additionally enables chain-write tests (consumes DEM)
 *
 * Run with:
 *   DACS_LIVE_NETWORK=1 npm test                      # network tests, no chain writes
 *   DACS_LIVE_NETWORK=1 DEMOS_MNEMONIC="..." npm test # full integration
 *
 * Default behaviour (no env): all integration tests skip cleanly — keeps the
 * default test run deterministic and offline-safe for CI.
 */

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { dahrFetch, connectDemos } from '../../src/demos/index.js';
import { sha256 } from '@noble/hashes/sha2';

// Strict env-var check — DACS_LIVE_NETWORK must equal '1' exactly.
// '0', 'false', '' (unset), or any other value all skip the live tests.
// (Codex round 4 #1: !!process.env.X treats '0'/'false' as truthy.)
const HAS_NETWORK = process.env.DACS_LIVE_NETWORK === '1';
const HAS_MNEMONIC = !!process.env.DEMOS_MNEMONIC && HAS_NETWORK;
const skipIfOffline = HAS_NETWORK ? { skip: false } : { skip: 'set DACS_LIVE_NETWORK=1 to run live-network tests' };
const skipIfNoMnemonic = HAS_MNEMONIC ? { skip: false } : { skip: 'set DACS_LIVE_NETWORK=1 + DEMOS_MNEMONIC to run chain-write tests' };

test('DAHR fetch — dry-run mode produces a synthetic AttestationRef without anchoring', skipIfOffline, async () => {
  const result = await dahrFetch(undefined, 'https://api.gleif.org/api/v1/lei-records/HWUPKR0MPOU8FGXBT394', {
    skipAnchor: true,
    recipe: 'gleif-cbp:1',
    headers: { Accept: 'application/vnd.api+json' },
  });
  assert.equal(result.attestation.anchor.substrate, 'demos');
  assert.match(result.attestation.anchor.locator, /^stor-stub-/);
  // v0.2 honest-scope marker — see test/vectors/demos-bridge.test.ts for the full rationale
  assert.equal(result.attestation.type, 'dahr-stub:gleif-cbp:1');
  assert.match(result.attestation.contentHash, /^[0-9a-f]{64}$/);
  assert.equal(result.responseStatus, 200);
});

test('DAHR fetch — invalid LEI returns 404 but still produces an AttestationRef', skipIfOffline, async () => {
  const result = await dahrFetch(undefined, 'https://api.gleif.org/api/v1/lei-records/ZZZZZZZZZZZZZZZZZZZZ', {
    skipAnchor: true,
    recipe: 'gleif-cbp:1',
    headers: { Accept: 'application/vnd.api+json' },
  });
  assert.equal(result.responseStatus, 404);
  assert.match(result.attestation.contentHash, /^[0-9a-f]{64}$/);
});

test('LIVE — DAHR contentHash equals sha256 of the actual GLEIF response bytes', skipIfOffline, async () => {
  // Live-network counterpart to the deterministic unit test in
  // test/vectors/demos-bridge.test.ts — confirms the same invariant
  // holds against the real GLEIF API.
  const url = 'https://api.gleif.org/api/v1/lei-records/HWUPKR0MPOU8FGXBT394';
  const res = await fetch(url, { headers: { Accept: 'application/vnd.api+json' } });
  const bytes = new Uint8Array(await res.arrayBuffer());
  const expectedHash = sha256(bytes);
  const expectedHashHex = Array.from(expectedHash, (b) => b.toString(16).padStart(2, '0')).join('');

  const dahr = await dahrFetch(undefined, url, {
    skipAnchor: true,
    recipe: 'gleif-cbp:1',
    headers: { Accept: 'application/vnd.api+json' },
  });
  assert.equal(dahr.attestation.contentHash, expectedHashHex);
});

test('Demos connection — connect + getAddress returns a non-empty 0x address', skipIfNoMnemonic, async () => {
  const handle = await connectDemos(process.env.DEMOS_MNEMONIC!);
  assert.match(handle.address, /^0x[0-9a-fA-F]+$/);
  assert.ok(handle.address.length >= 42, 'address should be at least 42 chars (0x + 40 hex)');
});

test('DAHR fetch — live anchor (consumes DEM)', skipIfNoMnemonic, async () => {
  const handle = await connectDemos(process.env.DEMOS_MNEMONIC!);
  const result = await dahrFetch(handle, 'https://api.gleif.org/api/v1/lei-records/HWUPKR0MPOU8FGXBT394', {
    recipe: 'gleif-cbp:1',
    anchorProgramName: 'dacs2:gleif-test',
  });
  assert.match(result.attestation.anchor.locator, /^stor-[0-9a-f]/);
  assert.ok(result.anchor.txHash && result.anchor.txHash !== 'stub-no-broadcast', 'should have a real tx hash');
});
