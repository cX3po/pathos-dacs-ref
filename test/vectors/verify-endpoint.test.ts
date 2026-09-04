/**
 * src/live/verify-endpoint.mts — the verifier behind a d402 gate.
 *
 * No network: the d402 verifier is a fake and the bundle is verified offline unless a chain
 * reader is injected. Proves the challenge shape (resourceId bound to the exact body bytes), the
 * paid path (verdict + receipt, proof committed only after delivery), redelivery from the cache and
 * after eviction, cross-body reuse refused, malformed bodies refused before any challenge, a
 * server-side chain failure answering 503 with the proof retained, concurrent same-proof use billed
 * once, request-level downgrade ignored, free healthz/schemas, the 413 limit, forced offline, and
 * the config/dry-run CLI paths.
 */
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createServer, request as httpRequest } from 'node:http';
import { ed25519 } from '@noble/curves/ed25519';
import { emitAttestationBundleV1 } from '../../src/lib/emit-bundle-v1.js';
import type { AttestationBundleV1 } from '../../src/types/bundle.js';
import { createD402Service, amountToOs, type D402PaymentRequirement, type D402VerificationResult, type D402Verifier } from '../../src/adapters/demos/d402-service.js';
import { createD402ProofStore } from '../../src/live/d402-organ.mjs';
import { createVerifyEndpointHandler, readConfig, resourceForBody } from '../../src/live/verify-endpoint.mjs';
import { MAX_VERIFY_BODY_BYTES, handleVerifyRequest } from '../../src/lib/verify-http.js';

const RECIPIENT = '0x' + 'ab'.repeat(32);
const AMOUNT_OS = '100000000'; // 0.1 DEM
const HASH = `0x${'cd'.repeat(32)}`;

const hexOf = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const mk = (fill: number) => { const priv = new Uint8Array(32).fill(fill); return { priv, pubHex: hexOf(ed25519.getPublicKey(priv)) }; };
function makeBundle(jobId = 'verify-endpoint-test-0001'): AttestationBundleV1 {
  const buyer = mk(0x41), seller = mk(0x42);
  const unsigned: Omit<AttestationBundleV1, 'signatures'> = {
    bundleVersion: '1', jobId, outcome: 'completed', anchoredByRole: 'buyer',
    listingRef: { listingId: 'lst-fixture', version: 1, contentHash: 'cd'.repeat(32) },
    parties: [
      { role: 'buyer', bundleHash: 'aa'.repeat(32), primaryClaim: { scheme: 'cci', identifier: buyer.pubHex } },
      { role: 'seller', bundleHash: 'bb'.repeat(32), primaryClaim: { scheme: 'cci', identifier: seller.pubHex } },
    ],
    phaseSummary: [{ index: 0, kind: 'vet-credentials', outcome: 'ok' }],
    vetRecords: [], settlementEvidence: [], recipeRegistryVersion: 1, railRegistryVersion: 1, finalisedAt: 1735689600000,
  };
  return emitAttestationBundleV1(unsigned, [
    { party: { scheme: 'cci', identifier: buyer.pubHex }, privKey: buyer.priv },
    { party: { scheme: 'cci', identifier: seller.pubHex }, privKey: seller.priv },
  ]);
}

class FakeVerifier implements D402Verifier {
  calls = 0;
  memo = '';
  amount = AMOUNT_OS;
  to = RECIPIENT;
  error?: Error;
  async verify(txHash: string): Promise<D402VerificationResult> {
    this.calls += 1;
    if (this.error) throw this.error;
    return { valid: true, verified_from: 'payer-address', verified_to: this.to, verified_amount: this.amount, verified_memo: this.memo, timestamp: 1 } as D402VerificationResult;
  }
  validatePayment(v: D402VerificationResult, r: D402PaymentRequirement): boolean {
    if (!v.valid || v.verified_to !== r.recipient || v.verified_amount === undefined) return false;
    try { if (amountToOs(v.verified_amount) < amountToOs(r.amount)) return false; } catch { return false; }
    return (v.verified_memo ?? '').startsWith(`resourceId:${r.resourceId}`);
  }
}

function setup(opts: { offline?: boolean; fetchAnchoredImpl?: any; maxDelivered?: number } = {}) {
  const fake = new FakeVerifier();
  const committed = new Set<string>();
  const reserved = new Set<string>();
  const delivered = new Map<string, string>();
  const service = createD402Service({ recipient: RECIPIENT, rpcUrl: 'https://unused.invalid', verifier: fake, usedProofs: createD402ProofStore(committed, reserved) });
  const handler = createVerifyEndpointHandler({ service, amountOs: AMOUNT_OS, priceDem: '0.1', recipient: RECIPIENT, committed, reserved, delivered, maxDelivered: opts.maxDelivered, verify: { fetchAnchoredImpl: opts.fetchAnchoredImpl }, offline: opts.offline ?? true });
  const server = createServer((req, res) => { void handler(req, res).catch(() => { if (!res.headersSent) { res.writeHead(500); res.end(); } }); });
  return { fake, committed, reserved, delivered, server };
}

function call(port: number, method: string, path: string, body?: string, headers: Record<string, string> = {}): Promise<{ status: number; body: any }> {
  return new Promise((res, rej) => {
    const req = httpRequest({ host: '127.0.0.1', port, path, method, headers: { ...(body !== undefined ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } : {}), ...headers } }, (r) => {
      const chunks: Buffer[] = [];
      r.on('data', (c) => chunks.push(c));
      r.on('end', () => { const text = Buffer.concat(chunks).toString('utf8'); res({ status: r.statusCode ?? 0, body: text ? JSON.parse(text) : null }); });
    });
    req.on('error', rej);
    req.end(body);
  });
}

async function listen(server: ReturnType<typeof createServer>): Promise<number> {
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  return (server.address() as { port: number }).port;
}

test('resource id is bound to the exact body bytes', () => {
  const a = resourceForBody('{"bundle":{}}', AMOUNT_OS);
  const b = resourceForBody('{"bundle": {}}', AMOUNT_OS);
  assert.notEqual(a.resourceId, b.resourceId);
  assert.equal(a.resourceId, `verify:${createHash('sha256').update('{"bundle":{}}').digest('hex').slice(0, 16)}`);
  assert.equal(a.amount, AMOUNT_OS);
});

test('unpaid POST /verify answers 402 with the requirement and reason; nothing is verified', async () => {
  const { server, fake } = setup();
  const port = await listen(server);
  try {
    const body = JSON.stringify({ bundle: makeBundle(), offline: true });
    const r = await call(port, 'POST', '/verify', body);
    assert.equal(r.status, 402);
    assert.equal(r.body.recipient, RECIPIENT);
    assert.equal(r.body.amount, AMOUNT_OS);
    assert.equal(r.body.resourceId, resourceForBody(body, AMOUNT_OS).resourceId);
    assert.equal(r.body.reason, 'missing-proof');
    assert.equal(fake.calls, 0);
    const bad = await call(port, 'POST', '/verify', body, { 'X-Payment-Proof': 'nope' });
    assert.equal(bad.status, 402);
    assert.equal(bad.body.reason, 'malformed-proof');
    assert.equal(fake.calls, 0);
  } finally { server.close(); }
});

test('paid POST /verify returns the verdict with a receipt, commits the proof, and refuses a replay', async () => {
  const { server, fake, committed, reserved } = setup();
  const port = await listen(server);
  try {
    const body = JSON.stringify({ bundle: makeBundle(), offline: true });
    const resource = resourceForBody(body, AMOUNT_OS);
    fake.memo = `resourceId:${resource.resourceId} - DACS attestation-bundle verification`;
    const r = await call(port, 'POST', '/verify', body, { 'X-Payment-Proof': HASH });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.apiVersion, 'pathos-dacs-verifier:1');
    assert.equal(r.body.verdict.decision, 'pass');
    assert.equal(r.body.exitCode, 0);
    // the gate canonicalises the hash (lowercase, no 0x prefix)
    assert.deepEqual(r.body.receipt, { txHash: HASH.slice(2), from: 'payer-address', amountOs: AMOUNT_OS, resourceId: resource.resourceId });
    assert.equal(committed.size, 1);
    assert.equal(reserved.size, 0);
    // the same paid request again is redelivered, not billed again and not refused
    const again = await call(port, 'POST', '/verify', body, { 'X-Payment-Proof': HASH });
    assert.equal(again.status, 200);
    assert.equal(again.body.verdict.decision, 'pass');
    assert.equal(again.body.receipt.redelivered, true);
    assert.equal(committed.size, 1);
    // the same proof does not pay for a different body either (resourceId differs -> memo mismatch)
    const other = JSON.stringify({ bundle: makeBundle('other-job'), offline: true });
    const wrong = await call(port, 'POST', '/verify', other, { 'X-Payment-Proof': HASH });
    assert.equal(wrong.status, 402);
    assert.equal(wrong.body.reason, 'mismatch');
  } finally { server.close(); }
});

test('a paid request evicted from the redelivery cache is re-verified and served, never refused', async () => {
  const { server, fake, committed, delivered } = setup({ maxDelivered: 1 });
  const port = await listen(server);
  try {
    const first = JSON.stringify({ bundle: makeBundle('evict-1') });
    const second = JSON.stringify({ bundle: makeBundle('evict-2') });
    fake.memo = `resourceId:${resourceForBody(first, AMOUNT_OS).resourceId}`;
    assert.equal((await call(port, 'POST', '/verify', first, { 'X-Payment-Proof': HASH })).status, 200);
    fake.memo = `resourceId:${resourceForBody(second, AMOUNT_OS).resourceId}`;
    const otherProof = `0x${'ee'.repeat(32)}`;
    assert.equal((await call(port, 'POST', '/verify', second, { 'X-Payment-Proof': otherProof })).status, 200);
    assert.equal(delivered.size, 1);
    assert.equal(committed.size, 2);
    const again = await call(port, 'POST', '/verify', first, { 'X-Payment-Proof': HASH });
    assert.equal(again.status, 200);
    assert.equal(again.body.verdict.decision, 'pass');
    assert.equal(again.body.receipt.redelivered, true);
    assert.equal(again.body.receipt.reverified, true);
    assert.equal(committed.size, 2);
    assert.equal(fake.calls, 2);
  } finally { server.close(); }
});

test('an evicted re-verify during a server chain outage answers 503 with the proof retained, like the fresh path', async () => {
  let fail = false;
  const fetchAnchoredImpl = async () => { if (fail) throw new Error('simulated RPC outage'); return null; };
  const { server, fake, committed } = setup({ offline: false, fetchAnchoredImpl, maxDelivered: 1 });
  const port = await listen(server);
  try {
    const first = JSON.stringify({ bundle: makeBundle('evict-a') });
    const second = JSON.stringify({ bundle: makeBundle('evict-b') });
    fake.memo = `resourceId:${resourceForBody(first, AMOUNT_OS).resourceId}`;
    assert.equal((await call(port, 'POST', '/verify', first, { 'X-Payment-Proof': HASH })).status, 200);
    fake.memo = `resourceId:${resourceForBody(second, AMOUNT_OS).resourceId}`;
    assert.equal((await call(port, 'POST', '/verify', second, { 'X-Payment-Proof': `0x${'ee'.repeat(32)}` })).status, 200);
    fail = true;
    const during = await call(port, 'POST', '/verify', first, { 'X-Payment-Proof': HASH });
    assert.equal(during.status, 503);
    assert.equal(during.body.proofRetained, true);
    fail = false;
    const after = await call(port, 'POST', '/verify', first, { 'X-Payment-Proof': HASH });
    assert.equal(after.status, 200);
    assert.equal(after.body.receipt.reverified, true);
    assert.equal(committed.size, 2);
  } finally { server.close(); }
});

test('underpayment and verifier outage are 402 with reasons, never a verdict', async () => {
  const { server, fake } = setup();
  const port = await listen(server);
  try {
    const body = JSON.stringify({ bundle: makeBundle(), offline: true });
    const resource = resourceForBody(body, AMOUNT_OS);
    fake.memo = `resourceId:${resource.resourceId}`;
    fake.amount = '1';
    const under = await call(port, 'POST', '/verify', body, { 'X-Payment-Proof': HASH });
    assert.equal(under.status, 402);
    assert.equal(under.body.reason, 'mismatch');
    fake.amount = AMOUNT_OS;
    fake.error = new Error('rpc down');
    const out = await call(port, 'POST', '/verify', body, { 'X-Payment-Proof': `0x${'ef'.repeat(32)}` });
    assert.equal(out.status, 402);
    assert.equal(out.body.reason, 'unverifiable');
  } finally { server.close(); }
});

test('a malformed body is refused before any challenge: nobody is asked to pay for it', async () => {
  const { server, fake, committed, reserved } = setup();
  const port = await listen(server);
  try {
    for (const body of ['not json', '[1]', '{"bundle": 5}', JSON.stringify({ bundle: {}, offline: 'yes' }), JSON.stringify({ bundle: {}, rpc: 'x' })]) {
      const r = await call(port, 'POST', '/verify', body);
      assert.equal(r.status, 400, body);
      assert.equal(r.body.recipient, undefined);
    }
    assert.equal(fake.calls, 0);
    assert.equal(committed.size + reserved.size, 0);
  } finally { server.close(); }
});

test('a verifier outage on the server answers 503, keeps the proof usable, and a retry is then answered and billed once', async () => {
  let fail = true;
  const fetchAnchoredImpl = async () => { if (fail) throw new Error('simulated RPC outage'); return null; };
  const { server, fake, committed, reserved } = setup({ offline: false, fetchAnchoredImpl });
  const port = await listen(server);
  try {
    const body = JSON.stringify({ bundle: makeBundle() });
    fake.memo = `resourceId:${resourceForBody(body, AMOUNT_OS).resourceId}`;
    const r = await call(port, 'POST', '/verify', body, { 'X-Payment-Proof': HASH });
    assert.equal(r.status, 503);
    assert.equal(r.body.proofRetained, true);
    assert.equal(committed.size, 0);
    assert.equal(reserved.size, 0);
    fail = false;
    const again = await call(port, 'POST', '/verify', body, { 'X-Payment-Proof': HASH });
    assert.equal(again.status, 200);
    // the chain answered "absent" this time: an unanchored bundle is indeterminate, and that IS an answer
    assert.equal(again.body.verdict.decision, 'indeterminate');
    assert.equal(again.body.receipt.redelivered, undefined);
    assert.equal(committed.size, 1);
  } finally { server.close(); }
});

test('two concurrent requests with the same proof: exactly one is billed and answered fresh', async () => {
  const { server, fake, committed } = setup();
  const port = await listen(server);
  try {
    const body = JSON.stringify({ bundle: makeBundle() });
    fake.memo = `resourceId:${resourceForBody(body, AMOUNT_OS).resourceId}`;
    const results = await Promise.all([1, 2, 3].map(() => call(port, 'POST', '/verify', body, { 'X-Payment-Proof': HASH })));
    const fresh = results.filter((r) => r.status === 200 && !r.body.receipt.redelivered);
    const refusedOrRedelivered = results.filter((r) => (r.status === 402 && r.body.reason === 'replayed') || (r.status === 200 && r.body.receipt.redelivered));
    assert.equal(fresh.length, 1);
    assert.equal(fresh.length + refusedOrRedelivered.length, 3);
    assert.equal(committed.size, 1);
    assert.equal(fake.calls, 1);
  } finally { server.close(); }
});

test('a paid caller cannot downgrade the verification: request-level offline and requireSignatures are ignored', async () => {
  const calls: string[] = [];
  const fetchAnchoredImpl = async (_rpc: string, addr: string) => { calls.push(addr); return null; };
  const { server, fake } = setup({ offline: false, fetchAnchoredImpl });
  const port = await listen(server);
  try {
    const body = JSON.stringify({ bundle: makeBundle(), offline: true, requireSignatures: false });
    fake.memo = `resourceId:${resourceForBody(body, AMOUNT_OS).resourceId}`;
    const r = await call(port, 'POST', '/verify', body, { 'X-Payment-Proof': HASH });
    assert.equal(r.status, 200);
    assert.ok(calls.length > 0, 'the chain must have been consulted despite offline:true in the request');
    assert.equal(r.body.verdict.decision, 'indeterminate');
    assert.ok(!r.body.verdict.steps.some((s: any) => s.step === 'two-sided-anchoring' && s.outcome === 'skipped'));
  } finally { server.close(); }
});

test('healthz and schemas are free; other paths 404/405; oversized bodies 413 before any gate', async () => {
  const { server, fake } = setup();
  const port = await listen(server);
  try {
    const h = await call(port, 'GET', '/healthz');
    assert.equal(h.status, 200);
    assert.equal(h.body.priceDem, '0.1');
    assert.equal(h.body.recipient, RECIPIENT);
    assert.equal(h.body.apiVersion, 'pathos-dacs-verifier:1');
    const s = await call(port, 'GET', '/schemas/verify-verdict.json');
    assert.equal(s.status, 200);
    assert.equal(s.body.title, 'dacs-verifier result (pathos-dacs-verifier:1)');
    assert.equal((await call(port, 'GET', '/verify')).status, 405);
    assert.equal((await call(port, 'GET', '/nope')).status, 404);
    const big = await call(port, 'POST', '/verify', '{"bundle":{"x":"' + 'a'.repeat(MAX_VERIFY_BODY_BYTES + 10) + '"}}');
    assert.equal(big.status, 413);
    assert.equal(fake.calls, 0);
  } finally { server.close(); }
});

test('forced offline deployment skips the anchor lookup even when the request does not ask for it', async () => {
  const { server, fake } = setup({ offline: true });
  const port = await listen(server);
  try {
    const body = JSON.stringify({ bundle: makeBundle() });
    fake.memo = `resourceId:${resourceForBody(body, AMOUNT_OS).resourceId}`;
    const r = await call(port, 'POST', '/verify', body, { 'X-Payment-Proof': HASH });
    assert.equal(r.status, 200);
    assert.equal(r.body.verdict.decision, 'pass');
    assert.ok(r.body.verdict.steps.some((s: any) => s.step === 'two-sided-anchoring' && s.outcome === 'skipped'));
  } finally { server.close(); }
});

test('readConfig validates the environment and --dry-run prints a challenge without a chain', () => {
  assert.deepEqual(readConfig({}), { error: 'VERIFY_RECIPIENT is required' });
  assert.ok('error' in readConfig({ VERIFY_RECIPIENT: RECIPIENT, VERIFY_PRICE_DEM: 'abc' }));
  assert.ok('error' in readConfig({ VERIFY_RECIPIENT: RECIPIENT, VERIFY_PRICE_DEM: '0' }));
  assert.ok('error' in readConfig({ VERIFY_RECIPIENT: 'merchant', VERIFY_PRICE_DEM: '0.1' }));
  assert.ok('error' in readConfig({ VERIFY_RECIPIENT: RECIPIENT, VERIFY_PORT: '70000' }));
  const ok = readConfig({ VERIFY_RECIPIENT: RECIPIENT, VERIFY_PRICE_DEM: '0.25' });
  assert.ok(!('error' in ok) && ok.amountOs === '250000000' && ok.port === 8403 && ok.host === '127.0.0.1');
  const r = spawnSync(process.execPath, ['--import', 'tsx', 'src/live/verify-endpoint.mts', '--dry-run'], { encoding: 'utf8', env: { ...process.env, VERIFY_RECIPIENT: RECIPIENT, VERIFY_PRICE_DEM: '0.1' } });
  assert.equal(r.status, 0, r.stderr);
  const challenge = JSON.parse(r.stdout);
  assert.equal(challenge.recipient, RECIPIENT);
  assert.equal(challenge.amount, AMOUNT_OS);
  assert.match(challenge.resourceId, /^verify:[0-9a-f]{16}$/);
  const missing = spawnSync(process.execPath, ['--import', 'tsx', 'src/live/verify-endpoint.mts', '--dry-run'], { encoding: 'utf8', env: { ...process.env, VERIFY_RECIPIENT: '' } });
  assert.equal(missing.status, 2);
});

test('a payment to the wrong recipient is refused through the handler; an overpayment is accepted', async () => {
  const { server, fake, committed } = setup();
  const port = await listen(server);
  try {
    const body = JSON.stringify({ bundle: makeBundle(), offline: true });
    fake.memo = `resourceId:${resourceForBody(body, AMOUNT_OS).resourceId}`;
    fake.to = '0x' + 'ef'.repeat(32);
    const wrong = await call(port, 'POST', '/verify', body, { 'X-Payment-Proof': HASH });
    assert.equal(wrong.status, 402);
    assert.equal(wrong.body.reason, 'mismatch');
    assert.equal(committed.size, 0);
    fake.to = RECIPIENT;
    fake.amount = '250000000'; // 0.25 DEM against a 0.1 DEM price
    const over = await call(port, 'POST', '/verify', body, { 'X-Payment-Proof': HASH });
    assert.equal(over.status, 200, JSON.stringify(over.body));
    assert.equal(over.body.receipt.amountOs, '250000000');
    assert.equal(committed.size, 1);
  } finally { server.close(); }
});

test('redelivery matches every spelling the gate accepts; spellings it does not accept are refused as malformed before any charge', async () => {
  const { server, fake, committed } = setup();
  const port = await listen(server);
  try {
    const body = JSON.stringify({ bundle: makeBundle(), offline: true });
    fake.memo = `resourceId:${resourceForBody(body, AMOUNT_OS).resourceId}`;
    const first = await call(port, 'POST', '/verify', body, { 'X-Payment-Proof': HASH });
    assert.equal(first.status, 200);
    // the gate accepts an optional lower-case 0x prefix and either hex case, and HTTP header parsing
    // strips surrounding whitespace; every accepted spelling maps to one canonical key
    for (const spelling of [HASH.slice(2), `0x${HASH.slice(2).toUpperCase()}`, HASH.slice(2).toUpperCase(), ` ${HASH} `]) {
      const again = await call(port, 'POST', '/verify', body, { 'X-Payment-Proof': spelling });
      assert.equal(again.status, 200, spelling);
      assert.equal(again.body.receipt.redelivered, true, spelling);
    }
    // an upper-case 0X prefix is not a proof the gate parses: 402 malformed-proof, nothing verified, nothing charged
    const before = fake.calls;
    for (const spelling of [HASH.toUpperCase()]) {
      const bad = await call(port, 'POST', '/verify', body, { 'X-Payment-Proof': spelling });
      assert.equal(bad.status, 402, spelling);
      assert.equal(bad.body.reason, 'malformed-proof', spelling);
    }
    assert.equal(fake.calls, before);
    assert.equal(committed.size, 1);
  } finally { server.close(); }
});

test('a genuine verdict carries no `incomplete` flag: the outage signal is the handler flag, never a step name', async () => {
  // Every malformed or unanchored bundle is a verdict (indeterminate/fail), not an outage; the flag is
  // set only when verifyDocument itself throws, which no request body can provoke. The endpoint keys
  // its 503 on that flag (plus its own RPC watch), so a verdict is always delivered to a paid caller.
  for (const bundle of [makeBundle(), {}, { bundleVersion: '1', jobId: null, parties: null, signatures: null }]) {
    const r = await handleVerifyRequest(JSON.stringify({ bundle, offline: true }), {});
    assert.equal(r.status, 200);
    assert.equal((r as { incomplete?: string }).incomplete, undefined);
  }
});
