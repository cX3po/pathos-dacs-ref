/**
 * delivery-recovery-fixture — the verify endpoint's durable delivery, offline, in one process.
 *
 * Pays once for a verification, then proves the original signed payload comes back unchanged (a) after a restart of the
 * handler over the same durable file, (b) after the redelivery cache evicted it, (c) for two concurrent duplicates of one
 * paid request (one verifier call, one payment), and (d) that the same proof presented for different bytes is refused
 * by the payment binding. No node, no credential, no DEM. Prints one JSON result; exit 0 only when every step passes.
 * Run: node --import tsx src/live/delivery-recovery-fixture.mts --json
 */
import { createServer, request as httpRequest } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ed25519 } from '@noble/curves/ed25519';
import { amountToOs, createD402Service, type D402PaymentRequirement, type D402VerificationResult, type D402Verifier } from '../adapters/demos/d402-service.js';
import { createD402ProofStore } from './d402-organ.mjs';
import { createVerifyEndpointHandler, resourceForBody, ENDPOINT_NAME, ENDPOINT_VERSION } from './verify-endpoint.mjs';
import { createFileDeliveryStore, SCOPE_MISMATCH, type DeliveryScope } from './delivery-store.js';
import { VERIFIER_API_VERSION } from '../lib/verify-document.js';
import { emitAttestationBundleV1 } from '../lib/emit-bundle-v1.js';
import type { AttestationBundleV1 } from '../types/bundle.js';

const RECIPIENT = '0x' + 'ab'.repeat(32);
const AMOUNT_OS = '100000000';
const HASH = `0x${'cd'.repeat(32)}`;
const hexOf = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const mk = (fill: number) => { const priv = new Uint8Array(32).fill(fill); return { priv, pubHex: hexOf(ed25519.getPublicKey(priv)) }; };

interface Step { step: string; outcome: 'pass' | 'fail'; detail: string }
const steps: Step[] = [];
const step = (name: string, ok: boolean, detail: string) => { steps.push({ step: name, outcome: ok ? 'pass' : 'fail', detail }); return ok; };

function makeBundle(jobId: string): AttestationBundleV1 {
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
  calls = 0; memo = '';
  /** When set, verify() waits for this barrier: the harness holds payment verification to prove coalescing. */
  barrier: Promise<void> | null = null;
  async verify(): Promise<D402VerificationResult> { this.calls += 1; if (this.barrier) await this.barrier; return { valid: true, verified_from: 'payer-address', verified_to: RECIPIENT, verified_amount: AMOUNT_OS, verified_memo: this.memo, timestamp: 1 } as D402VerificationResult; }
  validatePayment(v: D402VerificationResult, r: D402PaymentRequirement): boolean {
    if (!v.valid || v.verified_to !== r.recipient || v.verified_amount === undefined) return false;
    try { if (amountToOs(v.verified_amount) < amountToOs(r.amount)) return false; } catch { return false; }
    return (v.verified_memo ?? '').startsWith(`resourceId:${r.resourceId}`);
  }
}

const SELLER_KEY = new Uint8Array(32).fill(0x42);
const SELLER = { name: 'PATH-OS durable-delivery fixture', privKey: SELLER_KEY, pubKeyHex: hexOf(ed25519.getPublicKey(SELLER_KEY)), networkId: 'demos:testnet', networkMode: 'rehearsal' as const };
const scopeFor = (override: Partial<DeliveryScope> = {}): DeliveryScope => ({ recipient: RECIPIENT, sellerPubKeyHex: SELLER.pubKeyHex, networkId: SELLER.networkId, amountOs: AMOUNT_OS, offline: true, implementationVersion: `${ENDPOINT_NAME}@${ENDPOINT_VERSION}/${VERIFIER_API_VERSION}`, ...override });

function endpoint(storePath: string, fake: FakeVerifier, maxDelivered?: number, scope: DeliveryScope = scopeFor()) {
  const committed = new Set<string>(); const reserved = new Set<string>(); const delivered = new Map<string, string>();
  const service = createD402Service({ recipient: RECIPIENT, rpcUrl: 'https://unused.invalid', verifier: fake, usedProofs: createD402ProofStore(committed, reserved) });
  const store = createFileDeliveryStore(storePath, scope);
  const handler = createVerifyEndpointHandler({ seller: SELLER, service, amountOs: AMOUNT_OS, priceDem: '0.1', recipient: RECIPIENT, committed, reserved, delivered, maxDelivered, offline: true, store, waitMs: 5_000 });
  const server = createServer((req, res) => { void handler(req, res).catch(() => { if (!res.headersSent) { res.writeHead(500); res.end(); } }); });
  return { server, committed, reserved, handler, store };
}

function call(port: number, body: string, headers: Record<string, string> = {}): Promise<{ status: number; text: string; body: any }> {
  return new Promise((res, rej) => {
    const req = httpRequest({ host: '127.0.0.1', port, path: '/verify', method: 'POST', headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body), ...headers } }, (r) => {
      const chunks: Buffer[] = []; r.on('data', (c) => chunks.push(c));
      r.on('end', () => { const text = Buffer.concat(chunks).toString('utf8'); res({ status: r.statusCode ?? 0, text, body: text ? JSON.parse(text) : null }); });
    });
    req.on('error', rej); req.end(body);
  });
}
const listen = (server: ReturnType<typeof createServer>) => new Promise<number>((r) => server.listen(0, '127.0.0.1', () => r((server.address() as { port: number }).port)));
const close = (server: ReturnType<typeof createServer>) => new Promise<void>((r) => server.close(() => r()));
const strip = (b: any) => { const { receipt, ...rest } = b; const { redelivered, ...plain } = receipt ?? {}; return JSON.stringify({ ...rest, receipt: plain }); };

async function main(): Promise<number> {
  const json = process.argv.includes('--json');
  const dir = mkdtempSync(join(tmpdir(), 'delivery-recovery-'));
  const storePath = join(dir, 'deliveries.jsonl');
  const fake = new FakeVerifier();
  let payments = 0;
  try {
    const body = JSON.stringify({ bundle: makeBundle('delivery-recovery-0001'), offline: true });
    const resource = resourceForBody(body, AMOUNT_OS);
    fake.memo = `resourceId:${resource.resourceId} - DACS attestation-bundle verification`;
    // (0) pay once
    let ep = endpoint(storePath, fake);
    let port = await listen(ep.server);
    const first = await call(port, body, { 'X-Payment-Proof': HASH }); payments += 1;
    const original = first.text;
    step('paid', first.status === 200 && Boolean(first.body?.deliveryReceipt) && fake.calls === 1, `${first.status} verifier calls ${fake.calls}`);
    // (a) restart over the same store
    await close(ep.server);
    ep = endpoint(storePath, fake); port = await listen(ep.server);
    const afterRestart = await call(port, body, { 'X-Payment-Proof': HASH });
    step('restart-redelivers-original', afterRestart.status === 200 && afterRestart.body?.receipt?.redelivered === true && strip(afterRestart.body) === strip(JSON.parse(original)) && JSON.stringify(afterRestart.body.deliveryReceipt?.signature) === JSON.stringify(first.body.deliveryReceipt?.signature) && fake.calls === 1 && ep.committed.size === 1,
      `${afterRestart.status} redelivered=${afterRestart.body?.receipt?.redelivered} same signed payload=${strip(afterRestart.body) === strip(JSON.parse(original))} sig-equal=${JSON.stringify(afterRestart.body.deliveryReceipt?.signature) === JSON.stringify(first.body.deliveryReceipt?.signature)} receipt-keys=${Object.keys(first.body.deliveryReceipt ?? {}).join(',')} committed=${ep.committed.size} verifier calls ${fake.calls}`);
    await close(ep.server);
    // (b) eviction: cache bound 1, a second paid request evicts the first; the first must come back from the store
    const fake2 = new FakeVerifier();
    ep = endpoint(storePath, fake2, 1); port = await listen(ep.server);
    const body2 = JSON.stringify({ bundle: makeBundle('delivery-recovery-0002'), offline: true });
    const resource2 = resourceForBody(body2, AMOUNT_OS);
    fake2.memo = `resourceId:${resource2.resourceId} - DACS attestation-bundle verification`;
    const HASH2 = `0x${'ef'.repeat(32)}`;
    const second = await call(port, body2, { 'X-Payment-Proof': HASH2 }); payments += 1;
    const evicted = await call(port, body, { 'X-Payment-Proof': HASH });
    step('eviction-redelivers-original', second.status === 200 && evicted.status === 200 && evicted.body?.receipt?.redelivered === true && evicted.body?.receipt?.reverified !== true && strip(evicted.body) === strip(JSON.parse(original)) && fake2.calls === 1,
      `second ${second.status}; evicted first ${evicted.status} redelivered=${evicted.body?.receipt?.redelivered} reverified=${evicted.body?.receipt?.reverified ?? false} verifier calls ${fake2.calls}`);
    await close(ep.server);
    // (c) concurrent duplicates of one new paid request, with a deterministic barrier: the first request is held
    //     inside payment verification, the duplicate arrives, stays pending, then both complete on one verifier call
    const fake3 = new FakeVerifier();
    ep = endpoint(join(dir, 'concurrent.jsonl'), fake3); port = await listen(ep.server);
    const body3 = JSON.stringify({ bundle: makeBundle('delivery-recovery-0003'), offline: true });
    const resource3 = resourceForBody(body3, AMOUNT_OS);
    fake3.memo = `resourceId:${resource3.resourceId} - DACS attestation-bundle verification`;
    const HASH3 = `0x${'12'.repeat(32)}`;
    let release: () => void = () => {};
    fake3.barrier = new Promise<void>((r) => { release = r; });
    const p1 = call(port, body3, { 'X-Payment-Proof': HASH3 });
    await new Promise((r) => setTimeout(r, 150));
    const heldAtVerifier = fake3.calls === 1;
    let secondDone = false;
    const p2 = call(port, body3, { 'X-Payment-Proof': HASH3 }).then((r) => { secondDone = true; return r; });
    await new Promise((r) => setTimeout(r, 150));
    const secondPending = !secondDone;
    release();
    const [c1, c2] = await Promise.all([p1, p2]); payments += 1;
    const oneRedelivered = [c1, c2].filter((c) => c.body?.receipt?.redelivered === true).length === 1;
    step('concurrent-duplicate-redelivers', heldAtVerifier && secondPending && c1.status === 200 && c2.status === 200 && strip(c1.body) === strip(c2.body) && oneRedelivered && fake3.calls === 1,
      `held at verifier=${heldAtVerifier} duplicate pending=${secondPending} ${c1.status}/${c2.status} identical=${strip(c1.body) === strip(c2.body)} one redelivered=${oneRedelivered} verifier calls ${fake3.calls}`);
    // (d) the proof bought for body3 presented for different bytes is refused by the payment binding
    const body4 = JSON.stringify({ bundle: makeBundle('delivery-recovery-0004'), offline: true });
    const cross = await call(port, body4, { 'X-Payment-Proof': HASH3 });
    step('cross-request-proof-refused', cross.status === 402 && cross.body?.reason === 'mismatch', `${cross.status} ${cross.body?.reason}`);
    await close(ep.server);
    // (e) a buyer that disconnects while its payment is being verified leaves no durable record, no committed proof,
    //     and no stuck reservation (the proof can pay for a retry)
    const fake5 = new FakeVerifier();
    const ep5 = endpoint(join(dir, 'disconnected.jsonl'), fake5);
    const port5 = await listen(ep5.server);
    const body5 = JSON.stringify({ bundle: makeBundle('delivery-recovery-0005'), offline: true });
    fake5.memo = `resourceId:${resourceForBody(body5, AMOUNT_OS).resourceId} - DACS attestation-bundle verification`;
    const HASH5 = `0x${'34'.repeat(32)}`;
    let release5: () => void = () => {};
    fake5.barrier = new Promise<void>((r) => { release5 = r; });
    const req5 = httpRequest({ host: '127.0.0.1', port: port5, path: '/verify', method: 'POST', headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body5), 'X-Payment-Proof': HASH5 } });
    req5.on('error', () => { /* the client went away on purpose */ });
    req5.end(body5);
    await new Promise((r) => setTimeout(r, 150));
    const heldAtVerifier5 = fake5.calls === 1;
    req5.destroy(); // client disconnects before any response
    await new Promise((r) => setTimeout(r, 100));
    release5();
    await new Promise((r) => setTimeout(r, 300));
    const store5 = createFileDeliveryStore(join(dir, 'disconnected.jsonl'), scopeFor());
    const keys5 = store5.load().keys.length;
    step('disconnected-buyer-not-recorded', heldAtVerifier5 && keys5 === 0 && ep5.committed.size === 0 && ep5.reserved.size === 0, `held=${heldAtVerifier5} store keys=${keys5} committed=${ep5.committed.size} reserved after disconnect=${ep5.reserved.size}`);
    await close(ep5.server);
    // (f) a store written under another deployment scope is refused at startup
    let scopeRefused = '';
    try { endpoint(storePath, new FakeVerifier(), undefined, scopeFor({ recipient: '0x' + 'ff'.repeat(32) })); } catch (e) { scopeRefused = e instanceof Error ? e.message : String(e); }
    step('scope-mismatch-refused', scopeRefused === SCOPE_MISMATCH, scopeRefused || 'no refusal');
  } finally { rmSync(dir, { recursive: true, force: true }); }
  const rollup = steps.every((s) => s.outcome === 'pass') ? 'PASS' : 'FAIL';
  const out = { harness: 'delivery-recovery-fixture:0.1', mode: 'offline-fixture', rollup, payments, steps };
  process.stdout.write((json ? '' : `${rollup} delivery-recovery-fixture\n`) + JSON.stringify(out) + '\n');
  return rollup === 'PASS' ? 0 : 1;
}

process.exitCode = await main();
