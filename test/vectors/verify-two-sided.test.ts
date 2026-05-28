/**
 * DACS-5 verifier — two-sided anchoring tests (Codex M2 round-3 #4)
 *
 * Covers:
 *   - Inline counterpartyBundle: matching deal → pass
 *   - Inline counterpartyBundle: jobId mismatch → fail
 *   - Inline counterpartyBundle: cross-party identifier mismatch → fail
 *   - Inline counterpartyBundle: scheme mismatch → fail (Codex #2)
 *   - Inline counterpartyBundle: state mismatch → fail (Codex #1)
 *   - Inline counterpartyBundle: same role on both sides → fail
 *
 * No network. Each test crafts both buyer + seller bundles in-memory.
 */

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import type { AttestationBundle } from '../../src/types/index.js';
import { verifyBundle, bytesToHex } from '../../src/lib/verify-bundle.js';
import { sign, generateKeypair } from '../../src/lib/sign.js';
import { DOMAIN_SEPARATORS } from '../../src/domain-sep.js';
import { jcsCanonical, jcsHash } from '../../src/jcs.js';

interface PartyBundle {
  bundle: AttestationBundle;
  privKey: Uint8Array;
  pubKey: Uint8Array;
}

function makeBundle(opts: {
  jobId: string;
  role: 'buyer' | 'seller';
  selfPubKey: Uint8Array;
  selfPrivKey: Uint8Array;
  counterpartyClaim: { scheme: 'cci'; identifier: string };
  state?: AttestationBundle['state'];
}): AttestationBundle {
  const selfHex = bytesToHex(opts.selfPubKey);
  const unsigned: AttestationBundle = {
    v: 'dacs-5-bundle:0.1',
    jobId: opts.jobId,
    role: opts.role,
    party: { v: 'dacs-1:0.1', primary: { scheme: 'cci', identifier: selfHex }, claims: [], issuedAt: '2026-05-28T00:00:00Z', presentation: { kind: 'siwd' } },
    counterparty: { primary: opts.counterpartyClaim },
    state: opts.state ?? 'completed',
    phases: [],
    finalisedAt: '2026-05-28T01:00:00Z',
  };
  const canonical = jcsCanonical(unsigned);
  const bundleHash = jcsHash(unsigned);
  const sig = sign(DOMAIN_SEPARATORS.BUNDLE_DACS5, canonical, opts.selfPrivKey, bundleHash);
  return { ...unsigned, signature: Buffer.from(sig).toString('base64') };
}

/** Build a matched buyer + seller pair for the same deal. */
function makePair(jobId: string): { buyer: PartyBundle; seller: PartyBundle } {
  const buyerKeys = generateKeypair();
  const sellerKeys = generateKeypair();
  const buyer = makeBundle({
    jobId, role: 'buyer',
    selfPubKey: buyerKeys.pubKey, selfPrivKey: buyerKeys.privKey,
    counterpartyClaim: { scheme: 'cci', identifier: bytesToHex(sellerKeys.pubKey) },
  });
  const seller = makeBundle({
    jobId, role: 'seller',
    selfPubKey: sellerKeys.pubKey, selfPrivKey: sellerKeys.privKey,
    counterpartyClaim: { scheme: 'cci', identifier: bytesToHex(buyerKeys.pubKey) },
  });
  return {
    buyer: { bundle: buyer, privKey: buyerKeys.privKey, pubKey: buyerKeys.pubKey },
    seller: { bundle: seller, privKey: sellerKeys.privKey, pubKey: sellerKeys.pubKey },
  };
}

test('inline counterparty: matching deal → pass', async () => {
  const { buyer, seller } = makePair('two-sided-001');
  const verdict = await verifyBundle(buyer.bundle, { counterpartyBundle: seller.bundle, skipTwoSidedLookup: false });
  // Need to NOT skip two-sided lookup, but ALSO use counterpartyBundle path → set skipTwoSidedLookup: false but supply counterparty
  // The current code routes through counterparty path when set; verify pass.
  assert.equal(verdict.decision, 'pass', JSON.stringify(verdict.steps, null, 2));
});

test('inline counterparty: jobId mismatch → fail', async () => {
  const { buyer } = makePair('deal-A');
  const { seller: otherSeller } = makePair('deal-B');
  const verdict = await verifyBundle(buyer.bundle, { counterpartyBundle: otherSeller.bundle });
  assert.equal(verdict.decision, 'fail');
});

test('inline counterparty: same role → fail', async () => {
  const { buyer } = makePair('deal-C');
  const { buyer: otherBuyer } = makePair('deal-C');
  // Note: jobIds happen to match by construction (both 'deal-C') but roles are both 'buyer'
  const verdict = await verifyBundle(buyer.bundle, { counterpartyBundle: otherBuyer.bundle });
  assert.equal(verdict.decision, 'fail');
});

test('inline counterparty: cross-party identifier mismatch → fail', async () => {
  const { buyer } = makePair('deal-D');
  // Build a seller bundle that points at a DIFFERENT buyer (random keys, not the real buyer)
  const sellerKeys = generateKeypair();
  const wrongBuyerKeys = generateKeypair();
  const wrongSeller = makeBundle({
    jobId: buyer.bundle.jobId,
    role: 'seller',
    selfPubKey: sellerKeys.pubKey, selfPrivKey: sellerKeys.privKey,
    counterpartyClaim: { scheme: 'cci', identifier: bytesToHex(wrongBuyerKeys.pubKey) },
  });
  const verdict = await verifyBundle(buyer.bundle, { counterpartyBundle: wrongSeller });
  assert.equal(verdict.decision, 'fail');
});

test('Codex M2 round-3 #2: inline counterparty with WRONG SCHEME (cci vs erc8004) → fail (properly signed)', async () => {
  const { buyer } = makePair('deal-E');
  const sellerKeys = generateKeypair();
  // Build a counterparty that references the buyer with wrong scheme — and SIGN it correctly
  // so signature-verify passes and the scheme check is the actual reject reason.
  const wrongSchemeUnsigned: AttestationBundle = {
    v: 'dacs-5-bundle:0.1',
    jobId: buyer.bundle.jobId,
    role: 'seller',
    party: { v: 'dacs-1:0.1', primary: { scheme: 'cci', identifier: bytesToHex(sellerKeys.pubKey) }, claims: [], issuedAt: '2026-05-28T00:00:00Z', presentation: { kind: 'siwd' } },
    counterparty: { primary: { scheme: 'erc8004', identifier: buyer.bundle.party.primary.identifier } }, // wrong scheme
    state: 'completed', phases: [], finalisedAt: '2026-05-28T01:00:00Z',
  };
  const canonical = jcsCanonical(wrongSchemeUnsigned);
  const bundleHash = jcsHash(wrongSchemeUnsigned);
  const sig = sign(DOMAIN_SEPARATORS.BUNDLE_DACS5, canonical, sellerKeys.privKey, bundleHash);
  const wrongSchemeSeller: AttestationBundle = { ...wrongSchemeUnsigned, signature: Buffer.from(sig).toString('base64') };
  const verdict = await verifyBundle(buyer.bundle, { counterpartyBundle: wrongSchemeSeller });
  assert.equal(verdict.decision, 'fail',
    `scheme mismatch MUST fail; got verdict=${verdict.decision} steps=${JSON.stringify(verdict.steps.map(s => `${s.outcome}: ${s.step}`))}`);
  // Confirm the reason was scheme/identifier, not signature
  const twoSidedStep = verdict.steps.find(s => s.step === 'two-sided-anchoring');
  assert.ok(twoSidedStep?.detail.includes('cross-party') || twoSidedStep?.detail.includes('different deal'),
    `expected scheme/claim-mismatch reason; got: ${twoSidedStep?.detail}`);
});

test('Codex M2 round-3 #1: inline counterparty with state mismatch → fail (properly re-signed)', async () => {
  const { buyer, seller } = makePair('deal-F');
  // Build a state-mutated seller and SIGN it correctly so signature-verify passes
  // and the state check is the actual reject reason.
  const sellerKeys = (() => { const k = generateKeypair(); return k; })();
  // Rebuild seller with same identities as the makePair, but different state, signed
  const buyerSelfHex = buyer.bundle.party.primary.identifier;
  const sellerPubKey = hexToBytesFromHex(seller.bundle.party.primary.identifier);
  void sellerPubKey;
  void sellerKeys;
  const stateMutatedUnsigned: AttestationBundle = {
    ...seller.bundle,
    signature: undefined,
    state: 'aborted-by-seller',
  };
  // We need the seller's privKey to re-sign. Since makePair generated it ephemerally,
  // we reconstruct using the keys we have stored on the seller PartyBundle.
  const canonical = jcsCanonical(stateMutatedUnsigned);
  const bundleHash = jcsHash(stateMutatedUnsigned);
  const sig = sign(DOMAIN_SEPARATORS.BUNDLE_DACS5, canonical, seller.privKey, bundleHash);
  const stateMutated: AttestationBundle = { ...stateMutatedUnsigned, signature: Buffer.from(sig).toString('base64') };
  void buyerSelfHex;
  const verdict = await verifyBundle(buyer.bundle, { counterpartyBundle: stateMutated });
  assert.equal(verdict.decision, 'fail',
    `state mismatch MUST fail; got verdict=${verdict.decision} steps=${JSON.stringify(verdict.steps.map(s => `${s.outcome}: ${s.step}`))}`);
  const twoSidedStep = verdict.steps.find(s => s.step === 'two-sided-anchoring');
  assert.ok(twoSidedStep?.detail.includes('state mismatch'),
    `expected state-mismatch reason; got: ${twoSidedStep?.detail}`);
});

function hexToBytesFromHex(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

test('Codex M2 round-4 #2: counterparty bundle with tampered signature → fail', async () => {
  const { buyer, seller } = makePair('deal-G');
  // Tamper with seller's signature
  const sigBytes = Buffer.from(seller.bundle.signature!, 'base64');
  sigBytes[0] = sigBytes[0]! ^ 0xff;
  const tamperedSeller: AttestationBundle = { ...seller.bundle, signature: sigBytes.toString('base64') };
  const verdict = await verifyBundle(buyer.bundle, { counterpartyBundle: tamperedSeller });
  assert.equal(verdict.decision, 'fail', 'counterparty bundle with bad signature MUST fail even when relational checks would otherwise pass');
});

test('Codex M2 round-4 #2: counterparty bundle with NO signature → fail', async () => {
  const { buyer, seller } = makePair('deal-H');
  const unsignedSeller: AttestationBundle = { ...seller.bundle, signature: undefined };
  const verdict = await verifyBundle(buyer.bundle, { counterpartyBundle: unsignedSeller });
  assert.equal(verdict.decision, 'fail', 'unsigned counterparty bundle MUST fail');
});

/**
 * Build a mocked fetchAnchored that serves a fixed map of {storageAddress → FetchResult}.
 * Anchors not in the map return null (absent). Throws raise as "error" status.
 */
function makeMockFetch(map: Map<string, { data: string }>): typeof import('../../src/demos/storage.js').fetchAnchored {
  return async (_rpc: string, addr: string) => {
    const hit = map.get(addr);
    if (!hit) return null;
    return {
      storageAddress: addr,
      owner: '0xowner',
      data: hit.data,
      sizeBytes: hit.data.length,
      createdAt: '2026-05-28T00:00:00Z',
    };
  };
}

test('Codex M2 round-5 #2: chain-fetched buyer anchor with TAMPERED signature → fail', async () => {
  const jobId = 'chain-tampered-001';
  const { buyer, seller } = makePair(jobId);
  // Compute the deterministic anchor addresses
  const { computeAnchorPair } = await import('../../src/lib/verify-bundle.js');
  const pair = computeAnchorPair(jobId);

  // Tamper buyer-anchor bundle's signature
  const sigBytes = Buffer.from(buyer.bundle.signature!, 'base64');
  sigBytes[0] = sigBytes[0]! ^ 0xff;
  const tamperedBuyer: AttestationBundle = { ...buyer.bundle, signature: sigBytes.toString('base64') };

  const map = new Map([
    [pair.buyer, { data: JSON.stringify(tamperedBuyer) }],
    [pair.seller, { data: JSON.stringify(seller.bundle) }],
  ]);
  const fetchImpl = makeMockFetch(map);

  // Verify the SELLER's bundle (local) against the tampered buyer-anchor — should fail
  const verdict = await verifyBundle(seller.bundle, { fetchAnchoredImpl: fetchImpl });
  assert.equal(verdict.decision, 'fail',
    `tampered buyer-anchor signature MUST fail when fetched from chain; got verdict=${verdict.decision} steps=${JSON.stringify(verdict.steps.map(s => `${s.outcome}: ${s.step}: ${s.detail.slice(0, 80)}`))}`);
});

test('Codex M2 round-5 #2: chain-fetched seller anchor with NO signature → fail', async () => {
  const jobId = 'chain-unsigned-001';
  const { buyer, seller } = makePair(jobId);
  const { computeAnchorPair } = await import('../../src/lib/verify-bundle.js');
  const pair = computeAnchorPair(jobId);

  const unsignedSeller: AttestationBundle = { ...seller.bundle, signature: undefined };
  const map = new Map([
    [pair.buyer, { data: JSON.stringify(buyer.bundle) }],
    [pair.seller, { data: JSON.stringify(unsignedSeller) }],
  ]);
  const fetchImpl = makeMockFetch(map);

  const verdict = await verifyBundle(buyer.bundle, { fetchAnchoredImpl: fetchImpl });
  assert.equal(verdict.decision, 'fail',
    `unsigned seller-anchor MUST fail when fetched from chain; got: ${verdict.decision}`);
});

test('Codex M2 round-5 #1: third bundle riding along same jobId is REJECTED', async () => {
  const jobId = 'ride-along-001';
  const { buyer, seller } = makePair(jobId);
  const { computeAnchorPair } = await import('../../src/lib/verify-bundle.js');
  const pair = computeAnchorPair(jobId);

  // Now construct a third bundle (different content) that shares the jobId
  const thirdKeys = generateKeypair();
  const thirdUnsigned: AttestationBundle = {
    v: 'dacs-5-bundle:0.1', jobId, role: 'buyer',
    party: { v: 'dacs-1:0.1', primary: { scheme: 'cci', identifier: bytesToHex(thirdKeys.pubKey) }, claims: [], issuedAt: '', presentation: { kind: 'siwd' } },
    counterparty: { primary: { scheme: 'cci', identifier: 'a'.repeat(64) } }, // different counterparty entirely
    state: 'completed', phases: [], finalisedAt: '',
  };
  const canon = jcsCanonical(thirdUnsigned);
  const bh = jcsHash(thirdUnsigned);
  const tsig = sign(DOMAIN_SEPARATORS.BUNDLE_DACS5, canon, thirdKeys.privKey, bh);
  const thirdBundle: AttestationBundle = { ...thirdUnsigned, signature: Buffer.from(tsig).toString('base64') };

  // Chain serves the real buyer + seller anchors; we ask verifier to verify the THIRD bundle.
  const map = new Map([
    [pair.buyer, { data: JSON.stringify(buyer.bundle) }],
    [pair.seller, { data: JSON.stringify(seller.bundle) }],
  ]);
  const fetchImpl = makeMockFetch(map);

  const verdict = await verifyBundle(thirdBundle, { fetchAnchoredImpl: fetchImpl });
  assert.equal(verdict.decision, 'fail',
    `third bundle sharing jobId but not matching either anchor MUST fail`);
  const twoSidedStep = verdict.steps.find(s => s.step === 'two-sided-anchoring');
  assert.ok(twoSidedStep?.detail.includes('not byte-equal to EITHER party-anchored bundle'),
    `expected riding-along reject reason; got: ${twoSidedStep?.detail}`);
});

test('Codex M2 round-5 chain-fetched matched buyer-anchor → pass', async () => {
  const jobId = 'chain-matched-001';
  const { buyer, seller } = makePair(jobId);
  const { computeAnchorPair } = await import('../../src/lib/verify-bundle.js');
  const pair = computeAnchorPair(jobId);

  const map = new Map([
    [pair.buyer, { data: JSON.stringify(buyer.bundle) }],
    [pair.seller, { data: JSON.stringify(seller.bundle) }],
  ]);
  const fetchImpl = makeMockFetch(map);

  const verdict = await verifyBundle(buyer.bundle, { fetchAnchoredImpl: fetchImpl });
  assert.equal(verdict.decision, 'pass',
    `chain-fetched matched buyer-anchor MUST pass; got verdict=${verdict.decision} steps=${JSON.stringify(verdict.steps.map(s => `${s.outcome}: ${s.step}`))}`);
});
