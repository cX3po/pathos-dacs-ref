import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import * as ed25519 from '@noble/ed25519';
import { finalizeBundle, verifyBundleListing, verifyFinalizedBundleCold, type BundleFinalizerDependencies, type CompletedSessionEvidence, type ResolvedCommitment } from '../../src/adapters/dacs/bundle-finalizer.js';
import { commitAgreement, type AgreementCommitmentDependencies } from '../../src/adapters/dacs/agreement-commitment.js';
import { emitSettlementEvidenceV1, evidenceHashV1 } from '../../src/lib/emit-settlement-evidence-v1.js';
import { verifySettlementEvidenceV1 } from '../../src/lib/verify-settlement-evidence-v1.js';
import { resolveBundleBinding } from '../../src/lib/bundle-binding-v1.js';
import { verifyBundleV1 } from '../../src/lib/verify-bundle-v1.js';
import { sign, verify } from '../../src/lib/sign.js';
import { DOMAIN_SEPARATORS } from '../../src/domain-sep.js';
import { jcsCanonical, jcsHashHex } from '../../src/jcs.js';
import type { AnchorReceipt, AgreementPartyV1 } from '../../src/types/bundle.js';
import type { AttestationRef } from '../../src/types/verify-result.js';

const FIX = new URL('../fixtures/dacs-standard-63793a39/', import.meta.url);
const loadBytes = (name: string) => readFileSync(new URL(name, FIX));
const load = (name: string) => JSON.parse(loadBytes(name).toString('utf8'));
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const key = (n: number) => { const privateKey = new Uint8Array(32).fill(n); return { privateKey, publicKey: ed25519.getPublicKey(privateKey), claim: `cci:${hex(ed25519.getPublicKey(privateKey))}` }; };
const buyer = key(11), seller = key(12), orchestrator = key(13);
const keys = new Map([[buyer.claim, buyer.publicKey], [seller.claim, seller.publicKey], [orchestrator.claim, orchestrator.publicKey]]);
const signer = (k: ReturnType<typeof key>) => ({ claim: k.claim, sign: (domain: Parameters<typeof sign>[0], hash: string) => sign(domain, new TextEncoder().encode(hash), k.privateKey) });
const verifySignature = ({ domain, hash, signer: claim, value }: { domain: Parameters<typeof verify>[0]; hash: string; signer: string | object; algorithm: string; value: string }) => {
  const publicKey = keys.get(String(claim));
  return !!publicKey && verify(domain, new Uint8Array(Buffer.from(value, 'base64url')), new TextEncoder().encode(hash), publicKey);
};

function signedEvidence(unsigned: ReturnType<typeof emitSettlementEvidenceV1>, author = orchestrator) {
  return { ...unsigned, signature: { algorithm: 'ed25519' as const, signer: author.claim,
    value: Buffer.from(sign(DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE, new TextEncoder().encode(evidenceHashV1(unsigned)), author.privateKey)).toString('base64url') } };
}

function setup() {
  const memory = new Map<string, unknown>();
  const receipts = new Map<string, AnchorReceipt>();
  const commitments = new Map<string, ResolvedCommitment>();
  const bindings: unknown[] = [];
  const receipt = (logicalAddress: string, nativeAddress: string, contentHash: string, writer: string, storedContent: unknown, transactionRef = { kind: 'fake', value: `tx-${logicalAddress}` }, nonce = '0'): AnchorReceipt => ({
    receiptVersion: '1', substrate: 'test', finalityProfile: 'instant', logicalAddress, nativeAddress, contentHash, transactionRef,
    writer, nonce, state: 'finalized', observationDisposition: 'established', observedAt: 1_780_000_000_100,
    blockRef: { id: 'block', timestamp: 1_780_000_000_000 }, evidence: { kind: 'stored-bytes-base64url', value: Buffer.from(jcsCanonical(storedContent)).toString('base64url') },
  });
  const putEvidence = (logical: string, value: unknown) => {
    const hash = jcsHashHex(value); const transactionRef = { kind: 'fake', value: `tx-${logical}` };
    memory.set(logical, value); receipts.set(logical, receipt(logical, logical, hash, orchestrator.claim, value, transactionRef));
    const ref: AttestationRef = { anchor: { substrate: 'demos', locator: logical }, contentHash: hash, type: 'settlement-evidence', producedAt: new Date(1_780_000_000_000).toISOString(), signer: orchestrator.claim };
    return { ref, anchor: { logicalAddress: logical, nativeAddress: logical, transactionRef, writer: orchestrator.claim, nonce: '0' } };
  };
  let counter = 0;
  const deps: BundleFinalizerDependencies = {
    signers: { buyer: signer(buyer), seller: signer(seller), orchestrator: signer(orchestrator) }, now: () => 1_780_000_001_000,
    projectPaymentRail: (rail) => String(rail.railId), verifySignature,
    async anchor(request) {
      const nativeAddress = `bundle-native-${counter}`; const nonce = String(counter++);
      const writer = request.logicalAddress.includes('buyer') ? buyer.claim : request.logicalAddress.includes('seller') ? seller.claim : orchestrator.claim;
      const anchor = { logicalAddress: request.logicalAddress, nativeAddress, transactionRef: { kind: 'fake', value: `tx-${nativeAddress}` }, writer, nonce };
      memory.set(nativeAddress, request.content); receipts.set(request.logicalAddress, receipt(request.logicalAddress, nativeAddress, request.contentHash, writer, request.content, anchor.transactionRef, nonce)); return anchor;
    },
    async fetchAnchored(address) { if (!memory.has(address)) throw new Error('not found'); return memory.get(address); },
    async fetchReceipt(request) { const found = receipts.get(request.logicalAddress); if (!found) throw new Error('no receipt'); return found; },
    async fetchCommitment(ref) { const found = commitments.get(ref.anchor.locator); if (!found) throw new Error('no commitment'); return found; },
    async publishBundleBinding(binding) { bindings.push(binding); },
  };
  return { deps, memory, receipts, commitments, bindings, putEvidence };
}

async function session(state: ReturnType<typeof setup>): Promise<CompletedSessionEvidence> {
  const listing: Record<string, any> = {
    listingId: 'listing-bundle', listingVersion: 1,
    pricing: { kind: 'fixed', price: { amount: '10', currency: 'USDC' } },
    offering: { deliverable: { deliverableType: 'attested-payload', hash: 'de'.repeat(32) } },
    pipeline: [{ kind: 'negotiate-fixed-price' }, { kind: 'commit-agreement' }, { kind: 'pay-x402' }, { kind: 'deliver-attested-payload' }],
    acceptedRails: [{ railId: 'pay-x402' }], terms: { deadlineSecAfterCommit: 3600 }, validity: { notAfter: 1_790_000_000_000 },
  };
  listing.contentHash = jcsHashHex(listing);
  listing.signature = { algorithm: 'ed25519', signer: seller.claim, value: Buffer.from(sign(DOMAIN_SEPARATORS.LISTING, new TextEncoder().encode(listing.contentHash), seller.privateKey)).toString('base64url') };
  const vet = { anchor: { substrate: 'demos' as const, locator: 'vet' }, contentHash: 'ef'.repeat(32), type: 'vet', producedAt: new Date(0).toISOString() };
  const agreementParties: AgreementPartyV1[] = [
    { role: 'buyer', bundleHash: '01'.repeat(32), primaryClaim: buyer.claim, vetRecordRef: vet },
    { role: 'seller', bundleHash: '02'.repeat(32), primaryClaim: seller.claim, vetRecordRef: vet },
  ];
  const agreementDeps: AgreementCommitmentDependencies = { signers: { buyer: signer(buyer), seller: signer(seller), orchestrator: signer(orchestrator) }, anchor: state.deps.anchor, fetchAnchored: state.deps.fetchAnchored, receiptProvider: state.deps.fetchReceipt, now: () => 1_780_000_000_000 };
  const committed = await commitAgreement({ jobId: 'bundle-job', listing, parties: agreementParties, terms: { price: { amount: '10', currency: 'USDC' }, rail: { railId: 'pay-x402' }, deliverable: listing.offering.deliverable, deadline: 1_780_003_600_000 } }, agreementDeps);
  const commitmentRef: AttestationRef = { anchor: { substrate: 'demos', locator: committed.addresses.commitment.native }, contentHash: committed.commitmentHash, type: 'finality-commitment', producedAt: new Date(committed.committedAt).toISOString() };
  state.commitments.set(commitmentRef.anchor.locator, { commitment: committed.commitment, agreement: committed.agreement, receipt: committed.receipt, anchor: { logicalAddress: committed.addresses.commitment.logical, nativeAddress: committed.addresses.commitment.native, transactionRef: committed.receipt.transactionRef, writer: committed.receipt.writer, nonce: committed.receipt.nonce } });
  const paymentLogical = 'dacs4:payment:bundle-job:pay-x402:2';
  const payment = signedEvidence(emitSettlementEvidenceV1({ kind: 'payment', jobId: 'bundle-job', phase: 'pay-x402', phaseIndex: 2, outcome: 'success', observedAt: 1_780_000_000_000,
    paymentTxRefs: [{ rail: 'pay-x402', txHash: 'tx-payment', kind: 'x402' }], paymentAmount: '10', paymentCurrency: 'USDC', finalityModel: 'provider-receipt', finalityObservedAt: 1_780_000_000_000 }));
  const delivery = signedEvidence(emitSettlementEvidenceV1({ kind: 'delivery', jobId: 'bundle-job', phase: 'deliver-attested-payload', phaseIndex: 3, outcome: 'success', observedAt: 1_780_000_000_000,
    deliverableContentHash: 'de'.repeat(32), deliverableAnchorKind: 'https', deliverableAnchorLocator: 'https://example.invalid/result' }));
  const paymentStored = state.putEvidence(paymentLogical, payment), deliveryStored = state.putEvidence('evidence-delivery', delivery);
  return {
    jobId: 'bundle-job', listing, listingRef: { listingId: listing.listingId, version: listing.listingVersion, contentHash: listing.contentHash }, agreementRef: commitmentRef,
    parties: [{ role: 'buyer', bundleHash: '01'.repeat(32), primaryClaim: buyer.claim }, { role: 'seller', bundleHash: '02'.repeat(32), primaryClaim: seller.claim }, { role: 'orchestrator', bundleHash: '03'.repeat(32), primaryClaim: orchestrator.claim }],
    phaseResults: [
      { index: 0, kind: 'negotiate-fixed-price', outcome: 'ok', orchestrator: orchestrator.claim },
      { index: 1, kind: 'commit-agreement', outcome: 'ok', orchestrator: orchestrator.claim },
      { index: 2, kind: 'pay-x402', outcome: 'ok', orchestrator: orchestrator.claim, evidenceRef: paymentStored.ref, evidenceLogicalAddress: paymentLogical, evidenceAnchor: paymentStored.anchor },
      { index: 3, kind: 'deliver-attested-payload', outcome: 'ok', orchestrator: orchestrator.claim, evidenceRef: deliveryStored.ref, evidenceLogicalAddress: 'evidence-delivery', evidenceAnchor: deliveryStored.anchor },
    ], outcome: 'completed', faultedParty: 'none', recipeRegistryVersion: 1, railRegistryVersion: 1,
  };
}

test('finalizeBundle emits signed role copies after resolving a real finalized commitment', async () => {
  const state = setup(); const input = await session(state); const result = await finalizeBundle(input, state.deps);
  assert.deepEqual(Object.keys(result.bundles).sort(), ['buyer', 'orchestrator', 'seller']);
  assert.equal(result.bundles.buyer!.bundle.phaseSummary.length, 4);
  assert.equal(state.bindings.length, 3);
});

test('SEB refuses duplicate references, phase divergence, and wrong native receipt address', async () => {
  const duplicateState = setup(); const duplicate = await session(duplicateState); duplicate.phaseResults[3]!.evidenceRef = duplicate.phaseResults[2]!.evidenceRef;
  await assert.rejects(finalizeBundle(duplicate, duplicateState.deps), /duplicate reference/);
  const divergentState = setup(); const divergent = await session(divergentState); divergent.phaseResults[2]!.kind = 'pay-dem';
  await assert.rejects(finalizeBundle(divergent, divergentState.deps), /contiguous 0\.\.n prefix/);
  const addressState = setup(); const addressInput = await session(addressState); const logical = addressInput.phaseResults[2]!.evidenceLogicalAddress!;
  addressState.receipts.set(logical, { ...addressState.receipts.get(logical)!, nativeAddress: 'wrong-native' });
  await assert.rejects(finalizeBundle(addressInput, addressState.deps), /native address/);
});

test('terminal trace shapes enforce failed-counterparty, failed-substrate, and aborted forms', async () => {
  const subState = setup(); const sub = await session(subState); sub.outcome = 'failed-substrate'; sub.phaseResults = [{ index: 0, kind: 'negotiate-fixed-price', outcome: 'fail', errorClass: 'substrate', orchestrator: orchestrator.claim }];
  await assert.doesNotReject(finalizeBundle(sub, subState.deps));
  const cpState = setup(); const cp = await session(cpState); cp.outcome = 'failed-counterparty'; cp.faultedParty = 'seller'; cp.phaseResults = [{ index: 0, kind: 'negotiate-fixed-price', outcome: 'fail', errorClass: 'substrate', orchestrator: orchestrator.claim }];
  await assert.rejects(finalizeBundle(cp, cpState.deps), /terminal counterparty failure/);
  const invalidSubState = setup(); const invalidSub = await session(invalidSubState); invalidSub.outcome = 'failed-substrate'; invalidSub.phaseResults = [{ index: 0, kind: 'negotiate-fixed-price', outcome: 'fail', errorClass: 'counterparty', orchestrator: orchestrator.claim }];
  await assert.rejects(finalizeBundle(invalidSub, invalidSubState.deps), /terminal substrate failure/);
  const abortState = setup(); const abort = await session(abortState); abort.outcome = 'aborted-by-self'; abort.faultedParty = 'buyer'; abort.phaseResults = [{ index: 0, kind: 'negotiate-fixed-price', outcome: 'fail', errorClass: 'counterparty', orchestrator: orchestrator.claim }];
  await assert.rejects(finalizeBundle(abort, abortState.deps), /proper successful prefix/);
});

test('emission refuses an unresolved commitment with a typed error', async () => {
  const state = setup(); const input = await session(state); state.commitments.clear();
  await assert.rejects(finalizeBundle(input, state.deps), (error: unknown) => error instanceof Error && error.name === 'BundleFinalizationError' && /ST-11/.test(error.message));
});

test('ST-11 independently refetches the commitment receipt for emission and cold verification', async () => {
  const emissionState = setup(); const emissionInput = await session(emissionState);
  const commitmentLogical = `dacs3:commit:${emissionInput.jobId}`;
  const emissionResolved = emissionState.commitments.get(emissionInput.agreementRef!.anchor.locator)!;
  emissionResolved.receipt = { ...emissionResolved.receipt, logicalAddress: commitmentLogical, state: 'finalized', observationDisposition: 'established' };
  emissionState.receipts.set(commitmentLogical, { ...emissionState.receipts.get(commitmentLogical)!, state: 'included' });
  await assert.rejects(finalizeBundle(emissionInput, emissionState.deps), /not finalized/);

  const coldState = setup(); const coldInput = await session(coldState); const result = await finalizeBundle(coldInput, coldState.deps);
  coldState.receipts.set(commitmentLogical, { ...coldState.receipts.get(commitmentLogical)!, state: 'included' });
  const verdict = await verifyFinalizedBundleCold({ jobId: coldInput.jobId, ...result, session: coldInput }, coldState.deps);
  assert.equal(verdict.outcome, 'fail');
});

test('cold ST-11 fails without the commitment seam and is indeterminate only on seam transport error', async () => {
  const state = setup(); const input = await session(state); const result = await finalizeBundle(input, state.deps);
  const expectation = { jobId: input.jobId, ...result, session: input };
  const { fetchCommitment: _missing, ...withoutCommitment } = state.deps;
  const missing = await verifyFinalizedBundleCold(expectation, withoutCommitment);
  assert.deepEqual(missing, { outcome: 'fail', detail: 'commitment-unresolved' });
  const transport = await verifyFinalizedBundleCold(expectation, { ...state.deps, async fetchCommitment() { throw new Error('transport'); } });
  assert.equal(transport.outcome, 'indeterminate');
});

test('bundle receipts fail closed for unverifiable evidence kinds and mismatched stored bytes', async () => {
  const kindState = setup(); const kindInput = await session(kindState); const logical = kindInput.phaseResults[2]!.evidenceLogicalAddress!;
  kindState.receipts.set(logical, { ...kindState.receipts.get(logical)!, evidence: { kind: 'unrecognised-proof', value: 'proof' } });
  await assert.rejects(finalizeBundle(kindInput, kindState.deps), /recoverable stored bytes/);

  const hashState = setup(); const hashInput = await session(hashState); const hashLogical = hashInput.phaseResults[2]!.evidenceLogicalAddress!;
  hashState.receipts.set(hashLogical, { ...hashState.receipts.get(hashLogical)!, evidence: { kind: 'stored-bytes-base64url', value: Buffer.from('mismatched').toString('base64url') } });
  await assert.rejects(finalizeBundle(hashInput, hashState.deps), /evidence bytes/);
});

test('SEB never treats two distinct unparseable writer claims as equal', async () => {
  const state = setup(); const input = await session(state); const phase = input.phaseResults[2]!; const logical = phase.evidenceLogicalAddress!;
  const evidence = structuredClone(state.memory.get(phase.evidenceRef!.anchor.locator)) as Record<string, any>;
  evidence.signature.signer = '0xdef';
  const contentHash = jcsHashHex(evidence);
  state.memory.set(phase.evidenceRef!.anchor.locator, evidence);
  phase.evidenceRef = { ...phase.evidenceRef!, contentHash };
  phase.orchestrator = '0xdef';
  phase.evidenceAnchor = { ...phase.evidenceAnchor!, writer: '0xabc' };
  state.receipts.set(logical, {
    ...state.receipts.get(logical)!, contentHash, writer: '0xabc',
    evidence: { kind: 'stored-bytes-base64url', value: Buffer.from(jcsCanonical(evidence)).toString('base64url') },
  });
  await assert.rejects(finalizeBundle(input, { ...state.deps, verifySignature: async () => true }), /evidence writer is not/);
});

test('cold verification requires buyer and seller, reruns SEB, and needs a receipt seam', async () => {
  const state = setup(); const input = await session(state); const result = await finalizeBundle(input, state.deps); const expectation = { jobId: input.jobId, ...result, session: input };
  assert.equal((await verifyFinalizedBundleCold(expectation, state.deps)).outcome, 'pass');
  const missingSeller = { ...expectation, bundles: { ...expectation.bundles, seller: undefined } };
  assert.equal((await verifyFinalizedBundleCold(missingSeller, state.deps)).outcome, 'fail');
  const paymentLogical = input.phaseResults[2]!.evidenceLogicalAddress!;
  state.receipts.set(paymentLogical, { ...state.receipts.get(paymentLogical)!, contentHash: '00'.repeat(32) });
  assert.equal((await verifyFinalizedBundleCold(expectation, state.deps)).outcome, 'fail');
  const { fetchReceipt: _fetchReceipt, ...withoutReceipt } = state.deps;
  const noSeam = await verifyFinalizedBundleCold(expectation, withoutReceipt);
  assert.deepEqual(noSeam, { outcome: 'indeterminate', detail: 'evidence-not-refetched' });
});

test('pinned settlement fixtures replay hashes, structural outcomes, and signatures bytewise', () => {
  const files = [
    ['fixtures/settlement-evidence-payment-success.json', 'c0ea32737df64b4d49a92ff29e49637fd3a582327024a059381987e6136d0800'],
    ['fixtures/settlement-evidence-delivery-success.json', '94b35c596148ca5deeda1c788b80c67f3ba2bf4faa9d91b086ef4bf60e14207b'],
  ] as const;
  for (const [file, fileHash] of files) {
    const bytes = loadBytes(file); assert.equal(createHash('sha256').update(bytes).digest('hex'), fileHash);
    const fixture = JSON.parse(bytes.toString('utf8')); const evidence = fixture.evidence; const signature = evidence.signature; const unsigned = { ...evidence }; delete unsigned.signature;
    assert.equal(jcsHashHex(unsigned), fixture.evidenceHash);
    const structural = verifySettlementEvidenceV1(evidence);
    if (file.includes('payment')) assert.deepEqual(structural, { decision: 'fail', reasons: ['shape: each paymentTxRefs entry must be a {rail,txHash,kind?} object (rail+txHash required; kind optional)'] });
    else assert.equal(structural.decision, 'pass');
    const publicKey = new Uint8Array(Buffer.from(fixture.publicKeys[signature.signer], 'base64url'));
    assert.equal(verify(DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE, new Uint8Array(Buffer.from(signature.value, 'base64url')), new TextEncoder().encode(fixture.evidenceHash), publicKey), true);
  }
});

test('pinned BundleBinding vectors replay their stated outcomes', () => {
  const bytes = loadBytes('vectors/security/bundle-binding-v0.1.json');
  assert.equal(createHash('sha256').update(bytes).digest('hex'), 'c357360778e40fa6856f99c4c9b0ced4b0db7cc917cf881be56e820135674f00');
  const corpus = JSON.parse(bytes.toString('utf8'));
  for (const vector of corpus.vectors) {
    const result = resolveBundleBinding({ ...vector.request, publicKeys: corpus.publicKeys }, vector.bindings, (address) => vector.anchored[address]);
    const outcome = result.disposition === 'present' ? 'pass' : result.disposition;
    assert.equal(outcome, vector.expected, `${vector.name}: ${result.detail}`);
  }
});

test('pinned EBFAB bundle objects replay discriminator, domain, and signature outcomes', () => {
  const fixture = load('fixtures/evidence-bound-fault-bundle-compatibility-v0.4.json');
  const resolvePublicKey = (claim: unknown) => {
    const encoded = typeof claim === 'string' ? fixture.publicKeys[claim] : undefined;
    return typeof encoded === 'string' ? new Uint8Array(Buffer.from(encoded, 'base64url')) : null;
  };
  for (const entry of fixture.cases) {
    const verdict = verifyBundleV1(entry.bundle, { resolvePublicKey });
    const type = verdict.structurallyValid
      ? entry.bundle.evidenceBoundFaultBundleVersion === '1' ? 'evidence-bound' : 'fault'
      : null;
    assert.equal(type, entry.want.type, entry.name);
    assert.equal(verdict.cryptographicallyVerified, entry.want.signaturesValid, entry.name);
    const expectedDecision = entry.want.type !== null && entry.want.signaturesValid ? 'accept' : 'reject';
    assert.equal(verdict.decision, expectedDecision, entry.name);
  }
});

test('every pinned upstream input remains byte-identical to the README manifest', () => {
  const manifest: Record<string, string> = {
    'fixtures/evidence-bound-fault-bundle-compatibility-v0.4.json': 'b5bad52a6293ea0d02414cd68243587a29ce0c74e803e6f4f7e8f589b6db9dfa',
    'fixtures/settlement-evidence-delivery-success.json': '94b35c596148ca5deeda1c788b80c67f3ba2bf4faa9d91b086ef4bf60e14207b',
    'fixtures/settlement-evidence-payment-success.json': 'c0ea32737df64b4d49a92ff29e49637fd3a582327024a059381987e6136d0800',
    'vectors/security/agreement-listing-v0.1.json': '857ebf0ea4b885b92b0d6ad509a37cf5076218881c510ef2f2d05d734d94503b',
    'vectors/security/bundle-binding-v0.1.json': 'c357360778e40fa6856f99c4c9b0ced4b0db7cc917cf881be56e820135674f00',
    'vectors/security/bundle-settlement-evidence-bijection-v0.4.json': 'd4a68beb877e563114388cb3b53d2f67140b6136e6cec9883873f87e4c35a593',
    'vectors/security/commitment-anchor-authority-v0.3.json': 'c0bfadb6ecd0131962cc4e2f62672970e6f5a4be5d43b262261e0ba8c205500a',
    'vectors/security/commitment-record-compatibility-v0.1.json': '983010f2077e81427071da3fdad8a98f30da0b68248f285e22f1116efaf790b3',
    'vectors/security/phase-kind-divergence-v0.3.json': '0c2c97ca1d4dece0b1f16011834aa21c446b3226311ef0a23417228565ed151e',
  };
  for (const [file, hash] of Object.entries(manifest)) assert.equal(createHash('sha256').update(loadBytes(file)).digest('hex'), hash, file);
});
