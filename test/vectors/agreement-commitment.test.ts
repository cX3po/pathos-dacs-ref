import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as ed25519 from '@noble/ed25519';
import { sign } from '../../src/lib/sign.js';
import { jcsHashHex } from '../../src/jcs.js';
import { commitAgreement, verifyAgreementCommitmentCold, NotSupportedError, type AgreementCommitmentDependencies } from '../../src/adapters/dacs/agreement-commitment.js';
import type { AnchorReceipt, AgreementPartyV1 } from '../../src/types/bundle.js';

const FIX = new URL('../fixtures/dacs-standard-63793a39/', import.meta.url);
const load = (name: string) => JSON.parse(readFileSync(new URL(name, FIX), 'utf8'));
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const key = (n: number) => { const privateKey = new Uint8Array(32).fill(n); return { privateKey, claim: `cci:${hex(ed25519.getPublicKey(privateKey))}` }; };
const buyer = key(1), seller = key(2), orchestrator = key(3);
const signer = (k: ReturnType<typeof key>) => ({ claim: k.claim, sign: (domain: Parameters<typeof sign>[0], hash: string) => sign(domain, new TextEncoder().encode(hash), k.privateKey) });

function fixture(finalState: AnchorReceipt['state'] = 'finalized') {
  const memory = new Map<string, unknown>();
  const anchors = new Map<string, { logicalAddress: string; nativeAddress: string; transactionRef: { kind: string; value: string }; writer: string; nonce: string }>();
  const deps: AgreementCommitmentDependencies = {
    signers: { buyer: signer(buyer), seller: signer(seller), orchestrator: signer(orchestrator) },
    now: () => 1_780_000_000_000,
    async anchor(request) {
      const nativeAddress = `native-${anchors.size}`;
      const result = { logicalAddress: request.logicalAddress, nativeAddress, transactionRef: { kind: 'fake', value: `tx-${anchors.size}` }, writer: orchestrator.claim, nonce: String(anchors.size) };
      anchors.set(request.logicalAddress, result); memory.set(nativeAddress, request.content); return result;
    },
    async fetchAnchored(address) { if (!memory.has(address)) throw new Error('not found'); return memory.get(address); },
    async receiptProvider(request) {
      const anchor = request.anchor;
      return { receiptVersion: '1', substrate: 'test', finalityProfile: 'instant', logicalAddress: request.logicalAddress,
        nativeAddress: anchor.nativeAddress, contentHash: request.contentHash, transactionRef: anchor.transactionRef,
        writer: anchor.writer, nonce: anchor.nonce, state: finalState, observationDisposition: 'established', observedAt: 1_780_000_000_100,
        blockRef: { id: 'block-1', timestamp: 1_780_000_000_000 }, evidence: { kind: 'test-proof', value: 'proof' } };
    },
  };
  return { deps, memory, anchors };
}

function input() {
  const listing = {
    dacsVersion: '1', listingId: 'listing-1', listingVersion: 1, contentHash: 'ab'.repeat(32),
    pricing: { kind: 'fixed', price: { amount: '10', currency: 'USDC' } },
    offering: { deliverable: { deliverableType: 'attested-payload', hash: 'cd'.repeat(32) } },
    pipeline: [{ kind: 'negotiate-fixed-price' }, { kind: 'commit-agreement' }, { kind: 'pay-x402', parameters: { rail: 'pay-x402' } }],
    acceptedRails: [{ railId: 'pay-x402' }], terms: { deadlineSecAfterCommit: 3600 }, validity: { notBefore: 0, notAfter: 1_790_000_000_000 },
  };
  const vet = { anchor: { substrate: 'demos' as const, locator: 'vet' }, contentHash: 'ef'.repeat(32), type: 'vet', producedAt: new Date(0).toISOString() };
  const parties: AgreementPartyV1[] = [
    { role: 'buyer', bundleHash: '01'.repeat(32), primaryClaim: buyer.claim, vetRecordRef: vet },
    { role: 'seller', bundleHash: '02'.repeat(32), primaryClaim: seller.claim, vetRecordRef: vet },
  ];
  return { jobId: 'job-1', listing, parties, terms: { price: { amount: '10', currency: 'USDC' }, rail: { railId: 'pay-x402' }, deliverable: listing.offering.deliverable, deadline: 1_780_003_600_000 } };
}

test('commitAgreement emits signed AgreementDocument and finalized commitment at the mandated addresses', async () => {
  const { deps } = fixture();
  const result = await commitAgreement(input(), deps);
  assert.equal(result.committedAt, 1_780_000_000_000);
  assert.equal(result.addresses.commitment.logical, 'dacs3:commit:job-1');
  assert.equal(result.addresses.agreement?.logical, 'dacs3:agreement:job-1');
  assert.equal(result.commitment.agreementHash, result.agreementHash);
  assert.ok(result.agreement.signatures.every((s) => !s.value.includes('=')));
  assert.ok(!('committedAt' in result.commitment));
});

test('commitAgreement refuses a non-finalized receipt', async () => {
  const { deps } = fixture('included');
  await assert.rejects(commitAgreement(input(), deps), /not finalized/);
});

test('commitAgreement rejects payee-bound commitment with typed NotSupportedError', async () => {
  const f = input(); f.listing.pipeline[1] = { kind: 'commit-payee-bound-agreement' };
  await assert.rejects(commitAgreement(f, fixture().deps), NotSupportedError);
});

test('cold commitment verification re-fetches and passes the finalized binding', async () => {
  const state = fixture();
  const result = await commitAgreement(input(), state.deps);
  const verdict = await verifyAgreementCommitmentCold({ jobId: result.agreement.jobId, listing: input().listing, ...result }, {
    fetchAnchored: state.deps.fetchAnchored,
    receiptProvider: async (request) => state.deps.receiptProvider({ ...request, anchor: state.anchors.get(request.logicalAddress)! }),
  });
  assert.equal(verdict.outcome, 'pass');
});

test('cold commitment verification reports deterministic content tampering as fail', async () => {
  const state = fixture();
  const result = await commitAgreement(input(), state.deps);
  state.memory.set(result.addresses.commitment.native, { ...result.commitment, agreementHash: '00'.repeat(32) });
  const verdict = await verifyAgreementCommitmentCold({ jobId: result.agreement.jobId, listing: input().listing, ...result }, {
    fetchAnchored: state.deps.fetchAnchored,
    receiptProvider: async (request) => state.deps.receiptProvider({ ...request, anchor: state.anchors.get(request.logicalAddress)! }),
  });
  assert.equal(verdict.outcome, 'fail');
});

test('pinned agreement and commitment vectors expose the replayed rules', () => {
  const agreement = load('vectors/security/agreement-listing-v0.1.json');
  const compatibility = load('vectors/security/commitment-record-compatibility-v0.1.json');
  const authority = load('vectors/security/commitment-anchor-authority-v0.3.json');
  assert.ok(agreement.vectors.some((v: { name: string; expected: string }) => v.name === 'valid-in-band-rfq' && v.expected === 'accept'));
  assert.ok(compatibility.vectors.some((v: { name: string; signatureDomain: string }) => v.name === 'finality-record-uses-distinct-type-and-domain' && v.signatureDomain === 'dacs-finality-commitment:v1:'));
  assert.ok(authority.vectors.length > 0);
  assert.equal(jcsHashHex(agreement).length, 64);
});
