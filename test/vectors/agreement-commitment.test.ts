import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import * as ed25519 from '@noble/ed25519';
import { sign, verify } from '../../src/lib/sign.js';
import { jcsCanonical, jcsHashHex } from '../../src/jcs.js';
import { commitAgreement, verifyAgreementCommitmentCold, NotSupportedError, type AgreementCommitmentDependencies } from '../../src/adapters/dacs/agreement-commitment.js';
import { verifyBundleListing } from '../../src/adapters/dacs/bundle-finalizer.js';
import { validateAgreementAgainstListing } from '../../conformance/security-vectors/agreement-listing/validate.js';
import type { AnchorReceipt, AgreementPartyV1 } from '../../src/types/bundle.js';

const FIX = new URL('../fixtures/dacs-standard-63793a39/', import.meta.url);
const loadBytes = (name: string) => readFileSync(new URL(name, FIX));
const load = (name: string) => JSON.parse(loadBytes(name).toString('utf8'));
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const key = (n: number) => { const privateKey = new Uint8Array(32).fill(n); return { privateKey, publicKey: ed25519.getPublicKey(privateKey), claim: `cci:${hex(ed25519.getPublicKey(privateKey))}` }; };
const buyer = key(1), seller = key(2), orchestrator = key(3);
const keys = new Map([[buyer.claim, buyer.publicKey], [seller.claim, seller.publicKey], [orchestrator.claim, orchestrator.publicKey]]);
const signer = (k: ReturnType<typeof key>) => ({ claim: k.claim, sign: (domain: Parameters<typeof sign>[0], hash: string) => sign(domain, new TextEncoder().encode(hash), k.privateKey) });
const verifySignature = ({ domain, hash, signer: claim, value }: { domain: Parameters<typeof verify>[0]; hash: string; signer: string | object; algorithm: string; value: string }) => {
  const publicKey = keys.get(String(claim));
  return !!publicKey && verify(domain, new Uint8Array(Buffer.from(value, 'base64url')), new TextEncoder().encode(hash), publicKey);
};

function fixture(finalState: AnchorReceipt['state'] = 'finalized') {
  const memory = new Map<string, unknown>();
  const anchors = new Map<string, { logicalAddress: string; nativeAddress: string; transactionRef: { kind: string; value: string }; writer: string; nonce: string }>();
  let corruptEvidence = false;
  let evidenceKind = 'stored-bytes-base64url';
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
      const stored = memory.get(anchor.nativeAddress);
      const evidenceBytes = corruptEvidence ? new TextEncoder().encode('tampered') : jcsCanonical(stored);
      return { receiptVersion: '1', substrate: 'test', finalityProfile: 'instant', logicalAddress: request.logicalAddress,
        nativeAddress: anchor.nativeAddress, contentHash: request.contentHash, transactionRef: anchor.transactionRef,
        writer: anchor.writer, nonce: anchor.nonce, state: finalState, observationDisposition: 'established', observedAt: 1_780_000_000_100,
        blockRef: { id: 'block-1', timestamp: 1_780_000_000_000 }, evidence: { kind: evidenceKind, value: Buffer.from(evidenceBytes).toString('base64url') } };
    },
  };
  return { deps, memory, anchors, corruptEvidence: () => { corruptEvidence = true; }, setEvidenceKind: (kind: string) => { evidenceKind = kind; } };
}

function input() {
  const listing: Record<string, any> = {
    dacsVersion: '1', listingId: 'listing-1', listingVersion: 1,
    pricing: { kind: 'fixed', price: { amount: '10', currency: 'USDC' } },
    offering: { deliverable: { deliverableType: 'attested-payload', hash: 'cd'.repeat(32) } },
    pipeline: [{ kind: 'negotiate-fixed-price' }, { kind: 'commit-agreement' }, { kind: 'pay-x402', parameters: { rail: 'pay-x402' } }],
    acceptedRails: [{ railId: 'pay-x402' }], terms: { deadlineSecAfterCommit: 3600 }, validity: { notBefore: 0, notAfter: 1_790_000_000_000 },
  };
  listing.contentHash = jcsHashHex(listing);
  const vet = { anchor: { substrate: 'demos' as const, locator: 'vet' }, contentHash: 'ef'.repeat(32), type: 'vet', producedAt: new Date(0).toISOString() };
  const parties: AgreementPartyV1[] = [
    { role: 'buyer', bundleHash: '01'.repeat(32), primaryClaim: buyer.claim, vetRecordRef: vet },
    { role: 'seller', bundleHash: '02'.repeat(32), primaryClaim: seller.claim, vetRecordRef: vet },
  ];
  return { jobId: 'job-1', listing, parties, terms: { price: { amount: '10', currency: 'USDC' }, rail: { railId: 'pay-x402' }, deliverable: listing.offering.deliverable, deadline: 1_780_003_600_000 } };
}

function coldDeps(state: ReturnType<typeof fixture>) {
  return {
    fetchAnchored: state.deps.fetchAnchored,
    receiptProvider: async (request: Parameters<AgreementCommitmentDependencies['receiptProvider']>[0]) => state.deps.receiptProvider({ ...request, anchor: state.anchors.get(request.logicalAddress)! }),
    verifySignature,
  };
}

test('commitAgreement emits signed AgreementDocument and stores the signed-document hash in agreementRef', async () => {
  const { deps } = fixture();
  const result = await commitAgreement(input(), deps);
  assert.equal(result.committedAt, 1_780_000_000_000);
  assert.equal(result.addresses.commitment.logical, 'dacs3:commit:job-1');
  assert.equal(result.agreementRef.contentHash, jcsHashHex(result.agreement));
  assert.equal(result.agreementRef.unsignedContentHash, result.agreementHash);
  assert.ok(result.agreement.signatures.every((s) => !s.value.includes('=')));
});

test('commitAgreement refuses a non-finalized receipt', async () => {
  await assert.rejects(commitAgreement(input(), fixture('included').deps), /not finalized/);
});

test('commitAgreement refuses receipt evidence whose stored bytes do not hash to contentHash', async () => {
  const state = fixture(); state.corruptEvidence();
  await assert.rejects(commitAgreement(input(), state.deps), /evidence bytes/);
});

test('commitAgreement refuses receipt evidence with an unrecognised, byte-unverifiable kind', async () => {
  const state = fixture(); state.setEvidenceKind('unrecognised-proof');
  await assert.rejects(commitAgreement(input(), state.deps), (error: unknown) => error instanceof Error && /recoverable stored bytes/.test(error.message));
});

test('commitAgreement rejects payee-bound and prior-payment disposition with typed NotSupportedError', async () => {
  const payee = input(); payee.listing.pipeline[1] = { kind: 'commit-payee-bound-agreement' }; payee.listing.contentHash = (() => { const x = { ...payee.listing }; delete x.contentHash; return jcsHashHex(x); })();
  await assert.rejects(commitAgreement(payee, fixture().deps), NotSupportedError);
  const prior = input(); (prior.terms as Record<string, unknown>).priorPaymentDispositionRef = { id: 'prior' };
  await assert.rejects(commitAgreement(prior, fixture().deps), NotSupportedError);
});

test('commitAgreement recomputes the listing signed-scope hash', async () => {
  const value = input(); value.listing.contentHash = 'ab'.repeat(32);
  await assert.rejects(commitAgreement(value, fixture().deps), /contentHash does not match/);
});

test('APR-3 requires exactly one full canonical pay-alternative match', async () => {
  const differing = input();
  differing.listing.pipeline[2] = { kind: 'pay-alternative', parameters: { alternatives: [{ railId: 'pay-x402', endpoint: 'a' }] } };
  differing.terms.rail = { railId: 'pay-x402', endpoint: 'b' } as typeof differing.terms.rail;
  differing.listing.contentHash = (() => { const x = { ...differing.listing }; delete x.contentHash; return jcsHashHex(x); })();
  await assert.rejects(commitAgreement(differing, fixture().deps), /exactly one signed alternative/);
  const duplicate = input(); const rail = { railId: 'pay-x402', endpoint: 'a' };
  duplicate.listing.pipeline[2] = { kind: 'pay-alternative', parameters: { alternatives: [rail, { ...rail }] } }; duplicate.terms.rail = rail;
  duplicate.listing.contentHash = (() => { const x = { ...duplicate.listing }; delete x.contentHash; return jcsHashHex(x); })();
  await assert.rejects(commitAgreement(duplicate, fixture().deps), /exactly one signed alternative/);
});

test('SE-8 enforces demand and procurement listing-publisher direction', async () => {
  const demand = input(); demand.listing.pipeline[0] = { kind: 'negotiate-sealed-envelope', parameters: { auctionMode: 'demand' } }; demand.listing.seller = { primaryClaim: buyer.claim };
  demand.listing.contentHash = (() => { const x = { ...demand.listing }; delete x.contentHash; return jcsHashHex(x); })();
  await assert.rejects(commitAgreement({ ...demand, derivedFromPattern: 'sealed-envelope' }, fixture().deps), /direction/);
  const procurement = input(); procurement.listing.pipeline[0] = { kind: 'negotiate-sealed-envelope-procurement', parameters: { auctionMode: 'procurement' } }; procurement.listing.seller = { primaryClaim: seller.claim };
  procurement.listing.contentHash = (() => { const x = { ...procurement.listing }; delete x.contentHash; return jcsHashHex(x); })();
  await assert.rejects(commitAgreement({ ...procurement, derivedFromPattern: 'sealed-envelope' }, fixture().deps), /direction/);
});

test('cold commitment verification requires and verifies both party signatures', async () => {
  const state = fixture(); const result = await commitAgreement(input(), state.deps); const expected = { jobId: result.agreement.jobId, listing: input().listing, ...result };
  assert.equal((await verifyAgreementCommitmentCold(expected, coldDeps(state))).outcome, 'pass');
  const tampered = structuredClone(expected); tampered.agreement.signatures[0]!.value = tampered.agreement.signatures[0]!.value.replace(/^./, tampered.agreement.signatures[0]!.value[0] === 'A' ? 'B' : 'A');
  assert.equal((await verifyAgreementCommitmentCold(tampered, coldDeps(state))).outcome, 'fail');
  const missing = structuredClone(expected); missing.agreement.signatures = missing.agreement.signatures.filter((signature) => String(signature.party) !== seller.claim);
  assert.equal((await verifyAgreementCommitmentCold(missing, coldDeps(state))).outcome, 'fail');
  await assert.rejects(verifyAgreementCommitmentCold(expected, { ...coldDeps(state), verifySignature: undefined } as never), /verifySignature is required/);
});

test('pinned agreement vectors pass the adapter listing check and replay their stated agreement outcomes', async () => {
  const bytes = loadBytes('vectors/security/agreement-listing-v0.1.json');
  assert.equal(createHash('sha256').update(bytes).digest('hex'), '857ebf0ea4b885b92b0d6ad509a37cf5076218881c510ef2f2d05d734d94503b');
  const corpus = JSON.parse(bytes.toString('utf8'));
  for (const vector of corpus.vectors) {
    const listingScope = { ...vector.listing }; delete listingScope.signature; delete listingScope.contentHash;
    const contentHash = jcsHashHex(listingScope);
    const listing = {
      ...listingScope, contentHash,
      signature: { algorithm: 'ed25519', signer: seller.claim, value: Buffer.from(sign('dacs-listing:v1:', new TextEncoder().encode(contentHash), seller.privateKey)).toString('base64url') },
    };
    await assert.doesNotReject(verifyBundleListing(listing, { verifySignature }));
    const verdict = validateAgreementAgainstListing(vector.agreement, vector.listing, typeof vector.committedAt === 'number' ? vector.committedAt : undefined);
    assert.equal(verdict.decision, vector.expected, vector.name);
  }
  const authority = load('vectors/security/commitment-anchor-authority-v0.3.json');
  const agreementScope = { ...authority.agreement }; delete agreementScope.signatures;
  assert.equal(jcsHashHex(agreementScope), authority.agreementHash);
  for (const signature of authority.agreement.signatures) {
    const publicKey = new Uint8Array(Buffer.from(authority.publicKeys[signature.party], 'base64url'));
    assert.equal(verify('dacs-agreement:v1:', new Uint8Array(Buffer.from(signature.value, 'base64url')), new TextEncoder().encode(authority.agreementHash), publicKey), true);
  }
  assert.equal(jcsHashHex(authority.commitmentRecord), authority.commitmentRecordHash);
  const commitmentKey = new Uint8Array(Buffer.from(authority.publicKeys[authority.commitmentSignature.signer], 'base64url'));
  assert.equal(verify('dacs-commitment:v1:', new Uint8Array(Buffer.from(authority.commitmentSignature.value, 'base64url')), new TextEncoder().encode(authority.commitmentRecordHash), commitmentKey), true);
});
