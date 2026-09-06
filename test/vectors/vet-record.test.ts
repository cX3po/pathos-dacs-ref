// DACS-2 vet records (2026-09-06): the party evaluation the coordinator and the dry-run fixtures share.
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { sha256 } from '@noble/hashes/sha2';
import { ed25519 } from '@noble/curves/ed25519';
import { sign, verify } from '../../src/lib/sign.js';
import { jcsHashHex } from '../../src/jcs.js';
import { DOMAIN_SEPARATORS, type DomainSeparator } from '../../src/domain-sep.js';
import { dacs1Listing, signDacs1Listing, presentIdentity, selfSignedBundleRequirement, identityBundleHash } from '../../src/live/listing-wire.js';
import { vetParties } from '../../src/live/party-vet.js';
import { aggregateDecision, compositeRecordAddress, vetRecordAddress, vetRecordProgramName, emitCompositeRecord, requireConfiguredSellerIdentity } from '../../src/live/vet-record.js';
import type { AdapterSigner } from '../../src/adapters/dacs/agreement-commitment.js';

const enc = new TextEncoder();
function key(label: string) {
  const privateKey = sha256(enc.encode(`vet-record-test:${label}`));
  const publicKey = ed25519.getPublicKey(privateKey);
  const claim = `did:demos:agent:${Buffer.from(publicKey).toString('hex')}`;
  const signer: AdapterSigner = { claim, sign: (domain, hash) => sign(domain, enc.encode(hash), privateKey) };
  return { claim, publicKey, signer };
}
const buyer = key('buyer'); const seller = key('seller'); const stranger = key('stranger');
const keys = new Map([buyer, seller, stranger].map((k) => [k.claim, k.publicKey]));
const verifySignature = ({ domain, hash, signer, value }: { domain: DomainSeparator; hash: string; signer: string; algorithm: string; value: string }) => {
  const publicKey = keys.get(signer);
  return !!publicKey && verify(domain, new Uint8Array(Buffer.from(value, 'base64url')), enc.encode(hash), publicKey);
};
const NOW = 1_780_000_000_000;
async function listingBy(presenter: { signer: AdapterSigner }) {
  const identity = await presentIdentity(presenter.signer, NOW);
  const unsigned = dacs1Listing({ listingId: 'job-listing', listingVersion: 1, seller: { identity, displayName: 'x' },
    offering: { title: 't', description: 'd', category: 'c', tags: [], deliverable: { kind: 'storage-program' } },
    pricing: { kind: 'fixed', price: { amount: '1', currency: 'DEM' } }, acceptedRails: [{ railId: 'pay-dem' }], pipeline: [{ kind: 'pay-dem', parameters: { rail: 'pay-dem' } }],
    terms: { deadlineSecAfterCommit: 3600 }, validity: { notBefore: NOW - 1, notAfter: NOW + 1 } });
  return signDacs1Listing(unsigned, presenter.signer);
}
function memoryAnchor() {
  const store = new Map<string, unknown>(); let n = 0;
  const anchor = async (request: { logicalAddress: string; content: unknown; contentHash: string }) => { const nativeAddress = `stor-${n++}-${request.logicalAddress}`; store.set(nativeAddress, request.content); return { nativeAddress }; };
  return { store, anchor };
}
const listingRef = { anchor: { kind: 'storage-program' as const, locator: 'stor-listing' }, contentHash: 'ab'.repeat(32) };

test('vetParties: the seller the listing presents must be the configured seller (a valid listing by a stranger is refused)', async () => {
  const { listing } = await listingBy(stranger);
  const { anchor } = memoryAnchor();
  await assert.rejects(vetParties({ jobId: 'job', listing, listingRef, signers: { buyer: buyer.signer, seller: seller.signer }, anchor, verifySignature, now: NOW }), /listing presenter is not the configured seller/);
});

test('vetParties: a listing that presents no identity bundle has nothing to evaluate (refused, never a pass)', async () => {
  const { anchor } = memoryAnchor();
  const legacy = { listingVersion: 1, listingId: 'job-listing', seller: { primaryClaim: seller.claim }, signature: { algorithm: 'ed25519', signer: seller.claim, value: 'AA' } };
  await assert.rejects(vetParties({ jobId: 'job', listing: legacy, listingRef, signers: { buyer: buyer.signer, seller: seller.signer }, anchor, verifySignature, now: NOW }), /presents no seller identity bundle/);
  assert.throws(() => requireConfiguredSellerIdentity(legacy, seller.claim), /presents no seller identity bundle/);
});

test('vetParties: each party is evaluated by its counterparty under the requirement that counterparty holds, and the composites bind the presented bundles', async () => {
  const { listing } = await listingBy(seller);
  const { store, anchor } = memoryAnchor();
  const out = await vetParties({ jobId: 'job', listing, listingRef, signers: { buyer: buyer.signer, seller: seller.signer }, anchor, verifySignature, now: NOW });
  assert.deepEqual(out.records, { buyer: { method: 'self-signed', decision: 'pass', composite: 'pass' }, seller: { method: 'self-signed', decision: 'pass', composite: 'pass' } });
  const sellerComposite = store.get(out.refs.seller.composite.anchor.locator) as Record<string, unknown>;
  const buyerComposite = store.get(out.refs.buyer.composite.anchor.locator) as Record<string, unknown>;
  assert.equal((sellerComposite.signature as { signer: string }).signer, buyer.claim, 'the buyer vets the seller');
  assert.equal((buyerComposite.signature as { signer: string }).signer, seller.claim, 'the seller vets the buyer');
  assert.equal(sellerComposite.requirementHash, jcsHashHex(selfSignedBundleRequirement('did')));
  assert.equal(buyerComposite.requirementHash, jcsHashHex(listing.buyerRequirement));
  assert.equal(sellerComposite.bundleHash, identityBundleHash((listing.seller as { identity: never }).identity));
  const buyerBundle = store.get(out.buyerIdentityAnchor) as Record<string, unknown>;
  assert.equal(buyerBundle.presentedBy, buyer.claim); assert.equal(buyerComposite.bundleHash, identityBundleHash(buyerBundle as never));
  assert.equal(out.refs.buyer.bundleHash, buyerComposite.bundleHash); assert.equal(out.refs.seller.bundleHash, sellerComposite.bundleHash);
  assert.equal(out.refs.seller.composite.anchor.locator.endsWith(vetRecordProgramName(compositeRecordAddress('job', seller.claim))), true, 'anchored under the SDK-form composite program name');
  assert.equal(out.refs.seller.verifyResult.anchor.locator.endsWith(vetRecordProgramName(vetRecordAddress('job', 'did', seller.claim.slice(4), 1))), true);
  // The composite signature verifies under dacs-composite:v1: over the signature-excluded record, by the pinned signer.
  const { signature, ...scope } = sellerComposite as { signature: { signer: string; value: string } };
  assert.equal(verifySignature({ domain: DOMAIN_SEPARATORS.COMPOSITE_VERIFY, hash: jcsHashHex(scope), signer: signature.signer, algorithm: 'ed25519', value: signature.value }), true);
  assert.equal(out.refs.seller.composite.contentHash, jcsHashHex(scope)); assert.equal(out.refs.seller.composite.signer, signature.signer);
});

test('composite address: CF-4 encodes the job id and the evaluated party, and the program name escapes every colon', () => {
  assert.equal(compositeRecordAddress('01ABC', 'did:demos:agent:ff'), 'dacs2:composite:01ABC:did%3Ademos%3Aagent%3Aff');
  assert.equal(vetRecordProgramName(compositeRecordAddress('01ABC', 'did:demos:agent:ff')), 'dacs2%3Acomposite%3A01ABC%3Adid%3Ademos%3Aagent%3Aff');
});

test('aggregateDecision follows DACS-2 §7.7.1 as the pinned SDK recomputes it: a required member with no result fails; fail > error > indeterminate', () => {
  const requirement = selfSignedBundleRequirement('did');
  const r = (decision: 'pass' | 'fail' | 'indeterminate' | 'error') => ({ scheme: 'did', method: 'self-signed' as const, recipeVersion: 1, decision });
  assert.equal(aggregateDecision(requirement, []), 'fail');
  assert.equal(aggregateDecision(requirement, [r('pass')]), 'pass');
  assert.equal(aggregateDecision(requirement, [r('indeterminate')]), 'indeterminate');
  assert.equal(aggregateDecision(requirement, [r('error'), r('indeterminate')]), 'error');
  assert.equal(aggregateDecision(requirement, [r('fail'), r('error')]), 'fail');
  assert.equal(aggregateDecision(requirement, [{ ...r('pass'), method: 'consensus-backed-proxy' }]), 'fail', 'a result of another method does not satisfy a self-signed member');
  assert.equal(aggregateDecision({ requirementVersion: '1', required: [] }, []), 'pass', 'an empty requirement aggregates to pass (nothing was required)');
});

test('emitCompositeRecord refuses evidence that no requirement member binds', async () => {
  const ref = { anchor: { kind: 'storage-program' as const, locator: 'stor-r' }, contentHash: 'cd'.repeat(32), recipeVersion: 1 };
  await assert.rejects(emitCompositeRecord({ jobId: 'job', evaluatedParty: seller.claim, bundleHash: 'ef'.repeat(32), requirement: selfSignedBundleRequirement('lei'),
    dealSpecific: [{ ref, result: { scheme: 'did', method: 'self-signed', recipeVersion: 1, decision: 'pass' } }], generatedAt: NOW }, buyer.signer), /not bound to a requirement member/);
});
