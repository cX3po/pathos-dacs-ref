import { deepEqual, equal, match, notEqual, ok, rejects } from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { sha256 } from '@noble/hashes/sha2';
import { ed25519 } from '@noble/curves/ed25519';
import { verifyBundleListing } from '../../src/adapters/dacs/bundle-finalizer.js';
import { listingLogicalAddress } from '../../src/dacs1/addressing.js';
import { buildDiscoveryArtifacts } from '../../src/dacs1/discovery.js';
import { DOMAIN_SEPARATORS } from '../../src/domain-sep.js';
import { jcsCanonical, jcsHashHex } from '../../src/jcs.js';
import { sign, verify } from '../../src/lib/sign.js';
import { identityBundleHash, sdkListingProgramName, selfSignedBundleRequirement, signDacs1Listing } from '../../src/live/listing-wire.js';
import {
  agentDidForPubkey,
  agentDidSignatureVerifier,
  assertDacs1Listing,
  DACS1_LISTING_SIZE_CAP_BYTES,
  keypairSigner,
  publishProducerListing,
  type ProducerKeypair,
} from '../../src/live/producer-listing.js';

const keyOf = (label: string): ProducerKeypair => {
  const privKey = sha256(new TextEncoder().encode(`producer-listing:${label}`));
  return { privKey, pubKey: ed25519.getPublicKey(privKey) };
};
const seller = keyOf('seller');
const sellerDid = agentDidForPubkey(seller.pubKey);
const NOW = 1_788_720_000_000;
const PIPELINE = [
  { kind: 'vet-credentials' }, { kind: 'negotiate-fixed-price' }, { kind: 'commit-agreement' },
  { kind: 'pay-dem', parameters: { rail: 'pay-dem' } }, { kind: 'deliver-storage-program' },
] as const;

async function publish(anchored: Array<{ programName: string; bytes: string }> = []) {
  return publishProducerListing({
    jobId: 'job-producer-1', seller, displayName: 'PATH-OS proof organ',
    offering: { title: 'weather band', description: 'a public answer for a committed query', category: 'proof-organ', tags: ['nws_alerts'], deliverable: { kind: 'storage-program', accessModel: 'public' } },
    price: { amount: '1', currency: 'DEM' }, railId: 'pay-dem', pipeline: PIPELINE, now: NOW,
    anchor: (programName, bytes) => { anchored.push({ programName, bytes }); return `stor-${'ab'.repeat(20)}`; },
  });
}

test('the agent DID is the key itself, and the keypair signer signs under it', async () => {
  match(sellerDid, /^did:demos:agent:[0-9a-f]{64}$/);
  equal(sellerDid.slice('did:demos:agent:'.length), Buffer.from(seller.pubKey).toString('hex'));
  const signer = keypairSigner(seller);
  equal(String(signer.claim), sellerDid);
  const hash = jcsHashHex({ any: 'scope' });
  const value = Buffer.from(await signer.sign(DOMAIN_SEPARATORS.LISTING, hash) as Uint8Array).toString('base64url');
  equal(await agentDidSignatureVerifier({ domain: DOMAIN_SEPARATORS.LISTING, hash, signer: sellerDid, algorithm: 'ed25519', value }), true);
  // The verifier resolves the key from the DID alone; any other claim form is unknown to it, and a wrong domain fails.
  equal(await agentDidSignatureVerifier({ domain: DOMAIN_SEPARATORS.LISTING, hash, signer: `cci:${sellerDid.slice(-64)}`, algorithm: 'ed25519', value }), false);
  equal(await agentDidSignatureVerifier({ domain: DOMAIN_SEPARATORS.AGREEMENT, hash, signer: sellerDid, algorithm: 'ed25519', value }), false);
});

test('a producer listing is a DACS-1 §6.3.4 Listing presenting the seller identity under its agent DID, signed over the signature-excluded hash, named in the SDK form', async () => {
  const anchored: Array<{ programName: string; bytes: string }> = [];
  const published = await publish(anchored);
  const listing = published.listing;
  deepEqual(Object.keys(listing).sort(), ['acceptedRails', 'buyerRequirement', 'dacsVersion', 'listingId', 'listingVersion', 'logical_address', 'offering', 'pipeline', 'pricing', 'seller', 'signature', 'terms', 'validity']);
  equal(listing.dacsVersion, '1');
  equal(listing.listingId, 'job-producer-1-listing');
  equal(listing.listingVersion, 1);
  const identity = (listing.seller as { identity: Record<string, unknown> }).identity;
  equal(identity.presentedBy, sellerDid);
  deepEqual(identity.claims, [{ ref: sellerDid }]);
  equal(identity.presentedAt, NOW);
  deepEqual(published.identity, identity);
  const presentation = identity.presentation as { kind: string; signatures: Array<{ ref: string; signature: string }> };
  equal(presentation.kind, 'per-claim');
  ok(verify(DOMAIN_SEPARATORS.BUNDLE_PRESENTATION, new Uint8Array(Buffer.from(presentation.signatures[0]!.signature, 'base64url')), new TextEncoder().encode(identityBundleHash(identity as never)), seller.pubKey));
  deepEqual(listing.buyerRequirement, selfSignedBundleRequirement('did'));
  deepEqual(listing.pipeline, PIPELINE.map((step) => ('parameters' in step ? { kind: step.kind, parameters: step.parameters } : { kind: step.kind })));
  deepEqual(listing.pricing, { kind: 'fixed', price: { amount: '1', currency: 'DEM' } });
  deepEqual(listing.acceptedRails, [{ railId: 'pay-dem' }]);
  deepEqual(listing.validity, { notBefore: NOW - 60_000, notAfter: NOW + 7_200_000 });
  // The signature covers the listing minus itself; its signer is the presented claim.
  const { signature, ...scope } = listing;
  equal(published.contentHash, jcsHashHex(scope));
  const sig = signature as { algorithm: string; signer: string; value: string };
  equal(sig.signer, sellerDid);
  equal(sig.algorithm, 'ed25519');
  ok(verify(DOMAIN_SEPARATORS.LISTING, new Uint8Array(Buffer.from(sig.value, 'base64url')), new TextEncoder().encode(published.contentHash), seller.pubKey));
  // Address and program name: the logical address derives from the DID, is carried on the record inside the signed scope (§6.3.4(b)), and the program name is the SDK's percent-encoded form.
  equal(published.logicalAddress, listingLogicalAddress(sellerDid, 'job-producer-1-listing', 1));
  equal(listing.logical_address, published.logicalAddress);
  equal(published.programName, sdkListingProgramName(published.logicalAddress));
  equal(published.programName.includes(':'), false);
  match(published.programName, /^dacs1%3Adid%3Ademos%3Aagent%3A[0-9a-f]{64}%3Ajob-producer-1-listing%3Av1$/);
  // What was anchored is the JCS form of the signed listing, under that name, and the locator is what the anchor returned.
  equal(anchored.length, 1);
  equal(anchored[0]!.programName, published.programName);
  equal(anchored[0]!.bytes, new TextDecoder().decode(jcsCanonical(listing)));
  equal(published.locator, `stor-${'ab'.repeat(20)}`);
  equal(published.sellerClaim, sellerDid);
});

test('the coordinator\'s listing rules accept the producer listing and refuse a tampered one; discovery binds it to the DID seller', async () => {
  const published = await publish();
  await verifyBundleListing(published.listing as never, { verifySignature: agentDidSignatureVerifier as never });
  const tampered = { ...published.listing, pricing: { kind: 'fixed', price: { amount: '2', currency: 'DEM' } } };
  await rejects(verifyBundleListing(tampered as never, { verifySignature: agentDidSignatureVerifier as never }), /listing signature is invalid/);
  const stranger = keyOf('stranger');
  const strangerDid = agentDidForPubkey(stranger.pubKey);
  // A stranger's valid signature over the same scope is refused on the presenter check: the signer is not the claim the identity bundle presents.
  const strangerValue = Buffer.from(sign(DOMAIN_SEPARATORS.LISTING, new TextEncoder().encode(published.contentHash), stranger.privKey)).toString('base64url');
  const resigned = { ...published.listing, signature: { algorithm: 'ed25519', signer: strangerDid, value: strangerValue } };
  await rejects(verifyBundleListing(resigned as never, { verifySignature: agentDidSignatureVerifier as never }), /listing signer is not the primary claim/);
  const artifacts = buildDiscoveryArtifacts({ listing: published.listing, sellerPrimaryClaim: sellerDid, nativeAddress: published.locator, publisherOrigin: 'https://organ.path-os.invalid', generatedAt: NOW });
  equal(artifacts.index.seller, sellerDid);
  equal(artifacts.index.listings[0]!.contentHash, published.contentHash);
  equal(artifacts.index.listings[0]!.logical_address, published.logicalAddress);
  const anchorByOther = () => buildDiscoveryArtifacts({ listing: published.listing, sellerPrimaryClaim: strangerDid, nativeAddress: published.locator, publisherOrigin: 'https://organ.path-os.invalid', generatedAt: NOW });
  let refused = false;
  try { anchorByOther(); } catch (e) { refused = /does not present the address seller/.test((e as Error).message); }
  equal(refused, true);
});

test('the structural check refuses what the pinned SDK\'s isListing would refuse, member by member, on correctly signed records', async () => {
  const published = await publish();
  const signer = keypairSigner(seller);
  const { signature: _signature, ...scope } = published.listing; void _signature;
  const resign = async (mutate: (unsigned: Record<string, unknown>) => Record<string, unknown>) => (await signDacs1Listing(mutate({ ...scope }), signer)).listing;
  const refused = async (listing: unknown, reason: RegExp) => { let message = ''; try { assertDacs1Listing(listing); } catch (e) { message = (e as Error).message; } match(message, reason); };
  assertDacs1Listing(published.listing);
  // A member outside §6.3.4 inside the signed scope (the class the review found: a self contentHash the finalizer tolerates) is refused before any signature check.
  await refused(await resign((u) => ({ ...u, contentHash: published.contentHash })), /contentHash is not a DACS-1 §6.3.4 member/);
  await refused(await resign((u) => ({ ...u, offering: null })), /offering/);
  await refused(await resign((u) => ({ ...u, pricing: null })), /pricing/);
  await refused(await resign((u) => ({ ...u, buyerRequirement: null })), /buyerRequirement/);
  await refused(await resign((u) => ({ ...u, terms: null })), /terms/);
  await refused(await resign((u) => ({ ...u, validity: null })), /validity/);
  await refused(await resign((u) => ({ ...u, pipeline: [{ kind: 'identify' }, ...(u.pipeline as unknown[])] })), /not a PhaseStep kind: identify/);
  await refused(await resign((u) => ({ ...u, pipeline: [{ kind: 'pay-dem' }] })), /pay-dem needs parameters/);
  await refused(await resign((u) => ({ ...u, pipeline: [{ kind: 'vet-credentials', parameters: {} }] })), /takes no parameters/);
  await refused(await resign((u) => ({ ...u, listingId: 'has:colon' })), /listingId/);
  await refused(await resign((u) => ({ ...u, logical_address: listingLogicalAddress(sellerDid, 'other-listing', 1) })), /logical_address must be the CF-4 address/);
  await refused(await resign((u) => { const { logical_address: _l, ...rest } = u; void _l; return rest; }), /logical_address must be the CF-4 address/);
  await refused(await resign((u) => ({ ...u, validity: { notBefore: NOW, notAfter: NOW - 1 } })), /notAfter >= notBefore/);
  // A stranger presented as signer without a matching identity claim.
  await refused({ ...published.listing, signature: { ...(published.listing.signature as object), signer: agentDidForPubkey(keyOf('stranger').pubKey) } }, /signer must be the claim the seller identity bundle presents/);
});

test('the LR-2 cap is measured on the complete signed record, as the pinned SDK measures it', async () => {
  const published = await publish();
  const signer = keypairSigner(seller);
  const { signature: _signature, ...scope } = published.listing; void _signature;
  const signedOverhead = jcsCanonical(published.listing).length - jcsCanonical(scope).length;
  ok(signedOverhead > 100, `a signature adds ${signedOverhead} bytes`);
  // Pad an uncapped member (terms.termsOfServiceUrl) so the unsigned scope sits under the cap while the signed record does not.
  const withUrl = (url: string) => ({ ...scope, terms: { ...(scope.terms as object), termsOfServiceUrl: url } });
  const pad = (target: number) => { let d = 'https://terms.invalid/'; while (jcsCanonical(withUrl(d)).length < target) d += 'x'; return d; };
  const under = withUrl(pad(DACS1_LISTING_SIZE_CAP_BYTES - Math.floor(signedOverhead / 2)));
  equal(jcsCanonical(under).length <= DACS1_LISTING_SIZE_CAP_BYTES, true);
  const signedOver = (await signDacs1Listing(under, signer)).listing;
  ok(jcsCanonical(signedOver).length > DACS1_LISTING_SIZE_CAP_BYTES);
  let message = ''; try { assertDacs1Listing(signedOver); } catch (e) { message = (e as Error).message; }
  match(message, /over the LR-2 cap of 16384/);
  const fits = withUrl(pad(DACS1_LISTING_SIZE_CAP_BYTES - signedOverhead - 64));
  const signedFits = (await signDacs1Listing(fits, signer)).listing;
  ok(jcsCanonical(signedFits).length <= DACS1_LISTING_SIZE_CAP_BYTES);
  assertDacs1Listing(signedFits);
});

test('a listing the coordinator\'s rules would refuse never reaches the anchor', async () => {
  const anchored: Array<{ programName: string }> = [];
  const broken: ProducerKeypair = { privKey: seller.privKey, pubKey: keyOf('stranger').pubKey };
  await rejects(publishProducerListing({
    jobId: 'job-producer-2', seller: broken, displayName: 'x',
    offering: { title: 't', description: 'd', category: 'c', tags: [], deliverable: { kind: 'storage-program' } },
    price: { amount: '1', currency: 'DEM' }, railId: 'pay-dem', pipeline: PIPELINE, now: NOW,
    anchor: (programName) => { anchored.push({ programName }); return 'stor-never'; },
  }), /identity presentation does not verify|listing signature is invalid/);
  equal(anchored.length, 0);
});

test('the AP2 test agent and the organ gateway publish through the shared producer listing (no v0.1 body, no opaque name)', () => {
  for (const file of ['src/live/ap2-test-agent.mts', 'src/live/organ-gateway.mts']) {
    const source = readFileSync(file, 'utf8');
    match(source, /publishProducerListing\(\{/);
    match(source, /verifyBundleListing\(/);
    equal(source.includes('opaqueListingProgramName'), false, `${file} still names the listing opaquely`);
    equal(source.includes("v: 'dacs-listing:0.1'"), false, `${file} still emits the v0.1 listing body`);
  }
});

test('the AP2 test agent dry run anchors the DACS-1 listing under the SDK-form name and passes its own vet', () => {
  const childEnv: NodeJS.ProcessEnv = { ...process.env, JOB_ID: 'ap2-producer-test' };
  delete childEnv.NODE_TEST_CONTEXT;
  const run = spawnSync(process.execPath, ['--import', 'tsx', 'src/live/ap2-test-agent.mts'], { cwd: process.cwd(), encoding: 'utf8', env: childEnv, timeout: 120_000 });
  equal(run.status, 0, run.stderr);
  match(run.stdout, /\[DACS-2\] seller did:demos:agent:[0-9a-f]{12}… verified over the anchored listing/);
  const report = JSON.parse(run.stdout.slice(run.stdout.indexOf('{\n'))) as { anchors: { listingProgramName: string } };
  match(report.anchors.listingProgramName, /^dacs1%3Adid%3Ademos%3Aagent%3A[0-9a-f]{64}%3Aap2-producer-test-listing%3Av1$/);
  notEqual(report.anchors.listingProgramName.indexOf('%3A'), -1);
  equal(report.anchors.listingProgramName.includes(':'), false);
});
