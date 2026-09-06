/**
 * Differential: the producers' pre-flight (assertDacs1Listing) against the pinned dacs-sdk's own isListing, on the
 * shapes the producers emit and on every refusal the reviews of feat/producers-dacs1-listing found. A hand-written
 * mirror drifts; this test measures the drift instead of restating the mirror. Runs when DACS_SDK_DIR points at the
 * pinned SDK checkout (its dist/artifacts/validators.js); skipped otherwise, like the C1 bridge.
 */
import { equal, ok } from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { sha256 } from '@noble/hashes/sha2';
import { ed25519 } from '@noble/curves/ed25519';
import { jcsHashHex } from '../../src/jcs.js';
import { signDacs1Listing } from '../../src/live/listing-wire.js';
import { agentDidForPubkey, assertDacs1Listing, keypairSigner, publishProducerListing, type ProducerKeypair } from '../../src/live/producer-listing.js';

const sdkDir = process.env.DACS_SDK_DIR;
const validators = sdkDir ? join(sdkDir, 'dist', 'artifacts', 'validators.js') : undefined;
const skip = !validators || !existsSync(validators)
  ? 'SDK differential skipped: set DACS_SDK_DIR to the pinned dacs-sdk checkout (built dist)'
  : false;

const keyOf = (label: string): ProducerKeypair => {
  const privKey = sha256(new TextEncoder().encode(`producer-listing-differential:${label}`));
  return { privKey, pubKey: ed25519.getPublicKey(privKey) };
};
const seller = keyOf('seller');
const sellerDid = agentDidForPubkey(seller.pubKey);
const NOW = 1_788_720_000_000;
const PIPELINE = [
  { kind: 'vet-credentials' }, { kind: 'negotiate-fixed-price' }, { kind: 'commit-agreement' },
  { kind: 'pay-dem', parameters: { rail: 'pay-dem' } }, { kind: 'deliver-storage-program' },
] as const;

/** `stricter`: the SDK tolerates the shape; our pre-flight refuses it on purpose (declared, not drift). */
type Mutation = { name: string; stricter?: true; unsigned?: (u: Record<string, unknown>) => Record<string, unknown>; signed?: (l: Record<string, unknown>) => Record<string, unknown> };
const step = (kind: string, parameters?: Record<string, unknown>) => (parameters === undefined ? { kind } : { kind, parameters });

/** Every case both reviews raised, plus valid variants: each is applied to the unsigned scope and re-signed (a valid signature), or to the signed record. */
const MUTATIONS: Mutation[] = [
  { name: 'baseline' },
  // The SDK's isListing does not pin the member set; we refuse a member outside §6.3.4 on purpose (a self contentHash inside the signed scope).
  { name: 'contentHash member inside the signed scope', stricter: true, unsigned: (u) => ({ ...u, contentHash: jcsHashHex(u) }) },
  { name: 'offering null', unsigned: (u) => ({ ...u, offering: null }) },
  { name: 'pricing null', unsigned: (u) => ({ ...u, pricing: null }) },
  { name: 'buyerRequirement null', unsigned: (u) => ({ ...u, buyerRequirement: null }) },
  { name: 'terms null', unsigned: (u) => ({ ...u, terms: null }) },
  { name: 'validity null', unsigned: (u) => ({ ...u, validity: null }) },
  { name: 'amount "0"', unsigned: (u) => ({ ...u, pricing: { kind: 'fixed', price: { amount: '0', currency: 'DEM' } } }) },
  { name: 'amount "01"', unsigned: (u) => ({ ...u, pricing: { kind: 'fixed', price: { amount: '01', currency: 'DEM' } } }) },
  { name: 'amount "1.50"', unsigned: (u) => ({ ...u, pricing: { kind: 'fixed', price: { amount: '1.50', currency: 'DEM' } } }) },
  { name: 'currency ""', unsigned: (u) => ({ ...u, pricing: { kind: 'fixed', price: { amount: '1', currency: '' } } }) },
  { name: 'pipeline with identify', unsigned: (u) => ({ ...u, pipeline: [step('identify'), ...(u.pipeline as unknown[])] }) },
  { name: 'pipeline without commit', unsigned: (u) => ({ ...u, pipeline: [step('vet-credentials'), step('negotiate-fixed-price'), step('pay-dem', { rail: 'pay-dem' }), step('deliver-storage-program')] }) },
  { name: 'pipeline commit not right after negotiate', unsigned: (u) => ({ ...u, pipeline: [step('negotiate-fixed-price'), step('vet-credentials'), step('commit-agreement'), step('pay-dem', { rail: 'pay-dem' }), step('deliver-storage-program')] }) },
  { name: 'pipeline without deliver', unsigned: (u) => ({ ...u, pipeline: [step('negotiate-fixed-price'), step('commit-agreement'), step('pay-dem', { rail: 'pay-dem' })] }) },
  { name: 'pay-dem without parameters', unsigned: (u) => ({ ...u, pipeline: [step('negotiate-fixed-price'), step('commit-agreement'), step('pay-dem'), step('deliver-storage-program')] }) },
  { name: 'pay rail not in acceptedRails', unsigned: (u) => ({ ...u, pipeline: [step('negotiate-fixed-price'), step('commit-agreement'), step('pay-dem', { rail: 'pay-x402' }), step('deliver-storage-program')] }) },
  { name: 'acceptedRails empty with a pay phase', unsigned: (u) => ({ ...u, acceptedRails: [] }) },
  { name: 'acceptedRails repeated', unsigned: (u) => ({ ...u, acceptedRails: [{ railId: 'pay-dem' }, { railId: 'pay-dem' }] }) },
  { name: 'vet-credentials with parameters', unsigned: (u) => ({ ...u, pipeline: [step('vet-credentials', {}), step('negotiate-fixed-price'), step('commit-agreement'), step('pay-dem', { rail: 'pay-dem' }), step('deliver-storage-program')] }) },
  { name: 'rate with parameters null', unsigned: (u) => ({ ...u, pipeline: [...(u.pipeline as unknown[]), { kind: 'rate', parameters: null }] }) },
  { name: 'rate without parameters (valid)', unsigned: (u) => ({ ...u, pipeline: [...(u.pipeline as unknown[]), step('rate')] }) },
  { name: 'rate with required boolean (valid)', unsigned: (u) => ({ ...u, pipeline: [...(u.pipeline as unknown[]), step('rate', { required: true })] }) },
  { name: 'deliver-attested-payload without a verification method', unsigned: (u) => ({ ...u, offering: { ...(u.offering as object), deliverable: { kind: 'attested-payload', payloadFormat: 'application/json' } }, pipeline: [step('negotiate-fixed-price'), step('commit-agreement'), step('pay-dem', { rail: 'pay-dem' }), step('deliver-attested-payload')] }) },
  { name: 'deliver-attested-payload with self-signed (valid)', unsigned: (u) => ({ ...u, offering: { ...(u.offering as object), deliverable: { kind: 'attested-payload', payloadFormat: 'application/json', verificationMethod: { kind: 'self-signed' } } }, pipeline: [step('negotiate-fixed-price'), step('commit-agreement'), step('pay-dem', { rail: 'pay-dem' }), step('deliver-attested-payload')] }) },
  { name: 'recipeVersion null', unsigned: (u) => ({ ...u, buyerRequirement: { requirementVersion: '1', required: [{ scheme: 'did', verificationRequired: true, recipeVersion: null }] } }) },
  { name: 'requirement parameters null', unsigned: (u) => ({ ...u, buyerRequirement: { requirementVersion: '1', required: [{ scheme: 'did', verificationRequired: true, parameters: null }] } }) },
  { name: 'requirement maxAge uint (valid)', unsigned: (u) => ({ ...u, buyerRequirement: { requirementVersion: '1', required: [{ scheme: 'did', verificationRequired: true, maxAge: 3600 }] } }) },
  { name: 'storage-program schemaUrl null', unsigned: (u) => ({ ...u, offering: { ...(u.offering as object), deliverable: { kind: 'storage-program', schemaUrl: null } } }) },
  { name: 'storage-program schemaUrl string (valid)', unsigned: (u) => ({ ...u, offering: { ...(u.offering as object), deliverable: { kind: 'storage-program', schemaUrl: 'https://schema.invalid/answer.json' } } }) },
  { name: 'termsOfServiceUrl null', unsigned: (u) => ({ ...u, terms: { ...(u.terms as object), termsOfServiceUrl: null } }) },
  { name: 'termsOfServiceUrl string (valid)', unsigned: (u) => ({ ...u, terms: { ...(u.terms as object), termsOfServiceUrl: 'https://terms.invalid/' } }) },
  { name: 'jurisdictions bad code', unsigned: (u) => ({ ...u, terms: { ...(u.terms as object), jurisdictions: ['usa'] } }) },
  { name: 'requiredCapabilities SR-2 (valid)', unsigned: (u) => ({ ...u, requiredCapabilities: ['SR-2'] }) },
  { name: 'requiredCapabilities unknown', unsigned: (u) => ({ ...u, requiredCapabilities: ['sr-2-anchored-storage'] }) },
  { name: 'listingId with colon', unsigned: (u) => ({ ...u, listingId: 'has:colon' }) },
  { name: 'notAfter before notBefore', unsigned: (u) => ({ ...u, validity: { notBefore: NOW, notAfter: NOW - 1 } }) },
  { name: 'tags over 16', unsigned: (u) => ({ ...u, offering: { ...(u.offering as object), tags: Array.from({ length: 17 }, (_, i) => `t${i}`) } }) },
  { name: 'title over 200', unsigned: (u) => ({ ...u, offering: { ...(u.offering as object), title: 'x'.repeat(201) } }) },
  { name: 'category with empty part', unsigned: (u) => ({ ...u, offering: { ...(u.offering as object), category: 'proof..organ' } }) },
  { name: 'presentation signatures empty', unsigned: (u) => ({ ...u, seller: { ...(u.seller as object), identity: { ...((u.seller as { identity: object }).identity), presentation: { kind: 'per-claim', signatures: [] } } } }) },
  { name: 'signature value with padding', signed: (l) => ({ ...l, signature: { ...(l.signature as object), value: `${(l.signature as { value: string }).value}==` } }) },
  { name: 'signature value base64 (not url)', signed: (l) => ({ ...l, signature: { ...(l.signature as object), value: Buffer.from((l.signature as { value: string }).value, 'base64url').toString('base64') } }) },
];

test('the producers\' pre-flight agrees with the pinned SDK\'s isListing on every enumerated shape (logical_address and the sdk-form name included)', { skip }, async (t) => {
  const { isListing } = await import(validators!) as { isListing: (v: unknown) => boolean };
  const published = await publishProducerListing({
    jobId: 'job-differential', seller, displayName: 'PATH-OS proof organ',
    offering: { title: 'weather band', description: 'a public answer for a committed query', category: 'proof-organ', tags: ['nws_alerts'], deliverable: { kind: 'storage-program', accessModel: 'public' } },
    price: { amount: '1', currency: 'DEM' }, railId: 'pay-dem', pipeline: PIPELINE, now: NOW,
    anchor: () => `stor-${'ab'.repeat(20)}`,
  });
  const signer = keypairSigner(seller);
  const { signature: _signature, ...scope } = published.listing; void _signature;
  const disagreements: string[] = [];
  let refusals = 0;
  for (const m of MUTATIONS) {
    let record: Record<string, unknown>;
    if (m.unsigned) record = (await signDacs1Listing(m.unsigned({ ...scope }), signer)).listing;
    else record = { ...published.listing };
    if (m.signed) record = m.signed(record);
    let local = true; let reason = '';
    try { assertDacs1Listing(record); } catch (e) { local = false; reason = (e as Error).message; }
    const sdk = isListing(record);
    if (!sdk) refusals += 1;
    const expectedLocal = m.stricter ? false : sdk;
    if (m.stricter && !sdk) disagreements.push(`${m.name}: declared stricter than the SDK, but the SDK refuses it too (drop the flag)`);
    if (local !== expectedLocal) disagreements.push(`${m.name}: local=${local} sdk=${sdk}${reason ? ` (${reason})` : ''}`);
  }
  equal(disagreements.length, 0, disagreements.join('\n'));
  t.diagnostic(`SDK refused ${refusals} of ${MUTATIONS.length} shapes; local agreed on every one but the declared stricter rule`);
  ok(refusals >= 30, `the enumeration must exercise refusals (SDK refused ${refusals} of ${MUTATIONS.length})`);
  equal(isListing(published.listing), true);
});
