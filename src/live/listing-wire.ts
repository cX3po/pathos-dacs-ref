/**
 * DACS-1 §6.3.4 Listing and §6.3.2 IdentityBundle in the Standard's wire shape, as the pinned dacs-sdk's
 * isListing / isIdentityBundle validate them (dacs-sdk src/artifacts/validators.ts). The seller presents its own
 * identity bundle with a per-claim presentation: the wallet signs `dacs-bundle-presentation:v1:` || bundle_hash,
 * where bundle_hash is the JCS hash of the bundle with `presentation` omitted (DACS-1 §6.3.2). The listing is signed
 * over `dacs-listing:v1:` || JCS-hash(listing minus signature) (§6.3.4); it carries no self content hash, so the
 * ListingPin's contentHash and the signed scope are the same hash.
 */
import { DOMAIN_SEPARATORS } from '../domain-sep.js';
import { jcsHashHex } from '../jcs.js';
import type { AdapterSigner } from '../adapters/dacs/agreement-commitment.js';

export interface SellerIdentityBundle {
  bundleVersion: '1';
  presentedBy: string;
  presentedAt: number;
  claims: Array<{ ref: string }>;
  presentation: { kind: 'per-claim'; signatures: Array<{ ref: string; signature: string }> };
}

export interface Dacs1ListingInput {
  listingId: string;
  listingVersion: number;
  seller: { identity: SellerIdentityBundle; displayName: string };
  offering: { title: string; description: string; category: string; tags: string[]; deliverable: { kind: 'storage-program'; schemaUrl?: string; accessModel?: 'public' | 'buyer-only' | 'encrypt-to-buyer' } };
  pricing: { kind: 'fixed'; price: { amount: string; currency: string } };
  acceptedRails: Array<{ railId: string }>;
  pipeline: ReadonlyArray<{ kind: string; parameters?: Record<string, unknown> }>;
  terms: { deadlineSecAfterCommit?: number };
  validity: { notBefore: number; notAfter?: number };
}

function signatureValue(value: string | Uint8Array): string {
  return typeof value === 'string' ? value : Buffer.from(value).toString('base64url');
}

/** bundle_hash (§6.3.2): the identity bundle with `presentation` omitted. */
export function identityBundleHash(bundle: Omit<SellerIdentityBundle, 'presentation'> | SellerIdentityBundle): string {
  const { presentation: _presentation, ...scope } = bundle as SellerIdentityBundle;
  void _presentation;
  return jcsHashHex(scope);
}

/** The seller's own identity bundle: one claim (its primary claim), presented per-claim by the wallet that holds it. */
export async function presentSellerIdentity(signer: AdapterSigner, presentedAt: number): Promise<SellerIdentityBundle> {
  const claim = String(signer.claim);
  const unsigned = { bundleVersion: '1' as const, presentedBy: claim, presentedAt, claims: [{ ref: claim }] };
  const signature = signatureValue(await signer.sign(DOMAIN_SEPARATORS.BUNDLE_PRESENTATION, identityBundleHash(unsigned)));
  return { ...unsigned, presentation: { kind: 'per-claim', signatures: [{ ref: claim, signature }] } };
}

/** The unsigned DACS-1 Listing: exactly the Standard's members, with the fixed-price pattern and an empty buyer requirement. */
export function dacs1Listing(input: Dacs1ListingInput): Record<string, unknown> {
  return {
    dacsVersion: '1',
    listingVersion: input.listingVersion,
    listingId: input.listingId,
    seller: { identity: input.seller.identity, displayName: input.seller.displayName },
    offering: { title: input.offering.title, description: input.offering.description, category: input.offering.category, tags: input.offering.tags, deliverable: input.offering.deliverable },
    buyerRequirement: { requirementVersion: '1', required: [] },
    pipeline: input.pipeline.map((step) => (step.parameters === undefined ? { kind: step.kind } : { kind: step.kind, parameters: step.parameters })),
    pricing: input.pricing,
    acceptedRails: input.acceptedRails,
    terms: input.terms,
    validity: input.validity,
  };
}

/** Sign the listing (§6.3.4): `dacs-listing:v1:` || JCS-hash(listing minus signature). Returns the listing and that hash (the ListingPin contentHash). */
export async function signDacs1Listing(unsigned: Record<string, unknown>, signer: AdapterSigner): Promise<{ listing: Record<string, unknown>; contentHash: string }> {
  const contentHash = jcsHashHex(unsigned);
  const value = signatureValue(await signer.sign(DOMAIN_SEPARATORS.LISTING, contentHash));
  return { listing: { ...unsigned, signature: { algorithm: 'ed25519', signer: String(signer.claim), value } }, contentHash };
}

/**
 * The storage program name the pinned dacs-sdk resolves a listing by: its logical address with each `:` percent-encoded
 * (dacs-sdk src/canonical/addressing.ts logicalToStorageProgramName). DACS-1 leaves the name implementation-defined
 * and colon-free; matching the SDK's choice is what lets its Agent find the listing by (seller owner, name).
 */
export function sdkListingProgramName(logicalAddress: string): string {
  return logicalAddress.replace(/:/g, '%3A');
}

/** The DACS-4 DeliverableRef the agreement carries for a listing's DeliverableSpec, as agreement-commitment derives it: deliverableType = kind, hash = JCS hash of the spec. */
export function listingDeliverableRef(listing: Record<string, unknown>): { deliverableType: string; hash: string; schemaUrl?: string } {
  const offering = listing.offering as Record<string, unknown> | undefined;
  const spec = offering?.deliverable as Record<string, unknown> | undefined;
  if (!spec || typeof spec.kind !== 'string') throw new Error('listing offering.deliverable must be a DeliverableSpec with a kind');
  const ref: { deliverableType: string; hash: string; schemaUrl?: string } = { deliverableType: spec.kind, hash: jcsHashHex(spec) };
  if (typeof spec.schemaUrl === 'string') ref.schemaUrl = spec.schemaUrl;
  return ref;
}
