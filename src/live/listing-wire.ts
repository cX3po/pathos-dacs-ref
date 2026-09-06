/**
 * DACS-1 §6.3.4 Listing and §6.3.2 IdentityBundle in the Standard's wire shape, as the pinned dacs-sdk's
 * isListing / isIdentityBundle validate them (dacs-sdk src/artifacts/validators.ts). The seller presents its own
 * identity bundle with a per-claim presentation: the wallet signs `dacs-bundle-presentation:v1:` || bundle_hash,
 * where bundle_hash is the JCS hash of the bundle with `presentation` omitted (DACS-1 §6.3.2). The listing is signed
 * over `dacs-listing:v1:` || JCS-hash(listing minus signature) (§6.3.4); it carries no self content hash, so the
 * ListingPin's contentHash and the signed scope are the same hash.
 */
import { DOMAIN_SEPARATORS, type DomainSeparator } from '../domain-sep.js';
import { jcsHashHex } from '../jcs.js';
import type { AdapterSigner } from '../adapters/dacs/agreement-commitment.js';

/** DACS-1 §6.3.3 ClaimRequirement / BundleRequirement in the members this coordinator uses (the pinned SDK's isClaimRequirement / isBundleRequirement). */
export interface ClaimRequirementV1 { scheme: string; verificationRequired: boolean; maxAge?: number; recipeVersion?: number; parameters?: { verificationMethod?: string } }
export interface BundleRequirementV1 { requirementVersion: '1'; required: ClaimRequirementV1[] }

/** The requirement a party holds of a Demos agent counterparty: its DID claim, self-signed at recipe version 1 (the only recipe this session runs). */
export function selfSignedBundleRequirement(scheme: string): BundleRequirementV1 {
  return { requirementVersion: '1', required: [{ scheme, verificationRequired: true, recipeVersion: 1, parameters: { verificationMethod: 'self-signed' } }] };
}

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
/** An IdentityBundle presenting the signer's own primary claim with a per-claim presentation signature (DACS-1 §6.3.2). */
export async function presentIdentity(signer: AdapterSigner, presentedAt: number): Promise<SellerIdentityBundle> {
  const claim = String(signer.claim);
  const unsigned = { bundleVersion: '1' as const, presentedBy: claim, presentedAt, claims: [{ ref: claim }] };
  const signature = signatureValue(await signer.sign(DOMAIN_SEPARATORS.BUNDLE_PRESENTATION, identityBundleHash(unsigned)));
  return { ...unsigned, presentation: { kind: 'per-claim', signatures: [{ ref: claim, signature }] } };
}
export const presentSellerIdentity = presentIdentity;

export type PresentationSignatureVerifier = (request: { domain: DomainSeparator; hash: string; signer: string; algorithm: string; value: string }) => Promise<boolean> | boolean;

/**
 * DACS-1 §6.3.2: the bundle's presenter is one of its claims and its per-claim presentation signature verifies over
 * `dacs-bundle-presentation:v1:` || bundle_hash under that claim. Returns the presenter claim; throws otherwise.
 */
export async function verifyIdentityPresentation(identity: Record<string, unknown>, verifySignature: PresentationSignatureVerifier): Promise<string> {
  const presentedBy = identity.presentedBy;
  const claims = Array.isArray(identity.claims) ? identity.claims.map((c) => (c as { ref?: unknown })?.ref) : [];
  if (identity.bundleVersion !== '1' || typeof presentedBy !== 'string' || !claims.includes(presentedBy)) throw new Error('identity bundle presenter is not one of its claims (§6.3.2)');
  const presentation = identity.presentation as { kind?: unknown; signatures?: Array<{ ref?: unknown; signature?: unknown }> } | undefined;
  if (presentation?.kind !== 'per-claim' || !Array.isArray(presentation.signatures)) throw new Error('identity presentation kind is not supported here (per-claim expected)');
  const entry = presentation.signatures.find((entry) => entry?.ref === presentedBy);
  const { presentation: _presentation, ...scope } = identity; void _presentation;
  const ok = entry !== undefined && typeof entry.signature === 'string'
    && await verifySignature({ domain: DOMAIN_SEPARATORS.BUNDLE_PRESENTATION, hash: identityBundleHash(scope as Omit<SellerIdentityBundle, 'presentation'>), signer: presentedBy, algorithm: 'ed25519', value: entry.signature });
  if (!ok) throw new Error('identity presentation does not verify (§6.3.2)');
  return presentedBy;
}

/** The unsigned DACS-1 Listing: exactly the Standard's members, with the fixed-price pattern; the buyer requirement is the seller's actual policy: a Demos agent DID the buyer's wallet signs for (self-signed). */
export function dacs1Listing(input: Dacs1ListingInput): Record<string, unknown> {
  return {
    dacsVersion: '1',
    listingVersion: input.listingVersion,
    listingId: input.listingId,
    seller: { identity: input.seller.identity, displayName: input.seller.displayName },
    offering: { title: input.offering.title, description: input.offering.description, category: input.offering.category, tags: input.offering.tags, deliverable: input.offering.deliverable },
    buyerRequirement: selfSignedBundleRequirement('did'),
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
