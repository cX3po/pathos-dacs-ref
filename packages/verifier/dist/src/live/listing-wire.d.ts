/**
 * DACS-1 §6.3.4 Listing and §6.3.2 IdentityBundle in the Standard's wire shape, as the pinned dacs-sdk's
 * isListing / isIdentityBundle validate them (dacs-sdk src/artifacts/validators.ts). The seller presents its own
 * identity bundle with a per-claim presentation: the wallet signs `dacs-bundle-presentation:v1:` || bundle_hash,
 * where bundle_hash is the JCS hash of the bundle with `presentation` omitted (DACS-1 §6.3.2). The listing is signed
 * over `dacs-listing:v1:` || JCS-hash(listing minus signature) (§6.3.4); it carries no self content hash, so the
 * ListingPin's contentHash and the signed scope are the same hash.
 */
import { type DomainSeparator } from '../domain-sep.js';
import type { AdapterSigner } from '../adapters/dacs/agreement-commitment.js';
/** DACS-1 §6.3.3 ClaimRequirement / BundleRequirement in the members this coordinator uses (the pinned SDK's isClaimRequirement / isBundleRequirement). */
export interface ClaimRequirementV1 {
    scheme: string;
    verificationRequired: boolean;
    maxAge?: number;
    recipeVersion?: number;
    parameters?: {
        verificationMethod?: string;
    };
}
export interface BundleRequirementV1 {
    requirementVersion: '1';
    required: ClaimRequirementV1[];
}
/** The requirement a party holds of a Demos agent counterparty: its DID claim, self-signed at recipe version 1 (the only recipe this session runs). */
export declare function selfSignedBundleRequirement(scheme: string): BundleRequirementV1;
export interface SellerIdentityBundle {
    bundleVersion: '1';
    presentedBy: string;
    presentedAt: number;
    claims: Array<{
        ref: string;
    }>;
    presentation: {
        kind: 'per-claim';
        signatures: Array<{
            ref: string;
            signature: string;
        }>;
    };
}
export interface Dacs1ListingInput {
    listingId: string;
    listingVersion: number;
    seller: {
        identity: SellerIdentityBundle;
        displayName: string;
    };
    offering: {
        title: string;
        description: string;
        category: string;
        tags: string[];
        deliverable: {
            kind: 'storage-program';
            schemaUrl?: string;
            accessModel?: 'public' | 'buyer-only' | 'encrypt-to-buyer';
        };
    };
    pricing: {
        kind: 'fixed';
        price: {
            amount: string;
            currency: string;
        };
    };
    acceptedRails: Array<{
        railId: string;
    }>;
    pipeline: ReadonlyArray<{
        kind: string;
        parameters?: Record<string, unknown>;
    }>;
    terms: {
        deadlineSecAfterCommit?: number;
    };
    validity: {
        notBefore: number;
        notAfter?: number;
    };
}
/** bundle_hash (§6.3.2): the identity bundle with `presentation` omitted. */
export declare function identityBundleHash(bundle: Omit<SellerIdentityBundle, 'presentation'> | SellerIdentityBundle): string;
/** The seller's own identity bundle: one claim (its primary claim), presented per-claim by the wallet that holds it. */
/** An IdentityBundle presenting the signer's own primary claim with a per-claim presentation signature (DACS-1 §6.3.2). */
export declare function presentIdentity(signer: AdapterSigner, presentedAt: number): Promise<SellerIdentityBundle>;
export declare const presentSellerIdentity: typeof presentIdentity;
export type PresentationSignatureVerifier = (request: {
    domain: DomainSeparator;
    hash: string;
    signer: string;
    algorithm: string;
    value: string;
}) => Promise<boolean> | boolean;
/**
 * DACS-1 §6.3.2: the bundle's presenter is one of its claims and its per-claim presentation signature verifies over
 * `dacs-bundle-presentation:v1:` || bundle_hash under that claim. Returns the presenter claim; throws otherwise.
 */
export declare function verifyIdentityPresentation(identity: Record<string, unknown>, verifySignature: PresentationSignatureVerifier): Promise<string>;
/** The unsigned DACS-1 Listing: exactly the Standard's members, with the fixed-price pattern; the buyer requirement is the seller's actual policy: a Demos agent DID the buyer's wallet signs for (self-signed). */
export declare function dacs1Listing(input: Dacs1ListingInput): Record<string, unknown>;
/** Sign the listing (§6.3.4): `dacs-listing:v1:` || JCS-hash(listing minus signature). Returns the listing and that hash (the ListingPin contentHash). */
export declare function signDacs1Listing(unsigned: Record<string, unknown>, signer: AdapterSigner): Promise<{
    listing: Record<string, unknown>;
    contentHash: string;
}>;
/**
 * The storage program name the pinned dacs-sdk resolves a listing by: its logical address with each `:` percent-encoded
 * (dacs-sdk src/canonical/addressing.ts logicalToStorageProgramName). DACS-1 leaves the name implementation-defined
 * and colon-free; matching the SDK's choice is what lets its Agent find the listing by (seller owner, name).
 */
export declare function sdkListingProgramName(logicalAddress: string): string;
/** The DACS-4 DeliverableRef the agreement carries for a listing's DeliverableSpec, as agreement-commitment derives it: deliverableType = kind, hash = JCS hash of the spec. */
export declare function listingDeliverableRef(listing: Record<string, unknown>): {
    deliverableType: string;
    hash: string;
    schemaUrl?: string;
};
