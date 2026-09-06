import type { AdapterSigner } from '../adapters/dacs/agreement-commitment.js';
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
export declare function presentSellerIdentity(signer: AdapterSigner, presentedAt: number): Promise<SellerIdentityBundle>;
/** The unsigned DACS-1 Listing: exactly the Standard's members, with the fixed-price pattern and an empty buyer requirement. */
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
