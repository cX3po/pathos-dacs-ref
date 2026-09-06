export interface ClaimReferenceParts {
    scheme: string;
    identifier: string;
    params?: Record<string, string>;
}
export interface ListingLogicalAddressParts {
    sellerPrimaryClaim: string;
    listingId: string;
    listingVersion: number;
}
export declare function bytesSha256Hex(bytes: Uint8Array): string;
/** CORE §B.1 CF-4 percent-encoding for one variable logical-address segment. */
export declare function cf4Encode(segment: string): string;
/** Strict CF-4 decoder: malformed percent escapes are rejected, never preserved. */
export declare function cf4Decode(segment: string): string;
/** Render the legacy object form into the spec's canonical ClaimReference string form. */
export declare function formatClaimReference(ref: ClaimReferenceParts): string;
export declare function assertRegisteredClaimReference(claimReference: string): void;
/** Assemble the stable listing logical address with the seller claim CF-4 encoded. */
export declare function listingLogicalAddress(sellerPrimaryClaim: string, listingId: string, listingVersion: number): string;
export declare function parseListingLogicalAddress(logicalAddress: string): ListingLogicalAddressParts;
/**
 * Opaque, colon-free Demos write input. It is deliberately not a discovery key:
 * consumers resolve through the published logical→native binding (§6.3.4(c)).
 */
export declare function opaqueListingProgramName(logicalAddress: string): string;
