import { sha256 } from '@noble/hashes/sha2';
const CF4_RESERVED = /[:?&=%]/g;
const LISTING_ID = /^[A-Za-z0-9._~-]+$/;
const CLAIM_SCHEME = /^[a-z][a-z0-9-]*$/;
/** Closed DACS-1 v0.1 ClaimReference registry (§6.3.1). */
const REGISTERED_CLAIM_SCHEMES = new Set([
    'cci-xm',
    'cci-web2',
    'cci-pqc',
    'cci-ud',
    'cci-nomis',
    'cci-humanpassport',
    'cci-ethos',
    'cci-tlsn',
    'stor-cred',
    'did',
    'erc8004',
    'domain',
    'key',
    'substrate-validator-set',
    'lei',
    'finra-crd',
    'sam-uei',
    'fedramp',
    'naics',
    'cmmc',
]);
export function bytesSha256Hex(bytes) {
    return Array.from(sha256(bytes), (b) => b.toString(16).padStart(2, '0')).join('');
}
/** CORE §B.1 CF-4 percent-encoding for one variable logical-address segment. */
export function cf4Encode(segment) {
    return segment.replace(CF4_RESERVED, (ch) => `%${ch.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')}`);
}
/** Strict CF-4 decoder: malformed percent escapes are rejected, never preserved. */
export function cf4Decode(segment) {
    if (/%(?![0-9A-Fa-f]{2})/.test(segment)) {
        throw new Error(`malformed CF-4 percent escape in "${segment}"`);
    }
    return segment.replace(/%[0-9A-Fa-f]{2}/g, (hex) => String.fromCharCode(Number.parseInt(hex.slice(1), 16)));
}
/** Render the legacy object form into the spec's canonical ClaimReference string form. */
export function formatClaimReference(ref) {
    const scheme = ref.scheme.toLowerCase();
    if (!CLAIM_SCHEME.test(scheme))
        throw new Error(`invalid ClaimReference scheme: ${ref.scheme}`);
    if (!ref.identifier)
        throw new Error('ClaimReference identifier must be non-empty');
    const identifier = ref.identifier.normalize('NFC');
    const params = Object.entries(ref.params ?? {}).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
    if (params.length === 0)
        return `${scheme}:${identifier}`;
    const encoded = params.map(([key, value]) => `${cf4Encode(key)}=${cf4Encode(value)}`).join('&');
    return `${scheme}:${identifier}?${encoded}`;
}
export function assertRegisteredClaimReference(claimReference) {
    const colon = claimReference.indexOf(':');
    if (colon <= 0)
        throw new Error(`malformed ClaimReference: ${claimReference}`);
    const scheme = claimReference.slice(0, colon);
    if (!REGISTERED_CLAIM_SCHEMES.has(scheme)) {
        throw new Error(`ClaimReference scheme "${scheme}" is not registered in DACS-1 v0.1`);
    }
    const identifier = claimReference.slice(colon + 1).split('?', 1)[0];
    if (scheme === 'key' && !/^[0-9a-f]{64}$/.test(identifier)) {
        throw new Error('key: ClaimReference identifier must be a lowercase 32-byte hex public key');
    }
}
/** Assemble the stable listing logical address with the seller claim CF-4 encoded. */
export function listingLogicalAddress(sellerPrimaryClaim, listingId, listingVersion) {
    assertRegisteredClaimReference(sellerPrimaryClaim);
    if (!LISTING_ID.test(listingId) || listingId.length > 128) {
        throw new Error('listingId must be 1..128 URL-safe ASCII characters');
    }
    if (!Number.isSafeInteger(listingVersion) || listingVersion < 1) {
        throw new Error('listingVersion must be a positive safe integer');
    }
    return `dacs1:${cf4Encode(sellerPrimaryClaim)}:${listingId}:v${listingVersion}`;
}
export function parseListingLogicalAddress(logicalAddress) {
    const match = /^dacs1:([^:]+):([^:]+):v([1-9][0-9]*)$/.exec(logicalAddress);
    if (!match)
        throw new Error(`malformed DACS-1 listing logical address: ${logicalAddress}`);
    const sellerPrimaryClaim = cf4Decode(match[1]);
    const listingId = match[2];
    const listingVersion = Number(match[3]);
    const canonical = listingLogicalAddress(sellerPrimaryClaim, listingId, listingVersion);
    if (canonical !== logicalAddress) {
        throw new Error(`non-canonical DACS-1 listing logical address: ${logicalAddress}`);
    }
    return { sellerPrimaryClaim, listingId, listingVersion };
}
/**
 * Opaque, colon-free Demos write input. It is deliberately not a discovery key:
 * consumers resolve through the published logical→native binding (§6.3.4(c)).
 */
export function opaqueListingProgramName(logicalAddress) {
    parseListingLogicalAddress(logicalAddress);
    const digest = bytesSha256Hex(new TextEncoder().encode(logicalAddress));
    const programName = `dacs1listing-${digest}`;
    if (programName.includes(':'))
        throw new Error('listing Storage Program name must be colon-free');
    return programName;
}
