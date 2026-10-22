// Synthetic authority only. No identity, Vet or Listing verification is claimed.
export const NOW = 1780000000000;
export const JOB = '01J8ME0SXKQ4T9V2RC5HJ6WX7E';
export const claims = { buyer: 'did:demos:buyer-local-storyboard', seller: 'did:demos:seller-local-storyboard' };
function identity(ref) {
  return { bundleVersion: '1', presentedBy: ref, presentedAt: NOW - 1000,
    claims: [{ ref }], presentation: { kind: 'per-claim', signatures: [{ ref, signature: 'synthetic-identity-proof' }] } };
}
function party(role) {
  return { identityBundle: identity(claims[role]), vetRecordRef: {
    anchor: { kind: 'storage-program', locator: `stor:synthetic-${role}-vet` }, contentHash: 'a'.repeat(64) } };
}
export function input(contentHash) {
  const listing = {
    dacsVersion: '1', listingVersion: 3, listingId: 'local-rfq-storyboard', requiredCapabilities: ['SR-2', 'SR-4'],
    seller: { identity: identity(claims.seller), displayName: 'Local fixture seller', publicEndpoint: 'https://seller.example/dacs' },
    offering: { title: 'Local RFQ', description: 'Synthetic authority restart demonstration', category: 'data.finance', tags: ['rfq'],
      deliverable: { kind: 'attested-payload', payloadFormat: 'application/json', verificationMethod: { kind: 'self-signed' } } },
    buyerRequirement: { requirementVersion: '1', required: [] },
    pipeline: [{ kind: 'negotiate-rfq', parameters: { maxTurns: 5, timeoutSec: 10 } }, { kind: 'commit-agreement' }, { kind: 'deliver-attested-payload' }],
    pricing: { kind: 'negotiable', bandCenter: { amount: '10', currency: 'USDC' }, minPct: 20, maxPct: 20 },
    terms: { deadlineSecAfterCommit: 600 }, validity: { notBefore: NOW - 10000, notAfter: NOW + 1000000 },
    signature: { algorithm: 'ed25519', signer: claims.seller, value: Buffer.alloc(64, 7).toString('base64url') },
  };
  return { jobId: JOB, verifiedListing: { disposition: 'verified', listing,
    pin: { listingId: listing.listingId, version: listing.listingVersion, contentHash: contentHash(listing) } },
    buyer: party('buyer'), seller: party('seller'), channelId: 'local-storyboard-channel-01' };
}
