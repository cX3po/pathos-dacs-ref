/**
 * The vet phase's party evaluation, shared by the live coordinator and the dry-run fixtures so both anchor the same
 * records: each party presents a DACS-1 identity bundle (the seller's inside its listing, the buyer's here), the
 * counterparty's key signs a self-signed VerifyResult over that presentation and the DACS-2 §7.7 composite that
 * evaluates it under the requirement the counterparty holds, and the composite is what the agreement cites (DACS-3 §8.5).
 */
import { jcsHashHex } from '../jcs.js';
import { anchorNames } from './anchor-naming.js';
import { identityBundleHash, presentIdentity, verifyIdentityPresentation, selfSignedBundleRequirement, type BundleRequirementV1, type PresentationSignatureVerifier } from './listing-wire.js';
import { emitVerifyResult, emitCompositeRecord, compositeRecordAddress, vetRecordAddress, vetRecordProgramName, requireConfiguredSellerIdentity, splitClaim, type PartyVetRefs, type VetRecordRefs, type VetDecision, type VetMethod } from './vet-record.js';
import type { AdapterSigner } from '../adapters/dacs/agreement-commitment.js';
import type { AttestationRef } from '../types/verify-result.js';

export interface PartyVetRecordSummary { method: VetMethod; decision: VetDecision; composite: VetDecision }
export type PartyVetRecords = Record<'buyer' | 'seller', PartyVetRecordSummary>;

export interface PartyVetInput {
  jobId: string;
  listing: Record<string, unknown>;
  /** The anchored listing: the seller VerifyResult's attestation. */
  listingRef: AttestationRef;
  signers: { buyer: AdapterSigner; seller: AdapterSigner };
  anchor: (request: { logicalAddress: string; content: unknown; contentHash: string }) => Promise<{ nativeAddress: string }>;
  verifySignature: PresentationSignatureVerifier;
  now: number;
}

export interface PartyVetOutput { refs: VetRecordRefs; records: PartyVetRecords; buyerIdentityAnchor: string }

export async function vetParties(input: PartyVetInput): Promise<PartyVetOutput> {
  const sellerClaim = String(input.signers.seller.claim);
  const buyerClaim = String(input.signers.buyer.claim);
  // The seller: its identity bundle is the one its listing presents, and it must be this session's seller.
  const sellerIdentity = requireConfiguredSellerIdentity(input.listing, sellerClaim);
  await verifyIdentityPresentation(sellerIdentity, input.verifySignature);
  // The buyer: presents its identity bundle now, anchored by the buyer so a cold reader finds what was evaluated.
  const buyerIdentity = await presentIdentity(input.signers.buyer, input.now);
  await verifyIdentityPresentation(buyerIdentity as unknown as Record<string, unknown>, input.verifySignature);
  const buyerAnchor = await input.anchor({ logicalAddress: anchorNames.identityBundle(input.jobId, 'buyer'), content: buyerIdentity, contentHash: jcsHashHex(buyerIdentity) });
  const buyerBundleRef: AttestationRef = { anchor: { kind: 'storage-program', locator: buyerAnchor.nativeAddress }, contentHash: jcsHashHex(buyerIdentity) };
  const listingRequirement = input.listing.buyerRequirement as BundleRequirementV1 | undefined;
  if (!listingRequirement || listingRequirement.requirementVersion !== '1' || !Array.isArray(listingRequirement.required)) throw new Error('listing carries no DACS-1 buyerRequirement to evaluate the buyer under');

  const evaluations: Array<{ role: 'buyer' | 'seller'; claim: string; verifier: AdapterSigner; attestation: AttestationRef; bundleHash: string; requirement: BundleRequirementV1; reason: string }> = [
    { role: 'seller', claim: sellerClaim, verifier: input.signers.buyer, attestation: input.listingRef, bundleHash: identityBundleHash(sellerIdentity as never),
      requirement: selfSignedBundleRequirement(splitClaim(sellerClaim).scheme), reason: 'the seller wallet signed the identity bundle its listing presents (self-signed presentation verified in this phase; nothing beyond key possession is claimed)' },
    { role: 'buyer', claim: buyerClaim, verifier: input.signers.seller, attestation: buyerBundleRef, bundleHash: identityBundleHash(buyerIdentity),
      requirement: listingRequirement, reason: 'the buyer wallet signed the identity bundle it presented in this phase (self-signed presentation verified; nothing beyond key possession is claimed)' },
  ];
  const refs: Partial<VetRecordRefs> = {};
  const records: Partial<PartyVetRecords> = {};
  for (const evaluation of evaluations) {
    const { record, contentHash } = await emitVerifyResult({ claim: evaluation.claim, method: 'self-signed', decision: 'pass', reason: evaluation.reason, attestation: evaluation.attestation, fetchedAt: input.now, verifiedAt: input.now }, evaluation.verifier);
    const resultAnchor = await input.anchor({ logicalAddress: vetRecordProgramName(vetRecordAddress(input.jobId, record.scheme, record.identifier, record.recipeVersion)), content: record, contentHash: jcsHashHex(record) });
    const resultRef = { anchor: { kind: 'storage-program' as const, locator: resultAnchor.nativeAddress }, contentHash, recipeVersion: record.recipeVersion };
    const composite = await emitCompositeRecord({ jobId: input.jobId, evaluatedParty: evaluation.claim, bundleHash: evaluation.bundleHash, requirement: evaluation.requirement,
      dealSpecific: [{ ref: resultRef, result: record }], generatedAt: input.now }, evaluation.verifier);
    const compositeAnchor = await input.anchor({ logicalAddress: vetRecordProgramName(compositeRecordAddress(input.jobId, evaluation.claim)), content: composite.record, contentHash: jcsHashHex(composite.record) });
    const verifier = String(evaluation.verifier.claim);
    const partyRefs: PartyVetRefs = {
      composite: { anchor: { kind: 'storage-program', locator: compositeAnchor.nativeAddress }, contentHash: composite.contentHash, signer: verifier },
      verifyResult: { anchor: { kind: 'storage-program', locator: resultAnchor.nativeAddress }, contentHash, signer: verifier },
      bundleHash: evaluation.bundleHash,
    };
    refs[evaluation.role] = partyRefs;
    records[evaluation.role] = { method: record.method, decision: record.decision, composite: composite.record.overallDecision };
  }
  return { refs: refs as VetRecordRefs, records: records as PartyVetRecords, buyerIdentityAnchor: buyerAnchor.nativeAddress };
}
