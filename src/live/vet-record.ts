/**
 * DACS-2 vet records in the Standard's wire shape, as the pinned dacs-sdk validates them.
 *
 * - §7.5 VerifyResult (isVerifyResult: resultVersion "1", the claim split into scheme and identifier, recipeVersion, method,
 *   decision, reason, attestation, fetchedAt, verifiedAt, a ComponentSignature), signed over `dacs-verifyresult:v1:` ||
 *   JCS-hash(record minus signature) (CORE §B.7).
 * - §7.7 CompositeVerificationRecord (isCompositeVerificationRecord: recordVersion "1", jobId, evaluatedParty, bundleHash,
 *   requirementHash, freshness, supplementary, dealSpecific, overallDecision, generatedAt, signature), signed over
 *   `dacs-composite:v1:` || JCS-hash(record minus signature). DACS-3 §8.5: an AgreementParty.vetRecordRef cites the
 *   composite for that exact party, never a bare VerifyResult and never the listing.
 *
 * The honest vet this session can perform on a Demos agent DID is `self-signed`: the party's wallet key signed the identity
 * bundle it presented (the seller: inside its listing; the buyer: presented in this phase). Each party's counterparty
 * signs the VerifyResult and the composite that evaluates it; the composite's requirement is the one the counterparty
 * actually holds (the listing's buyerRequirement for the buyer, the buyer's self-signed requirement for the seller). The
 * pinned SDK aggregates a required claim with no VerifyResult as `fail`, so the VerifyResult is the composite's evidence.
 */
import { DOMAIN_SEPARATORS } from '../domain-sep.js';
import { jcsHashHex } from '../jcs.js';
import { cf4Encode } from '../dacs1/addressing.js';
import type { AdapterSigner } from '../adapters/dacs/agreement-commitment.js';
import type { AttestationRef } from '../types/verify-result.js';
import type { BundleRequirementV1, ClaimRequirementV1 } from './listing-wire.js';

export type VetDecision = 'pass' | 'fail' | 'indeterminate' | 'error';
export type VetMethod = 'self-signed' | 'consensus-backed-proxy';

export interface Dacs2VerifyResult {
  resultVersion: '1';
  scheme: string;
  identifier: string;
  recipeVersion: number;
  method: VetMethod;
  decision: VetDecision;
  reason: string;
  attestation: AttestationRef;
  fetchedAt: number;
  verifiedAt: number;
  signature: { algorithm: 'ed25519'; signer: string; value: string };
}

/** DACS-2 §7.7 VerifyResultRef: exactly anchor, contentHash, recipeVersion. */
export interface VerifyResultRefV1 { anchor: { kind: AttestationRef['anchor']['kind']; locator: string }; contentHash: string; recipeVersion: number }

export interface Dacs2CompositeRecord {
  recordVersion: '1';
  jobId: string;
  evaluatedParty: string;
  bundleHash: string;
  requirementHash: string;
  freshness: VerifyResultRefV1[];
  supplementary: never[];
  dealSpecific: VerifyResultRefV1[];
  overallDecision: VetDecision;
  generatedAt: number;
  signature: { algorithm: 'ed25519'; signer: string; value: string };
}

/** What the vet phase anchored for one party: the composite the agreement cites, its VerifyResult evidence, and the hash of the identity bundle it evaluated. */
export interface PartyVetRefs { composite: AttestationRef; verifyResult: AttestationRef; bundleHash: string }
export interface VetRecordRefs { buyer: PartyVetRefs; seller: PartyVetRefs }

export interface SingleFetchVet {
  executed: boolean;
  trustLevel: 'indeterminate' | 'not-applicable';
  reason: string;
}

/** A ClaimReference `<scheme>:<identifier>` split at its first colon. */
export function splitClaim(claim: string): { scheme: string; identifier: string } {
  const colon = claim.indexOf(':');
  if (colon <= 0 || colon === claim.length - 1) throw new Error('claim reference must be <scheme>:<identifier>');
  return { scheme: claim.slice(0, colon), identifier: claim.slice(colon + 1) };
}

/** DACS-2 CM-2 address: `dacs2:{jobId}:{scheme}:{identifier CF-4 encoded}:v{recipeVersion}` (the SDK's attestationAddress). */
export function vetRecordAddress(jobId: string, scheme: string, identifier: string, recipeVersion: number): string {
  return `dacs2:${jobId}:${scheme}:${cf4Encode(identifier)}:v${recipeVersion}`;
}

/** DACS-2 §7.7.2 composite address: `dacs2:composite:{jobId}:{evaluatedParty}` with both variable segments CF-4 encoded (the SDK's compositeVerificationAddress). */
export function compositeRecordAddress(jobId: string, evaluatedParty: string): string {
  return `dacs2:composite:${cf4Encode(jobId)}:${cf4Encode(evaluatedParty)}`;
}

/** The pinned SDK's program-name form for a logical address (':' → '%3A'). */
export function vetRecordProgramName(address: string): string {
  return address.replace(/:/g, '%3A');
}

/** An AttestationRef in the exact DACS-2 §7.5.2 wire form (anchor kind + locator, contentHash, optional signer). */
export function exactAttestationRef(ref: AttestationRef): AttestationRef {
  return { anchor: { kind: ref.anchor.kind, locator: ref.anchor.locator }, contentHash: ref.contentHash, ...(ref.signer === undefined ? {} : { signer: ref.signer }) };
}

async function componentSignature(verifier: AdapterSigner, separator: typeof DOMAIN_SEPARATORS.VERIFY_RESULT | typeof DOMAIN_SEPARATORS.COMPOSITE_VERIFY, contentHash: string) {
  const signed = await verifier.sign(separator, contentHash);
  const value = typeof signed === 'string' ? signed : Buffer.from(signed).toString('base64url');
  return { algorithm: 'ed25519' as const, signer: String(verifier.claim), value };
}

export async function emitVerifyResult(input: {
  claim: string; method: VetMethod; decision: VetDecision; reason: string; attestation: AttestationRef; fetchedAt: number; verifiedAt: number; recipeVersion?: number;
}, verifier: AdapterSigner): Promise<{ record: Dacs2VerifyResult; contentHash: string }> {
  const { scheme, identifier } = splitClaim(input.claim);
  const scope = {
    resultVersion: '1' as const, scheme, identifier, recipeVersion: input.recipeVersion ?? 1, method: input.method, decision: input.decision, reason: input.reason,
    attestation: exactAttestationRef(input.attestation), fetchedAt: input.fetchedAt, verifiedAt: input.verifiedAt,
  };
  const contentHash = jcsHashHex(scope);
  return { record: { ...scope, signature: await componentSignature(verifier, DOMAIN_SEPARATORS.VERIFY_RESULT, contentHash) }, contentHash };
}

/** The requirement member a VerifyResult satisfies, or undefined when the requirement does not cover its scheme and method. */
export function requirementMemberFor(requirement: BundleRequirementV1, result: Pick<Dacs2VerifyResult, 'scheme' | 'method' | 'recipeVersion'>): ClaimRequirementV1 | undefined {
  return requirement.required.find((member) => member.scheme === result.scheme
    && (member.recipeVersion === undefined || member.recipeVersion === result.recipeVersion)
    && (member.parameters?.verificationMethod === undefined || member.parameters.verificationMethod === result.method));
}

/**
 * DACS-2 §7.7.1 aggregation as the pinned SDK recomputes it for a requirement whose members are all `required`: a member
 * with no result fails; a pass satisfies; otherwise fail > error > indeterminate.
 */
export function aggregateDecision(requirement: BundleRequirementV1, results: Array<Pick<Dacs2VerifyResult, 'scheme' | 'method' | 'recipeVersion' | 'decision'>>): VetDecision {
  const buckets = { fail: 0, error: 0, indeterminate: 0 };
  for (const member of requirement.required) {
    const decisions = results.filter((r) => requirementMemberFor({ requirementVersion: '1', required: [member] }, r) !== undefined).map((r) => r.decision);
    if (decisions.includes('pass')) continue;
    if (decisions.length === 0 || decisions.includes('fail')) buckets.fail += 1;
    else if (decisions.includes('error')) buckets.error += 1;
    else buckets.indeterminate += 1;
  }
  if (buckets.fail > 0) return 'fail';
  if (buckets.error > 0) return 'error';
  if (buckets.indeterminate > 0) return 'indeterminate';
  return 'pass';
}

export async function emitCompositeRecord(input: {
  jobId: string; evaluatedParty: string; bundleHash: string; requirement: BundleRequirementV1;
  dealSpecific: Array<{ ref: VerifyResultRefV1; result: Pick<Dacs2VerifyResult, 'scheme' | 'method' | 'recipeVersion' | 'decision'> }>; generatedAt: number;
}, verifier: AdapterSigner): Promise<{ record: Dacs2CompositeRecord; contentHash: string }> {
  for (const entry of input.dealSpecific) {
    if (requirementMemberFor(input.requirement, entry.result) === undefined) throw new Error('composite evidence is not bound to a requirement member (DACS-2 §7.7)');
  }
  const scope = {
    recordVersion: '1' as const, jobId: input.jobId, evaluatedParty: input.evaluatedParty, bundleHash: input.bundleHash,
    requirementHash: jcsHashHex(input.requirement), freshness: [] as VerifyResultRefV1[], supplementary: [] as never[],
    dealSpecific: input.dealSpecific.map((entry) => ({ anchor: { kind: entry.ref.anchor.kind, locator: entry.ref.anchor.locator }, contentHash: entry.ref.contentHash, recipeVersion: entry.ref.recipeVersion })),
    overallDecision: aggregateDecision(input.requirement, input.dealSpecific.map((entry) => entry.result)), generatedAt: input.generatedAt,
  };
  const contentHash = jcsHashHex(scope);
  return { record: { ...scope, signature: await componentSignature(verifier, DOMAIN_SEPARATORS.COMPOSITE_VERIFY, contentHash) }, contentHash };
}

/**
 * The seller a listing presents must be the seller this session is configured for: `verifyBundleListing` authenticates
 * the listing's own signer, which says nothing about whose listing it is. Returns the presented identity bundle.
 */
export function requireConfiguredSellerIdentity(listing: Record<string, unknown>, sellerClaim: string): Record<string, unknown> {
  const seller = listing.seller as { identity?: Record<string, unknown> } | undefined;
  const identity = seller?.identity;
  if (identity === undefined || typeof identity !== 'object') throw new Error('listing presents no seller identity bundle; a self-signed vet has nothing to evaluate');
  if (identity.presentedBy !== sellerClaim) throw new Error('listing presenter is not the configured seller');
  return identity;
}

/** The `lei:` claim a listing's seller presents, if any: the only claim the GLEIF single-fetch recipe applies to. */
export function leiClaimOf(listing: Record<string, unknown>): string | undefined {
  const seller = listing.seller as { identity?: { claims?: Array<{ ref?: unknown }> } } | undefined;
  const refs = seller?.identity?.claims ?? [];
  const lei = refs.map((c) => c?.ref).find((r): r is string => typeof r === 'string' && r.startsWith('lei:'));
  return lei;
}

export function gleifRecordUrl(leiClaim: string): string {
  return `https://api.gleif.org/api/v1/lei-records/${encodeURIComponent(splitClaim(leiClaim).identifier)}`;
}
