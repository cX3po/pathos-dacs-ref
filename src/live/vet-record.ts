/**
 * DACS-2 §7.5 VerifyResult in the Standard's wire shape (the pinned dacs-sdk's isVerifyResult: resultVersion "1", the
 * claim split into scheme and identifier, recipeVersion, method, decision, reason, attestation, fetchedAt, verifiedAt,
 * a ComponentSignature), signed over `dacs-verifyresult:v1:` || JCS-hash(record minus signature) (CORE §B.7).
 *
 * The honest vet this session can perform on a Demos agent DID is `self-signed`: the party's wallet key signed what it
 * presented (the seller: its listing and its identity bundle; the buyer: nothing before the agreement, hence
 * indeterminate). A consensus-backed single fetch (the GLEIF recipe) applies only when a party presents an `lei:`
 * claim; a single fetch is never quorum, so its decision is at most indeterminate.
 */
import { DOMAIN_SEPARATORS } from '../domain-sep.js';
import { jcsHashHex } from '../jcs.js';
import { cf4Encode } from '../dacs1/addressing.js';
import type { AdapterSigner } from '../adapters/dacs/agreement-commitment.js';
import type { AttestationRef } from '../types/verify-result.js';

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

export interface VetRecordRefs { buyer: AttestationRef; seller: AttestationRef }

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

/** The pinned SDK's program-name form for a logical address (':' → '%3A'). */
export function vetRecordProgramName(address: string): string {
  return address.replace(/:/g, '%3A');
}

/** An AttestationRef in the exact DACS-2 §7.5.2 wire form (anchor kind + locator, contentHash, optional signer). */
export function exactAttestationRef(ref: AttestationRef): AttestationRef {
  return { anchor: { kind: ref.anchor.kind, locator: ref.anchor.locator }, contentHash: ref.contentHash, ...(ref.signer === undefined ? {} : { signer: ref.signer }) };
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
  const signed = await verifier.sign(DOMAIN_SEPARATORS.VERIFY_RESULT, contentHash);
  const value = typeof signed === 'string' ? signed : Buffer.from(signed).toString('base64url');
  return { record: { ...scope, signature: { algorithm: 'ed25519', signer: String(verifier.claim), value } }, contentHash };
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
