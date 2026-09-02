import { DOMAIN_SEPARATORS, ADDITIVE_DOMAIN_SEPARATORS, type DomainSeparator } from '../../domain-sep.js';
import { jcsHashHex } from '../../jcs.js';
import { deriveBundleLogicalAddress, type BundleBindingV1 } from '../../lib/bundle-binding-v1.js';
import { bundleSignedScopeHashV1 } from '../../lib/bundle-signed-scope-v1.js';
import { verify } from '../../lib/sign.js';
import { claimKey, decodeEd25519Sig, verifyBundleV1 } from '../../lib/verify-bundle-v1.js';
import { verifySettlementEvidenceV1 } from '../../lib/verify-settlement-evidence-v1.js';
import type {
  AnchorReceipt,
  BundleOutcome,
  BundleParty,
  BundlePhaseEntry,
  BundleSignature,
  CurrentAttestationBundle,
  EvidenceBoundFaultAttestationBundle,
  FaultAttestationBundle,
} from '../../types/bundle.js';
import type { ClaimRef } from '../../types/identity.js';
import type { AttestationRef } from '../../types/verify-result.js';
import type { AdapterSigner, AgreementAnchorResult } from './agreement-commitment.js';

type Claim = ClaimRef | string;
type Role = 'buyer' | 'seller' | 'orchestrator';
type JsonObject = Record<string, unknown>;

export class BundleFinalizationError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message);
    this.name = 'BundleFinalizationError';
  }
}

export interface ExecutedPhase {
  index: number;
  kind: string;
  outcome: 'ok' | 'fail';
  errorClass?: BundlePhaseEntry['errorClass'];
  retryExhausted?: true;
  txRefs?: BundlePhaseEntry['txRefs'];
  evidenceRef?: AttestationRef;
  orchestrator: Claim;
  evidenceLogicalAddress?: string;
}

export interface CompletedSessionEvidence {
  kind?: 'ebfab' | 'fab';
  jobId: string;
  listing: JsonObject;
  listingRef: { listingId: string; version: number; contentHash: string };
  agreementRef?: AttestationRef;
  agreement?: JsonObject;
  agreementHash?: string;
  parties: BundleParty[];
  phaseResults: ExecutedPhase[];
  outcome: BundleOutcome;
  faultedParty: 'buyer' | 'seller' | 'orchestrator' | 'none';
  vetRecords?: AttestationRef[];
  amendments?: AttestationRef[];
  ratingRefs?: AttestationRef[];
  recipeRegistryVersion: number;
  railRegistryVersion: number;
  finalisedAt?: number;
}

export interface BundleFinalizerDependencies {
  signers: { buyer: AdapterSigner; seller: AdapterSigner; orchestrator?: AdapterSigner };
  anchor(request: { logicalAddress: string; content: unknown; contentHash: string }): Promise<AgreementAnchorResult>;
  fetchAnchored(address: string): Promise<unknown>;
  receiptProvider(request: { logicalAddress: string; contentHash: string; anchor?: AgreementAnchorResult }): Promise<AnchorReceipt>;
  publishBundleBinding?: (binding: BundleBindingV1) => Promise<void>;
  verifySignature?: (request: { domain: DomainSeparator; hash: string; signer: Claim; algorithm: string; value: string }) => Promise<boolean> | boolean;
  projectPaymentRail?: (rail: JsonObject) => string;
  now?: () => number;
}

export interface FinalizedBundleSet {
  bundles: Partial<Record<Role, { bundle: CurrentAttestationBundle; hash: string; address: { logical: string; native: string }; receipt: AnchorReceipt; binding?: BundleBindingV1 }>>;
  scopeHash: string;
}

export interface FinalizedBundleExpectation {
  jobId: string;
  bundles: FinalizedBundleSet['bundles'];
  scopeHash: string;
  phases?: ExecutedPhase[];
}

export type BundleFinalizerReadDependencies = Pick<BundleFinalizerDependencies, 'fetchAnchored' | 'receiptProvider' | 'verifySignature'>;

const SETTLEMENT = new Set([
  'pay-evm-erc20', 'pay-solana-spl', 'pay-cross-chain-htlc', 'pay-cross-chain-liquidity-tank',
  'pay-ap2', 'pay-x402', 'pay-dem', 'deliver-storage-program', 'deliver-entitlement', 'deliver-attested-payload',
]);

function object(value: unknown): JsonObject {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new BundleFinalizationError('malformed', 'expected a JSON object');
  return value as JsonObject;
}

function parsed(value: unknown): JsonObject {
  return typeof value === 'string' ? object(JSON.parse(value)) : object(value);
}

function sigValue(value: string | Uint8Array): string {
  const result = value instanceof Uint8Array ? Buffer.from(value).toString('base64url') : value;
  if (!/^[A-Za-z0-9_-]+$/.test(result) || result.includes('=')) throw new BundleFinalizationError('signature-encoding', 'signature must use unpadded Base64URL');
  return result;
}

async function makeSignature(signer: AdapterSigner, domain: DomainSeparator, hash: string): Promise<BundleSignature> {
  return { party: signer.claim, algorithm: signer.algorithm ?? 'ed25519', value: sigValue(await signer.sign(domain, hash)) };
}

function cciKey(claim: Claim): Uint8Array | null {
  const raw = typeof claim === 'string'
    ? /^cci:(?:0x)?([0-9a-fA-F]{64})$/.exec(claim)?.[1]
    : claim.scheme === 'cci' ? claim.identifier.replace(/^0x/i, '') : undefined;
  return raw && /^[0-9a-fA-F]{64}$/.test(raw) ? Uint8Array.from(raw.match(/../g)!.map((x) => Number.parseInt(x, 16))) : null;
}

async function signatureValid(deps: Pick<BundleFinalizerDependencies, 'verifySignature'>, domain: DomainSeparator, hash: string, signature: JsonObject): Promise<boolean> {
  const signer = signature.signer as Claim;
  const algorithm = String(signature.algorithm);
  const value = String(signature.value);
  if (deps.verifySignature) return deps.verifySignature({ domain, hash, signer, algorithm, value });
  if (algorithm !== 'ed25519' || value.includes('=')) return false;
  const sig = decodeEd25519Sig(value), key = cciKey(signer);
  return !!sig && !!key && verify(domain, sig, new TextEncoder().encode(hash), key);
}

function effectivePipeline(input: CompletedSessionEvidence, deps: BundleFinalizerDependencies): JsonObject[] {
  if (!Array.isArray(input.listing.pipeline) || input.listing.pipeline.length === 0) throw new BundleFinalizationError('pipeline', 'listing pipeline must be non-empty');
  return input.listing.pipeline.map((raw) => {
    const phase = object(raw);
    if (phase.kind !== 'pay-alternative') return phase;
    const agreementRail = input.agreement && object(object(input.agreement.terms).rail);
    if (!agreementRail) throw new BundleFinalizationError('apr', 'pay-alternative requires the authenticated agreement rail');
    const alternatives = object(phase.parameters).alternatives;
    if (!Array.isArray(alternatives) || alternatives.filter((x) => jcsHashHex(x) === jcsHashHex(agreementRail)).length !== 1) {
      throw new BundleFinalizationError('apr', 'agreement rail does not select exactly one signed alternative');
    }
    const projected = deps.projectPaymentRail?.(agreementRail) ?? String(agreementRail.railId);
    if (!projected.startsWith('pay-') || projected === 'pay-alternative') throw new BundleFinalizationError('apr', 'selected rail cannot be projected to a concrete payment handler');
    return { kind: projected, parameters: { rail: agreementRail.railId } };
  });
}

function validateTrace(input: CompletedSessionEvidence, pipeline: JsonObject[]): BundlePhaseEntry[] {
  const phases = input.phaseResults;
  if (!Array.isArray(phases)) throw new BundleFinalizationError('phase-summary', 'phaseResults must be an array');
  for (let i = 0; i < phases.length; i++) {
    const phase = phases[i]!;
    if (phase.index !== i || pipeline[i]?.kind !== phase.kind) throw new BundleFinalizationError('phase-kind', 'phaseSummary must be a contiguous 0..n prefix of the effective pipeline');
    if (phase.outcome !== 'ok' && phase.outcome !== 'fail') throw new BundleFinalizationError('phase-outcome', 'invalid phase outcome');
  }
  if (input.outcome === 'completed' && phases.length !== pipeline.length) throw new BundleFinalizationError('phase-summary', 'completed bundle must cover the full effective pipeline');
  if (input.outcome === 'completed' && phases.some((p) => p.outcome === 'fail' && p.kind !== 'rate')) throw new BundleFinalizationError('phase-outcome', 'completed trace contains a failed non-rate phase');
  if (input.outcome === 'failed-perm') {
    const last = phases.at(-1);
    if (!last || last.outcome !== 'fail' || (last.errorClass !== 'permanent' && !(last.errorClass === 'transient' && last.retryExhausted))) throw new BundleFinalizationError('phase-outcome', 'failed-perm requires a terminal permanent or retry-exhausted transient failure');
  }
  return phases.map((p) => ({ index: p.index, kind: p.kind, outcome: p.outcome,
    ...(p.errorClass ? { errorClass: p.errorClass } : {}), ...(p.retryExhausted ? { retryExhausted: true as const } : {}),
    ...(p.txRefs ? { txRefs: p.txRefs } : {}), ...(p.evidenceRef ? { attestationRef: p.evidenceRef } : {}) }));
}

function validateReceipt(receipt: AnchorReceipt, expected: { logicalAddress: string; contentHash: string; anchor?: AgreementAnchorResult }, completed: boolean): void {
  if (receipt.receiptVersion !== '1' || receipt.observationDisposition !== 'established') throw new BundleFinalizationError('receipt', 'receipt is not established');
  if (receipt.logicalAddress !== expected.logicalAddress || receipt.contentHash !== expected.contentHash) throw new BundleFinalizationError('receipt-binding', 'receipt logical address/content hash mismatch');
  if (expected.anchor && (receipt.nativeAddress !== expected.anchor.nativeAddress || receipt.writer !== expected.anchor.writer ||
      receipt.transactionRef.kind !== expected.anchor.transactionRef.kind || receipt.transactionRef.value !== expected.anchor.transactionRef.value || receipt.nonce !== expected.anchor.nonce)) {
    throw new BundleFinalizationError('receipt-binding', 'receipt native address/transaction/writer/nonce mismatch');
  }
  const {
    state: lifecycle,
  } = receipt;
  const allowed = completed ? lifecycle === 'finalized' : lifecycle === 'included' || lifecycle === 'finalized';
  if (!allowed || !receipt.blockRef) throw new BundleFinalizationError('finality', completed ? 'completed bundle dependency is not finalized' : 'bundle dependency is not included');
}

async function resolveEvidence(input: CompletedSessionEvidence, deps: BundleFinalizerDependencies): Promise<AttestationRef[]> {
  const required = input.phaseResults.filter((p) => SETTLEMENT.has(p.kind));
  const refs = required.map((p) => p.evidenceRef);
  if (refs.some((r) => !r)) throw new BundleFinalizationError('seb-bijection', 'every executed payment/delivery result requires one evidenceRef');
  const canonicalRefs = refs.map((r) => jcsHashHex(r));
  if (new Set(canonicalRefs).size !== canonicalRefs.length) throw new BundleFinalizationError('seb-duplicate', 'settlementEvidence contains a duplicate reference');
  for (let i = 0; i < required.length; i++) {
    const phase = required[i]!, ref = refs[i]!;
    let evidence: JsonObject;
    try { evidence = parsed(await deps.fetchAnchored(ref.anchor.locator)); }
    catch { throw new BundleFinalizationError('evidence-unresolved', `evidence for phase ${phase.index} could not be resolved`); }
    if (jcsHashHex(evidence) !== ref.contentHash.replace(/^sha256:/, '')) throw new BundleFinalizationError('evidence-hash', `evidence hash mismatch for phase ${phase.index}`);
    const structural = verifySettlementEvidenceV1(evidence);
    if (structural.decision !== 'pass') throw new BundleFinalizationError('evidence-shape', structural.reasons.join('; '));
    if (evidence.jobId !== input.jobId || evidence.phase !== phase.kind || evidence.phaseIndex !== phase.index) throw new BundleFinalizationError('seb-binding', `evidence does not bind phase (${phase.index},${phase.kind})`);
    if ((evidence.outcome === 'success') !== (phase.outcome === 'ok')) throw new BundleFinalizationError('seb-outcome', `evidence outcome contradicts phase ${phase.index}`);
    const signature = object(evidence.signature);
    if (claimKey(signature.signer) !== claimKey(phase.orchestrator)) throw new BundleFinalizationError('seb-authorship', `evidence signer is not phase ${phase.index}'s authenticated orchestrator`);
    const unsigned = { ...evidence }; delete unsigned.signature;
    if (!await signatureValid(deps, DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE, jcsHashHex(unsigned), signature)) throw new BundleFinalizationError('seb-signature', `evidence signature invalid for phase ${phase.index}`);
    const receipt = await deps.receiptProvider({ logicalAddress: phase.evidenceLogicalAddress ?? ref.anchor.locator, contentHash: ref.contentHash.replace(/^sha256:/, '') });
    validateReceipt(receipt, { logicalAddress: phase.evidenceLogicalAddress ?? ref.anchor.locator, contentHash: ref.contentHash.replace(/^sha256:/, '') }, input.outcome === 'completed');
    if (receipt.writer !== (typeof phase.orchestrator === 'string' ? phase.orchestrator : phase.orchestrator.identifier)) throw new BundleFinalizationError('seb-authorship', `evidence writer is not phase ${phase.index}'s authenticated orchestrator`);
  }
  return refs as AttestationRef[];
}

function checkFault(input: CompletedSessionEvidence): void {
  const roles = new Set(input.parties.map((p) => p.role));
  if (!roles.has('buyer') || !roles.has('seller')) throw new BundleFinalizationError('parties', 'bundle must list buyer and seller');
  if ((input.outcome === 'completed' || input.outcome === 'failed-substrate') && input.faultedParty !== 'none') throw new BundleFinalizationError('fault', 'no-fault outcome must name none');
  if (input.faultedParty !== 'none' && !roles.has(input.faultedParty)) throw new BundleFinalizationError('fault', 'faultedParty is not a listed role');
}

async function emitBinding(input: CompletedSessionEvidence, deps: BundleFinalizerDependencies, role: Role, nativeAddress: string, scopeHash: string, anchor: AgreementAnchorResult): Promise<BundleBindingV1 | undefined> {
  if (!deps.publishBundleBinding) return undefined;
  const signer = role === 'orchestrator' ? deps.signers.orchestrator! : deps.signers[role];
  const unsigned = { bindingVersion: '1', jobId: input.jobId, role, logicalAddress: deriveBundleLogicalAddress(input.jobId, role), nativeAddress, bundleContentHash: scopeHash, anchorTx: anchor.transactionRef.value, signer: signer.claim };
  const value = sigValue(await signer.sign(DOMAIN_SEPARATORS.BUNDLE_BINDING, jcsHashHex(unsigned)));
  const binding: BundleBindingV1 = { ...unsigned, signature: { algorithm: signer.algorithm ?? 'ed25519', signer: signer.claim, value } };
  await deps.publishBundleBinding(binding);
  return binding;
}

export async function finalizeBundle(input: CompletedSessionEvidence, deps: BundleFinalizerDependencies): Promise<FinalizedBundleSet> {
  if (input.kind !== undefined && input.kind !== 'ebfab' && input.kind !== 'fab') throw new BundleFinalizationError('bundle-kind', 'legacy bundleVersion:"1" emission is not supported');
  checkFault(input);
  if (jcsHashHex(input.listingRef) !== jcsHashHex({ listingId: input.listing.listingId, version: input.listing.listingVersion, contentHash: input.listing.contentHash ?? (() => { const x = { ...input.listing }; delete x.signature; return jcsHashHex(x); })() })) throw new BundleFinalizationError('listing-ref', 'listingRef does not match listing');
  const pipeline = effectivePipeline(input, deps);
  const phaseSummary = validateTrace(input, pipeline);
  const evidence = await resolveEvidence(input, deps);
  const roles: Role[] = ['buyer', 'seller'];
  const distinctOrchestrator = deps.signers.orchestrator && ![deps.signers.buyer, deps.signers.seller].some((s) => claimKey(s.claim) === claimKey(deps.signers.orchestrator!.claim));
  if (distinctOrchestrator) roles.push('orchestrator');
  const domain = input.kind === 'fab' ? DOMAIN_SEPARATORS.FAULT_BUNDLE : ADDITIVE_DOMAIN_SEPARATORS.EVIDENCE_BOUND_FAULT_BUNDLE;
  const common = {
    ...(input.kind === 'fab' ? { faultBundleVersion: '1' as const } : { evidenceBoundFaultBundleVersion: '1' as const }),
    jobId: input.jobId, outcome: input.outcome, faultedParty: input.faultedParty, listingRef: input.listingRef,
    ...(input.agreementRef ? { agreementRef: input.agreementRef } : {}), parties: input.parties, phaseSummary,
    vetRecords: input.vetRecords ?? [], settlementEvidence: evidence,
    ...(input.amendments ? { amendments: input.amendments } : {}), ...(input.ratingRefs ? { ratingRefs: input.ratingRefs } : {}),
    recipeRegistryVersion: input.recipeRegistryVersion, railRegistryVersion: input.railRegistryVersion,
    finalisedAt: input.finalisedAt ?? deps.now?.() ?? Date.now(),
  };
  const scopeHash = bundleSignedScopeHashV1(common);
  const signatures = await Promise.all(roles.map((role) => makeSignature(role === 'orchestrator' ? deps.signers.orchestrator! : deps.signers[role], domain, scopeHash)));
  const bundles: FinalizedBundleSet['bundles'] = {};
  for (const role of roles) {
    const bundle = { ...common, anchoredByRole: role, signatures } as CurrentAttestationBundle;
    const verified = verifyBundleV1(bundle);
    if (verified.decision !== 'accept') throw new BundleFinalizationError('bundle-signature', verified.reasons.join('; '));
    const logical = deriveBundleLogicalAddress(input.jobId, role);
    const anchor = await deps.anchor({ logicalAddress: logical, content: bundle, contentHash: scopeHash });
    const fetched = parsed(await deps.fetchAnchored(anchor.nativeAddress));
    if (bundleSignedScopeHashV1(fetched) !== scopeHash || fetched.anchoredByRole !== role) throw new BundleFinalizationError('cold-read', `bundle copy for ${role} did not independently resolve`);
    const receipt = await deps.receiptProvider({ logicalAddress: logical, contentHash: scopeHash, anchor });
    validateReceipt(receipt, { logicalAddress: logical, contentHash: scopeHash, anchor }, input.outcome === 'completed');
    const binding = await emitBinding(input, deps, role, anchor.nativeAddress, scopeHash, anchor);
    bundles[role] = { bundle, hash: scopeHash, address: { logical, native: anchor.nativeAddress }, receipt, ...(binding ? { binding } : {}) };
  }
  return { bundles, scopeHash };
}

export async function verifyFinalizedBundleCold(expected: FinalizedBundleExpectation, deps: BundleFinalizerReadDependencies): Promise<{ outcome: 'pass' | 'fail' | 'indeterminate'; detail: string }> {
  try {
    const entries = Object.entries(expected.bundles) as Array<[Role, NonNullable<FinalizedBundleSet['bundles'][Role]>]>;
    if (entries.length < 2) return { outcome: 'indeterminate', detail: 'both buyer and seller bundle copies are required' };
    for (const [role, copy] of entries) {
      let fetched: JsonObject;
      try { fetched = parsed(await deps.fetchAnchored(copy.address.native)); }
      catch { return { outcome: 'indeterminate', detail: `${role} bundle copy is unavailable` }; }
      if (fetched.anchoredByRole !== role || fetched.jobId !== expected.jobId || bundleSignedScopeHashV1(fetched) !== expected.scopeHash) return { outcome: 'fail', detail: `${role} bundle copy binding/hash mismatch` };
      const verdict = verifyBundleV1(fetched as unknown as CurrentAttestationBundle);
      if (verdict.decision === 'reject') return { outcome: 'fail', detail: `${role} bundle verification failed: ${verdict.reasons.join('; ')}` };
      if (verdict.decision === 'indeterminate') return { outcome: 'indeterminate', detail: `${role} bundle signatures could not be verified` };
      let receipt: AnchorReceipt;
      try { receipt = await deps.receiptProvider({ logicalAddress: copy.address.logical, contentHash: expected.scopeHash }); }
      catch { return { outcome: 'indeterminate', detail: `${role} receipt is unavailable` }; }
      const expectedAnchor: AgreementAnchorResult = {
        logicalAddress: copy.address.logical,
        nativeAddress: copy.address.native,
        transactionRef: copy.receipt.transactionRef,
        writer: copy.receipt.writer,
        ...(copy.receipt.nonce !== undefined ? { nonce: copy.receipt.nonce } : {}),
      };
      try { validateReceipt(receipt, { logicalAddress: copy.address.logical, contentHash: expected.scopeHash, anchor: expectedAnchor }, fetched.outcome === 'completed'); }
      catch (error) {
        if (error instanceof BundleFinalizationError && error.code === 'finality') return { outcome: 'indeterminate', detail: error.message };
        return { outcome: 'fail', detail: error instanceof Error ? error.message : 'invalid receipt' };
      }
    }
    return { outcome: 'pass', detail: 'all role copies, signatures, hashes, addresses, and lifecycle receipts verified' };
  } catch (error) {
    return { outcome: 'fail', detail: error instanceof Error ? error.message : 'bundle verification failed' };
  }
}
