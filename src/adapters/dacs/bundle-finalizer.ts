import { DOMAIN_SEPARATORS, ADDITIVE_DOMAIN_SEPARATORS, type DomainSeparator } from '../../domain-sep.js';
import { jcsCanonical, jcsHashHex } from '../../jcs.js';
import { deriveBundleLogicalAddress, type BundleBindingV1 } from '../../lib/bundle-binding-v1.js';
import { bundleSignedScopeHashV1 } from '../../lib/bundle-signed-scope-v1.js';
import { verify } from '../../lib/sign.js';
import { sha256 } from '@noble/hashes/sha2';
import { claimKey, decodeEd25519Sig, verifyBundleV1 } from '../../lib/verify-bundle-v1.js';
import { verifySettlementEvidenceV1 } from '../../lib/verify-settlement-evidence-v1.js';
import type {
  AnchorReceipt,
  AgreementDocumentV1,
  BundleOutcome,
  BundleParty,
  BundlePhaseEntry,
  BundleSignature,
  CurrentAttestationBundle,
  EvidenceBoundFaultAttestationBundle,
  FaultAttestationBundle,
  FinalityCommitmentRecord,
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
  evidenceAnchor?: AgreementAnchorResult;
}

export interface ResolvedCommitment {
  commitment: FinalityCommitmentRecord;
  agreement: AgreementDocumentV1;
  receipt: AnchorReceipt;
  anchor?: AgreementAnchorResult;
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
  fetchReceipt(request: { logicalAddress: string; contentHash: string; anchor?: AgreementAnchorResult }): Promise<AnchorReceipt>;
  fetchCommitment?: (ref: AttestationRef) => Promise<ResolvedCommitment>;
  publishBundleBinding?: (binding: BundleBindingV1) => Promise<void>;
  verifySignature?: (request: { domain: DomainSeparator; hash: string; signer: Claim; algorithm: string; value: string }) => Promise<boolean> | boolean;
  projectPaymentRail(rail: JsonObject): string;
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
  session?: CompletedSessionEvidence;
}

export type BundleFinalizerReadDependencies = Partial<Pick<BundleFinalizerDependencies, 'fetchReceipt' | 'fetchCommitment'>> & Pick<BundleFinalizerDependencies, 'fetchAnchored' | 'verifySignature' | 'projectPaymentRail'>;

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

function effectivePipeline(input: CompletedSessionEvidence, deps: Pick<BundleFinalizerDependencies, 'projectPaymentRail'>, agreement?: AgreementDocumentV1): JsonObject[] {
  if (!Array.isArray(input.listing.pipeline) || input.listing.pipeline.length === 0) throw new BundleFinalizationError('pipeline', 'listing pipeline must be non-empty');
  return input.listing.pipeline.map((raw) => {
    const phase = object(raw);
    if (phase.kind !== 'pay-alternative') return phase;
    const agreementRail = agreement && object(object(agreement.terms).rail);
    if (!agreementRail) throw new BundleFinalizationError('apr', 'pay-alternative requires the authenticated agreement rail');
    const alternatives = object(phase.parameters).alternatives;
    if (!Array.isArray(alternatives) || alternatives.filter((x) => jcsHashHex(x) === jcsHashHex(agreementRail)).length !== 1) {
      throw new BundleFinalizationError('apr', 'agreement rail does not select exactly one signed alternative');
    }
    const projected = deps.projectPaymentRail(agreementRail);
    if (!projected.startsWith('pay-') || projected === 'pay-alternative') throw new BundleFinalizationError('apr', 'selected rail cannot be projected to a concrete payment handler');
    return { kind: projected, parameters: { rail: agreementRail.railId } };
  });
}

/** PC-2: the rail segment is the rail selected by the authenticated agreement and phase context — the projected
 *  `parameters.rail` for a pay-alternative phase, else the concrete pay-* kind — and is a CF-4 variable segment,
 *  percent-encoded before assembly (internal colons become %3A). */
export function paymentRailId(phase: { kind?: unknown; parameters?: unknown }): string {
  const params = phase.parameters && typeof phase.parameters === 'object' ? (phase.parameters as Record<string, unknown>) : {};
  const rail = typeof params.rail === 'string' && params.rail.length > 0 ? params.rail : String(phase.kind);
  return rail;
}
export function paymentLogicalAddress(jobId: string, railId: string, phaseIndex: number): string {
  return `dacs4:payment:${jobId}:${encodeURIComponent(railId)}:${phaseIndex}`;
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
  if (input.outcome === 'failed-counterparty' || input.outcome === 'failed-substrate') {
    const last = phases.at(-1);
    const required = input.outcome === 'failed-counterparty' ? 'counterparty' : 'substrate';
    if (!last || last.outcome !== 'fail' || last.errorClass !== required) throw new BundleFinalizationError('phase-outcome', `${input.outcome} requires one terminal ${required} failure`);
  }
  if (input.outcome === 'aborted-by-self' || input.outcome === 'aborted-by-other') {
    if (phases.length >= pipeline.length || phases.some((phase) => phase.outcome === 'fail')) throw new BundleFinalizationError('phase-outcome', 'aborted trace must be a proper successful prefix ending before the next phase');
  }
  return phases.map((p) => ({ index: p.index, kind: p.kind, outcome: p.outcome,
    ...(p.errorClass ? { errorClass: p.errorClass } : {}), ...(p.retryExhausted ? { retryExhausted: true as const } : {}),
    ...(p.txRefs ? { txRefs: p.txRefs } : {}), ...(p.evidenceRef ? { attestationRef: p.evidenceRef } : {}) }));
}

function validateReceipt(receipt: AnchorReceipt, expected: { logicalAddress: string; contentHash: string; anchor?: AgreementAnchorResult; storedContent: unknown }, completed: boolean): void {
  if (receipt.receiptVersion !== '1' || receipt.observationDisposition !== 'established') throw new BundleFinalizationError('receipt', 'receipt is not established');
  if (receipt.logicalAddress !== expected.logicalAddress || receipt.contentHash !== expected.contentHash) throw new BundleFinalizationError('receipt-binding', 'receipt logical address/content hash mismatch');
  if (expected.anchor && (receipt.nativeAddress !== expected.anchor.nativeAddress || receipt.writer !== expected.anchor.writer ||
      receipt.transactionRef.kind !== expected.anchor.transactionRef.kind || receipt.transactionRef.value !== expected.anchor.transactionRef.value || receipt.nonce !== expected.anchor.nonce)) {
    throw new BundleFinalizationError('receipt-binding', 'receipt native address/transaction/writer/nonce mismatch');
  }
  if (receipt.evidence.kind !== 'stored-bytes-base64url') {
    throw new BundleFinalizationError('evidence-unverifiable', 'receipt evidence does not carry recoverable stored bytes (SR2-4)');
  }
  if (!/^[A-Za-z0-9_-]*$/.test(receipt.evidence.value) || receipt.evidence.value.includes('=')) {
    throw new BundleFinalizationError('receipt-evidence', 'receipt evidence stored bytes are not valid unpadded Base64URL');
  }
  const storedBytes = Buffer.from(receipt.evidence.value, 'base64url');
  if (storedBytes.toString('base64url') !== receipt.evidence.value || Buffer.from(sha256(storedBytes)).toString('hex') !== expected.contentHash ||
      !storedBytes.equals(Buffer.from(jcsCanonical(expected.storedContent)))) {
    throw new BundleFinalizationError('receipt-evidence', 'receipt evidence bytes do not match the stored contentHash (SR2-4)');
  }
  const {
    state: lifecycle,
  } = receipt;
  const allowed = completed ? lifecycle === 'finalized' : lifecycle === 'included' || lifecycle === 'finalized';
  if (!allowed || !receipt.blockRef) throw new BundleFinalizationError('finality', completed ? 'completed bundle dependency is not finalized' : 'bundle dependency is not included');
}

async function resolveEvidence(input: CompletedSessionEvidence, deps: BundleFinalizerDependencies, pipeline: JsonObject[]): Promise<AttestationRef[]> {
  const required = input.phaseResults.filter((p) => SETTLEMENT.has(p.kind));
  const refs = required.map((p) => p.evidenceRef);
  if (refs.some((r) => !r)) throw new BundleFinalizationError('seb-bijection', 'every executed payment/delivery result requires one evidenceRef');
  const canonicalRefs = refs.map((r) => jcsHashHex(r));
  if (new Set(canonicalRefs).size !== canonicalRefs.length) throw new BundleFinalizationError('seb-duplicate', 'settlementEvidence contains a duplicate reference');
  for (let i = 0; i < required.length; i++) {
    const phase = required[i]!, ref = refs[i]!;
    let raw: unknown;
    try { raw = await deps.fetchAnchored(ref.anchor.locator); }
    catch { throw new BundleFinalizationError('evidence-transport', `evidence for phase ${phase.index} could not be fetched; a transport error is not absence`); }
    if (raw === null || raw === undefined) throw new BundleFinalizationError('evidence-unresolved', `evidence for phase ${phase.index} is absent at its anchor`);
    const evidence: JsonObject = parsed(raw);
    if (jcsHashHex(evidence) !== ref.contentHash.replace(/^sha256:/, '')) throw new BundleFinalizationError('evidence-hash', `evidence hash mismatch for phase ${phase.index}`);
    const structural = verifySettlementEvidenceV1(evidence);
    if (structural.decision !== 'pass') throw new BundleFinalizationError('evidence-shape', structural.reasons.join('; '));
    if (evidence.jobId !== input.jobId || evidence.phase !== phase.kind || evidence.phaseIndex !== phase.index) throw new BundleFinalizationError('seb-binding', `evidence does not bind phase (${phase.index},${phase.kind})`);
    if ((evidence.outcome === 'success') !== (phase.outcome === 'ok')) throw new BundleFinalizationError('seb-outcome', `evidence outcome contradicts phase ${phase.index}`);
    const signature = object(evidence.signature);
    const signerKey = claimKey(signature.signer), orchestratorSignerKey = claimKey(phase.orchestrator);
    const sameSigner = signerKey !== null && orchestratorSignerKey !== null
      ? signerKey === orchestratorSignerKey
      : typeof signature.signer === 'string' && typeof phase.orchestrator === 'string' && signature.signer === phase.orchestrator;
    if (!sameSigner) throw new BundleFinalizationError('seb-authorship', `evidence signer is not phase ${phase.index}'s authenticated orchestrator`);
    const unsigned = { ...evidence }; delete unsigned.signature;
    if (!await signatureValid(deps, DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE, jcsHashHex(unsigned), signature)) throw new BundleFinalizationError('seb-signature', `evidence signature invalid for phase ${phase.index}`);
    // PC-2: the rail comes from the effective pipeline entry (which carries the projected rail parameter for a
    // pay-alternative phase), never from the executed phase result alone.
    const railId = phase.kind.startsWith('pay-') ? paymentRailId(pipeline[phase.index] ?? phase) : undefined;
    const logicalAddress = railId === undefined ? phase.evidenceLogicalAddress : paymentLogicalAddress(input.jobId, railId, phase.index);
    if (!logicalAddress || (phase.evidenceLogicalAddress !== undefined && phase.evidenceLogicalAddress !== logicalAddress)) throw new BundleFinalizationError('receipt-binding', `caller evidence logical address contradicts PC-2 for phase ${phase.index}`);
    if (!phase.evidenceAnchor) throw new BundleFinalizationError('evidence-anchor', `evidence anchor metadata missing for phase ${phase.index}`);
    if (phase.evidenceAnchor.logicalAddress !== logicalAddress || phase.evidenceAnchor.nativeAddress !== ref.anchor.locator) throw new BundleFinalizationError('receipt-binding', `evidence anchor address mismatch for phase ${phase.index}`);
    let receipt: AnchorReceipt;
    try { receipt = await deps.fetchReceipt({ logicalAddress, contentHash: ref.contentHash.replace(/^sha256:/, ''), anchor: phase.evidenceAnchor }); }
    catch { throw new BundleFinalizationError('evidence-transport', `evidence receipt for phase ${phase.index} could not be independently fetched`); }
    validateReceipt(receipt, { logicalAddress, contentHash: ref.contentHash.replace(/^sha256:/, ''), anchor: phase.evidenceAnchor, storedContent: evidence }, input.outcome === 'completed');
    const writerKey = claimKey(receipt.writer), orchestratorKey = claimKey(phase.orchestrator);
    const sameWriter = writerKey !== null && orchestratorKey !== null
      ? writerKey === orchestratorKey
      : typeof phase.orchestrator === 'string' && receipt.writer === phase.orchestrator;
    if (!sameWriter) throw new BundleFinalizationError('seb-authorship', `evidence writer is not phase ${phase.index}'s authenticated orchestrator`);
  }
  return refs as AttestationRef[];
}

export async function verifyBundleListing(listing: JsonObject, deps: Pick<BundleFinalizerDependencies, 'verifySignature'>): Promise<void> {
  const signature = object(listing.signature);
  const scope = { ...listing }; delete scope.signature; delete scope.contentHash;
  const contentHash = jcsHashHex(scope);
  if (listing.contentHash !== contentHash) throw new BundleFinalizationError('listing-hash', 'listing contentHash does not match its signed scope (SEB-1)');
  if (!await signatureValid(deps, DOMAIN_SEPARATORS.LISTING, contentHash, signature)) throw new BundleFinalizationError('listing-signature', 'listing signature is invalid (SEB-1)');
}

async function resolveCommitment(input: CompletedSessionEvidence, deps: Pick<BundleFinalizerDependencies, 'fetchCommitment' | 'fetchReceipt' | 'verifySignature'>): Promise<ResolvedCommitment | undefined> {
  if (input.outcome !== 'completed' && input.outcome !== 'failed-counterparty') return undefined;
  if (!input.agreementRef) throw new BundleFinalizationError('commitment-unresolved', 'completed or failed-counterparty bundle requires a commitment reference (ST-11)');
  if (!deps.fetchCommitment) throw new BundleFinalizationError('commitment-not-refetched', 'commitment was not independently refetched (ST-11)');
  let resolved: ResolvedCommitment;
  try { resolved = await deps.fetchCommitment(input.agreementRef); }
  catch { throw new BundleFinalizationError('commitment-transport', 'agreement commitment could not be resolved (ST-11)'); }
  const commitmentHash = jcsHashHex(resolved.commitment);
  if (commitmentHash !== input.agreementRef.contentHash.replace(/^sha256:/, '') || resolved.commitment.jobId !== input.jobId) throw new BundleFinalizationError('commitment-binding', 'agreement commitment hash/job mismatch (ST-11)');
  const agreementScope = { ...resolved.agreement } as JsonObject; delete agreementScope.signatures;
  const agreementHash = jcsHashHex(agreementScope);
  if (agreementHash !== resolved.commitment.agreementHash) throw new BundleFinalizationError('commitment-binding', 'commitment agreementHash mismatch (ST-11)');
  const parties = new Map(resolved.agreement.parties.map((party) => [party.role, party]));
  for (const role of ['buyer', 'seller'] as const) {
    const party = parties.get(role);
    const signatures = party ? resolved.agreement.signatures.filter((signature) => claimKey(signature.party) === claimKey(party.primaryClaim)) : [];
    if (signatures.length !== 1) throw new BundleFinalizationError('commitment-signature', `agreement requires exactly one ${role} signature (ST-11)`);
    const signature = signatures[0]!;
    if (!await signatureValid(deps, DOMAIN_SEPARATORS.AGREEMENT, agreementHash, { signer: signature.party, algorithm: signature.algorithm, value: signature.value })) throw new BundleFinalizationError('commitment-signature', `agreement ${role} signature invalid (ST-11)`);
  }
  const commitmentScope = { ...resolved.commitment } as JsonObject; delete commitmentScope.signature;
  if (!await signatureValid(deps, ADDITIVE_DOMAIN_SEPARATORS.FINALITY_COMMITMENT, jcsHashHex(commitmentScope), object(resolved.commitment.signature))) throw new BundleFinalizationError('commitment-signature', 'commitment signature invalid (ST-11)');
  const logicalAddress = `dacs3:commit:${input.jobId}`;
  if (!resolved.anchor || resolved.anchor.logicalAddress !== logicalAddress || resolved.anchor.nativeAddress !== input.agreementRef.anchor.locator) {
    throw new BundleFinalizationError('commitment-binding', 'commitment anchor metadata is missing or mismatched (ST-11)');
  }
  let receipt: AnchorReceipt;
  try { receipt = await deps.fetchReceipt({ logicalAddress, contentHash: commitmentHash, anchor: resolved.anchor }); }
  catch { throw new BundleFinalizationError('commitment-transport', 'commitment receipt could not be independently fetched (ST-11); a transport error is not absence'); }
  try { validateReceipt(receipt, { logicalAddress, contentHash: commitmentHash, anchor: resolved.anchor, storedContent: resolved.commitment }, true); }
  catch (error) {
    if (error instanceof BundleFinalizationError && error.code === 'finality' && receipt.state === 'included') {
      throw new BundleFinalizationError('commitment-pending', 'commitment-pending');
    }
    throw new BundleFinalizationError('commitment-finality', error instanceof Error ? `${error.message} (ST-11)` : 'commitment receipt is not finalized and bound (ST-11)');
  }
  return resolved;
}

/** Two claims name the same key: by parsed key bytes when both parse, otherwise only by identical text (an alias in another scheme is not equated). */
function sameClaim(a: unknown, b: unknown): boolean {
  const aKey = claimKey(a as Claim), bKey = claimKey(b as Claim);
  return aKey !== null && bKey !== null ? aKey === bKey : a === b;
}

/** A role's bundle copy is anchored by that role's own key: a copy the counterparty wrote is not that party's attestation. */
function assertBundleWriter(role: Role, anchor: AgreementAnchorResult, signer: AdapterSigner): void {
  if (!sameClaim(anchor.writer, signer.claim)) throw new BundleFinalizationError('bundle-writer', `bundle copy for ${role} was anchored by ${String(anchor.writer)}, not by the ${role} key`);
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
  await verifyBundleListing(input.listing, deps);
  if (jcsHashHex(input.listingRef) !== jcsHashHex({ listingId: input.listing.listingId, version: input.listing.listingVersion, contentHash: input.listing.contentHash })) throw new BundleFinalizationError('listing-ref', 'listingRef does not match listing');
  const resolvedCommitment = await resolveCommitment(input, deps);
  if (resolvedCommitment) input = { ...input, agreement: resolvedCommitment.agreement as unknown as JsonObject };
  const pipeline = effectivePipeline(input, deps, resolvedCommitment?.agreement);
  const phaseSummary = validateTrace(input, pipeline);
  const evidence = await resolveEvidence(input, deps, pipeline);
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
    const storedContentHash = jcsHashHex(bundle);
    const anchor = await deps.anchor({ logicalAddress: logical, content: bundle, contentHash: storedContentHash });
    assertBundleWriter(role, anchor, role === 'orchestrator' ? deps.signers.orchestrator! : deps.signers[role]);
    const fetched = parsed(await deps.fetchAnchored(anchor.nativeAddress));
    if (bundleSignedScopeHashV1(fetched) !== scopeHash || fetched.anchoredByRole !== role) throw new BundleFinalizationError('cold-read', `bundle copy for ${role} did not independently resolve`);
    const receipt = await deps.fetchReceipt({ logicalAddress: logical, contentHash: storedContentHash, anchor });
    validateReceipt(receipt, { logicalAddress: logical, contentHash: storedContentHash, anchor, storedContent: fetched }, input.outcome === 'completed');
    const binding = await emitBinding(input, deps, role, anchor.nativeAddress, scopeHash, anchor);
    bundles[role] = { bundle, hash: scopeHash, address: { logical, native: anchor.nativeAddress }, receipt, ...(binding ? { binding } : {}) };
  }
  return { bundles, scopeHash };
}

export async function verifyFinalizedBundleCold(expected: FinalizedBundleExpectation, deps: BundleFinalizerReadDependencies): Promise<{ outcome: 'pass' | 'fail' | 'indeterminate'; detail: string }> {
  const fetchReceipt = deps.fetchReceipt;
  if (!fetchReceipt) return { outcome: 'indeterminate', detail: 'evidence-not-refetched' };
  try {
    if (!expected.bundles.buyer || !expected.bundles.seller) return { outcome: 'fail', detail: 'buyer and seller bundle copies are both required' };
    const entries = Object.entries(expected.bundles) as Array<[Role, NonNullable<FinalizedBundleSet['bundles'][Role]>]>;
    let authorityBundle: JsonObject | undefined;
    for (const [role, copy] of entries) {
      let fetched: JsonObject;
      try { fetched = parsed(await deps.fetchAnchored(copy.address.native)); }
      catch { return { outcome: 'indeterminate', detail: `${role} bundle copy is unavailable` }; }
      if (fetched.anchoredByRole !== role || fetched.jobId !== expected.jobId || bundleSignedScopeHashV1(fetched) !== expected.scopeHash) return { outcome: 'fail', detail: `${role} bundle copy binding/hash mismatch` };
      if (copy.hash !== expected.scopeHash) return { outcome: 'fail', detail: `${role} bundle copy declares a different hash` };
      const verdict = verifyBundleV1(fetched as unknown as CurrentAttestationBundle);
      if (verdict.decision === 'reject') return { outcome: 'fail', detail: `${role} bundle verification failed: ${verdict.reasons.join('; ')}` };
      if (verdict.decision === 'indeterminate') return { outcome: 'indeterminate', detail: `${role} bundle signatures could not be verified` };
      if (!deps.verifySignature) return { outcome: 'indeterminate', detail: 'bundle signature verifier unavailable' };
      const signatures = fetched.signatures;
      const parties = fetched.parties;
      if (!Array.isArray(signatures) || !Array.isArray(parties)) return { outcome: 'fail', detail: `${role} bundle signatures/parties malformed` };
      for (const partyRole of ['buyer', 'seller'] as const) {
        const party = (parties as JsonObject[]).find((candidate) => candidate.role === partyRole);
        const matching = party ? (signatures as JsonObject[]).filter((signature) => claimKey(signature.party as Claim) === claimKey(party.primaryClaim as Claim)) : [];
        if (matching.length !== 1) return { outcome: 'fail', detail: `${role} copy requires exactly one ${partyRole} signature` };
        const signature = matching[0]!;
        if (!await deps.verifySignature({ domain: fetched.faultBundleVersion === '1' ? DOMAIN_SEPARATORS.FAULT_BUNDLE : ADDITIVE_DOMAIN_SEPARATORS.EVIDENCE_BOUND_FAULT_BUNDLE, hash: expected.scopeHash, signer: signature.party as Claim, algorithm: String(signature.algorithm), value: String(signature.value) })) return { outcome: 'fail', detail: `${role} copy ${partyRole} signature invalid` };
      }
      const storedContentHash = jcsHashHex(fetched);
      let receipt: AnchorReceipt;
      try { receipt = await fetchReceipt({ logicalAddress: copy.address.logical, contentHash: storedContentHash }); }
      catch { return { outcome: 'indeterminate', detail: `${role} receipt is unavailable` }; }
      const expectedAnchor: AgreementAnchorResult = {
        logicalAddress: copy.address.logical,
        nativeAddress: copy.address.native,
        transactionRef: copy.receipt.transactionRef,
        writer: copy.receipt.writer,
        ...(copy.receipt.nonce !== undefined ? { nonce: copy.receipt.nonce } : {}),
      };
      try { validateReceipt(receipt, { logicalAddress: copy.address.logical, contentHash: storedContentHash, anchor: expectedAnchor, storedContent: fetched }, fetched.outcome === 'completed'); }
      catch (error) {
        if (error instanceof BundleFinalizationError && error.code === 'finality') return { outcome: 'indeterminate', detail: error.message };
        return { outcome: 'fail', detail: error instanceof Error ? error.message : 'invalid receipt' };
      }
      // The copy's on-chain writer is the party whose copy it is; a relayed or counterparty-written copy is not that party's attestation.
      const roleParty = (parties as JsonObject[]).find((candidate) => candidate.role === role);
      if (roleParty && !sameClaim(receipt.writer, roleParty.primaryClaim)) return { outcome: 'fail', detail: `${role} bundle copy was not anchored by the ${role} party` };
      if (!roleParty && role !== 'orchestrator') return { outcome: 'fail', detail: `${role} party is not listed in the bundle` };
      if (role === 'buyer') authorityBundle = fetched;
    }
    if (!expected.session || !authorityBundle) return { outcome: 'indeterminate', detail: 'evidence verification input unavailable' };
    await verifyBundleListing(expected.session.listing, deps);
    const listingScope = { ...expected.session.listing };
    delete listingScope.signature;
    delete listingScope.contentHash;
    const callerListingRef = {
      listingId: expected.session.listing.listingId,
      version: expected.session.listing.listingVersion,
      contentHash: jcsHashHex(listingScope),
    };
    if (jcsHashHex(callerListingRef) !== jcsHashHex(authorityBundle.listingRef)) {
      return { outcome: 'fail', detail: 'listingRef does not match the authority bundle' };
    }
    const phaseSummary = authorityBundle.phaseSummary as JsonObject[];
    const settlementEvidence = authorityBundle.settlementEvidence as AttestationRef[];
    if (!Array.isArray(phaseSummary) || !Array.isArray(settlementEvidence)) return { outcome: 'fail', detail: 'bundle evidence fields malformed' };
    const settlementByIndex = new Map<number, AttestationRef>();
    for (const entry of phaseSummary) if (entry.attestationRef) settlementByIndex.set(Number(entry.index), entry.attestationRef as AttestationRef);
    const replayInput: CompletedSessionEvidence = {
      ...expected.session,
      outcome: authorityBundle.outcome as BundleOutcome,
      agreementRef: authorityBundle.agreementRef as AttestationRef | undefined,
      phaseResults: expected.session.phaseResults.map((phase) => ({ ...phase, evidenceRef: settlementByIndex.get(phase.index) ?? phase.evidenceRef })),
    };
    const resolved = await resolveCommitment(replayInput, { ...deps, fetchReceipt });
    if (resolved) replayInput.agreement = resolved.agreement as unknown as JsonObject;
    const pipeline = effectivePipeline(replayInput, deps, resolved?.agreement);
    const replayedPhaseSummary = validateTrace(replayInput, pipeline);
    if (!Buffer.from(jcsCanonical(replayedPhaseSummary)).equals(Buffer.from(jcsCanonical(phaseSummary)))) {
      return { outcome: 'fail', detail: 'phaseSummary does not match the authority bundle' };
    }
    const refs = await resolveEvidence(replayInput, deps as BundleFinalizerDependencies, pipeline);
    if (jcsHashHex(refs) !== jcsHashHex(settlementEvidence)) return { outcome: 'fail', detail: 'bundle settlement evidence does not equal the re-derived SEB set' };
    return { outcome: 'pass', detail: 'buyer/seller copies, signatures, hashes, finalized commitment, and the shared evidence checks verified' };
  } catch (error) {
    if (error instanceof BundleFinalizationError && error.code === 'commitment-transport') return { outcome: 'indeterminate', detail: error.message };
    if (error instanceof BundleFinalizationError && error.code === 'commitment-not-refetched') return { outcome: 'indeterminate', detail: 'commitment-not-refetched' };
    if (error instanceof BundleFinalizationError && error.code === 'commitment-pending') return { outcome: 'indeterminate', detail: 'commitment-pending' };
    if (error instanceof BundleFinalizationError && error.code === 'evidence-transport') return { outcome: 'indeterminate', detail: 'evidence-not-refetched' };
    if (error instanceof BundleFinalizationError && error.code === 'commitment-unresolved') return { outcome: 'fail', detail: 'commitment-unresolved' };
    return { outcome: 'fail', detail: error instanceof Error ? error.message : 'bundle verification failed' };
  }
}
