/**
 * DACS-1 listings for the demo producers (the organ gateway and the AP2 test agent).
 *
 * A producer holds raw ed25519 keys for its parties. Its seller presents an IdentityBundle under the key's
 * self-certifying agent DID (DACS-1 §6.3.1), the listing takes the Standard's §6.3.4 members (listing-wire), is
 * signed over its signature-excluded JCS hash, carries its CF-4 logical address as metadata (§6.3.4(b)), is checked
 * structurally against the members the pinned dacs-sdk's isListing reads and the LR-2 size cap, is read back through
 * the same rules the coordinator applies to a counterparty's listing (verifyBundleListing) before it is anchored, and
 * is anchored under that SDK's program-name form so its Agent resolves the listing by (owner, name).
 */
import { verifyBundleListing } from '../adapters/dacs/bundle-finalizer.js';
import type { AdapterSigner } from '../adapters/dacs/agreement-commitment.js';
import { listingLogicalAddress } from '../dacs1/addressing.js';
import { jcsCanonical } from '../jcs.js';
import { sign, verify } from '../lib/sign.js';
import { bytesToHex } from '../lib/verify-bundle.js';
import {
  dacs1Listing,
  presentIdentity,
  sdkListingProgramName,
  signDacs1Listing,
  type Dacs1ListingInput,
  type PresentationSignatureVerifier,
  type SellerIdentityBundle,
} from './listing-wire.js';

export interface ProducerKeypair { privKey: Uint8Array; pubKey: Uint8Array }

const AGENT_DID = /^did:demos:agent:([0-9a-f]{64})$/;

/** The DACS-1 §6.3.1 self-certifying agent DID of an ed25519 public key: `did:demos:agent:<64 lowercase hex>`. */
export function agentDidForPubkey(pubKey: Uint8Array): string {
  return `did:demos:agent:${bytesToHex(pubKey).toLowerCase()}`;
}

/** An AdapterSigner over a raw ed25519 keypair whose claim is the key's agent DID. */
export function keypairSigner(keys: ProducerKeypair): AdapterSigner {
  return {
    claim: agentDidForPubkey(keys.pubKey) as AdapterSigner['claim'],
    algorithm: 'ed25519',
    sign: (domain, hash) => sign(domain, new TextEncoder().encode(hash), keys.privKey),
  };
}

/** Verifies an ed25519 signature under the key an agent DID names; any other claim form is unknown here and fails. */
export const agentDidSignatureVerifier: PresentationSignatureVerifier = ({ domain, hash, signer, value }) => {
  const did = AGENT_DID.exec(String(signer));
  if (!did) return false;
  try {
    return verify(domain, new Uint8Array(Buffer.from(value, 'base64url')), new TextEncoder().encode(hash), new Uint8Array(Buffer.from(did[1]!, 'hex')));
  } catch {
    return false;
  }
};

/** The §6.3.4 members a producer's listing may carry: the Standard's, plus the CF-4 logical address the anchored record carries as metadata (DACS-1-IDENTIFY §6.3.4(b)). */
const LISTING_MEMBERS = new Set(['dacsVersion', 'listingVersion', 'listingId', 'requiredCapabilities', 'seller', 'offering', 'buyerRequirement', 'pipeline', 'pricing', 'acceptedRails', 'terms', 'validity', 'signature', 'logical_address']);
/**
 * Mirrored from the pinned dacs-sdk's validators.ts (3aa1d7df) on 2026-09-06: PHASE_TYPES, NO_PARAMETER_PHASES and the
 * deliverable kinds. A drift from that file is a dated fact; the differential test
 * (test/vectors/producer-listing-sdk-differential.test.ts, run with DACS_SDK_DIR) measures this check against the SDK's
 * own isListing on the shapes the producers emit and the refusals reviews found.
 */
const PHASE_TYPES = new Set(['vet-credentials', 'negotiate-fixed-price', 'negotiate-rfq', 'negotiate-sealed-envelope', 'negotiate-sealed-envelope-procurement', 'commit-agreement', 'commit-payee-bound-agreement', 'pay-evm-erc20', 'pay-solana-spl', 'pay-cross-chain-htlc', 'pay-cross-chain-liquidity-tank', 'pay-ap2', 'pay-x402', 'pay-dem', 'pay-alternative', 'deliver-storage-program', 'deliver-entitlement', 'deliver-attested-payload', 'rate']);
const NO_PARAMETER_PHASES = new Set(['vet-credentials', 'negotiate-fixed-price', 'commit-agreement', 'commit-payee-bound-agreement', 'deliver-storage-program', 'deliver-entitlement', 'deliver-attested-payload']);
/** The verification-method kinds the pre-flight validates completely: the SDK's field-less kinds. Any other kind (tlsnotary, zktls, ...) carries fields this pre-flight does not check, so it is refused rather than half-validated (a declared stricter rule; the producers emit self-signed only). */
const FIELDLESS_VERIFICATION_METHOD_KINDS = new Set(['self-signed', 'demos-gcr-domain']);
/** LR-2: the complete canonical signed record, as the pinned dacs-sdk measures it (validators.ts isListingEnvelope). */
export const DACS1_LISTING_SIZE_CAP_BYTES = 16_384;

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const isStr = (v: unknown, max = Number.POSITIVE_INFINITY): v is string => typeof v === 'string' && v.length <= max;
const isOptStr = (v: unknown): boolean => v === undefined || typeof v === 'string';
const isUint = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;
const isPosInt = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 1;
const isClaimRef = (v: unknown): v is string => typeof v === 'string' && /^[a-z][a-z0-9-]*:.+$/.test(v) && v.trim() === v;
/** CD-1 canonical positive decimal: no leading zeros, no trailing zeros, not zero. */
const isPositiveCanonicalAmount = (v: unknown): boolean => typeof v === 'string' && /^(0|[1-9][0-9]*)(\.[0-9]*[1-9])?$/.test(v) && v !== '0';
const isCanonicalBase64Url = (v: unknown): boolean => typeof v === 'string' && v.length > 0 && /^[A-Za-z0-9_-]+$/.test(v) && Buffer.from(v, 'base64url').toString('base64url') === v;
function fail(reason: string): never { throw new Error(reason); }

function assertDeliverable(d: unknown): void {
  if (!isObj(d)) fail('listing.offering.deliverable must be a DeliverableSpec');
  switch (d.kind) {
    case 'storage-program':
      if (!isOptStr(d.schemaUrl) || (d.expectedSizeBytes !== undefined && !isUint(d.expectedSizeBytes)) || (d.accessModel !== undefined && !['public', 'buyer-only', 'encrypt-to-buyer'].includes(d.accessModel as string))) fail('listing.offering.deliverable (storage-program): schemaUrl string, expectedSizeBytes uint, accessModel public|buyer-only|encrypt-to-buyer');
      return;
    case 'entitlement':
      if (!isPosInt(d.durationSec) || typeof d.renewable !== 'boolean') fail('listing.offering.deliverable (entitlement): durationSec positive integer, renewable boolean');
      return;
    case 'attested-payload':
      if (!isStr(d.payloadFormat) || d.payloadFormat.length === 0 || (d.expectedSizeBytes !== undefined && !isUint(d.expectedSizeBytes))) fail('listing.offering.deliverable (attested-payload): payloadFormat non-empty, expectedSizeBytes uint');
      if (d.verificationMethod !== undefined && !(isObj(d.verificationMethod) && FIELDLESS_VERIFICATION_METHOD_KINDS.has(d.verificationMethod.kind as string) && Object.keys(d.verificationMethod).length === 1)) fail('listing.offering.deliverable.verificationMethod: this pre-flight accepts only { kind: "self-signed" } or { kind: "demos-gcr-domain" }; other kinds carry fields it does not validate');
      return;
    default:
      fail('listing.offering.deliverable.kind must be storage-program, entitlement or attested-payload here');
  }
}

function assertPipeline(listing: Record<string, unknown>): void {
  const pipeline = listing.pipeline;
  if (!Array.isArray(pipeline) || pipeline.length === 0) fail('listing.pipeline must be a non-empty PhaseStep array');
  const steps = pipeline as Array<Record<string, unknown>>;
  for (const step of steps) {
    if (!isObj(step) || !PHASE_TYPES.has(step.kind as string)) fail(`listing.pipeline step kind is not a PhaseStep kind: ${String(isObj(step) ? step.kind : step)}`);
    const kind = step.kind as string;
    if (NO_PARAMETER_PHASES.has(kind)) { if (step.parameters !== undefined) fail(`listing.pipeline ${kind} takes no parameters`); continue; }
    if (kind === 'rate') { if (step.parameters !== undefined && !(isObj(step.parameters) && (step.parameters.required === undefined || typeof step.parameters.required === 'boolean'))) fail('listing.pipeline rate parameters must be absent or { required?: boolean }'); continue; }
    if (!isObj(step.parameters)) fail(`listing.pipeline ${kind} needs parameters`);
    if (kind === 'pay-alternative') fail('listing.pipeline pay-alternative is not emitted by these producers');
    if (kind.startsWith('pay-') && !(isStr(step.parameters.rail) && step.parameters.rail.length > 0)) fail(`listing.pipeline ${kind} needs parameters.rail`);
    if (kind === 'negotiate-rfq' || kind.startsWith('negotiate-sealed')) fail(`listing.pipeline ${kind} is not emitted by these producers (fixed pricing only)`);
  }
  // DACS-3 §8.8 PS-1..PS-3: exactly one negotiation, exactly one commit right after it, fixed pricing under negotiate-fixed-price.
  const negotiate = steps.map((phase, index) => ({ phase, index })).filter(({ phase }) => (phase.kind as string).startsWith('negotiate-'));
  const commits = steps.map((phase, index) => ({ phase, index })).filter(({ phase }) => (phase.kind as string).startsWith('commit-'));
  if (negotiate.length !== 1 || commits.length !== 1 || commits[0]!.index !== negotiate[0]!.index + 1) fail('listing.pipeline must carry exactly one negotiate- step followed directly by exactly one commit- step (DACS-3 §8.8 PS-1/PS-2)');
  if (!steps.some((phase) => (phase.kind as string).startsWith('deliver-'))) fail('listing.pipeline must carry a deliver- step (DACS-4 §9.9 PIPE-1)');
  if (steps.some((phase) => phase.kind === 'deliver-attested-payload')) {
    const deliverable = isObj(listing.offering) ? (listing.offering as Record<string, unknown>).deliverable : undefined;
    if (!isObj(deliverable) || deliverable.kind !== 'attested-payload' || !isObj(deliverable.verificationMethod)) fail('listing.pipeline deliver-attested-payload needs an attested-payload deliverable with a verificationMethod (DACS-4 §9.6.3 DPA-1)');
  }
  // DACS-1 §6.3.4 step 8 / LRR-1: every payment phase names a rail the listing accepts, one phase kind per rail.
  const payPhases = steps.filter((phase) => (phase.kind as string).startsWith('pay-'));
  const rails = listing.acceptedRails as Array<{ railId?: unknown }> | undefined;
  if (payPhases.length > 0) {
    if (!rails || rails.length === 0) fail('listing.acceptedRails must name the rail(s) the payment phases use (DACS-1 §6.3.4 step 8)');
    const kindByRail = new Map<string, string>();
    for (const phase of payPhases) {
      const railId = (phase.parameters as Record<string, unknown>).rail as string;
      if (!rails.some((rail) => rail.railId === railId)) fail(`listing.pipeline ${String(phase.kind)} names rail ${railId}, which acceptedRails does not carry (LRR-1)`);
      const prior = kindByRail.get(railId);
      if (prior !== undefined && prior !== phase.kind) fail(`listing.pipeline binds rail ${railId} to two phase kinds (LRR-4)`);
      kindByRail.set(railId, phase.kind as string);
    }
  }
  if (rails) {
    const canonical = rails.map((rail) => JSON.stringify(rail, Object.keys(rail as object).sort()));
    if (new Set(canonical).size !== canonical.length) fail('listing.acceptedRails must not repeat a rail (LRR-1)');
  }
}

/**
 * Structural check of a signed DACS-1 §6.3.4 Listing before it is anchored or accepted for anchoring, mirroring the
 * pinned dacs-sdk's isListing for the shapes a producer emits: any member outside the set is refused (a stray
 * `contentHash` would otherwise sit inside the signed scope and split the record from its ListingPin), every member
 * has the Standard's shape, the pipeline uses the SDK's PhaseStep kinds with their parameter rules and coheres with the
 * pricing, the deliverable and the accepted rails, the signature value is canonical base64url, the record carries the
 * CF-4 logical address derived from (seller claim, listingId, listingVersion), and the complete canonical signed record
 * fits the LR-2 cap. Throws with the reason. It is a pre-flight, not the SDK's validator: the differential test keeps
 * the two in agreement on the shapes and refusals it enumerates.
 */
export function assertDacs1Listing(listing: unknown): asserts listing is Record<string, unknown> {
  if (!isObj(listing)) fail('listing must be an object');
  for (const key of Object.keys(listing)) if (!LISTING_MEMBERS.has(key)) fail(`listing.${key} is not a DACS-1 §6.3.4 member`);
  if (listing.dacsVersion !== '1') fail(`listing.dacsVersion must be "1" (a DACS-1 §6.3.4 Listing; got: ${String(listing.dacsVersion)})`);
  if (!isPosInt(listing.listingVersion)) fail('listing.listingVersion must be an integer >= 1');
  if (!isStr(listing.listingId) || !/^[A-Za-z0-9._~-]{1,128}$/.test(listing.listingId)) fail('listing.listingId must match ^[A-Za-z0-9._~-]{1,128}$');
  if (listing.requiredCapabilities !== undefined && !(Array.isArray(listing.requiredCapabilities) && listing.requiredCapabilities.every((c) => ['SR-1', 'SR-2', 'SR-3', 'SR-4', 'SR-5'].includes(c as string)))) fail('listing.requiredCapabilities must list SR-1..SR-5 only');
  const seller = listing.seller;
  if (!isObj(seller) || !isStr(seller.displayName, 200) || !isOptStr(seller.publicEndpoint)) fail('listing.seller.displayName must be a string of at most 200 characters (publicEndpoint, when present, a string)');
  const identity = seller.identity;
  if (!isObj(identity) || identity.bundleVersion !== '1' || !isClaimRef(identity.presentedBy) || !isUint(identity.presentedAt) || !isOptStr(identity.sessionNonce)) fail('listing.seller.identity must be an IdentityBundle (bundleVersion "1", presentedBy claim, presentedAt) (§6.3.2)');
  const claims = identity.claims;
  if (!Array.isArray(claims) || claims.length === 0 || !claims.every((c) => isObj(c) && isClaimRef(c.ref) && (c.issuedAt === undefined || isUint(c.issuedAt)) && (c.expiresAt === undefined || isUint(c.expiresAt)) && (c.metadata === undefined || isObj(c.metadata)) && c.verifiedBy === undefined)) fail('listing.seller.identity.claims must be a non-empty array of { ref } (issuedAt/expiresAt uint, metadata object; no verifiedBy here)');
  if (!claims.some((c) => (c as { ref: string }).ref === identity.presentedBy)) fail('listing.seller.identity.presentedBy must be one of its claims (§6.3.2 BP-3)');
  const presentation = identity.presentation;
  if (!isObj(presentation) || presentation.kind !== 'per-claim' || !Array.isArray(presentation.signatures) || presentation.signatures.length === 0 || !presentation.signatures.every((e) => isObj(e) && isClaimRef(e.ref) && isStr(e.signature))) fail('listing.seller.identity.presentation must be { kind: "per-claim", signatures: [{ ref, signature }] } with at least one signature');
  const offering = listing.offering;
  if (!isObj(offering) || !isStr(offering.title, 200) || !isStr(offering.description, 2_000)) fail('listing.offering.title (<= 200) and description (<= 2000) must be strings');
  if (!isStr(offering.category) || !offering.category.split('.').every((part) => part.length > 0)) fail('listing.offering.category must be a dotted non-empty path');
  if (!Array.isArray(offering.tags) || offering.tags.length > 16 || !offering.tags.every((t) => isStr(t, 32))) fail('listing.offering.tags must be at most 16 strings of at most 32 characters');
  if (!isOptStr(offering.extendedDescriptionUrl) || !isOptStr(offering.extendedDescriptionHash)) fail('listing.offering.extendedDescriptionUrl/Hash, when present, must be strings');
  assertDeliverable(offering.deliverable);
  const requirement = listing.buyerRequirement;
  const isClaimRequirement = (r: unknown): boolean => isObj(r) && isStr(r.scheme) && /^[a-z][a-z0-9-]*$/.test(r.scheme) && typeof r.verificationRequired === 'boolean' && (r.maxAge === undefined || isUint(r.maxAge)) && (r.recipeVersion === undefined || isPosInt(r.recipeVersion)) && (r.parameters === undefined || isObj(r.parameters));
  if (!isObj(requirement) || requirement.requirementVersion !== '1' || !Array.isArray(requirement.required) || !requirement.required.every(isClaimRequirement) || (requirement.oneOf !== undefined && !(Array.isArray(requirement.oneOf) && requirement.oneOf.every((g) => Array.isArray(g) && g.length > 0 && g.every(isClaimRequirement)))) || (requirement.preferredPresentation !== undefined && !['siwd', 'sr1-root', 'per-claim', 'session-key', 'any'].includes(requirement.preferredPresentation as string)) || (requirement.primaryClaimSelector !== undefined && !(isStr(requirement.primaryClaimSelector) && /^[a-z][a-z0-9-]*$/.test(requirement.primaryClaimSelector)))) fail('listing.buyerRequirement must be { requirementVersion: "1", required: [{ scheme, verificationRequired, maxAge?, recipeVersion?, parameters? }] } (§6.3.3)');
  const pricing = listing.pricing;
  if (!isObj(pricing) || pricing.kind !== 'fixed' || !isObj(pricing.price) || !isPositiveCanonicalAmount(pricing.price.amount) || !isStr(pricing.price.currency) || pricing.price.currency.length === 0 || !isOptStr(pricing.price.unit)) fail('listing.pricing must be { kind: "fixed", price: { amount (canonical decimal > 0), currency (non-empty) } } here');
  if (listing.acceptedRails !== undefined && !(Array.isArray(listing.acceptedRails) && listing.acceptedRails.every((r) => isObj(r) && isStr(r.railId) && r.railId.length > 0))) fail('listing.acceptedRails must be [{ railId }]');
  assertPipeline(listing);
  const terms = listing.terms;
  if (!isObj(terms) || !isOptStr(terms.termsOfServiceUrl) || !isOptStr(terms.termsOfServiceHash) || (terms.jurisdictions !== undefined && !(Array.isArray(terms.jurisdictions) && terms.jurisdictions.every((code) => isStr(code) && /^[A-Z]{2}$/.test(code)))) || (terms.deadlineSecAfterCommit !== undefined && !isPosInt(terms.deadlineSecAfterCommit)) || (terms.acceptanceModel !== undefined && terms.acceptanceModel !== 'auto-accept') || (terms.cancellationPolicy !== undefined && !['none', 'pre-commit', 'with-fee'].includes(terms.cancellationPolicy as string)) || (terms.retentionYears !== undefined && !isPosInt(terms.retentionYears))) fail('listing.terms members, when present, must take the Standard\'s shapes (termsOfServiceUrl/Hash strings, jurisdictions ISO codes, deadlineSecAfterCommit positive integer, acceptanceModel auto-accept, cancellationPolicy none|pre-commit|with-fee, retentionYears positive integer)');
  const validity = listing.validity;
  if (!isObj(validity) || !isUint(validity.notBefore) || (validity.notAfter !== undefined && !(isUint(validity.notAfter) && validity.notAfter >= validity.notBefore))) fail('listing.validity must carry notBefore (unix ms) and, when present, notAfter >= notBefore');
  const signature = listing.signature;
  if (!isObj(signature) || signature.algorithm !== 'ed25519' || !isClaimRef(signature.signer) || !isCanonicalBase64Url(signature.value)) fail('listing.signature must be { algorithm: "ed25519", signer, value } with a canonical base64url value (§6.3.4)');
  if (signature.signer !== identity.presentedBy) fail('listing signer must be the claim the seller identity bundle presents (§6.3.4)');
  const expectedLogical = listingLogicalAddress(identity.presentedBy, listing.listingId, listing.listingVersion);
  if (listing.logical_address !== expectedLogical) fail(`listing.logical_address must be the CF-4 address derived from (seller claim, listingId, listingVersion): ${expectedLogical}`);
  const size = jcsCanonical(listing).length;
  if (size > DACS1_LISTING_SIZE_CAP_BYTES) fail(`listing canonical signed record is ${size} bytes, over the LR-2 cap of ${DACS1_LISTING_SIZE_CAP_BYTES}`);
}

export interface ProducerListingInput {
  jobId: string;
  seller: ProducerKeypair;
  displayName: string;
  offering: Dacs1ListingInput['offering'];
  price: { amount: string; currency: string };
  railId: string;
  pipeline: Dacs1ListingInput['pipeline'];
  now: number;
  /** Anchors the JCS bytes of the signed listing under the given program name; returns the native locator. */
  anchor: (programName: string, bytes: string) => Promise<string> | string;
}

export interface ProducerListing {
  listingId: string;
  logicalAddress: string;
  programName: string;
  locator: string;
  listing: Record<string, unknown>;
  /** The listing's signature-excluded JCS hash: the ListingPin contentHash. */
  contentHash: string;
  sellerClaim: string;
  identity: SellerIdentityBundle;
}

/**
 * Present the seller's identity, build and sign the DACS-1 listing, verify it as a counterparty would, anchor it.
 * A listing the coordinator's rules would refuse never leaves the process.
 */
export async function publishProducerListing(input: ProducerListingInput): Promise<ProducerListing> {
  const signer = keypairSigner(input.seller);
  const sellerClaim = String(signer.claim);
  const listingId = `${input.jobId}-listing`;
  const logicalAddress = listingLogicalAddress(sellerClaim, listingId, 1);
  const identity = await presentIdentity(signer, input.now);
  const unsigned = {
    ...dacs1Listing({
      listingId,
      listingVersion: 1,
      seller: { identity, displayName: input.displayName },
      offering: input.offering,
      pricing: { kind: 'fixed', price: input.price },
      acceptedRails: [{ railId: input.railId }],
      pipeline: input.pipeline,
      terms: { deadlineSecAfterCommit: 3600 },
      validity: { notBefore: input.now - 60_000, notAfter: input.now + 7_200_000 },
    }),
    // DACS-1 §6.3.4(b): the anchored record carries its CF-4 logical address as metadata, inside the signed scope.
    logical_address: logicalAddress,
  };
  const { listing, contentHash } = await signDacs1Listing(unsigned, signer);
  assertDacs1Listing(listing);
  await verifyBundleListing(listing as Parameters<typeof verifyBundleListing>[0], { verifySignature: agentDidSignatureVerifier as never });
  const programName = sdkListingProgramName(logicalAddress);
  const locator = await input.anchor(programName, new TextDecoder().decode(jcsCanonical(listing)));
  return { listingId, logicalAddress, programName, locator, listing, contentHash, sellerClaim, identity };
}
