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
/** The pinned dacs-sdk's PhaseStep kinds (validators.ts PHASE_TYPES, 3aa1d7df); mirrored here with the date so a drift is a dated fact. 2026-09-06. */
const PHASE_TYPES = new Set(['vet-credentials', 'negotiate-fixed-price', 'negotiate-rfq', 'negotiate-sealed-envelope', 'negotiate-sealed-envelope-procurement', 'commit-agreement', 'commit-payee-bound-agreement', 'pay-evm-erc20', 'pay-solana-spl', 'pay-cross-chain-htlc', 'pay-cross-chain-liquidity-tank', 'pay-ap2', 'pay-x402', 'pay-dem', 'pay-alternative', 'deliver-storage-program', 'deliver-entitlement', 'deliver-attested-payload', 'rate']);
const NO_PARAMETER_PHASES = new Set(['vet-credentials', 'negotiate-fixed-price', 'commit-agreement', 'commit-payee-bound-agreement', 'deliver-storage-program', 'deliver-entitlement', 'deliver-attested-payload']);
const DELIVERABLE_KINDS = new Set(['storage-program', 'entitlement', 'attested-payload', 'external']);
/** LR-2: the complete canonical signed record, as the pinned dacs-sdk measures it (validators.ts isListingEnvelope). */
export const DACS1_LISTING_SIZE_CAP_BYTES = 16_384;

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const isStr = (v: unknown, max = Number.POSITIVE_INFINITY): v is string => typeof v === 'string' && v.length <= max;
const isUint = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;

/**
 * Structural check of a signed DACS-1 §6.3.4 Listing before it is anchored or accepted for anchoring, mirroring the
 * pinned dacs-sdk's isListing for the members a producer emits: any member outside the set is refused (a stray
 * `contentHash` would otherwise sit inside the signed scope and split the record from its ListingPin), every member
 * has the Standard's shape, the pipeline uses the SDK's PhaseStep kinds with their parameter rules, and the record
 * carries the CF-4 logical address derived from (seller claim, listingId, listingVersion). Throws with the reason.
 */
export function assertDacs1Listing(listing: unknown): asserts listing is Record<string, unknown> {
  if (!isObj(listing)) throw new Error('listing must be an object');
  for (const key of Object.keys(listing)) if (!LISTING_MEMBERS.has(key)) throw new Error(`listing.${key} is not a DACS-1 §6.3.4 member`);
  if (listing.dacsVersion !== '1') throw new Error(`listing.dacsVersion must be "1" (a DACS-1 §6.3.4 Listing; got: ${String(listing.dacsVersion)})`);
  if (!Number.isSafeInteger(listing.listingVersion) || (listing.listingVersion as number) < 1) throw new Error('listing.listingVersion must be an integer >= 1');
  if (!isStr(listing.listingId) || !/^[A-Za-z0-9._~-]{1,128}$/.test(listing.listingId)) throw new Error('listing.listingId must match ^[A-Za-z0-9._~-]{1,128}$');
  if (listing.requiredCapabilities !== undefined && !(Array.isArray(listing.requiredCapabilities) && listing.requiredCapabilities.every((c) => ['SR-1', 'SR-2', 'SR-3', 'SR-4', 'SR-5'].includes(c as string)))) throw new Error('listing.requiredCapabilities must list SR-1..SR-5 only');
  const seller = listing.seller;
  if (!isObj(seller) || !isStr(seller.displayName, 200)) throw new Error('listing.seller.displayName must be a string of at most 200 characters');
  const identity = seller.identity;
  if (!isObj(identity) || identity.bundleVersion !== '1' || !isStr(identity.presentedBy) || !isUint(identity.presentedAt)) throw new Error('listing.seller.identity must be an IdentityBundle (bundleVersion "1", presentedBy, presentedAt) (§6.3.2)');
  const claims = identity.claims;
  if (!Array.isArray(claims) || claims.length === 0 || !claims.every((c) => isObj(c) && isStr(c.ref))) throw new Error('listing.seller.identity.claims must be a non-empty array of { ref }');
  if (!claims.some((c) => (c as { ref: string }).ref === identity.presentedBy)) throw new Error('listing.seller.identity.presentedBy must be one of its claims (§6.3.2 BP-3)');
  const presentation = identity.presentation;
  if (!isObj(presentation) || presentation.kind !== 'per-claim' || !Array.isArray(presentation.signatures) || !presentation.signatures.every((e) => isObj(e) && isStr(e.ref) && isStr(e.signature))) throw new Error('listing.seller.identity.presentation must be { kind: "per-claim", signatures: [{ ref, signature }] }');
  const offering = listing.offering;
  if (!isObj(offering) || !isStr(offering.title, 200) || !isStr(offering.description, 2_000)) throw new Error('listing.offering.title (<= 200) and description (<= 2000) must be strings');
  if (!isStr(offering.category) || !offering.category.split('.').every((part) => part.length > 0)) throw new Error('listing.offering.category must be a dotted non-empty path');
  if (!Array.isArray(offering.tags) || offering.tags.length > 16 || !offering.tags.every((t) => isStr(t, 32))) throw new Error('listing.offering.tags must be at most 16 strings of at most 32 characters');
  const deliverable = offering.deliverable;
  if (!isObj(deliverable) || !DELIVERABLE_KINDS.has(deliverable.kind as string)) throw new Error('listing.offering.deliverable.kind must be storage-program, entitlement, attested-payload or external');
  if (deliverable.kind === 'storage-program' && deliverable.accessModel !== undefined && !['public', 'buyer-only', 'encrypt-to-buyer'].includes(deliverable.accessModel as string)) throw new Error('listing.offering.deliverable.accessModel must be public, buyer-only or encrypt-to-buyer');
  const requirement = listing.buyerRequirement;
  if (!isObj(requirement) || requirement.requirementVersion !== '1' || !Array.isArray(requirement.required) || !requirement.required.every((r) => isObj(r) && isStr(r.scheme) && /^[a-z][a-z0-9-]*$/.test(r.scheme) && typeof r.verificationRequired === 'boolean')) throw new Error('listing.buyerRequirement must be { requirementVersion: "1", required: [{ scheme, verificationRequired }] }');
  const pipeline = listing.pipeline;
  if (!Array.isArray(pipeline) || pipeline.length === 0) throw new Error('listing.pipeline must be a non-empty PhaseStep array');
  for (const step of pipeline) {
    if (!isObj(step) || !PHASE_TYPES.has(step.kind as string)) throw new Error(`listing.pipeline step kind is not a PhaseStep kind: ${String(isObj(step) ? step.kind : step)}`);
    const kind = step.kind as string;
    if (NO_PARAMETER_PHASES.has(kind)) { if (step.parameters !== undefined) throw new Error(`listing.pipeline ${kind} takes no parameters`); continue; }
    if (kind === 'rate') continue;
    if (!isObj(step.parameters)) throw new Error(`listing.pipeline ${kind} needs parameters`);
    if (kind.startsWith('pay-') && kind !== 'pay-alternative' && !(isStr(step.parameters.rail) && step.parameters.rail.length > 0)) throw new Error(`listing.pipeline ${kind} needs parameters.rail`);
  }
  const pricing = listing.pricing;
  if (!isObj(pricing) || pricing.kind !== 'fixed' || !isObj(pricing.price) || !isStr(pricing.price.amount) || !/^(0|[1-9][0-9]*)(\.[0-9]*[1-9])?$/.test(pricing.price.amount) || !isStr(pricing.price.currency)) throw new Error('listing.pricing must be { kind: "fixed", price: { amount (canonical decimal string), currency } } here');
  if (listing.acceptedRails !== undefined && !(Array.isArray(listing.acceptedRails) && listing.acceptedRails.every((r) => isObj(r) && isStr(r.railId) && r.railId.length > 0))) throw new Error('listing.acceptedRails must be [{ railId }]');
  const terms = listing.terms;
  if (!isObj(terms) || (terms.deadlineSecAfterCommit !== undefined && !(Number.isSafeInteger(terms.deadlineSecAfterCommit) && (terms.deadlineSecAfterCommit as number) >= 1))) throw new Error('listing.terms must be an object; deadlineSecAfterCommit, when present, a positive integer');
  const validity = listing.validity;
  if (!isObj(validity) || !isUint(validity.notBefore) || (validity.notAfter !== undefined && !(isUint(validity.notAfter) && validity.notAfter >= validity.notBefore))) throw new Error('listing.validity must carry notBefore (unix ms) and, when present, notAfter >= notBefore');
  const signature = listing.signature;
  if (!isObj(signature) || signature.algorithm !== 'ed25519' || !isStr(signature.signer) || !isStr(signature.value)) throw new Error('listing.signature must be { algorithm: "ed25519", signer, value } (§6.3.4)');
  if (signature.signer !== identity.presentedBy) throw new Error('listing signer must be the claim the seller identity bundle presents (§6.3.4)');
  const expectedLogical = listingLogicalAddress(identity.presentedBy, listing.listingId, listing.listingVersion as number);
  if (listing.logical_address !== expectedLogical) throw new Error(`listing.logical_address must be the CF-4 address derived from (seller claim, listingId, listingVersion): ${expectedLogical}`);
  const size = jcsCanonical(listing).length;
  if (size > DACS1_LISTING_SIZE_CAP_BYTES) throw new Error(`listing canonical signed record is ${size} bytes, over the LR-2 cap of ${DACS1_LISTING_SIZE_CAP_BYTES}`);
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
