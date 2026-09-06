/**
 * DACS-1 listings for the demo producers (the organ gateway and the AP2 test agent).
 *
 * A producer holds raw ed25519 keys for its parties. Its seller presents an IdentityBundle under the key's
 * self-certifying agent DID (DACS-1 §6.3.1), the listing takes the Standard's §6.3.4 members (listing-wire), is
 * signed over its signature-excluded JCS hash, is read back through the same rules the coordinator applies to a
 * counterparty's listing (verifyBundleListing) before it is anchored, and is anchored under the pinned dacs-sdk's
 * program-name form so that SDK's Agent resolves it by (owner, name).
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
  const unsigned = dacs1Listing({
    listingId,
    listingVersion: 1,
    seller: { identity, displayName: input.displayName },
    offering: input.offering,
    pricing: { kind: 'fixed', price: input.price },
    acceptedRails: [{ railId: input.railId }],
    pipeline: input.pipeline,
    terms: { deadlineSecAfterCommit: 3600 },
    validity: { notBefore: input.now - 60_000, notAfter: input.now + 7_200_000 },
  });
  const { listing, contentHash } = await signDacs1Listing(unsigned, signer);
  await verifyBundleListing(listing as Parameters<typeof verifyBundleListing>[0], { verifySignature: agentDidSignatureVerifier as never });
  const programName = sdkListingProgramName(logicalAddress);
  const locator = await input.anchor(programName, new TextDecoder().decode(jcsCanonical(listing)));
  return { listingId, logicalAddress, programName, locator, listing, contentHash, sellerClaim, identity };
}
