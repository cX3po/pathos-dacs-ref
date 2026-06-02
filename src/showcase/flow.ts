/**
 * DACS commerce showcase — the Vendor↔Shopper DACS-1→5 flow.
 *
 * Two agents (a Vendor/seller and a Shopper/buyer) execute a full DACS commerce
 * session over the reference impl, producing REAL signed, content-addressed
 * artifacts at every stage and a two-sided AttestationBundle that verifyBundle
 * PASSES. This is the backend for the "agents doing commerce on Telegram"
 * showcase — the display/relay layer (display.ts) renders each StageEvent below
 * to a chat surface; this module is transport-agnostic and runs headless.
 *
 * Settlement defaults to a deterministic MOCK (no funds/keys); swap in real
 * HTLC testnet via settle/htlc-testnet.ts later (see buildspec).
 *
 * Honest scope: this proves the artifact + verification shape end-to-end. It is
 * NOT live on-chain (mock settlement) and uses local keypairs, not deployed
 * identities — by design, so the demo runs anywhere with zero setup.
 */
import { generateKeypair, sign } from '../lib/sign.js';
import { verifyBundle, bytesToHex } from '../lib/verify-bundle.js';
import { computeAnchorPair } from '../lib/verify-bundle.js';
import { DOMAIN_SEPARATORS } from '../domain-sep.js';
import { jcsCanonical, jcsHash, jcsHashHex } from '../jcs.js';
import type { AttestationBundle, PhaseRecord } from '../types/index.js';
import type { VerifyVerdict } from '../types/bundle.js';
import { mockSettle, type MockSettlement } from './mock-settle.js';

export interface StageEvent {
  stage: 'DACS-1 Identify' | 'DACS-2 Vet' | 'DACS-3 Negotiate' | 'DACS-4 Settle' | 'DACS-5 Verify';
  actor: 'Vendor' | 'Shopper';
  line: string;          // human-readable line for the chat surface
  artifactHash?: string; // contentHash of the signed artifact produced this stage
}

export interface ShowcaseSession {
  jobId: string;
  vendorId: string;   // hex pubkey
  shopperId: string;  // hex pubkey
  events: StageEvent[];
  anchors: { buyer: string; seller: string };
  buyerBundle: AttestationBundle;
  sellerBundle: AttestationBundle;
  verdicts: { buyer: VerifyVerdict; seller: VerifyVerdict };
  settlement: MockSettlement;
}

/** A signed, content-addressed artifact (listing / agreement). */
function signArtifact(separator: string, body: Record<string, unknown>, privKey: Uint8Array) {
  const canonical = jcsCanonical(body);
  const sig = sign(separator, canonical, privKey);
  return { body, contentHash: jcsHashHex(body), signature: Buffer.from(sig).toString('base64') };
}

function phase(phaseId: string, outcome: PhaseRecord['outcome'], artifactHash?: string): PhaseRecord {
  return {
    phaseId,
    startedAt: '2026-06-02T00:00:00Z',
    endedAt: '2026-06-02T00:00:01Z',
    outcome,
    attestations: [],
    detail: artifactHash ? { artifactHash } : undefined,
  };
}

function buildBundle(
  jobId: string,
  role: 'buyer' | 'seller',
  selfPriv: Uint8Array,
  selfPubHex: string,
  otherPubHex: string,
  phases: PhaseRecord[],
): AttestationBundle {
  const unsigned: AttestationBundle = {
    v: 'dacs-5-bundle:0.1',
    jobId,
    role,
    party: {
      v: 'dacs-1:0.1',
      primary: { scheme: 'cci', identifier: selfPubHex },
      claims: [],
      issuedAt: '2026-06-02T00:00:00Z',
      presentation: { kind: 'siwd' },
    },
    counterparty: { primary: { scheme: 'cci', identifier: otherPubHex } },
    state: 'completed',
    phases,
    finalisedAt: '2026-06-02T00:00:02Z',
  };
  const canonical = jcsCanonical(unsigned);
  const bundleHash = jcsHash(unsigned);
  const sig = sign(DOMAIN_SEPARATORS.BUNDLE_DACS5, canonical, selfPriv, bundleHash);
  return { ...unsigned, signature: Buffer.from(sig).toString('base64') };
}

/**
 * Run one Vendor↔Shopper DACS-1→5 commerce session. Returns the full session
 * with ordered StageEvents (for the chat surface) + both verified bundles.
 */
export async function runShowcaseSession(opts: { jobId?: string; item?: string; priceOs?: string } = {}): Promise<ShowcaseSession> {
  const jobId = opts.jobId ?? 'showcase-0001';
  const item = opts.item ?? 'inference-job:gpt-class-summarisation';
  const priceOs = opts.priceOs ?? '5000000000'; // 5 DEM in OS

  const vendor = generateKeypair();
  const shopper = generateKeypair();
  const vendorId = bytesToHex(vendor.pubKey);
  const shopperId = bytesToHex(shopper.pubKey);

  const events: StageEvent[] = [];

  // DACS-1 Identify — Vendor publishes a signed listing; Shopper discovers it.
  const listing = signArtifact(DOMAIN_SEPARATORS.LISTING, {
    v: 'dacs-listing:0.1', listingId: `${jobId}-listing`, vendor: vendorId, item, priceOs,
    acceptedRails: ['pay-cross-chain-htlc'],
  }, vendor.privKey);
  events.push({ stage: 'DACS-1 Identify', actor: 'Vendor', line: `Listed "${item}" @ ${priceOs} OS`, artifactHash: listing.contentHash });
  events.push({ stage: 'DACS-1 Identify', actor: 'Shopper', line: `Discovered listing ${listing.contentHash.slice(0, 12)}…` });

  // DACS-2 Vet — Shopper verifies Vendor's identity/credential (cci primary claim).
  events.push({ stage: 'DACS-2 Vet', actor: 'Shopper', line: `Verified Vendor identity (cci:${vendorId.slice(0, 10)}…) ✓` });

  // DACS-3 Negotiate — fixed-price; Shopper accepts → signed AgreementDocument.
  const agreement = signArtifact(DOMAIN_SEPARATORS.AGREEMENT, {
    v: 'dacs-agreement:0.1', jobId, listingHash: listing.contentHash,
    terms: { priceOs, rail: 'pay-cross-chain-htlc' }, buyer: shopperId, seller: vendorId,
  }, shopper.privKey);
  events.push({ stage: 'DACS-3 Negotiate', actor: 'Shopper', line: `Accepted terms → signed Agreement`, artifactHash: agreement.contentHash });

  // DACS-4 Settle — Shopper pays; SettlementEvidence produced + anchored (mock).
  const settlement = mockSettle({ jobId, agreementHash: agreement.contentHash, priceOs, payerPriv: shopper.privKey });
  events.push({ stage: 'DACS-4 Settle', actor: 'Shopper', line: `Settled ${priceOs} OS via ${settlement.rail} (mock)`, artifactHash: settlement.contentHash });

  // DACS-5 Verify — both sides emit an AttestationBundle; each is verified.
  const phases: PhaseRecord[] = [
    phase('identify', 'pass', listing.contentHash),
    phase('vet-credentials', 'pass'),
    phase('negotiate-fixed-price', 'pass', agreement.contentHash),
    phase('pay-cross-chain-htlc', 'pass', settlement.contentHash),
  ];
  const sellerBundle = buildBundle(jobId, 'seller', vendor.privKey, vendorId, shopperId, phases);
  const buyerBundle = buildBundle(jobId, 'buyer', shopper.privKey, shopperId, vendorId, phases);

  const buyerVerdict = await verifyBundle(buyerBundle, { skipTwoSidedLookup: true });
  const sellerVerdict = await verifyBundle(sellerBundle, { skipTwoSidedLookup: true });
  events.push({ stage: 'DACS-5 Verify', actor: 'Vendor', line: `Seller AttestationBundle: ${sellerVerdict.decision.toUpperCase()}`, artifactHash: sellerVerdict.canonicalBundleHash });
  events.push({ stage: 'DACS-5 Verify', actor: 'Shopper', line: `Buyer AttestationBundle: ${buyerVerdict.decision.toUpperCase()}`, artifactHash: buyerVerdict.canonicalBundleHash });

  return {
    jobId, vendorId, shopperId, events,
    anchors: computeAnchorPair(jobId),
    buyerBundle, sellerBundle,
    verdicts: { buyer: buyerVerdict, seller: sellerVerdict },
    settlement,
  };
}
