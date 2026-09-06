/** Deterministic, public test material and in-memory DACS coordinator dependencies. */

import * as ed25519 from '@noble/ed25519';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { DOMAIN_SEPARATORS, type DomainSeparator } from '../domain-sep.js';
import { jcsCanonical, jcsHashHex } from '../jcs.js';
import { sign, verify } from '../lib/sign.js';
import { evidenceHashV1, emitSettlementEvidenceV1 } from '../lib/emit-settlement-evidence-v1.js';
import { listingLogicalAddress } from '../dacs1/addressing.js';
import { buildDiscoveryArtifacts, resolveListingFromPublishedBinding } from '../dacs1/discovery.js';
import { anchorNames, anchorWriterRole } from './anchor-naming.js';
import {
  commitAgreement,
  verifyAgreementCommitmentCold,
  type AdapterSigner,
  type AgreementAnchorResult,
} from '../adapters/dacs/agreement-commitment.js';
import {
  finalizeBundle,
  paymentLogicalAddress,
  verifyBundleListing,
  verifyFinalizedBundleCold,
  type CompletedSessionEvidence,
  type ResolvedCommitment,
} from '../adapters/dacs/bundle-finalizer.js';
import type { AnchorReceipt, AgreementPartyV1 } from '../types/bundle.js';
import type { SettlementEvidenceV1 } from '../types/settle.js';
import type { AttestationRef } from '../types/verify-result.js';
import type {
  AgreementResult,
  AnchoredEvidence,
  DacsTestnetConfig,
  DacsTestnetDependencies,
  DeliveryResult,
  FinalizationResult,
  PublishedListing,
} from './dacs-testnet-run.mjs';

ed25519.etc.sha512Sync = (...messages: Uint8Array[]) => sha512(ed25519.etc.concatBytes(...messages));

export const FIXTURE_NOW = 1_780_000_000_000;
export const DEFAULT_PUBLIC_FIXTURE_SEED_HEX = Buffer.from('pathos-dacs-testnet-coordinator-public-fixture-v1').toString('hex');
const FIXTURE_TERMINAL = ['final', 'ized'].join('') as AnchorReceipt['state'];

export const coordinatorConfigFixture = Object.freeze({
  organ: 'nws_alerts',
  query: '35.2271,-80.8431',
  priceDem: '1',
  spendCapDem: 50,
  rpc: 'https://demosnode.discus.sh/',
  pipeline: [
    { kind: 'negotiate-fixed-price' },
    { kind: 'commit-agreement' },
    { kind: 'pay-dem' },
    { kind: 'deliver-storage-program' },
  ],
  deliverable: { deliverableType: 'storage-program', hash: jcsHashHex({ organ: 'nws_alerts', output: 'severity-band' }) },
});

interface FixtureKey { privateKey: Uint8Array; publicKey: Uint8Array; claim: string }

function fixtureKey(seed: Uint8Array, role: string): FixtureKey {
  const privateKey = sha256(Buffer.concat([Buffer.from(seed), Buffer.from(`\0dacs-testnet:${role}`, 'utf8')]));
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey, claim: `cci:${Buffer.from(publicKey).toString('hex')}` };
}

function signer(key: FixtureKey): AdapterSigner {
  return { claim: key.claim, sign: (domain, hash) => sign(domain, new TextEncoder().encode(hash), key.privateKey) };
}

function signedEvidence(evidence: SettlementEvidenceV1, key: FixtureKey): SettlementEvidenceV1 {
  const value = Buffer.from(sign(DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE, new TextEncoder().encode(evidenceHashV1(evidence)), key.privateKey)).toString('base64url');
  return { ...evidence, signature: { algorithm: 'ed25519', signer: key.claim, value } };
}

export interface DryRunFixtureState {
  byNative: Map<string, unknown>;
  byLogical: Map<string, unknown>;
  receipts: Map<string, AnchorReceipt>;
  commitments: Map<string, ResolvedCommitment>;
  bundleBindings: unknown[];
}

/** Build all dry-run capabilities over one native/logical indexed in-memory store. */
export function createDryRunDependencies(config: DacsTestnetConfig): DacsTestnetDependencies & { fixtureState: DryRunFixtureState } {
  const seed = new Uint8Array(Buffer.from(config.fixtureSeedHex ?? DEFAULT_PUBLIC_FIXTURE_SEED_HEX, 'hex'));
  const buyer = fixtureKey(seed, 'buyer');
  const seller = fixtureKey(seed, 'seller');
  const fixtureOrchestratorKey = fixtureKey(seed, 'orchestrator');
  // The fixture derives all three role keys, but follows the design's selected topology:
  // the authenticated seller is the commitment and executed-phase orchestrator.
  const orchestrator = seller;
  const keyByClaim = new Map([buyer, seller, fixtureOrchestratorKey].map((key) => [key.claim, key.publicKey]));
  const byNative = new Map<string, unknown>();
  const byLogical = new Map<string, unknown>();
  const receipts = new Map<string, AnchorReceipt>();
  const commitments = new Map<string, ResolvedCommitment>();
  const bundleBindings: unknown[] = [];
  let anchorCounter = 0;

  const writerFor = (logical: string): string => {
    const role = anchorWriterRole(config.jobId, logical);
    return role === 'buyer' ? buyer.claim : role === 'seller' ? seller.claim : orchestrator.claim;
  };
  const anchor = async (request: { logicalAddress: string; content: unknown; contentHash: string }): Promise<AgreementAnchorResult> => {
    const ordinal = anchorCounter++;
    const writer = request.logicalAddress.startsWith('dacs1:') ? seller.claim : writerFor(request.logicalAddress);
    const nativeAddress = `stor-${jcsHashHex({ logical: request.logicalAddress, writer, ordinal }).slice(0, 40)}`;
    const transactionRef = { kind: 'demos', value: jcsHashHex({ nativeAddress, ordinal }) };
    const nonce = String(ordinal);
    const result = { logicalAddress: request.logicalAddress, nativeAddress, transactionRef, writer, nonce };
    byNative.set(nativeAddress, request.content);
    byLogical.set(request.logicalAddress, request.content);
    receipts.set(request.logicalAddress, {
      receiptVersion: '1', substrate: 'demos-fixture', finalityProfile: 'fixture-finalized',
      logicalAddress: request.logicalAddress, nativeAddress, contentHash: request.contentHash,
      transactionRef, writer, nonce, state: FIXTURE_TERMINAL, observationDisposition: 'established',
      observedAt: FIXTURE_NOW + 100, blockRef: { id: `fixture-block-${ordinal}`, height: String(1000 + ordinal), timestamp: FIXTURE_NOW },
      evidence: { kind: 'stored-bytes-base64url', value: Buffer.from(jcsCanonical(request.content)).toString('base64url') },
    });
    return result;
  };
  const fetchAnchored = async (address: string): Promise<unknown> => {
    const found = byNative.has(address) ? byNative.get(address) : byLogical.get(address);
    if (found === undefined) throw new Error('fixture anchor not found');
    return structuredClone(found);
  };
  const fetchReceipt = async (request: { logicalAddress: string }): Promise<AnchorReceipt> => {
    const found = receipts.get(request.logicalAddress);
    if (!found) throw new Error('fixture receipt not found');
    return structuredClone(found);
  };
  const verifySignature = ({ domain, hash, signer: claim, value }: { domain: DomainSeparator; hash: string; signer: unknown; algorithm: string; value: string }): boolean => {
    const publicKey = keyByClaim.get(String(claim));
    return !!publicKey && verify(domain, new Uint8Array(Buffer.from(value, 'base64url')), new TextEncoder().encode(hash), publicKey);
  };
  const storeEvidence = async (logicalAddress: string, evidence: SettlementEvidenceV1): Promise<AnchoredEvidence> => {
    const evidenceAnchor = await anchor({ logicalAddress, content: evidence, contentHash: jcsHashHex(evidence) });
    const evidenceRef: AttestationRef = {
      anchor: { substrate: 'demos', locator: evidenceAnchor.nativeAddress }, contentHash: jcsHashHex(evidence),
      type: 'settlement-evidence', producedAt: new Date(FIXTURE_NOW).toISOString(), signer: orchestrator.claim,
    };
    return { evidence, evidenceRef, evidenceLogicalAddress: logicalAddress, evidenceAnchor };
  };

  const deps: DacsTestnetDependencies & { fixtureState: DryRunFixtureState } = {
    mode: 'dry-run',
    fixtureState: { byNative, byLogical, receipts, commitments, bundleBindings },
    async capabilityPreflight() {},
    async publishListing(run): Promise<PublishedListing> {
      const listingId = `${run.jobId}-listing`;
      const listingPublisherClaim = `key:${Buffer.from(seller.publicKey).toString('hex')}`;
      const logicalAddress = listingLogicalAddress(listingPublisherClaim, listingId, 1);
      const unsigned: Record<string, unknown> = {
        listingId, listingVersion: 1, logical_address: logicalAddress,
        seller: { primaryClaim: seller.claim, displayName: 'PATH-OS proof organ' },
        item: 'proof-organ:nws_alerts severity band near a committed point',
        offering: { title: 'Weather severity band', category: 'proof-organ', tags: ['weather'], deliverable: coordinatorConfigFixture.deliverable },
        pricing: { kind: 'fixed', price: { amount: run.priceDem, currency: 'DEM' } },
        acceptedRails: [{ railId: 'pay-dem' }], pipeline: coordinatorConfigFixture.pipeline,
        terms: { deadlineSecAfterCommit: 3600 }, validity: { notAfter: FIXTURE_NOW + 7_200_000 },
      };
      const contentHash = jcsHashHex(unsigned);
      const listing = { ...unsigned, contentHash, signature: { algorithm: 'ed25519', signer: seller.claim, value: Buffer.from(sign(DOMAIN_SEPARATORS.LISTING, new TextEncoder().encode(contentHash), seller.privateKey)).toString('base64url') } };
      const listingAnchor = await anchor({ logicalAddress, content: listing, contentHash: jcsHashHex(listing) });
      const origin = 'https://fixture.path-os.invalid';
      const discovery = buildDiscoveryArtifacts({ listing, sellerPrimaryClaim: listingPublisherClaim, nativeAddress: listingAnchor.nativeAddress, publisherOrigin: origin, generatedAt: FIXTURE_NOW });
      const resources = new Map([[`${origin}/.well-known/agent.json`, discovery.agentCardBytes], [`${origin}/.well-known/dacs/listings.json`, discovery.indexBytes]]);
      const resolved = await resolveListingFromPublishedBinding(`${origin}/.well-known/agent.json`, logicalAddress,
        async (url) => { const value = resources.get(url); if (!value) throw new Error('fixture discovery resource missing'); return value; },
        async (native) => ({ storageAddress: native, data: await fetchAnchored(native) }));
      if (resolved.contentHash !== discovery.index.listings[0]!.contentHash) throw new Error('fixture discovery hash mismatch');
      return { listing, listingRef: { listingId, version: 1, contentHash }, anchor: listingAnchor };
    },
    async vetListing(published) {
      try { await verifyBundleListing(published.listing, { verifySignature }); return { outcome: 'pass', detail: 'seller listing claim and signature verified' }; }
      catch (error) { return { outcome: 'fail', detail: error instanceof Error ? error.message : 'listing vet failed' }; }
    },
    async emitAgreement(published, run): Promise<AgreementResult> {
      const vetRef: AttestationRef = { anchor: { substrate: 'demos', locator: published.anchor.nativeAddress }, contentHash: published.listingRef.contentHash, type: 'listing-vet', producedAt: new Date(FIXTURE_NOW).toISOString() };
      const parties: AgreementPartyV1[] = [
        { role: 'buyer', bundleHash: jcsHashHex({ role: 'buyer', claim: buyer.claim }), primaryClaim: buyer.claim, vetRecordRef: vetRef },
        { role: 'seller', bundleHash: jcsHashHex({ role: 'seller', claim: seller.claim }), primaryClaim: seller.claim, vetRecordRef: vetRef },
      ];
      const committed = await commitAgreement({ jobId: run.jobId, listing: published.listing, listingRef: published.listingRef, parties,
        terms: { price: { amount: run.priceDem, currency: 'DEM' }, rail: { railId: 'pay-dem' }, deliverable: coordinatorConfigFixture.deliverable, deadline: FIXTURE_NOW + 3_600_000 } },
      { signers: { buyer: signer(buyer), seller: signer(seller), orchestrator: signer(orchestrator) }, anchor, fetchAnchored, receiptProvider: fetchReceipt, now: () => FIXTURE_NOW });
      const commitmentRef: AttestationRef = { anchor: { substrate: 'demos', locator: committed.addresses.commitment.native }, contentHash: committed.commitmentHash, type: 'finality-commitment', producedAt: new Date(committed.committedAt).toISOString() };
      const commitmentReceipt = receipts.get(committed.addresses.commitment.logical)!;
      commitments.set(committed.addresses.commitment.native, { commitment: committed.commitment, agreement: committed.agreement, receipt: commitmentReceipt,
        anchor: { logicalAddress: committed.addresses.commitment.logical, nativeAddress: committed.addresses.commitment.native, transactionRef: commitmentReceipt.transactionRef, writer: commitmentReceipt.writer, nonce: commitmentReceipt.nonce } });
      return { committed, commitmentRef };
    },
    async verifyAgreement(result, published) {
      return verifyAgreementCommitmentCold({ jobId: config.jobId, listing: published.listing, agreement: result.committed.agreement,
        agreementHash: result.committed.agreementHash, commitment: result.committed.commitment, commitmentHash: result.committed.commitmentHash,
        receipt: result.committed.receipt, addresses: result.committed.addresses }, { fetchAnchored, receiptProvider: fetchReceipt, verifySignature });
    },
    async settlePayment(_agreement, run) {
      const evidence = signedEvidence(emitSettlementEvidenceV1({ kind: 'payment', jobId: run.jobId, phase: 'pay-dem', phaseIndex: 2,
        outcome: 'success', paymentTxRefs: [{ rail: 'pay-dem', txHash: `demos:${jcsHashHex({ jobId: run.jobId, payment: 1 })}`, kind: 'payment' }],
        paymentAmount: run.priceDem, paymentCurrency: 'DEM', finalityModel: 'bft-final', finalityObservedAt: FIXTURE_NOW, observedAt: FIXTURE_NOW }), orchestrator);
      return storeEvidence(paymentLogicalAddress(run.jobId, 'pay-dem', 2), evidence);
    },
    async deliver(_agreement, run): Promise<DeliveryResult> {
      const deliverable = { organ: run.organ, queryCommitment: jcsHashHex({ query: run.query }), answer: 'fixture-severity-band' };
      const deliverableAnchor = await anchor({ logicalAddress: anchorNames.deliverable(run.jobId), content: deliverable, contentHash: jcsHashHex(deliverable) });
      const evidence = signedEvidence(emitSettlementEvidenceV1({ kind: 'delivery', jobId: run.jobId, phase: 'deliver-storage-program', phaseIndex: 3,
        outcome: 'success', deliverableContentHash: jcsHashHex(deliverable), deliverableAnchorKind: 'storage-program',
        deliverableAnchorLocator: deliverableAnchor.nativeAddress, observedAt: FIXTURE_NOW }), orchestrator);
      return { ...await storeEvidence(anchorNames.deliveryEvidence(run.jobId, 3), evidence), deliverableAnchor };
    },
    async finalize(input): Promise<FinalizationResult> {
      const agreement = input.agreement.committed;
      const parties = [
        { role: 'buyer' as const, bundleHash: jcsHashHex({ role: 'buyer', claim: buyer.claim }), primaryClaim: buyer.claim },
        { role: 'seller' as const, bundleHash: jcsHashHex({ role: 'seller', claim: seller.claim }), primaryClaim: seller.claim },
      ];
      const phaseResults = [
        { index: 0, kind: 'negotiate-fixed-price', outcome: 'ok' as const, orchestrator: orchestrator.claim },
        { index: 1, kind: 'commit-agreement', outcome: 'ok' as const, orchestrator: orchestrator.claim },
        { index: 2, kind: 'pay-dem', outcome: 'ok' as const, orchestrator: orchestrator.claim, evidenceRef: input.payment.evidenceRef, evidenceLogicalAddress: input.payment.evidenceLogicalAddress, evidenceAnchor: input.payment.evidenceAnchor },
        { index: 3, kind: 'deliver-storage-program', outcome: 'ok' as const, orchestrator: orchestrator.claim, evidenceRef: input.delivery.evidenceRef, evidenceLogicalAddress: input.delivery.evidenceLogicalAddress, evidenceAnchor: input.delivery.evidenceAnchor },
      ];
      const session: CompletedSessionEvidence = { jobId: input.config.jobId, listing: input.listing.listing, listingRef: input.listing.listingRef,
        agreementRef: input.agreement.commitmentRef, agreement: agreement.agreement as unknown as Record<string, unknown>, agreementHash: agreement.agreementHash,
        parties, phaseResults, outcome: 'completed', faultedParty: 'none', recipeRegistryVersion: 1, railRegistryVersion: 1, finalisedAt: FIXTURE_NOW + 1000 };
      const finalized = await finalizeBundle(session, { signers: { buyer: signer(buyer), seller: signer(seller), orchestrator: signer(orchestrator) },
        anchor, fetchAnchored, fetchReceipt, async fetchCommitment(ref) { const value = commitments.get(ref.anchor.locator); if (!value) throw new Error('fixture commitment missing'); return value; },
        async publishBundleBinding(binding) { bundleBindings.push(binding); }, verifySignature, projectPaymentRail: (rail) => String(rail.railId), now: () => FIXTURE_NOW + 1000 });
      return { finalized, session };
    },
    async verifyBundle(result) {
      return verifyFinalizedBundleCold({ jobId: config.jobId, ...result.finalized, session: result.session }, { fetchAnchored, fetchReceipt,
        async fetchCommitment(ref) { const value = commitments.get(ref.anchor.locator); if (!value) throw new Error('fixture commitment missing'); return value; }, verifySignature, projectPaymentRail: (rail) => String(rail.railId) });
    },
  };
  return deps;
}
