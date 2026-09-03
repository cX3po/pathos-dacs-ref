/**
 * DACS testnet lifecycle coordinator.
 *
 * Recommended defaults selected where the design leaves a choice: dry-run is the
 * explicit default; ambiguous writes/payments fail closed without retry; the existing
 * pay-dem JSONL path remains the settlement journal. LIVE loads that policy/journal,
 * checks operator/hash authorization, then refuses at its CORE §5.1 capability check
 * before credentials are loaded. Dry-run's dependency capabilityPreflight is a no-op.
 * `organ-gateway.mts` is deliberately neither imported nor modified.
 */

import { pathToFileURL } from 'node:url';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { jcsHashHex } from '../jcs.js';
import type { AgreementAnchorResult, CommittedAgreement } from '../adapters/dacs/agreement-commitment.js';
import type { AdapterSigner } from '../adapters/dacs/agreement-commitment.js';
import type { CompletedSessionEvidence, FinalizedBundleSet } from '../adapters/dacs/bundle-finalizer.js';
import type { SettlementEvidenceV1 } from '../types/settle.js';
import type { AttestationRef } from '../types/verify-result.js';
import type { AnchorReceipt, AgreementPartyV1 } from '../types/bundle.js';
import type { PayPolicy, TransferAuthorization } from './pay-policy.js';
import type { PayDemAuthorizationGate } from './pay-dem-authorization.js';
import type { DemosHandle } from '../demos/connection.js';

export const COORDINATOR_PIPELINE = [
  { kind: 'negotiate-fixed-price' },
  { kind: 'commit-agreement' },
  { kind: 'pay-dem' },
  { kind: 'deliver-storage-program' },
] as const;

export interface DacsTestnetConfig {
  jobId: string;
  mode: 'dry-run' | 'live';
  organ: string;
  query: string;
  priceDem: string;
  spendCapDem: number;
  rpc: string;
  fixtureSeedHex?: string;
}

export type ColdVerdict = { outcome: 'pass' | 'fail' | 'indeterminate'; detail: string };

export interface PublishedListing {
  listing: Record<string, unknown>;
  listingRef: { listingId: string; version: number; contentHash: string };
  anchor: AgreementAnchorResult;
}

export interface AnchoredEvidence {
  evidence: SettlementEvidenceV1;
  evidenceRef: AttestationRef;
  evidenceLogicalAddress: string;
  evidenceAnchor: AgreementAnchorResult;
}

export interface DeliveryResult extends AnchoredEvidence {
  deliverableAnchor: AgreementAnchorResult;
}

export interface AgreementResult {
  committed: CommittedAgreement;
  commitmentRef: AttestationRef;
}

export interface FinalizationResult {
  finalized: FinalizedBundleSet;
  session: CompletedSessionEvidence;
}

export interface DacsTestnetDependencies {
  /** Execution capability represented by this set (legacy injected dry fakes omit it). */
  mode?: DacsTestnetConfig['mode'];
  capabilityPreflight(config: DacsTestnetConfig): Promise<void>;
  publishListing(config: DacsTestnetConfig): Promise<PublishedListing>;
  vetListing(listing: PublishedListing, config: DacsTestnetConfig): Promise<ColdVerdict>;
  emitAgreement(listing: PublishedListing, config: DacsTestnetConfig): Promise<AgreementResult>;
  verifyAgreement(agreement: AgreementResult, listing: PublishedListing, config: DacsTestnetConfig): Promise<ColdVerdict>;
  settlePayment(agreement: AgreementResult, config: DacsTestnetConfig): Promise<AnchoredEvidence>;
  deliver(agreement: AgreementResult, config: DacsTestnetConfig): Promise<DeliveryResult>;
  finalize(input: {
    config: DacsTestnetConfig;
    listing: PublishedListing;
    agreement: AgreementResult;
    payment: AnchoredEvidence;
    delivery: DeliveryResult;
  }): Promise<FinalizationResult>;
  verifyBundle(finalization: FinalizationResult, config: DacsTestnetConfig): Promise<ColdVerdict>;
}

export interface DacsTestnetRunResult {
  jobId: string;
  mode: 'dry-run' | 'live';
  rollup: 'PASS' | 'FAIL' | 'INDETERMINATE';
  phases: Array<{ index: number; kind: string; outcome: 'PASS' | 'FAIL' }>;
  verification: { agreement: ColdVerdict; bundle: ColdVerdict };
  anchors: Partial<Record<'listing' | 'agreement' | 'commitment' | 'paymentEvidence' | 'deliverable' | 'deliveryEvidence' | 'buyerBundle' | 'sellerBundle', string>>;
  paramHash: string;
  authorizeLiveWith?: string;
  error?: { stage: string; code: 'phase-failed' | 'verification-failed'; detail: string };
}

export class DacsTestnetRefusal extends Error {
  constructor(public readonly code: 'usage' | 'config' | 'policy' | 'spend' | 'capability', message: string) {
    super(message);
    this.name = 'DacsTestnetRefusal';
  }
}

export interface ReceiptObservation {
  outcome: 'indeterminate';
  detail: string;
  observed?: { nativeAddress: string; writer: string; sizeBytes: number; creationTransaction?: string; creationTime: string; contentHash: string };
}

export type LiveNodeReceiptObservation = ReceiptObservation;

export interface CoreReceiptProvider {
  describe(): { kind: 'core-5.1-receipts'; provesFinality: boolean; source: string };
  fetch(request: { logicalAddress: string; contentHash: string; anchor?: AgreementAnchorResult }): Promise<AnchorReceipt | ReceiptObservation>;
}

interface LiveAdapterWiring {
  signers: { buyer: AdapterSigner; seller: AdapterSigner; orchestrator: AdapterSigner };
  handles: { buyer: DemosHandle; seller: DemosHandle };
  anchor(request: { logicalAddress: string; content: unknown; contentHash: string }): Promise<AgreementAnchorResult>;
  fetchAnchored(address: string): Promise<unknown>;
}

export interface LiveSettlementSeams {
  loadPolicy(env: NodeJS.ProcessEnv): Promise<PayPolicy | { verdict: 'BLOCK'; reason: string }>;
  resolveJournalPath(env: NodeJS.ProcessEnv): Promise<string>;
  readJournal(path: string): Promise<unknown[]>;
  killSwitchPresent(path: string): Promise<boolean>;
  authorizeTransfer(policy: PayPolicy, input: Parameters<typeof import('./pay-policy.js').authorizeTransfer>[1]): Promise<TransferAuthorization>;
  createJournal(path: string): Promise<ReturnType<typeof import('./pay-dem-journal.js').createPayDemJsonlJournal>>;
  createOutcomeJournal(path: string): Promise<ReturnType<typeof import('./pay-dem-journal.js').createPayDemOutcomeJournal>>;
  createAuthorizationGate(options: Parameters<typeof import('./pay-dem-authorization.js').createPayDemAuthorizationGate>[0]): Promise<PayDemAuthorizationGate>;
  connect(config: DacsTestnetConfig, env: NodeJS.ProcessEnv, provider: CoreReceiptProvider): Promise<LiveAdapterWiring>;
  balance(handle: DemosHandle): Promise<number>;
  preflight(input: import('./spend-preflight.js').PreflightParams): Promise<import('./spend-preflight.js').PreflightResult>;
  settle(input: Parameters<typeof import('../adapters/dacs/pay-dem-demosdk.js').settlePayDem>[0]): ReturnType<typeof import('../adapters/dacs/pay-dem-demosdk.js').settlePayDem>;
}

const expandHome = (path: string): string => path === '~' ? homedir() : path.startsWith('~/') ? join(homedir(), path.slice(2)) : path;

const defaultLiveSettlementSeams = (): LiveSettlementSeams => ({
  async loadPolicy(env) {
    const { loadPayPolicy } = await import('./pay-policy.js');
    return loadPayPolicy(env, (path) => readFileSync(path, 'utf8'));
  },
  async resolveJournalPath(env) {
    const journal = await import('./pay-dem-journal.js');
    try {
      return journal.resolvePayDemJournalPath(env.DACS_PAYDEM_JOURNAL ?? journal.DEFAULT_PAY_DEM_JOURNAL);
    } catch {
      throw new DacsTestnetRefusal('config', 'pay-dem journal path configuration was refused');
    }
  },
  async readJournal(path) { return (await import('./pay-dem-journal.js')).readPayDemJournalOrEmpty(path); },
  async killSwitchPresent(path) { return (await import('./pay-dem-journal.js')).payKillSwitchPresent(path); },
  async authorizeTransfer(policy, input) { return (await import('./pay-policy.js')).authorizeTransfer(policy, input); },
  async createJournal(path) { return (await import('./pay-dem-journal.js')).createPayDemJsonlJournal(path); },
  async createOutcomeJournal(path) { return (await import('./pay-dem-journal.js')).createPayDemOutcomeJournal(path); },
  async createAuthorizationGate(options) { return (await import('./pay-dem-authorization.js')).createPayDemAuthorizationGate(options); },
  connect: createLiveAdapterWiring,
  async balance(handle) {
    const info = await handle.demos.getAddressInfo(handle.address);
    return Number((info as { balance?: bigint }).balance ?? 0n) / 1e9;
  },
  async preflight(input) { return (await import('./spend-preflight.js')).preflight(input); },
  async settle(input) { return (await import('../adapters/dacs/pay-dem-demosdk.js')).settlePayDem(input); },
});

export interface LiveSettlementDependency {
  wiring: LiveAdapterWiring;
  settlePayment: DacsTestnetDependencies['settlePayment'];
}

/**
 * Construct the native pay-dem dependency using the gateway's audited policy path.
 * The returned function has the same `settlePayment` signature as the dry fixture.
 */
export async function createLiveSettlementDependency(
  config: DacsTestnetConfig,
  env: NodeJS.ProcessEnv = process.env,
  receiptProvider: CoreReceiptProvider = createNodeReceiptProvider(config),
  seamOverrides: Partial<LiveSettlementSeams> = {},
): Promise<LiveSettlementDependency> {
  const seams = { ...defaultLiveSettlementSeams(), ...seamOverrides };

  // (1) Match the gateway: policy and durable journal location are selected first.
  const policyResult = await seams.loadPolicy(env);
  if ('verdict' in policyResult) throw new DacsTestnetRefusal('policy', 'pay-dem policy refused the session');
  const journalPath = await seams.resolveJournalPath(env);

  // (2) Apply the complete native-payment policy before capability, credentials, or RPC connection.
  const nowIso = new Date().toISOString();
  const amountOs = (await import('../adapters/dacs/pay-dem.js')).demToOs(config.priceDem);
  const authorization = await seams.authorizeTransfer(policyResult, {
    amountOs,
    rpcUrl: config.rpc,
    spentTodayOs: (await import('./pay-policy.js')).spentTodayFromJournal(await seams.readJournal(journalPath), nowIso),
    killSwitchPresent: await seams.killSwitchPresent(expandHome(policyResult.killSwitchFile)),
    nowIso,
  });
  if (authorization.verdict !== 'PROCEED') throw new DacsTestnetRefusal('policy', 'pay-dem policy refused the transfer');
  const journal = await import('./pay-dem-journal.js');
  const paymentJournal = await seams.createJournal(journalPath);
  const durableOutcomeJournal = await seams.createOutcomeJournal(journalPath);
  const gate = await seams.createAuthorizationGate({
    policy: policyResult, journalPath, acquireLock: journal.acquirePayDemJournalLock,
    readJournal: journal.readPayDemJournalOrEmpty, killSwitchPresent: journal.payKillSwitchPresent,
    resolveKillSwitchPath: expandHome, durableOutcomeJournal,
  });

  // (3) Bind the LIVE request to the exact dry run before capability and credentials.
  const suppliedHash = env.GATEWAY_DRYRUN_HASH ?? null;
  if (suppliedHash !== parameterHash(config)) {
    throw new DacsTestnetRefusal('spend', 'LIVE dry-run hash gate refused the session');
  }

  // (4), then (5): connect checks capability before loading dotenv/env credentials.
  const wiring = await seams.connect(config, env, receiptProvider);

  // (6) Only now query balance and run the gateway-equivalent spend estimate.
  const balanceDem = await seams.balance(wiring.handles.buyer);
  const spend = await seams.preflight({
    purpose: `dacs-testnet live session ${config.jobId}`, estWrites: 8, estCostPerWriteDem: 1,
    createCostDem: Number(config.priceDem), maxSpendDem: config.spendCapDem, balanceDem,
    balanceMarginDem: 2, operatorApproved: env.GATEWAY_LIVE_APPROVED === '1', dryRunHash: suppliedHash,
  });
  if (spend.verdict !== 'PROCEED') {
    throw new DacsTestnetRefusal('spend', 'spend preflight refused the session');
  }

  return { wiring, settlePayment: async (_agreement, run) => {
    // (7) The real adapter retains authorize, durable outcome, and last-moment beforeBroadcast gates.
    const settled = await seams.settle({
      buyer: wiring.handles.buyer, sellerAddress: wiring.handles.seller.address, amountOs,
      amountDemCanonical: run.priceDem, jobId: run.jobId, phaseIndex: 2,
      journal: paymentJournal, authorizeTransfer: gate.authorize,
      journalTransferOutcome: gate.journalOutcome, beforeBroadcast: gate.beforeBroadcast,
    });
    if (!settled.ok) throw new DacsTestnetRefusal('spend', 'pay-dem settlement was refused');
    const logicalAddress = (await import('../adapters/dacs/bundle-finalizer.js')).paymentLogicalAddress(run.jobId, 'pay-dem', 2);
    const signatureValue = await wiring.signers.orchestrator.sign((await import('../domain-sep.js')).DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE,
      (await import('../lib/emit-settlement-evidence-v1.js')).evidenceHashV1(settled.evidence));
    const evidence = { ...settled.evidence, signature: { algorithm: 'ed25519' as const, signer: String(wiring.signers.orchestrator.claim),
      value: typeof signatureValue === 'string' ? signatureValue : Buffer.from(signatureValue).toString('base64url') } };
    const contentHash = jcsHashHex(evidence);
    const evidenceAnchor = await wiring.anchor({ logicalAddress, content: evidence, contentHash });
    return {
      evidence,
      evidenceRef: { anchor: { substrate: 'demos', locator: evidenceAnchor.nativeAddress }, contentHash,
        type: 'settlement-evidence', producedAt: new Date(settled.finalityObservedAt).toISOString(), signer: String(wiring.signers.orchestrator.claim) },
      evidenceLogicalAddress: logicalAddress, evidenceAnchor,
    };
  } };
}

/**
 * Lazy LIVE signer/storage wiring. It checks the provider's declared finality
 * capability before dotenv is loaded or any credential environment property is read.
 */
export async function createLiveAdapterWiring(
  config: DacsTestnetConfig,
  env: NodeJS.ProcessEnv = process.env,
  receiptProvider: CoreReceiptProvider = createNodeReceiptProvider(config),
): Promise<LiveAdapterWiring> {
  try {
    const capability = receiptProvider.describe();
    if (capability.kind !== 'core-5.1-receipts' || capability.provesFinality !== true) throw new Error('not finality proving');
  } catch {
    throw new DacsTestnetRefusal('capability', 'CORE §5.1 finalized-receipt provider is not configured');
  }
  const { config: loadEnvFile } = await import('dotenv');
  loadEnvFile({ path: env.DACS_ENV_PATH ?? '.env', processEnv: env as Record<string, string> });
  const { connectDemos, mnemonicFromEnv } = await import('../demos/connection.js');
  const { claimRefFor, signDomainHashAsAgent } = await import('../adapters/demos/identity.js');
  const storage = await import('../demos/storage.js');
  const buyerHandle = await connectDemos(mnemonicFromEnv('DEMOS_MNEMONIC', env), config.rpc);
  const sellerHandle = await connectDemos(mnemonicFromEnv('DEMOS_SELLER_MNEMONIC', env), config.rpc);
  const buyer = { ...buyerHandle, name: 'buyer', role: 'buyer-reviewer' as const, mnemonicEnv: 'DEMOS_MNEMONIC', claim: claimRefFor(buyerHandle.address) };
  const seller = { ...sellerHandle, name: 'seller', role: 'seller' as const, mnemonicEnv: 'DEMOS_SELLER_MNEMONIC', claim: claimRefFor(sellerHandle.address) };
  const asSigner = (handle: typeof buyer | typeof seller): AdapterSigner => ({ claim: handle.claim, sign: (domain, hash) => signDomainHashAsAgent(handle, domain, hash) });
  return {
    handles: { buyer: buyerHandle, seller: sellerHandle },
    signers: { buyer: asSigner(buyer), seller: asSigner(seller), orchestrator: asSigner(seller) },
    async anchor(request) {
      const handle = request.logicalAddress.endsWith(':buyer') ? buyerHandle : sellerHandle;
      const result = await storage.anchor(handle, request.logicalAddress, request.content as Record<string, unknown> | string);
      if (result.nonce === undefined) throw new DacsTestnetRefusal('capability', 'SR-2 anchor result did not bind a nonce');
      return { logicalAddress: request.logicalAddress, nativeAddress: result.storageAddress,
        transactionRef: { kind: 'demos', value: result.txHash }, writer: handle === buyerHandle ? buyer.claim : seller.claim, nonce: result.nonce };
    },
    async fetchAnchored(address) {
      const result = await storage.fetchAnchored(config.rpc, address);
      if (!result) throw new Error('anchor unavailable');
      return result.data;
    },
  };
}

/** The repository's only receipt observer; node read-back does not prove finality. */
export function createNodeReceiptProvider(config: Pick<DacsTestnetConfig, 'rpc'>): CoreReceiptProvider {
  return {
    describe: () => ({ kind: 'core-5.1-receipts', provesFinality: false, source: 'demos-node-storage-observer' }),
    async fetch(request) {
      const result = await (await import('../demos/storage.js')).fetchAnchored(config.rpc, request.anchor?.nativeAddress ?? request.logicalAddress);
      if (!result) return { outcome: 'indeterminate', detail: 'node storage record unavailable' };
      return { outcome: 'indeterminate', detail: 'CORE §5.1 finality evidence is unavailable from the node storage read', observed: {
        nativeAddress: result.storageAddress, writer: result.owner, sizeBytes: result.sizeBytes,
        ...(result.createdByTx ? { creationTransaction: result.createdByTx } : {}), creationTime: result.createdAt,
        contentHash: jcsHashHex(result.data),
      } };
    },
  };
}

/** Construct the selected LIVE dependency set through the gateway-equivalent pay-dem gate. */
export async function createLiveDependencies(
  config: DacsTestnetConfig,
  env: NodeJS.ProcessEnv = process.env,
  receiptProvider: CoreReceiptProvider = createNodeReceiptProvider(config),
  settlementSeams: Partial<LiveSettlementSeams> = {},
): Promise<DacsTestnetDependencies> {
  const { wiring, settlePayment } = await createLiveSettlementDependency(config, env, receiptProvider, settlementSeams);
  const { DOMAIN_SEPARATORS } = await import('../domain-sep.js');
  const { listingLogicalAddress } = await import('../dacs1/addressing.js');
  const { commitAgreement, verifyAgreementCommitmentCold } = await import('../adapters/dacs/agreement-commitment.js');
  const { finalizeBundle, verifyBundleListing, verifyFinalizedBundleCold } = await import('../adapters/dacs/bundle-finalizer.js');
  const { anchorNames } = await import('./anchor-naming.js');
  const { emitSettlementEvidenceV1, evidenceHashV1 } = await import('../lib/emit-settlement-evidence-v1.js');
  const { verifyDomainHashAgentSignature } = await import('../adapters/demos/identity.js');
  const commitments = new Map<string, import('../adapters/dacs/bundle-finalizer.js').ResolvedCommitment>();
  const fetchReceipt = async (request: { logicalAddress: string; contentHash: string; anchor?: AgreementAnchorResult }): Promise<AnchorReceipt> => {
    const result = await receiptProvider.fetch(request);
    if (!('receiptVersion' in result)) throw new DacsTestnetRefusal('capability', 'receipt provider did not establish CORE §5.1 finality');
    return result;
  };
  const verifySignature = ({ domain, hash, signer, value }: { domain: import('../domain-sep.js').DomainSeparator; hash: string; signer: unknown; algorithm: string; value: string }): boolean => {
    if (typeof signer !== 'string') return false;
    try { return verifyDomainHashAgentSignature(signer as `${string}:${string}`, domain, hash, Buffer.from(value, 'base64url')); }
    catch { return false; }
  };
  const signEvidence = async (evidence: SettlementEvidenceV1): Promise<SettlementEvidenceV1> => {
    const signature = await wiring.signers.orchestrator.sign(DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE, evidenceHashV1(evidence));
    return { ...evidence, signature: { algorithm: 'ed25519', signer: String(wiring.signers.orchestrator.claim),
      value: typeof signature === 'string' ? signature : Buffer.from(signature).toString('base64url') } };
  };

  const deps: DacsTestnetDependencies = {
    mode: 'live',
    async capabilityPreflight() {
      try { if (receiptProvider.describe().provesFinality !== true) throw new Error('not finality proving'); }
      catch { throw new DacsTestnetRefusal('capability', 'CORE §5.1 finalized-receipt provider is unavailable'); }
    },
    async publishListing(run) {
      const listingId = `${run.jobId}-listing`;
      const logicalAddress = listingLogicalAddress(String(wiring.signers.seller.claim), listingId, 1);
      const unsigned = {
        listingId, listingVersion: 1, logical_address: logicalAddress,
        seller: { primaryClaim: wiring.signers.seller.claim, displayName: 'PATH-OS proof organ' },
        item: `proof-organ:${run.organ}`,
        offering: { title: `${run.organ} result`, category: 'proof-organ', tags: [run.organ], deliverable: { deliverableType: 'storage-program' } },
        pricing: { kind: 'fixed', price: { amount: run.priceDem, currency: 'DEM' } },
        acceptedRails: [{ railId: 'pay-dem' }], pipeline: COORDINATOR_PIPELINE,
        terms: { deadlineSecAfterCommit: 3600 }, validity: { notAfter: Date.now() + 7_200_000 },
      };
      const contentHash = jcsHashHex(unsigned);
      const signature = await wiring.signers.seller.sign(DOMAIN_SEPARATORS.LISTING, contentHash);
      const listing = { ...unsigned, contentHash, signature: { algorithm: 'ed25519', signer: wiring.signers.seller.claim,
        value: typeof signature === 'string' ? signature : Buffer.from(signature).toString('base64url') } };
      const anchor = await wiring.anchor({ logicalAddress, content: listing, contentHash: jcsHashHex(listing) });
      return { listing, listingRef: { listingId, version: 1, contentHash }, anchor };
    },
    async vetListing(published) {
      try { await verifyBundleListing(published.listing, { verifySignature }); return { outcome: 'pass', detail: 'listing signature verified' }; }
      catch { return { outcome: 'fail', detail: 'listing verification failed' }; }
    },
    async emitAgreement(published, run) {
      const vetRef: AttestationRef = { anchor: { substrate: 'demos', locator: published.anchor.nativeAddress }, contentHash: published.listingRef.contentHash,
        type: 'listing-vet', producedAt: new Date().toISOString() };
      const parties: AgreementPartyV1[] = [
        { role: 'buyer', bundleHash: jcsHashHex({ role: 'buyer', claim: wiring.signers.buyer.claim }), primaryClaim: wiring.signers.buyer.claim, vetRecordRef: vetRef },
        { role: 'seller', bundleHash: jcsHashHex({ role: 'seller', claim: wiring.signers.seller.claim }), primaryClaim: wiring.signers.seller.claim, vetRecordRef: vetRef },
      ];
      const committed = await commitAgreement({ jobId: run.jobId, listing: published.listing, listingRef: published.listingRef, parties,
        terms: { price: { amount: run.priceDem, currency: 'DEM' }, rail: { railId: 'pay-dem' }, deliverable: { deliverableType: 'storage-program' }, deadline: Date.now() + 3_600_000 } },
      { signers: wiring.signers, anchor: wiring.anchor, fetchAnchored: wiring.fetchAnchored, receiptProvider: fetchReceipt });
      const commitmentRef: AttestationRef = { anchor: { substrate: 'demos', locator: committed.addresses.commitment.native }, contentHash: committed.commitmentHash,
        type: 'finality-commitment', producedAt: new Date(committed.committedAt).toISOString() };
      commitments.set(committed.addresses.commitment.native, { commitment: committed.commitment, agreement: committed.agreement, receipt: committed.receipt,
        anchor: { logicalAddress: committed.addresses.commitment.logical, nativeAddress: committed.addresses.commitment.native,
          transactionRef: committed.receipt.transactionRef, writer: committed.receipt.writer, ...(committed.receipt.nonce === undefined ? {} : { nonce: committed.receipt.nonce }) } });
      return { committed, commitmentRef };
    },
    async verifyAgreement(result, published) {
      return verifyAgreementCommitmentCold({ jobId: config.jobId, listing: published.listing, agreement: result.committed.agreement,
        agreementHash: result.committed.agreementHash, commitment: result.committed.commitment, commitmentHash: result.committed.commitmentHash,
        receipt: result.committed.receipt, addresses: result.committed.addresses }, { fetchAnchored: wiring.fetchAnchored, receiptProvider: fetchReceipt, verifySignature });
    },
    settlePayment,
    async deliver(_agreement, run) {
      const deliverable = { organ: run.organ, query: run.query, producedAt: new Date().toISOString() };
      const deliverableAnchor = await wiring.anchor({ logicalAddress: anchorNames.deliverable(run.jobId), content: deliverable, contentHash: jcsHashHex(deliverable) });
      const evidence = await signEvidence(emitSettlementEvidenceV1({ kind: 'delivery', jobId: run.jobId, phase: 'deliver-storage-program', phaseIndex: 3,
        outcome: 'success', deliverableContentHash: jcsHashHex(deliverable), deliverableAnchorKind: 'storage-program',
        deliverableAnchorLocator: deliverableAnchor.nativeAddress, observedAt: Date.now() }));
      const logicalAddress = anchorNames.deliveryEvidence(run.jobId, 3);
      const contentHash = jcsHashHex(evidence);
      const evidenceAnchor = await wiring.anchor({ logicalAddress, content: evidence, contentHash });
      return { evidence, evidenceRef: { anchor: { substrate: 'demos', locator: evidenceAnchor.nativeAddress }, contentHash,
        type: 'settlement-evidence', producedAt: new Date().toISOString(), signer: String(wiring.signers.orchestrator.claim) },
        evidenceLogicalAddress: logicalAddress, evidenceAnchor, deliverableAnchor };
    },
    async finalize(input) {
      const agreement = input.agreement.committed;
      const parties = [
        { role: 'buyer' as const, bundleHash: jcsHashHex({ role: 'buyer', claim: wiring.signers.buyer.claim }), primaryClaim: wiring.signers.buyer.claim },
        { role: 'seller' as const, bundleHash: jcsHashHex({ role: 'seller', claim: wiring.signers.seller.claim }), primaryClaim: wiring.signers.seller.claim },
      ];
      const phaseResults = [
        { index: 0, kind: 'negotiate-fixed-price', outcome: 'ok' as const, orchestrator: wiring.signers.orchestrator.claim },
        { index: 1, kind: 'commit-agreement', outcome: 'ok' as const, orchestrator: wiring.signers.orchestrator.claim },
        { index: 2, kind: 'pay-dem', outcome: 'ok' as const, orchestrator: wiring.signers.orchestrator.claim, evidenceRef: input.payment.evidenceRef, evidenceLogicalAddress: input.payment.evidenceLogicalAddress, evidenceAnchor: input.payment.evidenceAnchor },
        { index: 3, kind: 'deliver-storage-program', outcome: 'ok' as const, orchestrator: wiring.signers.orchestrator.claim, evidenceRef: input.delivery.evidenceRef, evidenceLogicalAddress: input.delivery.evidenceLogicalAddress, evidenceAnchor: input.delivery.evidenceAnchor },
      ];
      const session: CompletedSessionEvidence = { jobId: input.config.jobId, listing: input.listing.listing, listingRef: input.listing.listingRef,
        agreementRef: input.agreement.commitmentRef, agreement: agreement.agreement as unknown as Record<string, unknown>, agreementHash: agreement.agreementHash,
        parties, phaseResults, outcome: 'completed', faultedParty: 'none', recipeRegistryVersion: 1, railRegistryVersion: 1 };
      const finalized = await finalizeBundle(session, { signers: wiring.signers, anchor: wiring.anchor, fetchAnchored: wiring.fetchAnchored, fetchReceipt,
        async fetchCommitment(ref) { const value = commitments.get(ref.anchor.locator); if (!value) throw new Error('commitment unavailable'); return value; },
        verifySignature, projectPaymentRail: (rail) => String(rail.railId) });
      return { finalized, session };
    },
    async verifyBundle(result) {
      return verifyFinalizedBundleCold({ jobId: config.jobId, ...result.finalized, session: result.session }, { fetchAnchored: wiring.fetchAnchored, fetchReceipt,
        async fetchCommitment(ref) { const value = commitments.get(ref.anchor.locator); if (!value) throw new Error('commitment unavailable'); return value; },
        verifySignature, projectPaymentRail: (rail) => String(rail.railId) });
    },
  };
  return deps;
}

export function parameterHash(config: Pick<DacsTestnetConfig, 'organ' | 'query' | 'priceDem' | 'spendCapDem'>): string {
  return jcsHashHex({
    version: 'dacs-testnet-coordinator-params:1',
    organ: config.organ,
    query: config.query,
    price: config.priceDem,
    cap: config.spendCapDem,
    pipeline: COORDINATOR_PIPELINE,
  });
}

export function rollupColdVerifications(agreement: ColdVerdict, bundle: ColdVerdict): DacsTestnetRunResult['rollup'] {
  if (agreement.outcome === 'fail' || bundle.outcome === 'fail') return 'FAIL';
  if (agreement.outcome === 'indeterminate' || bundle.outcome === 'indeterminate') return 'INDETERMINATE';
  return 'PASS';
}

const unavailable = (detail: string): ColdVerdict => ({ outcome: 'indeterminate', detail });
const redactedVerdict = (phase: 'agreement' | 'bundle', verdict: ColdVerdict): ColdVerdict => ({
  outcome: verdict.outcome,
  detail: `${phase} verification ${verdict.outcome === 'pass' ? 'passed' : verdict.outcome}`,
});

/** Execute listing/vet and the four indexed pipeline phases in fail-closed order. */
export async function runDacsTestnetSession(config: DacsTestnetConfig, deps: DacsTestnetDependencies): Promise<DacsTestnetRunResult> {
  const paramHash = parameterHash(config);
  const phases: DacsTestnetRunResult['phases'] = [];
  const anchors: DacsTestnetRunResult['anchors'] = {};
  let agreementVerification = unavailable('agreement verification was not reached');
  let bundleVerification = unavailable('bundle verification was not reached');

  const failed = (stage: string, code: 'phase-failed' | 'verification-failed' = 'phase-failed'): DacsTestnetRunResult => ({
    jobId: config.jobId,
    mode: config.mode,
    rollup: 'FAIL',
    phases,
    verification: { agreement: agreementVerification, bundle: bundleVerification },
    anchors,
    paramHash,
    error: { stage, code, detail: `${stage}: phase failed` },
  });

  const guarded = async <T,>(stage: string, operation: () => Promise<T>): Promise<T | DacsTestnetRunResult> => {
    try { return await operation(); }
    catch (error) {
      if (error instanceof DacsTestnetRefusal) throw error;
      return failed(stage);
    }
  };

  if (config.mode !== (deps.mode ?? 'dry-run')) throw new DacsTestnetRefusal('capability', 'coordinator mode does not match dependency mode');
  const preflight = await guarded('capability-preflight', () => deps.capabilityPreflight(config));
  if (typeof preflight === 'object') return preflight;
  let listing: PublishedListing;
  const published = await guarded('listing', () => deps.publishListing(config));
  if ('rollup' in published) return published;
  listing = published;
  anchors.listing = listing.anchor.nativeAddress;

  try {
    const vet = await deps.vetListing(listing, config);
    if (vet.outcome !== 'pass') {
      const result = failed('vet', 'verification-failed');
      result.rollup = vet.outcome === 'indeterminate' ? 'INDETERMINATE' : 'FAIL';
      return result;
    }
  } catch (error) {
    if (error instanceof DacsTestnetRefusal) throw error;
    return failed('vet');
  }

  phases.push({ index: 0, kind: 'negotiate-fixed-price', outcome: 'PASS' });
  let agreement: AgreementResult;
  try {
    agreement = await deps.emitAgreement(listing, config);
    anchors.agreement = agreement.committed.addresses.agreement?.native;
    anchors.commitment = agreement.committed.addresses.commitment.native;
  } catch (error) {
    if (error instanceof DacsTestnetRefusal) throw error;
    phases.push({ index: 1, kind: 'commit-agreement', outcome: 'FAIL' });
    return failed('agreement-emission');
  }

  try {
    agreementVerification = redactedVerdict('agreement', await deps.verifyAgreement(agreement, listing, config));
    if (agreementVerification.outcome !== 'pass') {
      phases.push({ index: 1, kind: 'commit-agreement', outcome: 'FAIL' });
      const result = failed('agreement-verification', 'verification-failed');
      result.rollup = agreementVerification.outcome === 'fail' ? 'FAIL' : 'INDETERMINATE';
      return result;
    }
  } catch (error) {
    if (error instanceof DacsTestnetRefusal) throw error;
    phases.push({ index: 1, kind: 'commit-agreement', outcome: 'FAIL' });
    return failed('agreement-verification');
  }
  phases.push({ index: 1, kind: 'commit-agreement', outcome: 'PASS' });

  let payment: AnchoredEvidence;
  try {
    payment = await deps.settlePayment(agreement, config);
    anchors.paymentEvidence = payment.evidenceAnchor.nativeAddress;
    phases.push({ index: 2, kind: 'pay-dem', outcome: 'PASS' });
  } catch (error) {
    if (error instanceof DacsTestnetRefusal) throw error;
    phases.push({ index: 2, kind: 'pay-dem', outcome: 'FAIL' });
    return failed('payment');
  }

  let delivery: DeliveryResult;
  try {
    delivery = await deps.deliver(agreement, config);
    anchors.deliverable = delivery.deliverableAnchor.nativeAddress;
    anchors.deliveryEvidence = delivery.evidenceAnchor.nativeAddress;
    phases.push({ index: 3, kind: 'deliver-storage-program', outcome: 'PASS' });
  } catch (error) {
    if (error instanceof DacsTestnetRefusal) throw error;
    phases.push({ index: 3, kind: 'deliver-storage-program', outcome: 'FAIL' });
    return failed('delivery');
  }

  let finalization: FinalizationResult;
  try {
    finalization = await deps.finalize({ config, listing, agreement, payment, delivery });
    anchors.buyerBundle = finalization.finalized.bundles.buyer?.address.native;
    anchors.sellerBundle = finalization.finalized.bundles.seller?.address.native;
  } catch (error) {
    if (error instanceof DacsTestnetRefusal) throw error;
    return failed('finalization');
  }

  try {
    bundleVerification = redactedVerdict('bundle', await deps.verifyBundle(finalization, config));
  } catch (error) {
    if (error instanceof DacsTestnetRefusal) throw error;
    return failed('bundle-verification');
  }
  const rollup = rollupColdVerifications(agreementVerification, bundleVerification);
  return {
    jobId: config.jobId, mode: config.mode, rollup, phases,
    verification: { agreement: agreementVerification, bundle: bundleVerification },
    anchors, paramHash,
    ...(rollup === 'PASS' && config.mode === 'dry-run'
      ? { authorizeLiveWith: 'GATEWAY_LIVE_APPROVED=1 GATEWAY_DRYRUN_HASH=' + paramHash + ' LIVE=1' }
      : {}),
  };
}

interface CliOptions { dryRun: boolean; json: boolean; help: boolean; jobId: string; fixtureSeedHex?: string }

function parseCli(argv: readonly string[], env: NodeJS.ProcessEnv): CliOptions {
  let explicitDry = false, json = false, help = false, jobId: string | undefined, fixtureSeedHex: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === '--dry-run') explicitDry = true;
    else if (arg === '--json') json = true;
    else if (arg === '--help' || arg === '-h') help = true;
    else if (arg === '--job-id') {
      jobId = argv[++i];
      if (jobId === undefined) throw new DacsTestnetRefusal('usage', '--job-id requires a value');
    } else if (arg === '--fixture-seed') {
      fixtureSeedHex = argv[++i];
      if (fixtureSeedHex === undefined) throw new DacsTestnetRefusal('usage', '--fixture-seed requires a value');
    }
    else throw new DacsTestnetRefusal('usage', `unknown option: ${arg}`);
  }
  if (!jobId) jobId = 'fixture-job';
  if (!jobId || jobId.includes(':') || jobId.normalize('NFC') !== jobId) throw new DacsTestnetRefusal('usage', '--job-id must be NFC text without a colon');
  if (env.LIVE === '1' && explicitDry) throw new DacsTestnetRefusal('usage', 'LIVE=1 and --dry-run are contradictory mode selections');
  if (env.LIVE === '1' && fixtureSeedHex !== undefined) throw new DacsTestnetRefusal('usage', '--fixture-seed is refused in LIVE mode');
  if (fixtureSeedHex !== undefined && !/^[0-9a-fA-F]+$/.test(fixtureSeedHex)) throw new DacsTestnetRefusal('usage', '--fixture-seed must be hexadecimal');
  return { dryRun: env.LIVE !== '1', json, help, jobId, ...(fixtureSeedHex ? { fixtureSeedHex: fixtureSeedHex.toLowerCase() } : {}) };
}

const HELP = `Usage: node --import tsx src/live/dacs-testnet-run.mts [--dry-run] [--job-id ID] [--fixture-seed HEX] [--json]\n\nLIVE=1 selects LIVE. --dry-run is the explicit default and overrides no LIVE request.`;

export async function main(
  argv = process.argv.slice(2),
  env: NodeJS.ProcessEnv = process.env,
  dependencyFactory?: (config: DacsTestnetConfig) => DacsTestnetDependencies | Promise<DacsTestnetDependencies>,
): Promise<number> {
  try {
    const cli = parseCli(argv, env);
    if (cli.help) { process.stdout.write(HELP + '\n'); return 0; }
    const mode = cli.dryRun ? 'dry-run' : 'live';
    const config: DacsTestnetConfig = {
      jobId: cli.jobId, mode, organ: 'nws_alerts', query: env.ORGAN_QUERY ?? '35.2271,-80.8431',
      priceDem: '1', spendCapDem: Number(env.GATEWAY_SPEND_CAP_DEM ?? '50'),
      rpc: env.DEMOS_RPC ?? 'https://demosnode.discus.sh/', ...(cli.fixtureSeedHex ? { fixtureSeedHex: cli.fixtureSeedHex } : {}),
    };
    if (!Number.isFinite(config.spendCapDem) || config.spendCapDem < 0) throw new DacsTestnetRefusal('config', 'invalid spend cap configuration');
    const deps = dependencyFactory !== undefined
      ? await dependencyFactory(config)
      : mode === 'live'
        ? await createLiveDependencies(config, env)
        : (await import('./testnet-run-fixtures.js')).createDryRunDependencies(config);
    const result = await runDacsTestnetSession(config, deps);
    if (!cli.json) process.stdout.write(`${result.rollup} ${result.jobId} (${result.mode})\n`);
    process.stdout.write(JSON.stringify(result) + '\n');
    return result.rollup === 'PASS' ? 0 : 1;
  } catch (error) {
    const refusal = error instanceof DacsTestnetRefusal;
    process.stderr.write(JSON.stringify(refusal
      ? { outcome: 'REFUSED', reason: error.code, detail: `${error.code}: request refused` }
      : { outcome: 'REFUSED', reason: 'internal', detail: 'coordinator failed' }) + '\n');
    return refusal ? 2 : 1;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href || process.argv[1]?.replaceAll('\\', '/').endsWith('/dacs-testnet-run.mts')) {
  process.exitCode = await main();
}
