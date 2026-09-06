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
import { dahrFetch } from '../demos/dahr.js';
import { leiClaimOf, gleifRecordUrl, type VetRecordRefs, type SingleFetchVet } from './vet-record.js';
import { vetParties, type PartyVetRecords } from './party-vet.js';
import { dacs1Listing, presentSellerIdentity, signDacs1Listing, listingDeliverableRef } from './listing-wire.js';
import { settlementTxRefs } from '../adapters/dacs/bundle-finalizer.js';
import { signatureExcludedHash } from '../lib/content-hash.js';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { execFile } from 'node:child_process';
import { statSync } from 'node:fs';
import { promisify } from 'node:util';
import { join } from 'node:path';
import { jcsHashHex } from '../jcs.js';
import { createDemosNodeReceiptProvider } from './demos-node-receipt-provider.js';
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
  { kind: 'pay-dem', parameters: { rail: 'pay-dem' } },
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
  /** CORE §5.1 receipt source for LIVE. `demos-node` proves finality from the node's confirmed
   *  block; the default observer only reads storage back and refuses LIVE at the capability check. */
  receiptProvider?: 'observer' | 'demos-node';
  /** Which two-sided bundle form the session finalizes: this repository's additive evidence-bound form
   *  (default) or the DACS-5 §10.4 FaultAttestationBundle that the pinned dacs-sdk also recognises. */
  bundleKind?: 'ebfab' | 'fab';
}

export type ColdVerdict = { outcome: 'pass' | 'fail' | 'indeterminate'; detail: string };

export interface PublishedListing {
  listing: Record<string, unknown>;
  listingRef: { listingId: string; version: number; contentHash: string };
  anchor: AgreementAnchorResult;
  /** Set by the runner after the vet phase: each party's anchored DACS-2 composite (cited by the agreement), its VerifyResult evidence and the evaluated identity bundle hash. */
  vetRecordRefs?: VetRecordRefs;
}

/** The vet phase's verdict plus what it recorded: per party a VerifyResult and the composite that cites it, and the single-fetch (GLEIF) outcome. */
export interface VetVerdict extends ColdVerdict {
  vetRecordRefs?: VetRecordRefs;
  records?: PartyVetRecords;
  singleFetch?: SingleFetchVet;
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
  vetListing(listing: PublishedListing, config: DacsTestnetConfig): Promise<VetVerdict>;
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
  verification: { agreement: ColdVerdict; bundle: ColdVerdict; vet?: { outcome: ColdVerdict['outcome']; detail: string; records?: VetVerdict['records']; singleFetch?: SingleFetchVet } };
  anchors: Partial<Record<'listing' | 'agreement' | 'commitment' | 'paymentEvidence' | 'deliverable' | 'deliveryEvidence' | 'buyerBundle' | 'sellerBundle', string>>;
  paramHash: string;
  authorizeLiveWith?: string;
  error?: { stage: string; code: 'phase-failed' | 'verification-failed' | 'settlement-failed'; detail: string; settlement?: Readonly<import('../adapters/dacs/pay-dem.js').PayDemSettlementWitness> };
}

export class DacsTestnetRefusal extends Error {
  /** `detail` carries only allowlisted identity fields (settlementKey, txHash) for the operator; never free text. */
  constructor(public readonly code: 'usage' | 'config' | 'policy' | 'spend' | 'capability', message: string, public readonly detail?: Readonly<Partial<Record<'settlementKey' | 'txHash', string>>>) {
    super(message);
    this.name = 'DacsTestnetRefusal';
  }
}

/**
 * The state of a pay-dem settlement key in the durable journal: a prepared transfer is unresolved until an outcome row
 * says it aborted before broadcast (nothing moved) or a resolution row says it was refunded; a settled resolution means
 * the job was paid and must not be paid again either.
 */
/** The included witness of a settled payment, from its anchored evidence record's demos ChainTxRef. */
export function includedWitnessOf(evidence: { paymentTxRefs?: unknown }): import('../adapters/dacs/pay-dem.js').PayDemSettlementWitness | undefined {
  const refs = Array.isArray(evidence.paymentTxRefs) ? evidence.paymentTxRefs : [];
  const demos = refs.find((r) => r && typeof r === 'object' && (r as { kind?: unknown }).kind === 'demos') as { txHash?: unknown; blockNumber?: unknown } | undefined;
  if (!demos || typeof demos.txHash !== 'string') return undefined;
  const blockNumber = Number.isSafeInteger(demos.blockNumber) ? (demos.blockNumber as number) : undefined;
  return Object.freeze({ stage: 'post-broadcast' as const, txHash: demos.txHash, state: 'included' as const, ...(blockNumber === undefined ? {} : { blockNumber }),
    rawWitness: Object.freeze({ ok: true, hash: demos.txHash, state: 'included' as const, ...(blockNumber === undefined ? {} : { blockNumber }) }) });
}

export function settlementKeyState(rows: readonly unknown[], settlementKey: string): { state: 'none' | 'unresolved' | 'settled' | 'aborted' | 'refunded'; txHash?: string } {
  // Every prepared transfer is an attempt keyed by its transaction hash; a resolution or an abort applies only to the
  // attempt it names. The key is settled if any attempt settled; unresolved if any attempt has neither an abort nor a
  // refund; otherwise the last attempt's terminal state.
  const attempts = new Map<string, 'unresolved' | 'aborted' | 'refunded' | 'settled'>();
  for (const raw of rows) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) continue;
    const row = raw as Record<string, unknown>;
    const recovery = row.recovery as { settlementKey?: unknown } | undefined;
    if (recovery?.settlementKey === settlementKey && typeof row.txHash === 'string') { if (!attempts.has(row.txHash)) attempts.set(row.txHash, 'unresolved'); continue; }
    if (row.settlementKey !== settlementKey || typeof row.txHash !== 'string') continue;
    const current = attempts.get(row.txHash);
    if (row.resolution === 'settled') attempts.set(row.txHash, 'settled');
    else if (row.resolution === 'refunded' && current !== 'settled') attempts.set(row.txHash, 'refunded');
    else if (row.outcome === 'aborted-before-broadcast' && (current === undefined || current === 'unresolved')) attempts.set(row.txHash, 'aborted');
    else if (row.outcome === 'broadcast-attempted' && current === undefined) attempts.set(row.txHash, 'unresolved');
  }
  if (attempts.size === 0) return { state: 'none' };
  const entries = [...attempts.entries()];
  const settled = entries.find(([, st]) => st === 'settled'); if (settled) return { state: 'settled', txHash: settled[0] };
  const unresolved = entries.find(([, st]) => st === 'unresolved'); if (unresolved) return { state: 'unresolved', txHash: unresolved[0] };
  const last = entries[entries.length - 1]!; return { state: last[1], txHash: last[0] };
}

/**
 * A payment reached the chain but could not be witnessed to inclusion. Unlike a refusal (nothing was spent), this
 * ends the session as a settlement FAIL that keeps the transaction hash, the observed state and the raw node result
 * in the run result, so the DEM that may have moved is never lost behind a generic 'spend' refusal.
 */
export class SettlementWitnessFailure extends Error {
  constructor(message: string, public readonly witness: Readonly<import('../adapters/dacs/pay-dem.js').PayDemSettlementWitness>) {
    super(message);
    this.name = 'SettlementWitnessFailure';
  }
}

export interface ReceiptObservation {
  outcome: 'indeterminate';
  detail: string;
  /** Whatever the source did establish (address, writer, hashes, block data); never a finality claim. */
  observed?: Record<string, unknown>;
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
  /** The anchor this session wrote under a logical address, so a cold receipt read can name the native object. */
  anchored?(logicalAddress: string): AgreementAnchorResult | undefined;
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
  receiptProvider: CoreReceiptProvider = selectReceiptProvider(config),
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
  const journalRows = await seams.readJournal(journalPath);
  const authorization = await seams.authorizeTransfer(policyResult, {
    amountOs,
    rpcUrl: config.rpc,
    spentTodayOs: (await import('./pay-policy.js')).spentTodayFromJournal(journalRows, nowIso),
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
    // Measured on the testnet (2026-09-06): every transaction carries a 2 DEM fee (network 1 + rpc 1), the
    // eight SR-2 writes included, and the pay-dem transfer pays that fee on top of the price.
    purpose: `dacs-testnet live session ${config.jobId}`, estWrites: 8, estCostPerWriteDem: TESTNET_FEE_PER_TX_DEM,
    createCostDem: Number(config.priceDem) + TESTNET_FEE_PER_TX_DEM, maxSpendDem: config.spendCapDem, balanceDem,
    balanceMarginDem: 2, operatorApproved: env.GATEWAY_LIVE_APPROVED === '1', dryRunHash: suppliedHash,
  });
  if (spend.verdict !== 'PROCEED') {
    throw new DacsTestnetRefusal('spend', 'spend preflight refused the session');
  }

  return { wiring, settlePayment: async (_agreement, run) => {
    // A transfer already prepared for this job and phase is never paid again on a rerun unless the journal proves it
    // never moved DEM (aborted before broadcast) or was refunded; a settled key is done. The journal is re-read here,
    // at settle time, not from the startup snapshot.
    const settlementKey = `pay-dem:${run.jobId}:2`;
    const keyState = settlementKeyState(await seams.readJournal(journalPath), settlementKey);
    if (keyState.state === 'unresolved' || keyState.state === 'settled') {
      const detail = { settlementKey, ...(keyState.txHash === undefined ? {} : { txHash: keyState.txHash }) };
      throw new DacsTestnetRefusal('policy', keyState.state === 'settled'
        ? `pay-dem settlement ${settlementKey} is already settled; it is not paid again`
        : `a pay-dem transfer for ${settlementKey} is prepared and unresolved; resolve its witness before paying again`, detail);
    }
    // (7) The real adapter retains authorize, durable outcome, and last-moment beforeBroadcast gates.
    const settled = await seams.settle({
      buyer: wiring.handles.buyer, sellerAddress: wiring.handles.seller.address, amountOs,
      amountDemCanonical: run.priceDem, jobId: run.jobId, phaseIndex: 2,
      journal: paymentJournal, authorizeTransfer: gate.authorize,
      journalTransferOutcome: gate.journalOutcome, beforeBroadcast: gate.beforeBroadcast,
    });
    if (!settled.ok) {
      if (settled.witness) throw new SettlementWitnessFailure(settled.reason, settled.witness);
      throw new DacsTestnetRefusal('spend', 'pay-dem settlement was refused');
    }
    // From here the DEM has moved: any failure while signing or anchoring the evidence keeps the included witness.
    const includedWitness = Object.freeze({ stage: 'post-broadcast' as const, txHash: settled.txHash, state: 'included' as const, blockNumber: settled.blockNumber,
      rawWitness: Object.freeze({ ok: true, hash: settled.txHash, state: 'included' as const, blockNumber: settled.blockNumber }) });
    try {
      const logicalAddress = (await import('../adapters/dacs/bundle-finalizer.js')).paymentLogicalAddress(run.jobId, 'pay-dem', 2);
      const signatureValue = await wiring.signers.orchestrator.sign((await import('../domain-sep.js')).DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE,
        (await import('../lib/emit-settlement-evidence-v1.js')).evidenceHashV1(settled.evidence));
      const evidence = { ...settled.evidence, signature: { algorithm: 'ed25519' as const, signer: String(wiring.signers.orchestrator.claim),
        value: typeof signatureValue === 'string' ? signatureValue : Buffer.from(signatureValue).toString('base64url') } };
      const contentHash = jcsHashHex(evidence);
      const evidenceAnchor = await wiring.anchor({ logicalAddress, content: evidence, contentHash });
      // The settlement is resolved: the durable journal records it so this key is never paid again.
      await durableOutcomeJournal({ timestamp: new Date().toISOString(), resolution: 'settled', settlementKey, txHash: settled.txHash });
      return {
        evidence,
        evidenceRef: { anchor: { kind: 'storage-program', locator: evidenceAnchor.nativeAddress }, contentHash: signatureExcludedHash(evidence), signer: String(wiring.signers.orchestrator.claim) },
        evidenceLogicalAddress: logicalAddress, evidenceAnchor,
      };
    } catch (error) {
      if (error instanceof SettlementWitnessFailure) throw error;
      throw new SettlementWitnessFailure('payment evidence could not be signed or anchored after the transfer was included', includedWitness);
    }
  } };
}

/**
 * Lazy LIVE signer/storage wiring. It checks the provider's declared finality
 * capability before dotenv is loaded or any credential environment property is read.
 */
export async function createLiveAdapterWiring(
  config: DacsTestnetConfig,
  env: NodeJS.ProcessEnv = process.env,
  receiptProvider: CoreReceiptProvider = selectReceiptProvider(config),
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
  const { claimRefFor, agentDidForAddress, keyClaimForPubkeyClaim, signDomainHashAsAgent } = await import('../adapters/demos/identity.js');
  const storage = await import('../demos/storage.js');
  const buyerHandle = await connectDemos(mnemonicFromEnv('DEMOS_MNEMONIC', env), config.rpc);
  const sellerHandle = await connectDemos(mnemonicFromEnv('DEMOS_SELLER_MNEMONIC', env), config.rpc);
  // DACS artifacts present the `cci:<pubkey>` claim, the form this repository's verifiers, the bundle finalizer
  // and the dry-run fixtures resolve to a public key; the DACS-1 listing address takes the registered `key:`
  // form of the same key; the wallet signs through its `demos:` claim (same ed25519 key: the address is the
  // public key). Anchor writers and the node receipt provider both use the DACS-1 §6.3.1 agent DID form so authorship binds and any reader resolves the key from the claim itself.
  const buyer = { ...buyerHandle, name: 'buyer', role: 'buyer-reviewer' as const, mnemonicEnv: 'DEMOS_MNEMONIC', claim: claimRefFor(buyerHandle.address), dacsClaim: agentDidForAddress(buyerHandle.address) };
  const seller = { ...sellerHandle, name: 'seller', role: 'seller' as const, mnemonicEnv: 'DEMOS_SELLER_MNEMONIC', claim: claimRefFor(sellerHandle.address), dacsClaim: agentDidForAddress(sellerHandle.address) };
  const asSigner = (handle: typeof buyer | typeof seller): AdapterSigner => ({ claim: handle.dacsClaim, sign: (domain, hash) => signDomainHashAsAgent(handle, domain, hash) });
  const anchorsByLogical = new Map<string, AgreementAnchorResult>();
  return {
    handles: { buyer: buyerHandle, seller: sellerHandle },
    signers: { buyer: asSigner(buyer), seller: asSigner(seller), orchestrator: asSigner(seller) },
    async anchor(request) {
      // The buyer's wallet writes the buyer's bundle copy; the seller (also the orchestrator) writes everything else.
      const role = (await import('./anchor-naming.js')).anchorWriterRole(config.jobId, request.logicalAddress);
      const handle = role === 'buyer' ? buyerHandle : sellerHandle;
      const result = await storage.anchor(handle, request.logicalAddress, request.content as Record<string, unknown> | string);
      if (result.nonce === undefined) throw new DacsTestnetRefusal('capability', 'SR-2 anchor result did not bind a nonce');
      const anchored: AgreementAnchorResult = { logicalAddress: request.logicalAddress, nativeAddress: result.storageAddress,
        transactionRef: { kind: 'demos', value: result.txHash }, writer: handle === buyerHandle ? buyer.dacsClaim : seller.dacsClaim, nonce: result.nonce };
      anchorsByLogical.set(request.logicalAddress, anchored);
      return anchored;
    },
    anchored: (logicalAddress) => anchorsByLogical.get(logicalAddress),
    async fetchAnchored(address) {
      const result = await storage.fetchAnchored(config.rpc, address);
      if (!result) throw new Error('anchor unavailable');
      return result.data;
    },
  };
}

/** Read-only storage observer; node read-back alone does not prove finality (see demos-node-receipt-provider for the one that does). */
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

/** The seller's real deliverable in LIVE: a PATH-OS proof-organ answer, produced by the organ bridge CLI. */
export interface OrganDeliverable {
  v: 'pathos-organ-deliverable:0.1';
  jobId: string;
  organ: string;
  answer: Record<string, unknown>;
  input_commitment: string;
  commitment_scheme: string;
  fetched_at: string;
}

/** A bridge output or run problem after payment is a delivery-phase failure, never a refusal that hides the session. */
export class OrganDeliverableError extends Error {
  constructor(message: string) { super(message); this.name = 'OrganDeliverableError'; }
}

const HEX64 = /^[0-9a-f]{64}$/;
const NONCE = /^[0-9a-f]{16,128}$/;

/** Public answer schemas per organ: only these keys, with these value shapes, are ever anchored.
 *  The bridge is trusted to compute the answer; this projection is the confidentiality boundary. */
const ORGAN_ANSWER_PROJECTIONS: ReadonlyMap<string, (answer: Record<string, unknown>) => Record<string, unknown>> = new Map([
  ['nws_alerts', (answer: Record<string, unknown>): Record<string, unknown> => {
    const out: Record<string, unknown> = {};
    const own = (key: string): unknown => (Object.hasOwn(answer, key) ? answer[key] : undefined);
    const coverage = own('coverage');
    if (coverage !== 'indeterminate' && coverage !== 'verified-empty' && coverage !== 'reported') throw new OrganDeliverableError('nws_alerts answer.coverage is not a known value');
    out.coverage = coverage;
    const active = own('active');
    if (active !== null && typeof active !== 'boolean') throw new OrganDeliverableError('nws_alerts answer.active is not boolean or null');
    out.active = active ?? null;
    for (const key of ['highest_band', 'count_band'] as const) {
      const value = own(key);
      if (value !== undefined) {
        if (typeof value !== 'string' || !/^[a-z-]{1,32}$/.test(value)) throw new OrganDeliverableError(`nws_alerts answer.${key} is not a short band label`);
        out[key] = value;
      }
    }
    const basis = own('basis');
    if (basis !== undefined) {
      if (typeof basis !== 'string' || basis.length > 200) throw new OrganDeliverableError('nws_alerts answer.basis is not a short string');
      out.basis = basis;
    }
    return out;
  }],
]);

export function supportedOrgans(): string[] { return [...ORGAN_ANSWER_PROJECTIONS.keys()]; }

/** The listing's deliverable specification: what the seller commits to deliver, hashed so the agreement terms and
 *  the listing name the same thing (the agreement adapter requires `deliverableType` plus `hash`). */
export function liveDeliverableSpec(run: Pick<DacsTestnetConfig, 'organ'>): { deliverableType: 'storage-program'; hash: string } {
  return { deliverableType: 'storage-program', hash: jcsHashHex({ v: 'pathos-organ-deliverable:0.1', organ: run.organ, output: 'projected-public-answer' }) };
}

function containsNonce(value: unknown, nonce: string): boolean {
  if (typeof value === 'string') return value.includes(nonce);
  if (Array.isArray(value)) return value.some((v) => containsNonce(v, nonce));
  if (typeof value === 'object' && value !== null) return Object.entries(value).some(([k, v]) => k.includes(nonce) || containsNonce(v, nonce));
  return false;
}

/** Validate the organ bridge's JSON and shape the deliverable. The commitment nonce keys the HMAC input
 *  commitment: it must be present as a hex string (so it can be checked) and no key or string value of the
 *  deliverable may contain it. Only the organ's projected public answer fields are carried. */
export function organDeliverableFrom(raw: string, run: Pick<DacsTestnetConfig, 'jobId' | 'organ'>): OrganDeliverable {
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { throw new OrganDeliverableError('organ bridge output is not JSON'); }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new OrganDeliverableError('organ bridge output is not an object');
  const o = parsed as Record<string, unknown>;
  if ('error' in o) throw new OrganDeliverableError('organ bridge reported an error');
  if (o.organ !== run.organ) throw new OrganDeliverableError('organ bridge answered for a different organ');
  const project = ORGAN_ANSWER_PROJECTIONS.get(run.organ);
  if (!project) throw new OrganDeliverableError(`organ ${run.organ} has no public answer schema`);
  if (typeof o.answer !== 'object' || o.answer === null || Array.isArray(o.answer) || Object.keys(o.answer as object).length === 0) {
    throw new OrganDeliverableError('organ bridge produced no answer');
  }
  if (typeof o.input_commitment !== 'string' || !HEX64.test(o.input_commitment)) throw new OrganDeliverableError('organ bridge input commitment is not a 64-hex digest');
  if (typeof o.commitment_scheme !== 'string' || !o.commitment_scheme || o.commitment_scheme.length > 120) throw new OrganDeliverableError('organ bridge names no commitment scheme');
  if (typeof o.fetched_at !== 'string' || Number.isNaN(Date.parse(o.fetched_at))) throw new OrganDeliverableError('organ bridge fetched_at is not a timestamp');
  if (typeof o.commitment_nonce !== 'string' || !NONCE.test(o.commitment_nonce)) throw new OrganDeliverableError('organ bridge nonce is missing or not a hex string; the commitment cannot be trusted');
  const deliverable: OrganDeliverable = {
    v: 'pathos-organ-deliverable:0.1', jobId: run.jobId, organ: run.organ, answer: project(o.answer as Record<string, unknown>),
    input_commitment: o.input_commitment, commitment_scheme: o.commitment_scheme, fetched_at: o.fetched_at,
  };
  if (containsNonce(deliverable, o.commitment_nonce)) throw new OrganDeliverableError('organ bridge nonce would be anchored');
  return deliverable;
}

/** Configuration the LIVE deliverable needs, checked before any phase runs (so before payment). */
export function requireOrganBridgeConfig(env: NodeJS.ProcessEnv, run: Pick<DacsTestnetConfig, 'organ'>, exists: (path: string) => boolean = (path) => { try { return statSync(path).isFile(); } catch { return false; } }): { cli: string; py: string } {
  const cli = env.ORGAN_CLI;
  if (!cli || cli.trim() !== cli) throw new DacsTestnetRefusal('config', 'LIVE delivery requires ORGAN_CLI (the proof-organ bridge); a placeholder deliverable is never anchored in LIVE');
  if (!exists(cli)) throw new DacsTestnetRefusal('config', 'ORGAN_CLI does not name an existing file');
  const py = env.AXIOM_PY ?? 'python3';
  if (py.includes('/') && !exists(py)) throw new DacsTestnetRefusal('config', 'AXIOM_PY does not name an existing interpreter');
  if (!ORGAN_ANSWER_PROJECTIONS.has(run.organ)) throw new DacsTestnetRefusal('config', `organ ${run.organ} has no public answer schema for LIVE delivery`);
  return { cli, py };
}

export type OrganExec = (file: string, args: string[], options: { timeout: number; maxBuffer: number; env: NodeJS.ProcessEnv }) => Promise<{ stdout: string }>;
const defaultOrganExec: OrganExec = promisify(execFile) as unknown as OrganExec;

/** Run the configured organ bridge for the session's organ and query. Runtime failure is a delivery failure. */
export async function runOrganBridge(env: NodeJS.ProcessEnv, run: Pick<DacsTestnetConfig, 'jobId' | 'organ' | 'query'>, execImpl: OrganExec = defaultOrganExec): Promise<OrganDeliverable> {
  // Configuration was checked at construction; a change between then and delivery (a path that vanished)
  // is a delivery-phase failure with the session's evidence preserved, never a refusal that hides the run.
  let cli: string, py: string;
  try { ({ cli, py } = requireOrganBridgeConfig(env, run)); }
  catch (error) { throw new OrganDeliverableError(error instanceof Error ? `bridge configuration changed after construction: ${error.message}` : 'bridge configuration changed after construction'); }
  let stdout: string;
  try {
    ({ stdout } = await execImpl(py, [cli, run.organ, run.query], { timeout: 60_000, maxBuffer: 1_048_576, env: { PATH: env.PATH ?? '', HOME: env.HOME ?? '' } }));
  } catch {
    throw new OrganDeliverableError('organ bridge did not complete');
  }
  return organDeliverableFrom(stdout, run);
}

/** Construct the selected LIVE dependency set through the gateway-equivalent pay-dem gate. */
export async function createLiveDependencies(
  config: DacsTestnetConfig,
  env: NodeJS.ProcessEnv = process.env,
  receiptProvider: CoreReceiptProvider = selectReceiptProvider(config),
  settlementSeams: Partial<LiveSettlementSeams> = {},
): Promise<DacsTestnetDependencies> {
  const { wiring, settlePayment } = await createLiveSettlementDependency(config, env, receiptProvider, settlementSeams);
  // The deliverable's configuration is checked here, before any phase (so before payment) can run.
  requireOrganBridgeConfig(env, config);
  const { DOMAIN_SEPARATORS } = await import('../domain-sep.js');
  const { listingLogicalAddress } = await import('../dacs1/addressing.js');
  const { commitAgreement, verifyAgreementCommitmentCold } = await import('../adapters/dacs/agreement-commitment.js');
  const { finalizeBundle, verifyBundleListing, verifyFinalizedBundleCold } = await import('../adapters/dacs/bundle-finalizer.js');
  const { anchorNames } = await import('./anchor-naming.js');
  const { emitSettlementEvidenceV1, evidenceHashV1 } = await import('../lib/emit-settlement-evidence-v1.js');
  const { verifyDomainHashAgentSignature, keyClaimForPubkeyClaim } = await import('../adapters/demos/identity.js');
  const commitments = new Map<string, import('../adapters/dacs/bundle-finalizer.js').ResolvedCommitment>();
  const fetchReceipt = async (request: { logicalAddress: string; contentHash: string; anchor?: AgreementAnchorResult }): Promise<AnchorReceipt> => {
    // A cold read names only the logical address; the anchor this session wrote under that name
    // gives the provider the native object to read. The provider still checks the node's own
    // programName and storageAddress against both, so a wrong or tampered entry stays indeterminate.
    const result = await receiptProvider.fetch(withSessionAnchor(request, wiring));
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
      // DACS-1 §6.3.4: the logical address derives from the seller's primary claim as the bundle presents it (the agent DID,
      // a registered scheme); the program is named in the pinned SDK's form so its Agent resolves the listing by (owner, name).
      const sellerClaim = String(wiring.signers.seller.claim);
      const logicalAddress = listingLogicalAddress(sellerClaim, listingId, 1);
      const identity = await presentSellerIdentity(wiring.signers.seller, Date.now());
      const unsigned = dacs1Listing({
        listingId, listingVersion: 1, seller: { identity, displayName: 'PATH-OS proof organ' },
        offering: { title: `${run.organ} result`, description: `Proof organ ${run.organ}: a public answer for a committed query, delivered as a storage program.`, category: 'proof-organ', tags: [run.organ], deliverable: { kind: 'storage-program' } },
        pricing: { kind: 'fixed', price: { amount: run.priceDem, currency: 'DEM' } }, acceptedRails: [{ railId: 'pay-dem' }], pipeline: COORDINATOR_PIPELINE,
        terms: { deadlineSecAfterCommit: 3600 }, validity: { notBefore: Date.now() - 60_000, notAfter: Date.now() + 7_200_000 },
      });
      const { listing, contentHash } = await signDacs1Listing(unsigned, wiring.signers.seller);
      const anchor = await wiring.anchor({ logicalAddress: anchorNames.listing(logicalAddress), content: listing, contentHash: jcsHashHex(listing) });
      return { listing, listingRef: { listingId, version: 1, contentHash }, anchor };
    },
    async vetListing(published, run) {
      try { await verifyBundleListing(published.listing, { verifySignature }); }
      catch { return { outcome: 'fail', detail: 'listing verification failed' }; }
      // The honest vet: each party's counterparty signs a self-signed VerifyResult over the identity bundle the party
      // presented and the DACS-2 §7.7 composite that evaluates it; the agreement cites the composites (DACS-3 §8.5).
      // A consensus-backed single fetch (GLEIF) runs only for an lei: claim and is never more than indeterminate.
      const now = Date.now();
      const listingRef = { anchor: { kind: 'storage-program' as const, locator: published.anchor.nativeAddress }, contentHash: published.listingRef.contentHash };
      let vetted;
      try {
        vetted = await vetParties({ jobId: run.jobId, listing: published.listing, listingRef, signers: { buyer: wiring.signers.buyer, seller: wiring.signers.seller },
          anchor: wiring.anchor, verifySignature: (request) => verifySignature(request as Parameters<typeof verifySignature>[0]), now });
      } catch (error) {
        return { outcome: 'fail', detail: error instanceof Error ? error.message : 'party vet failed' };
      }
      const lei = leiClaimOf(published.listing);
      let singleFetch: SingleFetchVet = { executed: false, trustLevel: 'not-applicable', reason: 'no lei: claim presented; the GLEIF single-fetch recipe does not apply' };
      if (lei) {
        try { await dahrFetch(undefined, gleifRecordUrl(lei), { skipAnchor: true, recipe: 'gleif-cbp:1' }); singleFetch = { executed: true, trustLevel: 'indeterminate', reason: 'single fetch, no validator quorum' }; }
        catch { singleFetch = { executed: true, trustLevel: 'indeterminate', reason: 'single fetch did not complete; no validator quorum' }; }
      }
      return { outcome: 'pass', detail: 'listing signature verified; party vet composites anchored', vetRecordRefs: vetted.refs, records: vetted.records, singleFetch };
    },
    async emitAgreement(published, run) {
      // Each party cites the DACS-2 composite its counterparty anchored in the vet phase (DACS-3 §8.5) and carries the hash
      // of the identity bundle that composite evaluated; a session without vet records cannot commit an agreement.
      const vet = published.vetRecordRefs;
      if (!vet) throw new DacsTestnetRefusal('policy', 'agreement refused: the vet phase anchored no party vet records');
      const parties: AgreementPartyV1[] = [
        { role: 'buyer', bundleHash: vet.buyer.bundleHash, primaryClaim: wiring.signers.buyer.claim, vetRecordRef: vet.buyer.composite },
        { role: 'seller', bundleHash: vet.seller.bundleHash, primaryClaim: wiring.signers.seller.claim, vetRecordRef: vet.seller.composite },
      ];
      const committed = await commitAgreement({ jobId: run.jobId, listing: published.listing, listingRef: published.listingRef, parties,
        terms: { price: { amount: run.priceDem, currency: 'DEM' }, rail: { railId: 'pay-dem' }, deliverable: listingDeliverableRef(published.listing), deadline: Date.now() + 3_600_000 } },
      { signers: wiring.signers, anchor: wiring.anchor, fetchAnchored: wiring.fetchAnchored, receiptProvider: fetchReceipt });
      // The reference pins the orchestrator that signed the commitment: a cold verifier has no other way to know
      // which listed party orchestrated when no distinct orchestrator party is listed.
      const commitmentRef: AttestationRef = { anchor: { kind: 'storage-program', locator: committed.addresses.commitment.native }, contentHash: signatureExcludedHash(committed.commitment), signer: wiring.signers.orchestrator.claim };
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
      const deliverable = await runOrganBridge(env, run);
      const deliverableAnchor = await wiring.anchor({ logicalAddress: anchorNames.deliverable(run.jobId), content: deliverable, contentHash: jcsHashHex(deliverable) });
      const evidence = await signEvidence(emitSettlementEvidenceV1({ kind: 'delivery', jobId: run.jobId, phase: 'deliver-storage-program',
        outcome: 'success', deliverableContentHash: jcsHashHex(deliverable), deliverableAnchorKind: 'storage-program',
        deliverableAnchorLocator: deliverableAnchor.nativeAddress, observedAt: Date.now() }));
      const logicalAddress = anchorNames.deliveryEvidence(run.jobId, 3);
      const contentHash = jcsHashHex(evidence);
      const evidenceAnchor = await wiring.anchor({ logicalAddress, content: evidence, contentHash });
      return { evidence, evidenceRef: { anchor: { kind: 'storage-program', locator: evidenceAnchor.nativeAddress }, contentHash: signatureExcludedHash(evidence), signer: String(wiring.signers.orchestrator.claim) },
        evidenceLogicalAddress: logicalAddress, evidenceAnchor, deliverableAnchor };
    },
    async finalize(input) {
      const agreement = input.agreement.committed;
      const vet = input.listing.vetRecordRefs;
      if (!vet) throw new DacsTestnetRefusal('policy', 'finalization refused: the session carries no party vet records');
      // The bundle's parties carry the identity bundle hashes the vet composites evaluated (the SDK binds a composite to a party by claim and bundleHash).
      // bundle.vetRecords stays empty on purpose: the pinned SDK marks every listed composite invalid unless the consumer supplies verifyCompositeRecord,
      // which needs a signed RecipeDescriptor for the self-signed recipe and an authority-attestation verifier that no cold verifier of ours has yet;
      // the agreement's party citations are the record of the vet until that consumer exists.
      const parties = [
        { role: 'buyer' as const, bundleHash: vet.buyer.bundleHash, primaryClaim: wiring.signers.buyer.claim },
        { role: 'seller' as const, bundleHash: vet.seller.bundleHash, primaryClaim: wiring.signers.seller.claim },
      ];
      const phaseResults = [
        { index: 0, kind: 'negotiate-fixed-price', outcome: 'ok' as const, orchestrator: wiring.signers.orchestrator.claim },
        { index: 1, kind: 'commit-agreement', outcome: 'ok' as const, orchestrator: wiring.signers.orchestrator.claim },
        { index: 2, kind: 'pay-dem', outcome: 'ok' as const, orchestrator: wiring.signers.orchestrator.claim, evidenceRef: input.payment.evidenceRef, txRefs: settlementTxRefs(input.payment.evidence), evidenceLogicalAddress: input.payment.evidenceLogicalAddress, evidenceAnchor: input.payment.evidenceAnchor },
        { index: 3, kind: 'deliver-storage-program', outcome: 'ok' as const, orchestrator: wiring.signers.orchestrator.claim, evidenceRef: input.delivery.evidenceRef, evidenceLogicalAddress: input.delivery.evidenceLogicalAddress, evidenceAnchor: input.delivery.evidenceAnchor },
      ];
      const session: CompletedSessionEvidence = { jobId: input.config.jobId, listing: input.listing.listing, listingRef: input.listing.listingRef,
        agreementRef: input.agreement.committed.agreementRef, commitmentRef: input.agreement.commitmentRef, agreement: agreement.agreement as unknown as Record<string, unknown>, agreementHash: agreement.agreementHash,
        parties, phaseResults, outcome: 'completed', faultedParty: 'none', recipeRegistryVersion: 1, railRegistryVersion: 1,
        ...(input.config.bundleKind ? { kind: input.config.bundleKind } : {}) };
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

/** The bundle form is a session parameter: anything but the two known forms is a configuration refusal. */
/** Fee the testnet charged on every transaction we measured (network 1 DEM + rpc 1 DEM). */
export const TESTNET_FEE_PER_TX_DEM = 2;

export function parseBundleKind(raw: string): 'ebfab' | 'fab' {
  if (raw === 'ebfab' || raw === 'fab') return raw;
  throw new DacsTestnetRefusal('config', `DACS_BUNDLE_KIND must be "ebfab" or "fab", got "${raw}"`);
}

export function parameterHash(config: Pick<DacsTestnetConfig, 'organ' | 'query' | 'priceDem' | 'spendCapDem' | 'receiptProvider' | 'bundleKind'>): string {
  return jcsHashHex({
    version: 'dacs-testnet-coordinator-params:3',
    organ: config.organ,
    query: config.query,
    price: config.priceDem,
    cap: config.spendCapDem,
    receipts: config.receiptProvider ?? 'observer',
    bundle: config.bundleKind ?? 'ebfab',
    pipeline: COORDINATOR_PIPELINE,
  });
}

/** A cold receipt request names only the logical address; the anchor this session wrote under that
 *  name gives the provider the native object to read. An explicit anchor on the request wins. */
export function withSessionAnchor<T extends { logicalAddress: string; anchor?: AgreementAnchorResult }>(
  request: T, wiring: Pick<LiveAdapterWiring, 'anchored'>,
): T {
  if (request.anchor) return request;
  const anchor = wiring.anchored?.(request.logicalAddress);
  return anchor ? { ...request, anchor } : request;
}

/** The receipt source a config selects: the finality-proving node provider only when asked for by name. */
export function selectReceiptProvider(config: Pick<DacsTestnetConfig, 'rpc' | 'receiptProvider'>): CoreReceiptProvider {
  return config.receiptProvider === 'demos-node' ? createDemosNodeReceiptProvider(config) : createNodeReceiptProvider(config);
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

  let paidWitness: import('../adapters/dacs/pay-dem.js').PayDemSettlementWitness | undefined;
  let vetVerification: NonNullable<DacsTestnetRunResult['verification']['vet']> | undefined;
  const failed = (stage: string, code: 'phase-failed' | 'verification-failed' = 'phase-failed'): DacsTestnetRunResult => ({
    jobId: config.jobId,
    mode: config.mode,
    rollup: 'FAIL',
    phases,
    verification: { agreement: agreementVerification, bundle: bundleVerification, ...(vetVerification ? { vet: vetVerification } : {}) },
    anchors,
    paramHash,
    // Once a payment was included, every later failure carries its witness so the moved DEM is never lost behind the stage that failed.
    error: paidWitness ? { stage, code: 'settlement-failed', detail: `${stage}: failed after an included payment`, settlement: paidWitness } : { stage, code, detail: `${stage}: phase failed` },
  });

  const guarded = async <T,>(stage: string, operation: () => Promise<T>): Promise<T | DacsTestnetRunResult> => {
    try { return await operation(); }
    catch (error) {
      // A refusal after the payment was included is not a refusal any more: the session failed with DEM moved.
      if (error instanceof DacsTestnetRefusal && !paidWitness) throw error;
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
    vetVerification = { outcome: vet.outcome, detail: vet.detail, ...(vet.records ? { records: vet.records } : {}), ...(vet.singleFetch ? { singleFetch: vet.singleFetch } : {}) };
    if (vet.outcome !== 'pass') {
      const result = failed('vet', 'verification-failed');
      result.rollup = vet.outcome === 'indeterminate' ? 'INDETERMINATE' : 'FAIL';
      return result;
    }
    if (vet.vetRecordRefs) listing = { ...listing, vetRecordRefs: vet.vetRecordRefs };
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
    // The DEM has moved: from here every failure, including a refusal, is reported with the included witness.
    paidWitness = includedWitnessOf(payment.evidence as { paymentTxRefs?: unknown });
  } catch (error) {
    if (error instanceof DacsTestnetRefusal && !paidWitness) throw error;
    phases.push({ index: 2, kind: 'pay-dem', outcome: 'FAIL' });
    if (error instanceof SettlementWitnessFailure) {
      // The payment reached the chain: a settlement FAIL with its witness, never a generic refusal.
      const result = failed('payment');
      result.error = { stage: 'payment', code: 'settlement-failed', detail: 'payment: settlement-unwitnessed', settlement: error.witness };
      return result;
    }
    return failed('payment');
  }

  let delivery: DeliveryResult;
  try {
    delivery = await deps.deliver(agreement, config);
    anchors.deliverable = delivery.deliverableAnchor.nativeAddress;
    anchors.deliveryEvidence = delivery.evidenceAnchor.nativeAddress;
    phases.push({ index: 3, kind: 'deliver-storage-program', outcome: 'PASS' });
  } catch (error) {
    if (error instanceof DacsTestnetRefusal && !paidWitness) throw error;
    phases.push({ index: 3, kind: 'deliver-storage-program', outcome: 'FAIL' });
    return failed('delivery');
  }

  let finalization: FinalizationResult;
  try {
    finalization = await deps.finalize({ config, listing, agreement, payment, delivery });
    anchors.buyerBundle = finalization.finalized.bundles.buyer?.address.native;
    anchors.sellerBundle = finalization.finalized.bundles.seller?.address.native;
  } catch (error) {
    if (error instanceof DacsTestnetRefusal && !paidWitness) throw error;
    return failed('finalization');
  }

  try {
    bundleVerification = redactedVerdict('bundle', await deps.verifyBundle(finalization, config));
  } catch (error) {
    if (error instanceof DacsTestnetRefusal && !paidWitness) throw error;
    return failed('bundle-verification');
  }
  const rollup = rollupColdVerifications(agreementVerification, bundleVerification);
  return {
    jobId: config.jobId, mode: config.mode, rollup, phases,
    verification: { agreement: agreementVerification, bundle: bundleVerification, ...(vetVerification ? { vet: vetVerification } : {}) },
    anchors, paramHash,
    ...(rollup === 'PASS' && config.mode === 'dry-run'
      ? { authorizeLiveWith: 'GATEWAY_LIVE_APPROVED=1 GATEWAY_DRYRUN_HASH=' + paramHash + ' LIVE=1' }
      : {}),
  };
}

interface CliOptions { dryRun: boolean; json: boolean; help: boolean; jobId: string; fixtureSeedHex?: string; receiptProvider?: 'observer' | 'demos-node' }

function parseCli(argv: readonly string[], env: NodeJS.ProcessEnv): CliOptions {
  let explicitDry = false, json = false, help = false, jobId: string | undefined, fixtureSeedHex: string | undefined, receiptProvider: 'observer' | 'demos-node' | undefined;
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
    } else if (arg === '--receipt-provider') {
      const value = argv[++i];
      if (value !== 'observer' && value !== 'demos-node') throw new DacsTestnetRefusal('usage', '--receipt-provider must be observer or demos-node');
      receiptProvider = value;
    }
    else throw new DacsTestnetRefusal('usage', `unknown option: ${arg}`);
  }
  if (!jobId) jobId = 'fixture-job';
  if (!jobId || jobId.includes(':') || jobId.normalize('NFC') !== jobId) throw new DacsTestnetRefusal('usage', '--job-id must be NFC text without a colon');
  if (env.LIVE === '1' && explicitDry) throw new DacsTestnetRefusal('usage', 'LIVE=1 and --dry-run are contradictory mode selections');
  if (env.LIVE === '1' && fixtureSeedHex !== undefined) throw new DacsTestnetRefusal('usage', '--fixture-seed is refused in LIVE mode');
  if (fixtureSeedHex !== undefined && !/^[0-9a-fA-F]+$/.test(fixtureSeedHex)) throw new DacsTestnetRefusal('usage', '--fixture-seed must be hexadecimal');
  return { dryRun: env.LIVE !== '1', json, help, jobId, ...(fixtureSeedHex ? { fixtureSeedHex: fixtureSeedHex.toLowerCase() } : {}), ...(receiptProvider ? { receiptProvider } : {}) };
}

const HELP = `Usage: node --import tsx src/live/dacs-testnet-run.mts [--dry-run] [--job-id ID] [--fixture-seed HEX] [--receipt-provider observer|demos-node] [--json]\n\nLIVE=1 selects LIVE. --dry-run is the explicit default and overrides no LIVE request.\n--receipt-provider demos-node selects the finality-proving CORE §5.1 receipt source (the node's confirmed block); it enters the parameter hash, so the dry run and the LIVE run must both name it.\nLIVE delivery runs the proof-organ bridge: ORGAN_CLI (script path) under AXIOM_PY (default python3) with <organ> <query>; its JSON answer becomes the anchored deliverable, minus the commitment nonce.`;

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
      ...(cli.receiptProvider ? { receiptProvider: cli.receiptProvider } : {}),
      ...(env.DACS_BUNDLE_KIND !== undefined ? { bundleKind: parseBundleKind(env.DACS_BUNDLE_KIND) } : {}),
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
      ? { outcome: 'REFUSED', reason: error.code, detail: `${error.code}: request refused`, ...(error.detail ? { settlement: error.detail } : {}) }
      : { outcome: 'REFUSED', reason: 'internal', detail: 'coordinator failed' }) + '\n');
    return refusal ? 2 : 1;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href || process.argv[1]?.replaceAll('\\', '/').endsWith('/dacs-testnet-run.mts')) {
  process.exitCode = await main();
}
