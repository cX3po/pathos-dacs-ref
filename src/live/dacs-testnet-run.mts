/**
 * DACS testnet lifecycle coordinator.
 *
 * Recommended defaults selected where the design leaves a choice: dry-run is the
 * explicit default; ambiguous writes/payments fail closed without retry; the existing
 * pay-dem JSONL path remains the settlement journal; and LIVE refuses during capability
 * preflight until a genuine CORE §5.1 finalized-receipt provider is available.
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

export interface LiveNodeReceiptObservation {
  outcome: 'indeterminate';
  detail: string;
  observed?: { nativeAddress: string; writer: string; sizeBytes: number; creationTransaction?: string; creationTime: string; contentHash: string };
}

type LiveReceiptProvider = (request: {
  logicalAddress: string;
  contentHash: string;
  anchor?: AgreementAnchorResult;
}) => Promise<import('../types/bundle.js').AnchorReceipt>;

/**
 * Construct the native pay-dem dependency using the gateway's audited policy path.
 * The returned function has the same `settlePayment` signature as the dry fixture.
 */
export async function createLiveSettlementDependency(
  config: DacsTestnetConfig,
  handles: { buyer: import('../demos/connection.js').DemosHandle; seller: import('../demos/connection.js').DemosHandle },
  anchor: (request: { logicalAddress: string; content: unknown; contentHash: string }) => Promise<AgreementAnchorResult>,
  orchestratorClaim: string,
  env: NodeJS.ProcessEnv = process.env,
): Promise<DacsTestnetDependencies['settlePayment']> {
  const { loadPayPolicy, authorizeTransfer, spentTodayFromJournal } = await import('./pay-policy.js');
  const policyResult = loadPayPolicy(env, (path) => readFileSync(path, 'utf8'));
  if ('verdict' in policyResult) throw new DacsTestnetRefusal('policy', 'pay-dem policy refused the session');

  const journal = await import('./pay-dem-journal.js');
  const journalPath = journal.resolvePayDemJournalPath(env.DACS_PAYDEM_JOURNAL ?? journal.DEFAULT_PAY_DEM_JOURNAL);
  const expandHome = (path: string): string => path === '~' ? homedir() : path.startsWith('~/') ? join(homedir(), path.slice(2)) : path;
  const nowIso = new Date().toISOString();
  const amountOs = (await import('../adapters/dacs/pay-dem.js')).demToOs(config.priceDem);
  const authorization = authorizeTransfer(policyResult, {
    amountOs,
    rpcUrl: config.rpc,
    spentTodayOs: spentTodayFromJournal(journal.readPayDemJournalOrEmpty(journalPath), nowIso),
    killSwitchPresent: journal.payKillSwitchPresent(expandHome(policyResult.killSwitchFile)),
    nowIso,
  });
  if (authorization.verdict !== 'PROCEED') throw new DacsTestnetRefusal('policy', 'pay-dem policy refused the transfer');

  const durableOutcomeJournal = journal.createPayDemOutcomeJournal(journalPath);
  const paymentJournal = journal.createPayDemJsonlJournal(journalPath);
  const { createPayDemAuthorizationGate } = await import('./pay-dem-authorization.js');
  const gate = createPayDemAuthorizationGate({
    policy: policyResult, journalPath, acquireLock: journal.acquirePayDemJournalLock,
    readJournal: journal.readPayDemJournalOrEmpty, killSwitchPresent: journal.payKillSwitchPresent,
    resolveKillSwitchPath: expandHome, durableOutcomeJournal,
  });

  const addressInfo = await handles.buyer.demos.getAddressInfo(handles.buyer.address);
  const balanceDem = Number((addressInfo as { balance?: bigint }).balance ?? 0n) / 1e9;
  const { preflight } = await import('./spend-preflight.js');
  const spend = preflight({
    purpose: `dacs-testnet live session ${config.jobId}`, estWrites: 8, estCostPerWriteDem: 1,
    createCostDem: Number(config.priceDem), maxSpendDem: config.spendCapDem, balanceDem,
    operatorApproved: env.GATEWAY_LIVE_APPROVED === '1', dryRunHash: env.GATEWAY_DRYRUN_HASH ?? null,
  });
  if (spend.verdict !== 'PROCEED' || env.GATEWAY_DRYRUN_HASH !== parameterHash(config)) {
    throw new DacsTestnetRefusal('spend', 'spend preflight refused the session');
  }

  return async (_agreement, run) => {
    const { settlePayDem } = await import('../adapters/dacs/pay-dem-demosdk.js');
    const settled = await settlePayDem({
      buyer: handles.buyer, sellerAddress: handles.seller.address, amountOs,
      amountDemCanonical: run.priceDem, jobId: run.jobId, phaseIndex: 2,
      journal: paymentJournal, authorizeTransfer: gate.authorize,
      journalTransferOutcome: gate.journalOutcome, beforeBroadcast: gate.beforeBroadcast,
    });
    if (!settled.ok) throw new DacsTestnetRefusal('spend', 'pay-dem settlement was refused');
    const logicalAddress = (await import('../adapters/dacs/bundle-finalizer.js')).paymentLogicalAddress(run.jobId, 'pay-dem', 2);
    const contentHash = jcsHashHex(settled.evidence);
    const evidenceAnchor = await anchor({ logicalAddress, content: settled.evidence, contentHash });
    return {
      evidence: settled.evidence,
      evidenceRef: { anchor: { substrate: 'demos', locator: evidenceAnchor.nativeAddress }, contentHash,
        type: 'settlement-evidence', producedAt: new Date(settled.finalityObservedAt).toISOString(), signer: orchestratorClaim },
      evidenceLogicalAddress: logicalAddress, evidenceAnchor,
    };
  };
}

/**
 * Lazy LIVE signer/storage wiring. Capability preflight is intentionally performed by
 * `main` before this function can read credentials or expose an anchor capability.
 * The node receipt seam reports only what the storage read establishes and never
 * manufactures finality, a block reference, or a creation nonce.
 */
export async function createLiveAdapterWiring(
  config: DacsTestnetConfig,
  env: NodeJS.ProcessEnv = process.env,
  receiptProvider?: LiveReceiptProvider,
): Promise<{
  signers: { buyer: AdapterSigner; seller: AdapterSigner; orchestrator: AdapterSigner };
  anchor(request: { logicalAddress: string; content: unknown; contentHash: string }): Promise<AgreementAnchorResult>;
  fetchAnchored(address: string): Promise<unknown>;
  observeNodeReceipt(address: string): Promise<LiveNodeReceiptObservation>;
}> {
  // Never expose an SR-2 writer or read credentials without this trust boundary.
  if (receiptProvider === undefined) {
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
    signers: { buyer: asSigner(buyer), seller: asSigner(seller), orchestrator: asSigner(seller) },
    async anchor(request) {
      const result = await storage.anchor(sellerHandle, request.logicalAddress, request.content as Record<string, unknown> | string);
      if (result.nonce === undefined) throw new DacsTestnetRefusal('capability', 'SR-2 anchor result did not bind a nonce');
      return { logicalAddress: request.logicalAddress, nativeAddress: result.storageAddress,
        transactionRef: { kind: 'demos', value: result.txHash }, writer: seller.claim, nonce: result.nonce };
    },
    async fetchAnchored(address) {
      const result = await storage.fetchAnchored(config.rpc, address);
      if (!result) throw new Error('anchor unavailable');
      return result.data;
    },
    async observeNodeReceipt(address) {
      const result = await storage.fetchAnchored(config.rpc, address);
      if (!result) return { outcome: 'indeterminate', detail: 'node storage record unavailable' };
      return { outcome: 'indeterminate', detail: 'CORE §5.1 finality evidence is unavailable from the node storage read', observed: {
        nativeAddress: result.storageAddress, writer: result.owner, sizeBytes: result.sizeBytes,
        ...(result.createdByTx ? { creationTransaction: result.createdByTx } : {}), creationTime: result.createdAt,
        contentHash: jcsHashHex(result.data),
      } };
    },
  };
}

/** Construct the selected LIVE dependency set; currently refuses before any write. */
export async function createLiveDependencies(
  config: DacsTestnetConfig,
  env: NodeJS.ProcessEnv = process.env,
): Promise<DacsTestnetDependencies> {
  await createLiveAdapterWiring(config, env);
  throw new DacsTestnetRefusal('capability', 'LIVE dependency construction is unavailable');
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
