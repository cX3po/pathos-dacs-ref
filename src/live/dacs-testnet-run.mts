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
  error?: { stage: string; detail: string };
}

export class DacsTestnetRefusal extends Error {
  constructor(public readonly code: 'usage' | 'configuration' | 'policy' | 'spend' | 'live-capability', message: string) {
    super(message);
    this.name = 'DacsTestnetRefusal';
  }
}

export interface LiveNodeReceiptObservation {
  outcome: 'indeterminate';
  detail: string;
  observed?: { nativeAddress: string; writer: string; sizeBytes: number; creationTransaction?: string; creationTime: string; contentHash: string };
}

/**
 * Lazy LIVE signer/storage wiring. Capability preflight is intentionally performed by
 * `main` before this function can read credentials or expose an anchor capability.
 * The node receipt seam reports only what the storage read establishes and never
 * manufactures finality, a block reference, or a creation nonce.
 */
export async function createLiveAdapterWiring(config: DacsTestnetConfig, env: NodeJS.ProcessEnv = process.env): Promise<{
  signers: { buyer: AdapterSigner; seller: AdapterSigner; orchestrator: AdapterSigner };
  anchor(request: { logicalAddress: string; content: unknown; contentHash: string }): Promise<AgreementAnchorResult>;
  fetchAnchored(address: string): Promise<unknown>;
  observeNodeReceipt(address: string): Promise<LiveNodeReceiptObservation>;
}> {
  const { config: loadEnvFile } = await import('dotenv');
  loadEnvFile({ path: env.DACS_ENV_PATH ?? '.env' });
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
      const handle = request.logicalAddress.endsWith(':buyer') ? buyerHandle : sellerHandle;
      const result = await storage.anchor(handle, request.logicalAddress, request.content as Record<string, unknown> | string);
      return { logicalAddress: request.logicalAddress, nativeAddress: result.storageAddress,
        transactionRef: { kind: 'demos', value: result.txHash }, writer: handle.address };
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

/** Execute listing/vet and the four indexed pipeline phases in fail-closed order. */
export async function runDacsTestnetSession(config: DacsTestnetConfig, deps: DacsTestnetDependencies): Promise<DacsTestnetRunResult> {
  const paramHash = parameterHash(config);
  const phases: DacsTestnetRunResult['phases'] = [];
  const anchors: DacsTestnetRunResult['anchors'] = {};
  let agreementVerification = unavailable('agreement verification was not reached');
  let bundleVerification = unavailable('bundle verification was not reached');

  const failed = (stage: string, error: unknown): DacsTestnetRunResult => ({
    jobId: config.jobId,
    mode: config.mode,
    rollup: 'FAIL',
    phases,
    verification: { agreement: agreementVerification, bundle: bundleVerification },
    anchors,
    paramHash,
    error: { stage, detail: error instanceof Error ? error.message : String(error) },
  });

  await deps.capabilityPreflight(config);
  let listing: PublishedListing;
  try {
    listing = await deps.publishListing(config);
    anchors.listing = listing.anchor.nativeAddress;
  } catch (error) { return failed('listing', error); }

  try {
    const vet = await deps.vetListing(listing, config);
    if (vet.outcome !== 'pass') return failed('vet', new Error(vet.detail));
  } catch (error) { return failed('vet', error); }

  phases.push({ index: 0, kind: 'negotiate-fixed-price', outcome: 'PASS' });
  let agreement: AgreementResult;
  try {
    agreement = await deps.emitAgreement(listing, config);
    anchors.agreement = agreement.committed.addresses.agreement?.native;
    anchors.commitment = agreement.committed.addresses.commitment.native;
  } catch (error) {
    phases.push({ index: 1, kind: 'commit-agreement', outcome: 'FAIL' });
    return failed('agreement-emission', error);
  }

  try {
    agreementVerification = await deps.verifyAgreement(agreement, listing, config);
    if (agreementVerification.outcome !== 'pass') {
      phases.push({ index: 1, kind: 'commit-agreement', outcome: 'FAIL' });
      const result = failed('agreement-verification', new Error(agreementVerification.detail));
      result.rollup = agreementVerification.outcome === 'fail' ? 'FAIL' : 'INDETERMINATE';
      return result;
    }
  } catch (error) {
    phases.push({ index: 1, kind: 'commit-agreement', outcome: 'FAIL' });
    return failed('agreement-verification', error);
  }
  phases.push({ index: 1, kind: 'commit-agreement', outcome: 'PASS' });

  let payment: AnchoredEvidence;
  try {
    payment = await deps.settlePayment(agreement, config);
    anchors.paymentEvidence = payment.evidenceAnchor.nativeAddress;
    phases.push({ index: 2, kind: 'pay-dem', outcome: 'PASS' });
  } catch (error) {
    phases.push({ index: 2, kind: 'pay-dem', outcome: 'FAIL' });
    return failed('payment', error);
  }

  let delivery: DeliveryResult;
  try {
    delivery = await deps.deliver(agreement, config);
    anchors.deliverable = delivery.deliverableAnchor.nativeAddress;
    anchors.deliveryEvidence = delivery.evidenceAnchor.nativeAddress;
    phases.push({ index: 3, kind: 'deliver-storage-program', outcome: 'PASS' });
  } catch (error) {
    phases.push({ index: 3, kind: 'deliver-storage-program', outcome: 'FAIL' });
    return failed('delivery', error);
  }

  let finalization: FinalizationResult;
  try {
    finalization = await deps.finalize({ config, listing, agreement, payment, delivery });
    anchors.buyerBundle = finalization.finalized.bundles.buyer?.address.native;
    anchors.sellerBundle = finalization.finalized.bundles.seller?.address.native;
  } catch (error) { return failed('finalization', error); }

  try {
    bundleVerification = await deps.verifyBundle(finalization, config);
  } catch (error) { return failed('bundle-verification', error); }
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

export async function main(argv = process.argv.slice(2), env: NodeJS.ProcessEnv = process.env): Promise<number> {
  try {
    const cli = parseCli(argv, env);
    if (cli.help) { process.stdout.write(HELP + '\n'); return 0; }
    const mode = cli.dryRun ? 'dry-run' : 'live';
    const config: DacsTestnetConfig = {
      jobId: cli.jobId, mode, organ: 'nws_alerts', query: env.ORGAN_QUERY ?? '35.2271,-80.8431',
      priceDem: '1', spendCapDem: Number(env.GATEWAY_SPEND_CAP_DEM ?? '50'),
      rpc: env.DEMOS_RPC ?? 'https://demosnode.discus.sh/', ...(cli.fixtureSeedHex ? { fixtureSeedHex: cli.fixtureSeedHex } : {}),
    };
    if (!Number.isFinite(config.spendCapDem) || config.spendCapDem < 0) throw new DacsTestnetRefusal('configuration', 'invalid spend cap configuration');
    const paramHash = parameterHash(config);
    if (mode === 'live') {
      if (env.GATEWAY_LIVE_APPROVED !== '1') throw new DacsTestnetRefusal('policy', 'LIVE requires GATEWAY_LIVE_APPROVED=1');
      if (env.GATEWAY_DRYRUN_HASH !== paramHash) throw new DacsTestnetRefusal('policy', 'GATEWAY_DRYRUN_HASH does not match the current parameters');
      throw new DacsTestnetRefusal('live-capability', 'LIVE requires a CORE §5.1 finalized-receipt provider; none is configured');
    }
    const { createDryRunDependencies } = await import('./testnet-run-fixtures.js');
    const result = await runDacsTestnetSession(config, createDryRunDependencies(config));
    process.stdout.write(JSON.stringify(result) + '\n');
    return result.rollup === 'PASS' ? 0 : 1;
  } catch (error) {
    const refusal = error instanceof DacsTestnetRefusal;
    const safe = refusal ? error.message : 'coordinator failed';
    process.stderr.write(JSON.stringify({ outcome: 'REFUSED', detail: safe }) + '\n');
    return refusal ? 2 : 1;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href || process.argv[1]?.replaceAll('\\', '/').endsWith('/dacs-testnet-run.mts')) {
  process.exitCode = await main();
}
