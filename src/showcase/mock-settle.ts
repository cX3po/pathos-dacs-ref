/**
 * Deterministic MOCK settlement for the showcase — no funds, no keys, no network.
 * Produces a signed, content-addressed SettlementEvidence-shaped artifact so the
 * DACS-4 stage is real (signed + hashable) without touching a testnet. Swap for
 * settle/htlc-testnet.ts (Base Sepolia + Solana devnet) to settle for real.
 */
import { sign } from '../lib/sign.js';
import { DOMAIN_SEPARATORS } from '../domain-sep.js';
import { jcsCanonical, jcsHashHex } from '../jcs.js';

export interface MockSettlement {
  rail: string;
  evidence: Record<string, unknown>;
  contentHash: string;
  signature: string; // base64
}

export function mockSettle(opts: {
  jobId: string; agreementHash: string; priceOs: string; payerPriv: Uint8Array;
}): MockSettlement {
  const evidence = {
    v: 'dacs-settlement-evidence:0.1',
    jobId: opts.jobId,
    agreementHash: opts.agreementHash,
    rail: 'pay-cross-chain-htlc',
    outcome: 'success' as const,
    amountOs: opts.priceOs,
    // mock txRefs — shaped like the real HTLC evidence (lock + reveal), deterministic
    paymentTxRefs: [
      { kind: 'htlc-lock', chain: 'base-sepolia', tx: '0xmocklock' + opts.jobId },
      { kind: 'htlc-reveal', chain: 'solana-devnet', tx: 'mockreveal' + opts.jobId },
    ],
    settledAt: '2026-06-02T00:00:01Z',
    mock: true,
  };
  const sig = sign(DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE, jcsCanonical(evidence), opts.payerPriv);
  return { rail: 'pay-cross-chain-htlc', evidence, contentHash: jcsHashHex(evidence), signature: Buffer.from(sig).toString('base64') };
}
