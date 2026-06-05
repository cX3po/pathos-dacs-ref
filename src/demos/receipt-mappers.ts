/**
 * Receipt mappers — turn PATH-OS artifacts into receipt-ledger entries.
 *
 * The bridge between what PATH-OS already produces (DACS-5 verify verdicts, gate verdicts, capture
 * milestones) and the append-only on-chain ledger (receipt-ledger.ts). Every mapper reuses the
 * repo's CANONICAL hasher (jcsHashHex — the same JCS+sha256 that produces bundleHash), so a receipt's
 * contentHash matches the artifact's own canonical hash exactly. No divergent hashing.
 *
 * Pure functions, no network — the timestamp is the only ambient input and is injectable for tests.
 */

import { jcsHashHex } from '../jcs.js';
import type { VerifyVerdict } from '../types/bundle.js';
import type { ReceiptEntry } from './receipt-ledger.js';

/**
 * Map a DACS-5 verify verdict to a ledger receipt. Reuses the verdict's own `canonicalBundleHash`
 * and `decision` — no re-hashing, so the receipt anchors exactly what the verifier checked.
 */
export function fromVerifyVerdict(verdict: VerifyVerdict, at: string = new Date().toISOString()): ReceiptEntry {
  return {
    kind: 'dacs5-verdict',
    ref: verdict.jobId,
    contentHash: verdict.canonicalBundleHash,
    outcome: verdict.decision,
    at,
    detail: {
      signersVerified: verdict.signersVerified.length,
      attestationsVerified: verdict.attestationsVerified,
      attestationsFailed: verdict.attestationsFailed,
    },
  };
}

/**
 * Map any PATH-OS artifact to a ledger receipt. `contentHash` is the JCS-canonical sha256 of the
 * artifact (same hasher as bundleHash), so the same artifact always yields the same receipt hash.
 * Use for gate verdicts, capture milestones, build records — anything we want tamper-evidently anchored.
 */
export function fromArtifact(
  kind: string,
  ref: string,
  artifact: unknown,
  opts: { outcome?: string; at?: string; detail?: Record<string, unknown> } = {}
): ReceiptEntry {
  return {
    kind,
    ref,
    contentHash: jcsHashHex(artifact),
    outcome: opts.outcome,
    at: opts.at ?? new Date().toISOString(),
    detail: opts.detail,
  };
}
