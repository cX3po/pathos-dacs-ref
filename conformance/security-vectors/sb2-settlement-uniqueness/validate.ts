/**
 * DACS §9.5.8 — SB-2 settlement-tx uniqueness (cross-session double-count defence).
 *
 * THREAT: a consumer aggregating SettlementEvidence across sessions (e.g. the §10.5.1 reputation /
 * volume reconciliation) counts the SAME settlement transaction more than once by accepting it under
 * two different `(jobId, phaseIndex)` tuples — inflating volume / completion. (Structurally this is the
 * §B.8 SN-4 single-use marker with the scope INVERTED: SN-4 keys a nonce per `jobId` and *allows* the
 * same nonce under a different `jobId`; SB-2 keys a settlement-tx-id and *forbids* it under a second
 * `(jobId, phaseIndex)` — cX3po's #159 observation.)
 *
 * SB-1 binding key (per #161 c09d85f): the `settlement-tx-id` is event/instruction-level and
 * chain-namespaced — `evm`: chainId+txHash+logIndex · `solana`: cluster+signature+instructionIndex ·
 * `demos-native`: txHash (a single native transfer has nothing to disambiguate, so no index — per the
 * #168 pay-dem review). This module canonicalises a `SettlementRef` to that namespaced key and enforces
 * SB-2 over it.
 *
 * CANONICALISATION IS LOAD-BEARING. The whole defence is the key, so two encodings of the SAME tx MUST
 * produce the SAME key (else a double-count slips through a key-split, and two DIFFERENT txs MUST NOT
 * collide. So: EVM/demos hashes strip an optional `0x`, lowercase, and require an exact byte length;
 * Solana clusters are a closed set; Solana signatures are validated base58 (case-sensitive). A malformed
 * ref yields no key → `error` (never silently a distinct key).
 *
 * SB-2 rule: a `settlement-tx-id` MUST map to at most ONE `(jobId, phaseIndex)` within a consumer's own
 * reconciliation set. First claim is countable; an exact re-presentation of the same tuple is idempotent
 * (already counted — MUST NOT count again); a presentation under a DIFFERENT tuple is a double-count and
 * MUST be rejected.
 *
 * Pure, offline, deterministic, dependency-free.
 *
 * Returns BOTH a §7.5.1 4-value `decision` AND an unambiguous `effect`, because "pass" alone is unsafe:
 * a first-claim and an idempotent re-presentation are both non-rejecting (`pass`) but only the FIRST is
 * countable. Consumers MUST drive counting off `effect`, not off `decision`.
 *   decision: pass · fail · indeterminate · error
 *   effect:   count (pass, new) · already-counted (pass, idempotent — do NOT count) · reject (fail,
 *             double-count) · no-decision (indeterminate — ledger unreadable) · verifier-error (error)
 *
 * SCOPE: this is the CONSUMER-VIEW-SCOPED rule (#159 caveat). Two reconcilers with separate views each
 * count once; cross-reconciler safety needs a shared/anchored consumed-set, and the consume must be
 * durable + atomic — both impl/substrate properties, out of scope for these vectors.
 */

export type Decision = 'pass' | 'fail' | 'indeterminate' | 'error';
export type Effect = 'count' | 'already-counted' | 'reject' | 'no-decision' | 'verifier-error';

/** SB-1 chain-namespaced settlement reference. Event/instruction-level for batched-tx disambiguation. */
export type SettlementRef =
  | { rail: 'evm'; chainId: number; txHash: string; logIndex: number }
  | { rail: 'solana'; cluster: string; signature: string; instructionIndex: number }
  | { rail: 'demos-native'; txHash: string }; // single native transfer → no index (pay-dem, #168)

export interface SettlementRecord {
  settlementRef: SettlementRef;
  jobId: string;
  phaseIndex: number;
}

/**
 * The consumer's reconciliation set: settlement-tx-id (canonical key) -> the (jobId, phaseIndex) it
 * was first counted under. `null` models an unreadable/unavailable ledger (→ indeterminate).
 */
export type ConsumedSet = Record<string, { jobId: string; phaseIndex: number }> | null;

const EVM_TX_BYTES = 32;     // keccak-256 tx hash
const DEMOS_TX_BYTES = 32;   // ASSUMPTION — confirm the native Demos tx-hash width with the SDK; one-line change if it differs
const SOL_CLUSTERS = new Set(['mainnet', 'devnet', 'testnet']); // SB-1 / ChainTxRef closed set
const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'; // excludes 0 O I l
const SOL_SIG_BYTES = 64; // an ed25519 Solana tx signature decodes to exactly 64 bytes

/** Minimal base58 decode → byte length, or null on any non-base58 char. (Length is all we need to
 *  enforce canonical signature width; a base58-alphabet string can still decode to the wrong size.) */
function base58DecodedLen(s: string): number | null {
  if (s.length === 0) return null;
  const bytes: number[] = [];
  for (const ch of s) {
    const val = B58_ALPHABET.indexOf(ch);
    if (val < 0) return null;
    let carry = val;
    for (let i = 0; i < bytes.length; i++) { carry += bytes[i] * 58; bytes[i] = carry & 0xff; carry = Math.floor(carry / 256); }
    while (carry > 0) { bytes.push(carry & 0xff); carry = Math.floor(carry / 256); }
  }
  let leadingZeros = 0;
  for (const ch of s) { if (ch === '1') leadingZeros++; else break; }
  return leadingZeros + bytes.length;
}

const safeIdx = (n: unknown): n is number => typeof n === 'number' && Number.isSafeInteger(n) && n >= 0;
const nonEmpty = (s: unknown): s is string => typeof s === 'string' && s.length > 0;

/** Strip an optional 0x, require EXACTLY `bytes` bytes of hex, lowercase. null on any deviation. */
function normHash(s: unknown, bytes: number): string | null {
  if (typeof s !== 'string') return null;
  const h = (s.startsWith('0x') || s.startsWith('0X')) ? s.slice(2) : s;
  if (h.length !== bytes * 2 || !/^[0-9a-fA-F]+$/.test(h)) return null;
  return h.toLowerCase();
}

/** Validate a base58 Solana signature: must decode to EXACTLY 64 bytes (case-sensitive). null if not.
 *  Length-in-chars isn't enough — a base58-alphabet string can decode to the wrong byte width and mint
 *  a non-canonical "valid" key, so we check the decoded byte length. */
function normSolSig(s: unknown): string | null {
  if (typeof s !== 'string') return null;
  return base58DecodedLen(s) === SOL_SIG_BYTES ? s : null;
}

/**
 * Canonical SB-1 settlement-tx-id. Chain-namespaced so an EVM tx and a Solana sig can never collide,
 * event/instruction-indexed so two transfers batched in one tx are distinct, and canonicalised so two
 * encodings of the same tx produce one key. Returns null on a malformed ref (→ caller maps to `error`).
 */
export function settlementTxId(ref: unknown): string | null {
  if (!ref || typeof ref !== 'object') return null;
  const r = ref as Record<string, unknown>;
  switch (r.rail) {
    case 'evm': {
      const tx = normHash(r.txHash, EVM_TX_BYTES);
      if (!safeIdx(r.chainId) || tx === null || !safeIdx(r.logIndex)) return null;
      return `evm:${r.chainId}:${tx}:${r.logIndex}`;
    }
    case 'solana': {
      const sig = normSolSig(r.signature);
      if (typeof r.cluster !== 'string' || !SOL_CLUSTERS.has(r.cluster) || sig === null || !safeIdx(r.instructionIndex)) return null;
      return `solana:${r.cluster}:${sig}:${r.instructionIndex}`;
    }
    case 'demos-native': {
      const tx = normHash(r.txHash, DEMOS_TX_BYTES);
      if (tx === null) return null;
      return `demos-native:${tx}`;
    }
    default:
      return null;
  }
}

/**
 * Apply SB-2 to one record against a consumer's consumed-set. Pure: does NOT mutate `consumed`
 * (a real consumer mutates atomically only on `effect === 'count'`; the vectors pass the pre-state
 * and assert the (decision, effect) pair). See module header for the semantics.
 */
export function checkSettlementUniqueness(rec: unknown, consumed: ConsumedSet): { decision: Decision; effect: Effect; reason: string } {
  // ── malformed record → error (verifier-side parse; never fail) ──
  if (!rec || typeof rec !== 'object') return { decision: 'error', effect: 'verifier-error', reason: 'record is not an object' };
  const r = rec as Record<string, unknown>;
  if (!nonEmpty(r.jobId)) return { decision: 'error', effect: 'verifier-error', reason: 'jobId missing/empty' };
  if (!safeIdx(r.phaseIndex)) return { decision: 'error', effect: 'verifier-error', reason: 'phaseIndex missing or not a safe integer ≥ 0' };
  const id = settlementTxId(r.settlementRef);
  if (id === null) return { decision: 'error', effect: 'verifier-error', reason: 'settlementRef malformed / unknown rail / non-canonical id' };

  // ── consumed-set unreadable → indeterminate (MUST NOT count, MUST NOT reject) ──
  if (consumed === null) return { decision: 'indeterminate', effect: 'no-decision', reason: 'consumer reconciliation set unavailable — cannot decide uniqueness' };

  const prior = consumed[id];
  if (prior === undefined) {
    return { decision: 'pass', effect: 'count', reason: `first claim of ${id} → count under (${r.jobId}, ${r.phaseIndex})` };
  }
  // ── same (jobId, phaseIndex) → idempotent re-presentation; already counted; do NOT count again ──
  if (prior.jobId === r.jobId && prior.phaseIndex === r.phaseIndex) {
    return { decision: 'pass', effect: 'already-counted', reason: `idempotent re-presentation of ${id} under the same (jobId, phaseIndex) — already counted, MUST NOT count again` };
  }
  // ── different (jobId, phaseIndex) → double-count, reject ──
  return {
    decision: 'fail',
    effect: 'reject',
    reason: `${id} already counted under (${prior.jobId}, ${prior.phaseIndex}); re-presented under (${r.jobId}, ${r.phaseIndex}) — cross-session/phase double-count, reject`,
  };
}
