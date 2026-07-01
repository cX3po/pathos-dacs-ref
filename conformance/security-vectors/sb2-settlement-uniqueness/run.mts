/**
 * Conformance vectors for DACS §9.5.8 SB-2 — settlement-tx uniqueness per (jobId, phaseIndex)
 * (cross-session / cross-phase double-count defence). Built off the SN-4 single-use template,
 * scope-inverted (cX3po #159 / #161). Keyed on the SB-1 chain-namespaced settlement-tx-id, with
 * canonicalisation-attack coverage (0x / case / length / cluster) since the key IS the defence.
 *
 *   npx tsx conformance/security-vectors/sb2-settlement-uniqueness/run.mts
 *
 * Cross-impl convergence: a dacs-verify (or any) consumer keying on the same SB-1 settlement-tx-id
 * and the same (jobId, phaseIndex) tuple MUST produce these (decision, effect) pairs identically.
 */
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { checkSettlementUniqueness, settlementTxId, type ConsumedSet, type Decision, type Effect } from './validate.js';

const DIR = fileURLToPath(new URL('.', import.meta.url)).replace(/\/$/, '');
if (!existsSync(`${DIR}/vectors`)) mkdirSync(`${DIR}/vectors`, { recursive: true });
const sha = (s: string) => createHash('sha256').update(s).digest('hex');

// Fixed, deterministic settlement refs (lowercase, no 0x — the canonical form).
// minimal base58 encoder — to mint VALID (64-byte) and invalid-width Solana sigs deterministically.
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const b58encode = (bytes: Uint8Array): string => {
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) { carry += digits[i] << 8; digits[i] = carry % 58; carry = (carry / 58) | 0; }
    while (carry > 0) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  let zeros = 0; for (const b of bytes) { if (b === 0) zeros++; else break; }
  return '1'.repeat(zeros) + digits.reverse().map((d) => B58[d]).join('');
};
const TX = 'ab'.repeat(32);            // an EVM tx hash (32 bytes)
const TX2 = 'cd'.repeat(32);           // a different EVM tx hash
const SOLSIG = b58encode(new Uint8Array(64).fill(5));        // a VALID 64-byte Solana signature
const SOLSIG_LONG = b58encode(new Uint8Array(65).fill(5));   // base58-valid but decodes to 65 bytes
const SOLSIG_SHORT = b58encode(new Uint8Array(63).fill(5));  // base58-valid but decodes to 63 bytes
const DEMTX = 'ef'.repeat(32);         // a demos-native tx hash
const evm = (txHash: string, logIndex = 0, chainId = 8453) => ({ rail: 'evm' as const, chainId, txHash, logIndex });

// The canonical id for the base EVM ref, so consumed-set keys match what settlementTxId() produces.
const ID_TX0 = settlementTxId(evm(TX))!;                 // evm:8453:<tx>:0
const ID_SOL = settlementTxId({ rail: 'solana', cluster: 'mainnet', signature: SOLSIG, instructionIndex: 2 })!;
const under = (id: string, jobId: string, phaseIndex: number): ConsumedSet => ({ [id]: { jobId, phaseIndex } });

type Case = { name: string; decision: Decision; effect: Effect; consumed: ConsumedSet; record: unknown; note: string };

const cases: Case[] = [
  // ── first claim + idempotency (the count/already-counted distinction Codex flagged) ──
  { name: 'first-claim-evm', decision: 'pass', effect: 'count', consumed: {}, record: { settlementRef: evm(TX), jobId: 'job-A', phaseIndex: 3 },
    note: 'a settlement-tx-id never seen → countable under (job-A, 3)' },
  { name: 'idempotent-not-recounted', decision: 'pass', effect: 'already-counted', consumed: under(ID_TX0, 'job-A', 3),
    record: { settlementRef: evm(TX), jobId: 'job-A', phaseIndex: 3 },
    note: 'same tx-id re-presented under the SAME (jobId, phaseIndex) → already counted; pass but effect MUST be already-counted, never re-count' },

  // ── the headline: cross-session double-count ──
  { name: 'cross-session-double-count', decision: 'fail', effect: 'reject', consumed: under(ID_TX0, 'job-A', 3),
    record: { settlementRef: evm(TX), jobId: 'job-B', phaseIndex: 3 },
    note: 'same settlement-tx-id under a DIFFERENT jobId → cross-session double-count, reject' },
  { name: 'cross-phase-double-count', decision: 'fail', effect: 'reject', consumed: under(ID_TX0, 'job-A', 3),
    record: { settlementRef: evm(TX), jobId: 'job-A', phaseIndex: 4 },
    note: 'same tx-id, same job, DIFFERENT phaseIndex → second (jobId,phaseIndex) tuple → reject (SB-2)' },

  // ── legitimate distinctness ──
  { name: 'distinct-tx-same-job', decision: 'pass', effect: 'count', consumed: under(ID_TX0, 'job-A', 3),
    record: { settlementRef: evm(TX2), jobId: 'job-A', phaseIndex: 4 },
    note: 'a DIFFERENT settlement-tx-id under the same job → distinct settlement, count' },
  { name: 'batched-tx-distinct-logindex', decision: 'pass', effect: 'count', consumed: under(ID_TX0, 'job-A', 3),
    record: { settlementRef: evm(TX, 1), jobId: 'job-A', phaseIndex: 4 },
    note: 'SAME txHash but logIndex 1 (second transfer batched in one tx) → event-level key → distinct settlement, count (SB-1 disambiguation)' },

  // ── canonicalisation attacks: the key IS the defence; equivalent encodings MUST collapse to one key ──
  { name: 'evm-0x-prefix-collapses', decision: 'fail', effect: 'reject', consumed: under(ID_TX0, 'job-A', 3),
    record: { settlementRef: evm('0x' + TX), jobId: 'job-B', phaseIndex: 3 },
    note: 'same tx with a 0x prefix under a different jobId → 0x is stripped → key matches → double-count CAUGHT (no key-split)' },
  { name: 'evm-uppercase-collapses', decision: 'fail', effect: 'reject', consumed: under(ID_TX0, 'job-A', 3),
    record: { settlementRef: evm(TX.toUpperCase()), jobId: 'job-B', phaseIndex: 3 },
    note: 'same tx UPPERCASED under a different jobId → lowercased → key matches → double-count CAUGHT' },
  { name: 'demos-0x-prefix-first-claim', decision: 'pass', effect: 'count', consumed: {},
    record: { settlementRef: { rail: 'demos-native', txHash: '0x' + DEMTX }, jobId: 'job-D', phaseIndex: 0 },
    note: 'demos-native with 0x prefix → normalised + accepted → first claim, count' },
  { name: 'evm-wrong-length-error', decision: 'error', effect: 'verifier-error', consumed: {},
    record: { settlementRef: evm('ab'.repeat(31)), jobId: 'job-A', phaseIndex: 3 },
    note: '31-byte EVM tx hash → not exactly 32 bytes → error (never a distinct durable key)' },
  { name: 'evm-odd-hex-error', decision: 'error', effect: 'verifier-error', consumed: {},
    record: { settlementRef: evm('abc'), jobId: 'job-A', phaseIndex: 3 },
    note: 'odd/short hex → error' },

  // ── rail-agnostic + solana canonicalisation ──
  { name: 'solana-cross-session-double-count', decision: 'fail', effect: 'reject', consumed: under(ID_SOL, 'job-A', 1),
    record: { settlementRef: { rail: 'solana', cluster: 'mainnet', signature: SOLSIG, instructionIndex: 2 }, jobId: 'job-C', phaseIndex: 1 },
    note: 'rail-agnostic: same Solana (cluster, sig, instructionIndex) under a different jobId → double-count, reject' },
  { name: 'solana-noncanonical-cluster-error', decision: 'error', effect: 'verifier-error', consumed: {},
    record: { settlementRef: { rail: 'solana', cluster: 'mainnet-beta', signature: SOLSIG, instructionIndex: 2 }, jobId: 'job-A', phaseIndex: 1 },
    note: "cluster 'mainnet-beta' not in the canonical {mainnet,devnet,testnet} set → error (alias must not mint a second key for the same sig)" },
  { name: 'solana-bad-signature-error', decision: 'error', effect: 'verifier-error', consumed: {},
    record: { settlementRef: { rail: 'solana', cluster: 'mainnet', signature: 'not-base58-0OIl', instructionIndex: 2 }, jobId: 'job-A', phaseIndex: 1 },
    note: 'non-base58 signature → error' },
  { name: 'solana-sig-decoded-too-long-error', decision: 'error', effect: 'verifier-error', consumed: {},
    record: { settlementRef: { rail: 'solana', cluster: 'mainnet', signature: SOLSIG_LONG, instructionIndex: 2 }, jobId: 'job-A', phaseIndex: 1 },
    note: 'base58-valid but decodes to 65 bytes (not the canonical 64) → error (non-canonical width must not mint a key)' },
  { name: 'solana-sig-decoded-too-short-error', decision: 'error', effect: 'verifier-error', consumed: {},
    record: { settlementRef: { rail: 'solana', cluster: 'mainnet', signature: SOLSIG_SHORT, instructionIndex: 2 }, jobId: 'job-A', phaseIndex: 1 },
    note: 'base58-valid but decodes to 63 bytes → error' },

  // ── 4-value: do-not-collapse ──
  { name: 'ledger-unreadable-indeterminate', decision: 'indeterminate', effect: 'no-decision', consumed: null,
    record: { settlementRef: evm(TX), jobId: 'job-A', phaseIndex: 3 },
    note: 'consumer reconciliation set unavailable → indeterminate (MUST NOT count, MUST NOT reject) — never collapse' },
  { name: 'malformed-missing-ref-error', decision: 'error', effect: 'verifier-error', consumed: {},
    record: { jobId: 'job-A', phaseIndex: 3 },
    note: 'no settlementRef → verifier-side parse failure → error, not fail' },
  { name: 'malformed-phaseindex-error', decision: 'error', effect: 'verifier-error', consumed: {},
    record: { settlementRef: evm(TX), jobId: 'job-A', phaseIndex: -1 },
    note: 'phaseIndex not a safe integer ≥ 0 → error' },
  { name: 'unknown-rail-error', decision: 'error', effect: 'verifier-error', consumed: {},
    record: { settlementRef: { rail: 'bitcoin', txHash: TX }, jobId: 'job-A', phaseIndex: 3 },
    note: 'unknown rail → settlement-tx-id uncomputable → error' },
];

const vectors = cases.map((c) => ({ name: c.name, decision: c.decision, effect: c.effect, note: c.note, consumed: c.consumed, record: c.record }));
const setHash = sha(JSON.stringify(vectors));
writeFileSync(`${DIR}/vectors/sb2-settlement-uniqueness-v0.1.json`, JSON.stringify({
  set: 'sb2-settlement-uniqueness-v0.1', spec: 'DACS §9.5.8 (SB-2); SB-1 key', hash: setHash, count: vectors.length, vectors,
}, null, 2) + '\n');

let pass = 0;
console.log('\n=== DACS §9.5.8 SB-2 settlement-tx uniqueness conformance vectors v0.1 ===');
for (const c of cases) {
  const v = checkSettlementUniqueness(c.record, c.consumed);
  const ok = v.decision === c.decision && v.effect === c.effect;
  pass += ok ? 1 : 0;
  console.log(`  [${ok ? '✓' : '✗'}] ${c.name.padEnd(34)} exp=${c.decision}/${c.effect.padEnd(15)} got=${v.decision}/${v.effect}${ok ? '' : '  ‹‹ MISMATCH'}`);
}
console.log(`\nset hash: ${setHash.slice(0, 24)}…`);
console.log(`${pass}/${cases.length} vectors pass → vectors/sb2-settlement-uniqueness-v0.1.json`);
if (pass !== cases.length) process.exit(1);
