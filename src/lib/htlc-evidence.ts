/**
 * DACS-4 Settle — HTLC SettlementEvidence build + verify
 *
 * Spec source: DACS v0.7 + DACS-1..5 v0.1, §9.5 + §7.7.
 *
 * Assembles the lock/reveal (or lock/refund) phase evidence for a Hashed-TimeLock
 * Contract settlement, canonicalises it (JCS, RFC 8785), domain-separates under
 * "dacs-evidence:v1:" (v0.1 §B.7; DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE), and signs/verifies
 * via the repo's ed25519 pattern (src/lib/sign.ts).
 *
 * **Signed-bytes discipline (repo invariant):**
 *   signed_bytes := domain_separator || sha256-hex(JCS(unsignedEvidence))
 * i.e. the body after the separator is the *hex string* of the SHA-256 of the JCS
 * canonical bytes, encoded as UTF-8. We use the hex form (not the raw 32 bytes) so
 * the on-the-wire signed payload is the same string a logging/receipt layer prints
 * (jcsHashHex), keeping the audit trail and the cryptographic commitment identical.
 *
 * **Timelock-asymmetry safety check (the load-bearing HTLC invariant):**
 * On the happy (settled) path the seller's reveal MUST land strictly before the
 * source-chain lock's `timelockExpiry` — otherwise the buyer could refund the same
 * lock the seller is claiming. On the refund path the buyer's refund MUST wait
 * until at/after `timelockExpiry`, and there must be NO valid reveal. Both
 * buildHtlcSettlementEvidence and verifyHtlcSettlementEvidence enforce this.
 */

import { sha256 } from '@noble/hashes/sha2';
import { jcsHashHex } from '../jcs.js';
import { sign, verify as edVerify } from './sign.js';
import { DOMAIN_SEPARATORS } from '../domain-sep.js';
import { hexToBytes, bytesToHex } from './verify-bundle.js';
import { canonicalPrice } from '../types/settle.js';
import {
  RailAvailability,
  type SettlementEvidence,
  type PriceTerm,
  type HtlcLockTxRef,
  type HtlcRevealTxRef,
  type HtlcRefundTxRef,
  type HtlcTxRef,
} from '../types/settle.js';

/** Result of a settlement-evidence verification — mirrors the §7.5.1 three-state discipline. */
export interface HtlcVerifyResult {
  /** `pass` only if signature + hashlock + timelock-asymmetry all hold. */
  decision: 'pass' | 'fail';
  jobId: string;
  /** The SHA-256 hex of the JCS canonical bytes the verifier hashed (the signed commitment). */
  evidenceHashHex: string;
  /** Ordered per-check log so a consumer sees exactly which invariant failed. */
  checks: { check: string; outcome: 'pass' | 'fail'; detail: string }[];
}

/** Strip the `signature` field — that is the payload that gets canonicalised + hashed. */
function unsignedEvidence(ev: SettlementEvidence): Omit<SettlementEvidence, 'signature'> {
  const { signature: _omit, ...rest } = ev;
  return rest;
}

/** Re-normalise a PriceTerm's amount through canonicalPrice so the hashed form is reproducible (finding #27). */
function normalisePrice(price: PriceTerm): PriceTerm {
  return { ...price, amount: canonicalPrice(price) };
}

/**
 * True iff the canonical amount is strictly positive — neither negative (leading '-')
 * nor zero (/^0(\.0*)?$/). An HTLC settles a monetary `price`; a negative or zero
 * settled amount is contradictory value evidence. Returns false on any non-canonicalisable
 * amount so the verify walk treats it as a reject (fail-closed). Mirrors
 * tank-lock-evidence.ts::isPositiveAmount exactly.
 */
function isPositiveAmount(p: PriceTerm): boolean {
  let c: string;
  try {
    c = canonicalPrice(p);
  } catch {
    return false;
  }
  if (c.startsWith('-')) return false;
  if (/^0(\.0*)?$/.test(c)) return false;
  return true;
}

/** sha256(preimageBytes) as hex, comparing case-insensitively against a stored hashlock. */
function hashlockFor(preimageHex: string): string {
  return bytesToHex(sha256(hexToBytes(preimageHex)));
}

/* -------------------------------------------------------------------------- */
/*  Build                                                                      */
/* -------------------------------------------------------------------------- */

export interface BuildHtlcEvidenceInput {
  jobId: string;
  rail: RailAvailability;
  price: PriceTerm;
  settler: SettlementEvidence['settler'];
  /** Settling party's ed25519 private key. */
  settlerPrivKey: Uint8Array;
  /** Settling party's ed25519 public key (recorded on the evidence + checked at verify). */
  settlerPubkey: Uint8Array;
  /** The source-chain lock tx. Required on every path. */
  lock: HtlcLockTxRef;
  /** Present on the happy path. */
  reveal?: HtlcRevealTxRef;
  /** Present on the timeout path. */
  refund?: HtlcRefundTxRef;
  /** When the evidence was assembled (ISO 8601). Defaults to now. */
  settledAt?: string;
}

/**
 * Assemble + sign HTLC SettlementEvidence.
 *
 * Enforces, at build time, the same invariants the verifier checks, so a producer
 * cannot mint structurally-unsafe evidence:
 *   - exactly one of {reveal, refund} (mutually exclusive lifecycle ends), unless
 *     `rail === Failed` with neither (a lock-only failure record)
 *   - every txRef carries the SAME hashlock as the lock
 *   - reveal.preimage hashes to that hashlock
 *   - timelock asymmetry, checking the SAME fields the verifier does: on the happy
 *     path BOTH reveal.revealDeadline AND reveal.observedAt strictly before
 *     lock.timelockExpiry; on the refund path BOTH refund.refundedAfter AND
 *     refund.observedAt at/after it. (Build/verify symmetry — a builder that checked
 *     fewer fields could mint evidence its own verifier rejects.)
 */
export function buildHtlcSettlementEvidence(input: BuildHtlcEvidenceInput): SettlementEvidence {
  const { jobId, rail, settler, lock, reveal, refund } = input;

  if (reveal && refund) {
    throw new Error('buildHtlcSettlementEvidence: reveal and refund are mutually exclusive HTLC outcomes');
  }

  let outcome: SettlementEvidence['outcome'];
  let txRefs: HtlcTxRef[];

  if (reveal) {
    assertHashlockMatch(lock, reveal);
    assertPreimageMatchesHashlock(reveal);
    assertRevealBeforeTimelock(lock, reveal);
    outcome = 'settled';
    txRefs = [lock, reveal];
  } else if (refund) {
    assertHashlockMatch(lock, refund);
    assertRefundAfterTimelock(lock, refund);
    outcome = 'refunded';
    txRefs = [lock, refund];
  } else {
    // Neither reveal nor refund — only valid as a failed-rail lock-only record.
    if (rail !== RailAvailability.Failed) {
      throw new Error(
        `buildHtlcSettlementEvidence: no reveal and no refund requires rail=${RailAvailability.Failed}, got "${rail}"`
      );
    }
    outcome = 'failed';
    txRefs = [lock];
  }

  const unsigned: Omit<SettlementEvidence, 'signature'> = {
    v: 'dacs-4-settlement-evidence:0.1',
    jobId,
    method: 'htlc',
    rail,
    price: normalisePrice(input.price),
    settler,
    settlerPubkey: bytesToHex(input.settlerPubkey),
    outcome,
    txRefs,
    settledAt: input.settledAt ?? new Date().toISOString(),
  };

  // signed_bytes = "dacs-evidence:v1:" || sha256-hex(JCS(unsigned))
  const hashHex = jcsHashHex(unsigned);
  const body = new TextEncoder().encode(hashHex);
  const sig = sign(DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE, body, input.settlerPrivKey);

  return { ...unsigned, signature: Buffer.from(sig).toString('base64') };
}

/* -------------------------------------------------------------------------- */
/*  Verify                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Verify HTLC SettlementEvidence.
 *
 * Walk (any `fail` ⇒ overall fail):
 *   1. signature present + decodes to 64 bytes
 *   2. ed25519 verifies over (separator || sha256-hex(JCS(unsigned))) against settlerPubkey
 *   3. price re-canonicalises to the carried amount (finding #27 — no float drift)
 *   4. lock present + every txRef shares the lock's hashlock
 *   5. outcome-specific invariants:
 *        settled  → reveal preimage hashes to hashlock AND reveal strictly before lock.timelockExpiry
 *        refunded → refund at/after lock.timelockExpiry AND no valid reveal rides along
 *        failed   → lock present, rail=failed
 */
export function verifyHtlcSettlementEvidence(
  evidence: SettlementEvidence,
  expectedSettlerPubkey?: Uint8Array
): HtlcVerifyResult {
  const checks: HtlcVerifyResult['checks'] = [];
  const add = (check: string, outcome: 'pass' | 'fail', detail: string): void => {
    checks.push({ check, outcome, detail });
  };

  const unsigned = unsignedEvidence(evidence);
  const evidenceHashHex = jcsHashHex(unsigned);
  const body = new TextEncoder().encode(evidenceHashHex);

  // 1 + 2 — signature
  if (!evidence.signature) {
    add('signature-present', 'fail', 'evidence.signature is absent');
  } else {
    let sig: Uint8Array;
    try {
      sig = new Uint8Array(Buffer.from(evidence.signature, 'base64'));
    } catch (e) {
      add('signature-decode', 'fail', `signature is not valid base64: ${(e as Error).message}`);
      sig = new Uint8Array(0);
    }
    if (sig.length === 64) {
      let pubkey: Uint8Array | null = null;
      try {
        pubkey = expectedSettlerPubkey ?? hexToBytes(evidence.settlerPubkey);
      } catch (e) {
        add('signature-pubkey', 'fail', `settlerPubkey is not valid hex: ${(e as Error).message}`);
      }
      // If an expected key was supplied, it MUST match the one recorded on the evidence.
      if (pubkey && expectedSettlerPubkey) {
        try {
          if (bytesToHex(expectedSettlerPubkey).toLowerCase() !== evidence.settlerPubkey.toLowerCase()) {
            add('signature-pubkey', 'fail',
              'expectedSettlerPubkey does not match evidence.settlerPubkey');
            pubkey = null;
          }
        } catch {
          pubkey = null;
        }
      }
      if (pubkey) {
        const ok = edVerify(DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE, sig, body, pubkey);
        add('signature', ok ? 'pass' : 'fail',
          ok
            ? `ed25519 verified over separator || sha256-hex(JCS) against ${evidence.settlerPubkey.slice(0, 12)}…`
            : `ed25519 verification FAILED (evidenceHash=${evidenceHashHex.slice(0, 16)}…)`);
      }
    } else if (evidence.signature) {
      add('signature-length', 'fail', `decoded signature is ${sig.length} bytes; ed25519 requires 64`);
    }
  }

  // 3 — price re-canonicalisation (finding #27)
  try {
    const recomputed = canonicalPrice(evidence.price);
    if (recomputed !== evidence.price.amount) {
      add('price-canonical', 'fail',
        `price.amount "${evidence.price.amount}" is not canonical — re-normalises to "${recomputed}" (finding #27)`);
    } else {
      add('price-canonical', 'pass', `amount "${recomputed}" ${evidence.price.asset} is canonical`);
    }
  } catch (e) {
    add('price-canonical', 'fail', `price.amount failed canonicalisation: ${(e as Error).message}`);
  }

  // 3.5 — settled amount must be strictly positive. The HTLC settles `price`; a
  // negative or zero settled amount is contradictory value evidence (a settlement that
  // moves no — or negative — value). Mirrors the positive-amount guard the tank/bridge
  // verifiers enforce. Reject on any non-canonicalisable amount (fail-closed).
  const pricePositive = isPositiveAmount(evidence.price);
  add('price-positive',
    pricePositive ? 'pass' : 'fail',
    pricePositive
      ? `settled amount "${evidence.price.amount}" ${evidence.price.asset} is positive`
      : `htlc settlement amount must be positive (got "${evidence.price.amount} ${evidence.price.asset}") ` +
        `— a negative or zero HTLC settlement is contradictory`);

  // 4 — lock + hashlock consistency
  const lock = evidence.txRefs.find((t): t is HtlcLockTxRef => t.phase === 'htlc-lock');
  if (!lock) {
    add('htlc-lock-present', 'fail', 'no htlc-lock txRef in evidence');
  } else {
    const mismatched = evidence.txRefs.filter(t => t.hashlock.toLowerCase() !== lock.hashlock.toLowerCase());
    if (mismatched.length > 0) {
      add('hashlock-consistency', 'fail',
        `${mismatched.length} txRef(s) carry a different hashlock than the lock — phases not bound to one HTLC`);
    } else {
      add('hashlock-consistency', 'pass', `all ${evidence.txRefs.length} txRef(s) share hashlock ${lock.hashlock.slice(0, 16)}…`);
    }
  }

  // 5 — outcome-specific invariants
  const reveal = evidence.txRefs.find((t): t is HtlcRevealTxRef => t.phase === 'htlc-reveal');
  const refund = evidence.txRefs.find((t): t is HtlcRefundTxRef => t.phase === 'htlc-refund');

  if (evidence.outcome === 'settled') {
    if (refund) {
      // Mutual exclusion (mirrors buildHtlcSettlementEvidence's reveal&&refund rejection):
      // a settled outcome MUST NOT carry a refund txRef — lock+reveal+refund is contradictory.
      add('settled-no-refund', 'fail',
        'outcome=settled but a htlc-refund txRef rides along — contradictory settle+refund evidence');
    }
    if (!reveal) {
      add('settled-has-reveal', 'fail', 'outcome=settled but no htlc-reveal txRef');
    } else if (lock) {
      // preimage hashes to hashlock
      let preimageOk = false;
      try {
        preimageOk = hashlockFor(reveal.preimage).toLowerCase() === lock.hashlock.toLowerCase();
      } catch (e) {
        add('preimage', 'fail', `reveal.preimage is not valid hex: ${(e as Error).message}`);
      }
      add('preimage', preimageOk ? 'pass' : 'fail',
        preimageOk
          ? 'sha256(preimage) === hashlock'
          : 'sha256(preimage) !== hashlock — revealed preimage does not open the lock');
      // timelock asymmetry: reveal strictly before lock.timelockExpiry
      const safe = isStrictlyBefore(reveal.revealDeadline, lock.timelockExpiry)
        && isStrictlyBefore(reveal.observedAt, lock.timelockExpiry);
      add('timelock-asymmetry', safe ? 'pass' : 'fail',
        safe
          ? `reveal (deadline=${reveal.revealDeadline}, observed=${reveal.observedAt}) lands strictly before source timelock ${lock.timelockExpiry}`
          : `UNSAFE: reveal does not land strictly before source timelock ${lock.timelockExpiry} — buyer could refund the same lock`);
    }
  } else if (evidence.outcome === 'refunded') {
    if (reveal) {
      add('refund-no-reveal', 'fail', 'outcome=refunded but a htlc-reveal txRef rides along — a valid reveal forecloses refund');
    }
    if (!refund) {
      add('refunded-has-refund', 'fail', 'outcome=refunded but no htlc-refund txRef');
    } else if (lock) {
      // refund must wait until at/after the lock timelock, and must reference that exact timelock
      const refundedAtOrAfter = !isStrictlyBefore(refund.refundedAfter, lock.timelockExpiry);
      const matchesTimelock = refund.refundedAfter === lock.timelockExpiry
        || !isStrictlyBefore(refund.refundedAfter, lock.timelockExpiry);
      const observedAtOrAfter = !isStrictlyBefore(refund.observedAt, lock.timelockExpiry);
      const safe = refundedAtOrAfter && matchesTimelock && observedAtOrAfter;
      add('timelock-asymmetry', safe ? 'pass' : 'fail',
        safe
          ? `refund (after=${refund.refundedAfter}, observed=${refund.observedAt}) waited until source timelock ${lock.timelockExpiry}`
          : `UNSAFE: refund did not wait until source timelock ${lock.timelockExpiry} expired`);
    }
  } else if (evidence.outcome === 'failed') {
    // failed evidence is lock-only (mirrors the builder, lines 128-137): a reveal or refund
    // txRef riding along is contradictory and must fail closed — do not pass on rail alone.
    if (reveal || refund) {
      add('failed-lock-only', 'fail',
        'outcome=failed but a htlc-reveal/htlc-refund txRef rides along — failed evidence must be lock-only');
    }
    if (evidence.rail !== RailAvailability.Failed) {
      add('failed-rail', 'fail', `outcome=failed but rail="${evidence.rail}" (expected "${RailAvailability.Failed}")`);
    } else {
      add('failed-rail', 'pass', 'outcome=failed with rail=failed');
    }
  } else {
    // Fail CLOSED on any unrecognised outcome — a signed runtime object with an unknown
    // outcome must never skip the outcome-specific checks and fall through to 'pass'.
    add('unknown-outcome', 'fail',
      'unrecognised outcome — verifier fails closed on unknown evidence.outcome values');
  }

  const decision: 'pass' | 'fail' = checks.some(c => c.outcome === 'fail') ? 'fail' : 'pass';
  return { decision, jobId: evidence.jobId, evidenceHashHex, checks };
}

/* -------------------------------------------------------------------------- */
/*  Internal invariant helpers                                                 */
/* -------------------------------------------------------------------------- */

function assertHashlockMatch(lock: HtlcLockTxRef, other: HtlcTxRef): void {
  if (lock.hashlock.toLowerCase() !== other.hashlock.toLowerCase()) {
    throw new Error(
      `HTLC phase "${other.phase}" hashlock ${other.hashlock.slice(0, 16)}… ` +
      `does not match lock hashlock ${lock.hashlock.slice(0, 16)}…`
    );
  }
}

function assertPreimageMatchesHashlock(reveal: HtlcRevealTxRef): void {
  if (hashlockFor(reveal.preimage).toLowerCase() !== reveal.hashlock.toLowerCase()) {
    throw new Error('HTLC reveal preimage does not hash to the declared hashlock');
  }
}

// Builder-side timelock checks are kept IDENTICAL to the verifier's (§5 of
// verifyHtlcSettlementEvidence): both revealDeadline AND observedAt must land
// strictly before the source timelock on the happy path, and both refundedAfter
// AND observedAt must land at/after it on the refund path. If the builder checked
// fewer fields than the verifier, a producer could mint evidence its OWN verifier
// rejects — the build/verify asymmetry this closes.
function assertRevealBeforeTimelock(lock: HtlcLockTxRef, reveal: HtlcRevealTxRef): void {
  if (!isStrictlyBefore(reveal.revealDeadline, lock.timelockExpiry)) {
    throw new Error(
      `HTLC timelock-asymmetry violation: reveal deadline ${reveal.revealDeadline} ` +
      `is not strictly before source lock timelock ${lock.timelockExpiry}`
    );
  }
  if (!isStrictlyBefore(reveal.observedAt, lock.timelockExpiry)) {
    throw new Error(
      `HTLC timelock-asymmetry violation: reveal observedAt ${reveal.observedAt} ` +
      `is not strictly before source lock timelock ${lock.timelockExpiry}`
    );
  }
}

function assertRefundAfterTimelock(lock: HtlcLockTxRef, refund: HtlcRefundTxRef): void {
  if (isStrictlyBefore(refund.refundedAfter, lock.timelockExpiry)) {
    throw new Error(
      `HTLC refund waited until ${refund.refundedAfter}, which is before the source lock timelock ${lock.timelockExpiry}`
    );
  }
  if (isStrictlyBefore(refund.observedAt, lock.timelockExpiry)) {
    throw new Error(
      `HTLC refund observedAt ${refund.observedAt} is before the source lock timelock ${lock.timelockExpiry}`
    );
  }
}

/** ISO-8601 strict-before comparison. Throws on unparseable timestamps. */
function isStrictlyBefore(a: string, b: string): boolean {
  const ta = Date.parse(a);
  const tb = Date.parse(b);
  if (Number.isNaN(ta)) throw new Error(`unparseable ISO 8601 timestamp: "${a}"`);
  if (Number.isNaN(tb)) throw new Error(`unparseable ISO 8601 timestamp: "${b}"`);
  return ta < tb;
}
