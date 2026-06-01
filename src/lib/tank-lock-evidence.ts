/**
 * Liquidity-tank LOCK verifier — negative-evidence-first.
 *
 * Spec source: DACS v0.7 + DACS-1..5 v0.1, §9 (Settle). PATH-OS Labs extension to
 * the §9.5 SettlementEvidence family; NOT part of the normative DACS v1 §7.7 closed
 * registry — its domain separator lives in PATHOS_EXTENSION_SEPARATORS so the
 * "exactly 17 spec separators" invariant stays green.
 *
 * What a liquidity tank is, and what this closes:
 *   A liquidity tank holds bridged value against a job (bridge_id). The escrow code
 *   can mark a tank "locked" and emit a partial release — but a CORRECT tank lock
 *   MUST positively prove, on the negative side, that:
 *     (a) a CONFIRMED source-chain deposit actually backs the lock, and that deposit
 *         binds to the SAME bridge_id + amount the tank claims (no minting value with
 *         no inbound deposit), and
 *     (b) a MAJORITY of the bridge shard set signed the lock state (not one node, not
 *         a replayed signature, not the same signer counted twice, not N fresh keys
 *         an attacker generated), and
 *     (c) IF the tank is partially_released, the released amount is present, is the
 *         SAME asset, and does NOT exceed the locked amount (a partial release that
 *         exceeds the lock over-pays the tank).
 *
 * This verifier is NEGATIVE-evidence-first: it REJECTS by default and only returns
 * { ok:true, decision:'pass' } when every guarantee is positively established. It
 * fails CLOSED on contradictory/unknown state.
 *
 * Two trust anchors are AUTHORITATIVE (verifier-supplied via options), never read
 * from the evidence object:
 *   - authorizedShardSet — only signatures from MEMBER shards count toward quorum;
 *     a producer cannot self-declare its signers as shards. Absent ⇒ indeterminate.
 *   - consumedDepositLedger — optional here (a lock does not consume a deposit), but
 *     when supplied a deposit already consumed by a prior release fails closed.
 *
 * decision ∈ {'pass','fail','indeterminate'} is never coerced (sibling to §7.5.1).
 *
 * Signed-bytes discipline (repo invariant):
 *   signed_bytes := TANK_LOCK_ATTESTATION || utf8( sha256-hex( JCS(tankLockCommitment) ) )
 * where tankLockCommitment is the deterministic tuple every shard signs.
 */

import { jcsHashHex } from '../jcs.js';
import { sign as edSign, verify as edVerify } from './sign.js';
import { PATHOS_EXTENSION_SEPARATORS } from '../domain-sep.js';
import { hexToBytes, bytesToHex } from './verify-bundle.js';
import { canonicalPrice, type PriceTerm } from '../types/settle.js';
import {
  type SourceChainDepositProof,
  type ShardSignature,
  type VerifyResult,
} from './settlement-evidence-verifier.js';

/* -------------------------------------------------------------------------- */
/*  Types                                                                      */
/* -------------------------------------------------------------------------- */

/** Lifecycle states a liquidity tank lock can be in. */
export type TankLockState = 'locked' | 'partially_released' | 'released' | 'expired';

/**
 * A liquidity-tank lock, plus the negative evidence required to trust it.
 *
 * `bridge_id` + `amount` are the lock's identity; the deposit proof MUST bind to
 * both, and >= requiredQuorum DISTINCT AUTHORIZED shard signers MUST sign the
 * commitment.
 */
export interface TankLockEvidence {
  v: 'dacs-tank-lock-evidence:0.1';
  /** Job/session this tank lock belongs to (matches the DACS-5 bundle jobId). */
  jobId: string;
  /** The bridge instance whose tank holds this value. */
  bridge_id: string;
  /** The total amount locked in the tank (decimal-string PriceTerm — finding #27, no floats). */
  amount: PriceTerm;
  /** Current lifecycle state of the tank lock. */
  lockState: TankLockState;
  /**
   * Amount released so far. REQUIRED when lockState='partially_released'; MUST be the
   * same asset as `amount` and MUST NOT exceed it. Ignored for other states.
   */
  releasedAmount?: PriceTerm;
  /** Absolute time after which the lock expires and the deposit becomes refund-eligible (ISO 8601). */
  lockExpiry: string;
  /** The confirmed source-chain deposit that backs the lock. */
  source_chain_deposit_proof: SourceChainDepositProof;
  /** The shard quorum's signatures over the lock commitment. */
  shard_quorum_signatures: ShardSignature[];
}

/** Options bag — authoritative trust anchors are verifier-supplied here. */
export interface VerifyTankLockOptions {
  /**
   * Minimum number of DISTINCT, valid, AUTHORIZED shard signers required
   * (majority-of-shard). The caller computes this from the shard-set size
   * (e.g. floor(N/2)+1).
   */
  requiredQuorum: number;
  /** Total shard-set size, if known — lets the verifier check requiredQuorum is a true majority. */
  shardSetSize?: number;
  /**
   * The KNOWN, AUTHORIZED bridge shard signer pubkeys (hex). Only signatures whose
   * signer is a MEMBER of this set count toward `requiredQuorum`; a cryptographically
   * valid signature from a NON-member is rejected (defeats forge-N-fresh-keys). If
   * OMITTED, the verifier cannot establish signers are authorised shards and MUST
   * return decision='indeterminate' (§7.5.1 — never coerced to 'pass').
   */
  authorizedShardSet?: Iterable<string>;
  /**
   * Optional AUTHORITATIVE ledger of deposit_ids already consumed by a prior release
   * through this bridge_id. A lock does NOT consume a deposit, so this is optional;
   * but when supplied, a deposit already present here means the tank is locking value
   * that was already released elsewhere → fail closed. Verifier-controlled state,
   * never read from the evidence object.
   */
  consumedDepositLedger?: readonly string[];
}

/* -------------------------------------------------------------------------- */
/*  Commitment                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * The deterministic tuple every shard signs for a tank lock. Binding all fields
 * means a signature authorising lock state S for amount A through bridge B against
 * deposit D cannot be replayed to authorise a lock that differs in ANY of those.
 */
export interface TankLockCommitment {
  bridge_id: string;
  amount: { amount: string; asset: string };
  lockState: TankLockState;
  releasedAmount: { amount: string; asset: string } | null;
  lockExpiry: string;
  deposit_id: string;
}

/** Build the canonical commitment for an evidence object (prices re-normalised). */
export function buildTankLockCommitment(evidence: TankLockEvidence): TankLockCommitment {
  return {
    bridge_id: evidence.bridge_id,
    amount: { amount: canonicalPrice(evidence.amount), asset: evidence.amount.asset },
    lockState: evidence.lockState,
    releasedAmount:
      evidence.releasedAmount !== undefined
        ? { amount: canonicalPrice(evidence.releasedAmount), asset: evidence.releasedAmount.asset }
        : null,
    lockExpiry: evidence.lockExpiry,
    deposit_id: evidence.source_chain_deposit_proof.deposit_id,
  };
}

/** signed_bytes body = utf8( sha256-hex( JCS(commitment) ) ) — same audit-trail discipline as htlc-evidence.ts. */
function commitmentBody(commitment: TankLockCommitment): Uint8Array {
  return new TextEncoder().encode(jcsHashHex(commitment));
}

/* -------------------------------------------------------------------------- */
/*  Helpers — price compare (mirrors settlement-evidence-verifier priceEqual)  */
/* -------------------------------------------------------------------------- */

/**
 * True iff the canonical amount is strictly positive — neither negative (leading '-')
 * nor zero (/^0(\.0*)?$/). A monetary lock/refund amount MUST be > 0: a negative or
 * zero amount is contradictory value evidence (and a negative amount that "matches" a
 * negative deposit-proof amount would otherwise pass equality/ceiling checks).
 * Returns false on any non-canonicalisable amount so the caller treats it as a reject.
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

/**
 * True iff the canonical amount is non-negative (no leading '-'). Zero is allowed.
 * Used for releasedAmount, where 0 is a legitimate "nothing released yet" value but a
 * negative release is contradictory (it would pass the <= amount ceiling).
 * Returns false on any non-canonicalisable amount so the caller treats it as a reject.
 */
function isNonNegativeAmount(p: PriceTerm): boolean {
  let c: string;
  try {
    c = canonicalPrice(p);
  } catch {
    return false;
  }
  return !c.startsWith('-');
}

/** Compare two PriceTerms by canonical amount + asset (finding #27 — no float drift). */
function priceEqual(a: PriceTerm, b: PriceTerm): boolean {
  if (a.asset !== b.asset) return false;
  try {
    return canonicalPrice(a) === canonicalPrice(b);
  } catch {
    return false;
  }
}

/**
 * True iff `a <= b` as scaled-decimal amounts of the SAME asset (BigInt compare, no
 * float). Returns false on asset mismatch or any non-canonicalisable amount so the
 * caller treats it as a reject. Scaling uses the max fractional length of the two
 * canonical forms, so "10" <= "10.000000" compares equal.
 */
function priceLessOrEqual(a: PriceTerm, b: PriceTerm): boolean {
  if (a.asset !== b.asset) return false;
  let ca: string;
  let cb: string;
  try {
    ca = canonicalPrice(a);
    cb = canonicalPrice(b);
  } catch {
    return false;
  }
  try {
    const [ai, bi] = scaledBigInts(ca, cb);
    return ai <= bi;
  } catch {
    return false;
  }
}

/** Scale two canonical decimal strings to a common fractional length and return BigInts. */
function scaledBigInts(a: string, b: string): [bigint, bigint] {
  const fracLen = (s: string): number => {
    const i = s.indexOf('.');
    return i === -1 ? 0 : s.length - i - 1;
  };
  const scale = Math.max(fracLen(a), fracLen(b));
  const toScaled = (s: string): bigint => {
    const neg = s.startsWith('-');
    const body = neg ? s.slice(1) : s;
    const dot = body.indexOf('.');
    const intPart = dot === -1 ? body : body.slice(0, dot);
    const fracPart = dot === -1 ? '' : body.slice(dot + 1);
    const digits = (intPart + fracPart.padEnd(scale, '0')) || '0';
    const v = BigInt(digits === '' ? '0' : digits);
    return neg ? -v : v;
  };
  return [toScaled(a), toScaled(b)];
}

/* -------------------------------------------------------------------------- */
/*  Verify                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Verify a liquidity-tank lock under negative-evidence rules. REJECTS unless:
 *   (a) a CONFIRMED source-chain deposit proof binds to the tank's bridge_id +
 *       amount (and, if a consumed ledger is supplied, is not already consumed); AND
 *   (b) IF lockState='partially_released': releasedAmount is present, same asset,
 *       and <= amount (BigInt scaled-decimal compare); AND
 *   (c) >= requiredQuorum DISTINCT AUTHORIZED valid shard signers signed the lock
 *       commitment (majority-of-shard).
 *
 * Returns on the FIRST failed guarantee. With no authorizedShardSet the majority-of-
 * shard guarantee is unprovable → decision='indeterminate' (never 'pass').
 */
export function verifyTankLock(
  evidence: TankLockEvidence,
  options: VerifyTankLockOptions
): VerifyResult {
  const fail = (reason: string): VerifyResult => ({ ok: false, decision: 'fail', reason });
  const indeterminate = (reason: string): VerifyResult => ({ ok: false, decision: 'indeterminate', reason });

  const { requiredQuorum, shardSetSize, authorizedShardSet, consumedDepositLedger } = options;

  // Normalise the authorized shard pubkey set once (lower-cased hex, 0x stripped).
  let authorizedShards: Set<string> | undefined;
  if (authorizedShardSet !== undefined) {
    authorizedShards = new Set<string>();
    for (const k of authorizedShardSet) {
      const norm = k.toLowerCase().replace(/^0x/, '');
      if (norm.length > 0) authorizedShards.add(norm);
    }
  }

  // Reject-first: positive-integer quorum that is a true majority of the shard set.
  if (!Number.isInteger(requiredQuorum) || requiredQuorum < 1) {
    return fail(`requiredQuorum must be a positive integer (got ${requiredQuorum}) — a lock cannot be authorised by zero shards`);
  }
  if (shardSetSize !== undefined) {
    const majority = Math.floor(shardSetSize / 2) + 1;
    if (requiredQuorum < majority) {
      return fail(`requiredQuorum=${requiredQuorum} is not a majority of shardSetSize=${shardSetSize} (need >= ${majority})`);
    }
  }

  // Fail closed on an unrecognised lockState — a signed object with an unknown state
  // must never skip the state-specific checks and fall through to 'pass'.
  const KNOWN_STATES: readonly TankLockState[] = ['locked', 'partially_released', 'released', 'expired'];
  if (!KNOWN_STATES.includes(evidence.lockState)) {
    return fail(`unrecognised lockState="${String(evidence.lockState)}" — verifier fails closed on unknown tank states`);
  }

  // Reject-first: the locked amount MUST be a positive monetary value. A negative or
  // zero amount is contradictory value evidence — and must be rejected BEFORE any
  // priceEqual/ceiling compare, so a negative amount can never reach (and pass) one.
  if (!isPositiveAmount(evidence.amount)) {
    return fail(
      `tank amount must be a positive value (got "${evidence.amount.amount} ${evidence.amount.asset}") ` +
      `— a tank lock cannot lock a negative or zero amount`
    );
  }

  const proof = evidence.source_chain_deposit_proof;

  /* ---- Guarantee (a): confirmed deposit that binds to bridge_id + amount ---- */

  if (!proof) {
    return fail('no source_chain_deposit_proof — a tank lock with no inbound deposit mints value');
  }
  if (!proof.confirmed || !proof.confirmedAt) {
    return fail(
      `source-chain deposit is not confirmed (confirmed=${proof.confirmed}, confirmedAt=${proof.confirmedAt ?? 'absent'}) ` +
      `— an unconfirmed deposit MUST NOT back a tank lock`
    );
  }
  if (
    proof.requiredConfirmations !== undefined &&
    (proof.confirmations === undefined || proof.confirmations < proof.requiredConfirmations)
  ) {
    return fail(
      `deposit confirmations=${proof.confirmations ?? 0} < requiredConfirmations=${proof.requiredConfirmations}`
    );
  }
  if (proof.bridge_id !== evidence.bridge_id) {
    return fail(
      `deposit proof bridge_id="${proof.bridge_id}" does not bind to tank bridge_id="${evidence.bridge_id}"`
    );
  }
  if (!isPositiveAmount(proof.amount)) {
    return fail(
      `deposit proof amount must be a positive value (got "${proof.amount.amount} ${proof.amount.asset}") ` +
      `— a negative or zero deposit amount cannot back a tank lock`
    );
  }
  if (!priceEqual(proof.amount, evidence.amount)) {
    return fail(
      `deposit amount (${proof.amount.amount} ${proof.amount.asset}) does not match tank amount ` +
      `(${evidence.amount.amount} ${evidence.amount.asset})`
    );
  }

  // If an AUTHORITATIVE consumed ledger is supplied, a deposit already consumed by a
  // prior release must not be locked again → fail closed. Optional for a lock.
  if (consumedDepositLedger !== undefined && consumedDepositLedger.includes(proof.deposit_id)) {
    return fail(
      `deposit_id="${proof.deposit_id}" is already in the authoritative consumed ledger for bridge_id="${evidence.bridge_id}" ` +
      `— cannot lock value already released elsewhere`
    );
  }

  /* ---- Guarantee (b): partial-release ceiling ---- */

  if (evidence.lockState === 'partially_released') {
    if (evidence.releasedAmount === undefined) {
      return fail('lockState=partially_released but releasedAmount is absent — a partial release MUST declare how much was released');
    }
    if (evidence.releasedAmount.asset !== evidence.amount.asset) {
      return fail(
        `releasedAmount asset "${evidence.releasedAmount.asset}" != locked asset "${evidence.amount.asset}" ` +
        `— a partial release must be the same asset as the lock`
      );
    }
    // Reject a negative release BEFORE the <= ceiling compare: a negative releasedAmount
    // trivially passes "<= amount" yet is contradictory value evidence.
    if (!isNonNegativeAmount(evidence.releasedAmount)) {
      return fail(
        `releasedAmount must be >= 0 (got "${evidence.releasedAmount.amount} ${evidence.releasedAmount.asset}") ` +
        `— a partial release cannot release a negative amount`
      );
    }
    if (!priceLessOrEqual(evidence.releasedAmount, evidence.amount)) {
      return fail(
        `releasedAmount (${evidence.releasedAmount.amount} ${evidence.releasedAmount.asset}) exceeds locked amount ` +
        `(${evidence.amount.amount} ${evidence.amount.asset}) — a partial release cannot exceed the lock`
      );
    }
  }

  /* ---- Guarantee (c): majority-of-shard distinct AUTHORIZED signatures ---- */

  const sigs = evidence.shard_quorum_signatures;
  if (!sigs || sigs.length === 0) {
    return fail('shard_quorum_signatures is empty — no shard authorised the tank lock');
  }

  // No declared authorized set ⇒ cannot establish signers are registered shards →
  // indeterminate (§7.5.1 — never coerced to 'pass'). Closes forge-N-fresh-keys.
  if (authorizedShards === undefined) {
    return indeterminate(
      `no authorizedShardSet supplied for bridge_id="${evidence.bridge_id}" — cannot establish that signers ` +
      `are registered shards (majority-of-shard guarantee unprovable; a valid signature is not an authorised one)`
    );
  }

  const commitment = buildTankLockCommitment(evidence);
  const body = commitmentBody(commitment);

  const validSigners = new Set<string>();
  let rejectedNonMembers = 0;
  for (const s of sigs) {
    let pubKey: Uint8Array;
    try {
      pubKey = hexToBytes(s.signer);
    } catch {
      continue; // malformed signer key — does NOT count toward quorum
    }
    if (pubKey.length !== 32) continue; // ed25519 pubkeys are 32 bytes
    let sig: Uint8Array;
    try {
      sig = hexToBytes(s.signature);
    } catch {
      continue;
    }
    if (sig.length !== 64) continue; // ed25519 signatures are 64 bytes
    const ok = edVerify(PATHOS_EXTENSION_SEPARATORS.TANK_LOCK_ATTESTATION, sig, body, pubKey);
    if (!ok) continue;
    const normSigner = bytesToHex(pubKey).toLowerCase();
    // AUTHORIZATION: a valid signature from a NON-member shard does NOT count.
    if (!authorizedShards.has(normSigner)) {
      rejectedNonMembers++;
      continue;
    }
    // DISTINCTness keyed on the normalised signer hex — same signer twice counts once.
    validSigners.add(normSigner);
  }

  if (validSigners.size < requiredQuorum) {
    return fail(
      `sub-quorum: ${validSigners.size} distinct AUTHORIZED valid shard signer(s) over the tank-lock commitment ` +
      `< requiredQuorum=${requiredQuorum}` +
      (rejectedNonMembers > 0
        ? ` (${rejectedNonMembers} valid signature(s) rejected as non-members of the authorized shard set)`
        : '')
    );
  }

  return {
    ok: true,
    decision: 'pass',
    reason:
      `confirmed deposit ${proof.deposit_id} binds to bridge_id="${evidence.bridge_id}" + amount ` +
      `${commitment.amount.amount} ${commitment.amount.asset}; lockState=${evidence.lockState}` +
      (evidence.lockState === 'partially_released'
        ? ` (releasedAmount ${commitment.releasedAmount?.amount} <= ${commitment.amount.amount})`
        : '') +
      `; ${validSigners.size}-of-${sigs.length} distinct AUTHORIZED valid shard signatures (>= ${requiredQuorum} required)`,
  };
}

/* -------------------------------------------------------------------------- */
/*  Helper for producers / tests — sign the commitment with a shard key.       */
/* -------------------------------------------------------------------------- */

/** Produce one shard's hex signature over a tank-lock commitment. */
export function signTankLockCommitment(
  commitment: TankLockCommitment,
  shardPrivKey: Uint8Array,
  shardPubKey: Uint8Array
): ShardSignature {
  const sig = edSign(PATHOS_EXTENSION_SEPARATORS.TANK_LOCK_ATTESTATION, commitmentBody(commitment), shardPrivKey);
  return { signer: bytesToHex(shardPubKey), signature: bytesToHex(sig) };
}
