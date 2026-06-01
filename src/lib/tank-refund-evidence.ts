/**
 * Liquidity-tank REFUND verifier — negative-evidence-first.
 *
 * Spec source: DACS v0.7 + DACS-1..5 v0.1, §9 (Settle). PATH-OS Labs extension to
 * the §9.5 SettlementEvidence family; NOT part of the normative DACS v1 §7.7 closed
 * registry — its domain separator lives in PATHOS_EXTENSION_SEPARATORS so the
 * "exactly 17 spec separators" invariant stays green.
 *
 * What this defines (the public-OK counterpart):
 *   A tank lock can EXPIRE. Marking a lock expired is not the same as REFUNDING the
 *   depositor — and a correct refund is the only thing that returns the depositor's
 *   value once the lock is past its window. This verifier states what a CORRECT
 *   refund MUST positively prove, so a refund cannot mint, double-pay, refund early,
 *   or pay the wrong party:
 *     (a) a CONFIRMED source-chain deposit binds to the tank's bridge_id + amount;
 *     (b) the refund happened AT/AFTER lockExpiry — never before (mirrors the HTLC
 *         assertRefundAfterTimelock asymmetry: refunding before expiry could race a
 *         still-claimable lock);
 *     (c) the deposit has NOT already been consumed by a release (no refund-after-
 *         release double-pay) — checked against the AUTHORITATIVE consumed ledger;
 *     (d) the refund recipient EQUALS the deposit's original depositor (a refund
 *         returns value to whoever deposited it, structurally — not to an attacker-
 *         chosen address);
 *     (e) a MAJORITY of the AUTHORIZED bridge shard set signed the refund commitment.
 *
 * NEGATIVE-evidence-first: REJECTS by default; { ok:true, decision:'pass' } only when
 * every guarantee positively holds. Fails CLOSED on contradictory/unknown state.
 *
 * Trust anchors are AUTHORITATIVE (verifier-supplied via options), never read from
 * the evidence object:
 *   - consumedDepositLedger — REQUIRED here. A refund double-pay is exactly the
 *     fact a malicious producer would hide, so its absence cannot reach a PASS:
 *     decision='indeterminate' (§7.5.1 — never coerced).
 *   - authorizedShardSet — only MEMBER-shard signatures count toward quorum; absent
 *     ⇒ indeterminate (defeats forge-N-fresh-keys).
 *
 * Signed-bytes discipline (repo invariant):
 *   signed_bytes := TANK_REFUND_ATTESTATION || utf8( sha256-hex( JCS(tankRefundCommitment) ) )
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

/** The on-chain refund transaction the shard quorum is attesting. */
export interface TankRefundTx {
  /** Source chain / substrate the refund landed on (opaque). */
  chain: string;
  /** Refund transaction hash (hex; compared as a string). */
  txHash: string;
}

/**
 * A liquidity-tank refund, plus the negative evidence required to trust it.
 *
 * `bridge_id` + `amount` are the refund's identity; the deposit proof MUST bind to
 * both, and >= requiredQuorum DISTINCT AUTHORIZED shard signers MUST sign the
 * commitment.
 */
export interface TankRefundEvidence {
  v: 'dacs-tank-refund-evidence:0.1';
  /** Job/session this refund belongs to (matches the DACS-5 bundle jobId). */
  jobId: string;
  /** The bridge instance whose tank is refunding. */
  bridge_id: string;
  /** The amount being refunded (decimal-string PriceTerm — finding #27, no floats). */
  amount: PriceTerm;
  /** The address the refund pays out to — MUST equal the deposit's original depositor. */
  refundRecipient: string;
  /** The confirmed source-chain deposit that backs the refund. */
  source_chain_deposit_proof: SourceChainDepositProof;
  /** Absolute time after which the lock expired and the deposit became refund-eligible (ISO 8601). */
  lockExpiry: string;
  /** When the refund actually landed (ISO 8601). MUST be at/after lockExpiry. */
  refundedAfter: string;
  /** The refund transaction. */
  refund_tx: TankRefundTx;
  /** The shard quorum's signatures over the refund commitment. */
  shard_quorum_signatures: ShardSignature[];
}

/** Options bag — authoritative trust anchors are verifier-supplied here. */
export interface VerifyTankRefundOptions {
  /** Minimum DISTINCT, valid, AUTHORIZED shard signers required (majority-of-shard). */
  requiredQuorum: number;
  /** Total shard-set size, if known — lets the verifier check requiredQuorum is a true majority. */
  shardSetSize?: number;
  /**
   * The KNOWN, AUTHORIZED bridge shard signer pubkeys (hex). Only MEMBER signatures
   * count toward quorum (defeats forge-N-fresh-keys). OMITTED ⇒ indeterminate.
   */
  authorizedShardSet?: Iterable<string>;
  /**
   * AUTHORITATIVE ledger of deposit_ids already consumed by a prior RELEASE through
   * this bridge_id. A deposit present here that equals this refund's deposit means
   * the value was already released — a refund would double-pay → fail. Verifier-
   * controlled state, never read from the evidence object (a producer would hide a
   * deposit it intends to double-pay). OMITTED ⇒ indeterminate (§7.5.1 — never 'pass').
   * Supply an empty array to assert "ledger known, deposit not yet released".
   */
  consumedDepositLedger?: readonly string[];
}

/* -------------------------------------------------------------------------- */
/*  Commitment                                                                 */
/* -------------------------------------------------------------------------- */

/** The deterministic tuple every shard signs for a tank refund. */
export interface TankRefundCommitment {
  bridge_id: string;
  amount: { amount: string; asset: string };
  refundRecipient: string;
  deposit_id: string;
  lockExpiry: string;
  refundedAfter: string;
  refund_tx: string;
}

/** Build the canonical commitment for an evidence object (price re-normalised). */
export function buildTankRefundCommitment(evidence: TankRefundEvidence): TankRefundCommitment {
  return {
    bridge_id: evidence.bridge_id,
    amount: { amount: canonicalPrice(evidence.amount), asset: evidence.amount.asset },
    refundRecipient: evidence.refundRecipient,
    deposit_id: evidence.source_chain_deposit_proof.deposit_id,
    lockExpiry: evidence.lockExpiry,
    refundedAfter: evidence.refundedAfter,
    refund_tx: evidence.refund_tx.txHash,
  };
}

/** signed_bytes body = utf8( sha256-hex( JCS(commitment) ) ). */
function commitmentBody(commitment: TankRefundCommitment): Uint8Array {
  return new TextEncoder().encode(jcsHashHex(commitment));
}

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * True iff the canonical amount is strictly positive — neither negative (leading '-')
 * nor zero (/^0(\.0*)?$/). A refund amount MUST be > 0: a negative or zero amount is
 * contradictory value evidence (and a negative amount that "matches" a negative
 * deposit-proof amount would otherwise pass the equality check).
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
 * ISO-8601 strict-before, mirroring htlc-evidence.ts::isStrictlyBefore. Returns null
 * on an unparseable timestamp (caller treats as reject — fail closed).
 */
function isStrictlyBefore(a: string, b: string): boolean | null {
  const ta = Date.parse(a);
  const tb = Date.parse(b);
  if (Number.isNaN(ta) || Number.isNaN(tb)) return null;
  return ta < tb;
}

/* -------------------------------------------------------------------------- */
/*  Verify                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Verify a liquidity-tank refund under negative-evidence rules. REJECTS unless ALL
 * hold (returns on the FIRST failed guarantee):
 *   (a) confirmed deposit binds to bridge_id + amount;
 *   (b) refundedAfter is NOT strictly before lockExpiry (refund waited for expiry —
 *       mirrors HTLC assertRefundAfterTimelock);
 *   (c) deposit_id NOT in the authoritative consumedDepositLedger (no double-pay);
 *   (d) refundRecipient EQUALS the deposit's original depositor;
 *   (e) >= requiredQuorum DISTINCT AUTHORIZED valid shard signers signed the refund.
 *
 * Missing authoritative state (no consumedDepositLedger / no authorizedShardSet) ⇒
 * decision='indeterminate' — never coerced to 'pass' (§7.5.1).
 */
export function verifyTankRefund(
  evidence: TankRefundEvidence,
  options: VerifyTankRefundOptions
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
    return fail(`requiredQuorum must be a positive integer (got ${requiredQuorum}) — a refund cannot be authorised by zero shards`);
  }
  if (shardSetSize !== undefined) {
    const majority = Math.floor(shardSetSize / 2) + 1;
    if (requiredQuorum < majority) {
      return fail(`requiredQuorum=${requiredQuorum} is not a majority of shardSetSize=${shardSetSize} (need >= ${majority})`);
    }
  }

  // Reject-first: the refund amount MUST be a positive monetary value. A negative or
  // zero amount is contradictory value evidence — and must be rejected BEFORE the
  // priceEqual compare, so a negative amount can never reach (and pass) it.
  if (!isPositiveAmount(evidence.amount)) {
    return fail(
      `refund amount must be a positive value (got "${evidence.amount.amount} ${evidence.amount.asset}") ` +
      `— a refund cannot return a negative or zero amount`
    );
  }

  const proof = evidence.source_chain_deposit_proof;

  /* ---- Guarantee (a): confirmed deposit that binds to bridge_id + amount ---- */

  if (!proof) {
    return fail('no source_chain_deposit_proof — a refund with no inbound deposit mints value');
  }
  if (!proof.confirmed || !proof.confirmedAt) {
    return fail(
      `source-chain deposit is not confirmed (confirmed=${proof.confirmed}, confirmedAt=${proof.confirmedAt ?? 'absent'}) ` +
      `— an unconfirmed deposit MUST NOT back a refund`
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
      `deposit proof bridge_id="${proof.bridge_id}" does not bind to refund bridge_id="${evidence.bridge_id}"`
    );
  }
  if (!isPositiveAmount(proof.amount)) {
    return fail(
      `deposit proof amount must be a positive value (got "${proof.amount.amount} ${proof.amount.asset}") ` +
      `— a negative or zero deposit amount cannot back a refund`
    );
  }
  if (!priceEqual(proof.amount, evidence.amount)) {
    return fail(
      `deposit amount (${proof.amount.amount} ${proof.amount.asset}) does not match refund amount ` +
      `(${evidence.amount.amount} ${evidence.amount.asset})`
    );
  }

  /* ---- Guarantee (b): refund at/after lockExpiry (mirrors assertRefundAfterTimelock) ---- */

  const before = isStrictlyBefore(evidence.refundedAfter, evidence.lockExpiry);
  if (before === null) {
    return fail(
      `unparseable timestamp in refund-after-expiry check (refundedAfter="${evidence.refundedAfter}", ` +
      `lockExpiry="${evidence.lockExpiry}")`
    );
  }
  if (before) {
    return fail(
      `refund-before-expiry: refundedAfter=${evidence.refundedAfter} is strictly before lockExpiry=${evidence.lockExpiry} ` +
      `— a refund MUST wait until at/after the lock expires (mirrors HTLC assertRefundAfterTimelock)`
    );
  }

  /* ---- Guarantee (d): refundRecipient equals the deposit's original depositor ---- */

  // Structural binding. The deposit proof MUST carry its original depositor, and the
  // refund MUST pay exactly that address — a refund returns value to whoever deposited
  // it. Absence of `depositor` means we cannot prove the binding → fail closed.
  if (proof.depositor === undefined || proof.depositor.length === 0) {
    return fail(
      `deposit proof has no original depositor — cannot prove refundRecipient returns value to the depositor`
    );
  }
  if (evidence.refundRecipient !== proof.depositor) {
    return fail(
      `refundRecipient="${evidence.refundRecipient}" does not equal the deposit's original depositor="${proof.depositor}" ` +
      `— a refund MUST return value to whoever deposited it`
    );
  }

  /* ---- Guarantee (c): not already consumed by a release (AUTHORITATIVE ledger) ---- */

  // The consumed ledger is the one fact a malicious producer would hide to double-pay
  // (refund a deposit already released). With NO authoritative ledger we cannot assert
  // the not-already-released guarantee → indeterminate (§7.5.1 — never 'pass').
  if (consumedDepositLedger === undefined) {
    return indeterminate(
      `no authoritative consumedDepositLedger supplied for bridge_id="${evidence.bridge_id}" ` +
      `— cannot assert deposit_id="${proof.deposit_id}" was not already released (double-pay guarantee unprovable)`
    );
  }
  if (consumedDepositLedger.includes(proof.deposit_id)) {
    return fail(
      `deposit_id="${proof.deposit_id}" is already in the authoritative consumed ledger for bridge_id="${evidence.bridge_id}" ` +
      `— refund-after-release double-pay`
    );
  }

  /* ---- Guarantee (e): majority-of-shard distinct AUTHORIZED signatures ---- */

  const sigs = evidence.shard_quorum_signatures;
  if (!sigs || sigs.length === 0) {
    return fail('shard_quorum_signatures is empty — no shard authorised the refund');
  }

  if (authorizedShards === undefined) {
    return indeterminate(
      `no authorizedShardSet supplied for bridge_id="${evidence.bridge_id}" — cannot establish that signers ` +
      `are registered shards (majority-of-shard guarantee unprovable; a valid signature is not an authorised one)`
    );
  }

  const commitment = buildTankRefundCommitment(evidence);
  const body = commitmentBody(commitment);

  const validSigners = new Set<string>();
  let rejectedNonMembers = 0;
  for (const s of sigs) {
    let pubKey: Uint8Array;
    try {
      pubKey = hexToBytes(s.signer);
    } catch {
      continue;
    }
    if (pubKey.length !== 32) continue;
    let sig: Uint8Array;
    try {
      sig = hexToBytes(s.signature);
    } catch {
      continue;
    }
    if (sig.length !== 64) continue;
    const ok = edVerify(PATHOS_EXTENSION_SEPARATORS.TANK_REFUND_ATTESTATION, sig, body, pubKey);
    if (!ok) continue;
    const normSigner = bytesToHex(pubKey).toLowerCase();
    if (!authorizedShards.has(normSigner)) {
      rejectedNonMembers++;
      continue;
    }
    validSigners.add(normSigner);
  }

  if (validSigners.size < requiredQuorum) {
    return fail(
      `sub-quorum: ${validSigners.size} distinct AUTHORIZED valid shard signer(s) over the tank-refund commitment ` +
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
      `${commitment.amount.amount} ${commitment.amount.asset}; refundedAfter=${evidence.refundedAfter} >= lockExpiry=${evidence.lockExpiry}; ` +
      `refundRecipient == depositor; deposit not in consumed ledger; ` +
      `${validSigners.size}-of-${sigs.length} distinct AUTHORIZED valid shard signatures (>= ${requiredQuorum} required)`,
  };
}

/* -------------------------------------------------------------------------- */
/*  Helper for producers / tests — sign the commitment with a shard key.       */
/* -------------------------------------------------------------------------- */

/** Produce one shard's hex signature over a tank-refund commitment. */
export function signTankRefundCommitment(
  commitment: TankRefundCommitment,
  shardPrivKey: Uint8Array,
  shardPubKey: Uint8Array
): ShardSignature {
  const sig = edSign(PATHOS_EXTENSION_SEPARATORS.TANK_REFUND_ATTESTATION, commitmentBody(commitment), shardPrivKey);
  return { signer: bytesToHex(shardPubKey), signature: bytesToHex(sig) };
}
