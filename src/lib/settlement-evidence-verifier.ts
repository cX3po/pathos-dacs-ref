/**
 * Negative-evidence bridge-release verifier — the two yellowpaper guarantees
 * the v0.2 escrow code skips.
 *
 * Spec source: DACS v0.7 + DACS-1..5 v0.1, §9 (Settle) — cross-substrate bridge
 * release. PATH-OS Labs extension to the §9.5 SettlementEvidence family; NOT part
 * of the normative DACS v1 §7.7 closed registry (its domain separator lives in
 * PATHOS_EXTENSION_SEPARATORS, so the "exactly 17 spec separators" invariant stays
 * green).
 *
 * The gap this closes:
 *   A bridge release moves value on the DESTINATION chain because the buyer made a
 *   deposit on the SOURCE chain. The escrow code today emits a release and anchors
 *   it — but it never proves, on the negative side, that:
 *     (a) a CONFIRMED source-chain deposit actually backs this release, and that
 *         deposit binds to the SAME bridge_id + amount the release pays out, and
 *     (b) a MAJORITY of the bridge shard set signed the release (not one node, not
 *         a replayed signature, not the same signer counted twice).
 *   Without (a) a release can mint value with no inbound deposit. Without (b) a
 *   single compromised/relaying node can authorise a release unilaterally — the
 *   exact single-node-relay trust gap cross-vps-attest.ts closes for web2 reads,
 *   here applied to value movement.
 *
 * This verifier is NEGATIVE-evidence-first: it REJECTS by default and only returns
 * { ok:true, decision:'pass' } when every guarantee is positively established. A
 * correct implementation MUST reject:
 *   - a sub-quorum release (single signer where majority is required),
 *   - a release with no confirmed deposit proof,
 *   - a deposit double-confirmed against the same bridge_id (replay / double-spend),
 *   - an expire-then-confirm race (the deposit confirmed only AFTER the bridge
 *     deposit window closed — i.e. the release raced a refund-eligible deposit),
 *   - a deposit whose bound bridge_id/amount does not match the release.
 *
 * Double-spend ledger is AUTHORITATIVE, never evidence-supplied. The set of
 * already-consumed deposit_ids is the one fact the evidence producer must NOT be
 * trusted to report — a malicious producer would simply omit its own deposit from
 * a self-supplied ledger to replay it. The ledger therefore arrives through
 * VerifyBridgeReleaseOptions (verifier-controlled state), and if NO authoritative
 * ledger is supplied the verifier CANNOT assert the not-already-consumed guarantee:
 * it returns decision='indeterminate' (§7.5.1 three-state — NEVER coerced to 'pass').
 *
 * Signed-bytes discipline (repo invariant, mirrors htlc-evidence.ts):
 *   signed_bytes := domain_separator || utf8( sha256-hex( JCS(releaseCommitment) ) )
 * where releaseCommitment is the deterministic { bridge_id, amount, deposit_id,
 * release_tx } tuple every shard signs. Signing the COMMITMENT (not just the
 * bridge_id) is what makes a signature non-replayable across amounts/releases.
 *
 * decision ∈ {'pass','fail','indeterminate'} is never coerced (sibling to §7.5.1).
 */

import { jcsHashHex } from '../jcs.js';
import { sign as edSign, verify as edVerify } from './sign.js';
import { PATHOS_EXTENSION_SEPARATORS } from '../domain-sep.js';
import { hexToBytes, bytesToHex } from './verify-bundle.js';
import { canonicalPrice, type PriceTerm } from '../types/settle.js';

/* -------------------------------------------------------------------------- */
/*  Types — self-contained                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Proof that a deposit landed on the SOURCE chain and was confirmed by the bridge.
 *
 * `confirmed` is the load-bearing negative-evidence flag: an UNCONFIRMED proof
 * (pending, observed-but-not-final) MUST NOT back a release. `confirmations` /
 * `requiredConfirmations` make the confirmation auditable rather than asserted.
 *
 * The binding fields — `bridge_id` and `amount` — let the verifier prove the
 * deposit is for THIS release and not some other (a) replayed or (b) cheaper
 * deposit being reused to authorise a larger payout.
 */
export interface SourceChainDepositProof {
  /** Stable id for this deposit on the source chain (e.g. "<chain>:<txHash>:<logIndex>"). */
  deposit_id: string;
  /** Source chain / substrate id (opaque, e.g. "eip155:8453", "demos"). */
  source_chain: string;
  /** Source-chain deposit transaction hash (hex; compared as a string). */
  deposit_tx: string;
  /** The bridge this deposit was made into — MUST equal the release's bridge_id. */
  bridge_id: string;
  /** The deposited amount — MUST equal (canonically) the release amount. */
  amount: PriceTerm;
  /** True iff the bridge considers this deposit final/confirmed. Default-reject when false. */
  confirmed: boolean;
  /** Observed confirmation depth (informational + auditable). */
  confirmations?: number;
  /** Confirmation depth the bridge requires before a release may be authorised. */
  requiredConfirmations?: number;
  /** When the deposit was first observed on the source chain (ISO 8601). */
  observedAt: string;
  /** When the deposit reached confirmed/final status (ISO 8601). Absent ⇒ not confirmed. */
  confirmedAt?: string;
  /**
   * Absolute time after which the bridge's deposit-acceptance window closes and the
   * deposit becomes refund-eligible (ISO 8601). A confirmation that lands at/after
   * this deadline is an expire-then-confirm RACE: the release would pay out a
   * deposit the source side may already be refunding.
   */
  depositWindowExpiry?: string;
}

/** One shard's signature over the bridge-release commitment. */
export interface ShardSignature {
  /** The shard signer's ed25519 public key (hex). Distinctness is keyed on this. */
  signer: string;
  /** ed25519 signature (hex) over the domain-separated release commitment. */
  signature: string;
}

/** The destination-chain release the shard quorum is authorising. */
export interface BridgeReleaseTx {
  /** Destination chain / substrate id (opaque). */
  dest_chain: string;
  /** Destination-chain release transaction hash (hex; compared as a string). */
  release_tx: string;
  /** Recipient address on the destination chain (opaque). */
  recipient: string;
  /** When the release landed / is proposed (ISO 8601). */
  releasedAt: string;
}

/**
 * A bridge release, plus the negative evidence required to trust it.
 *
 * `bridge_id` + `amount` are the release's identity; the deposit proof MUST bind to
 * both, and ≥ requiredQuorum DISTINCT shard signers MUST sign the commitment.
 */
export interface BridgeReleaseEvidence {
  v: 'pathos-bridge-release-evidence:0.1';
  /** Job/session this release belongs to (matches the DACS-5 bundle jobId). */
  jobId: string;
  /** The bridge instance authorising the release. */
  bridge_id: string;
  /** The amount being released (decimal-string PriceTerm — finding #27, no floats). */
  amount: PriceTerm;
  /** The confirmed source-chain deposit that backs the release. */
  source_chain_deposit_proof: SourceChainDepositProof;
  /** The shard quorum's signatures over the release commitment. */
  shard_quorum_signatures: ShardSignature[];
  /** The destination-chain release transaction. */
  release_tx: BridgeReleaseTx;
}

/** Options bag — at minimum the majority threshold the caller demands. */
export interface VerifyBridgeReleaseOptions {
  /**
   * Minimum number of DISTINCT, valid shard signers required (majority-of-shard).
   * The caller computes this from the shard-set size (e.g. floor(N/2)+1).
   */
  requiredQuorum: number;
  /** Total shard-set size, if known — lets the verifier sanity-check requiredQuorum is a true majority. */
  shardSetSize?: number;
  /**
   * The KNOWN, AUTHORIZED bridge shard signer pubkeys (hex). Only signatures whose
   * signer is a MEMBER of this set count toward `requiredQuorum`; a cryptographically
   * valid signature from a NON-member is rejected (does NOT count). This closes the
   * Codex-flagged hole where quorum counted "any distinct valid key" — an attacker
   * could otherwise mint a quorum by generating N fresh keypairs and signing the
   * commitment with each. Authorisation is not "the signature verifies"; it is
   * "the signature verifies AND the signer is a registered shard".
   *
   * Membership is matched on the normalised (lower-cased) 32-byte hex pubkey, so a
   * member listed in mixed case still matches its lower-cased signature entry.
   *
   * If this is OMITTED, the verifier cannot establish that signers are authorised
   * shards and MUST return decision='indeterminate' (never 'pass') — same §7.5.1
   * three-state discipline as the consumed-deposit ledger: an unprovable trust
   * property is NEVER coerced to a pass.
   */
  authorizedShardSet?: Iterable<string>;
  /**
   * AUTHORITATIVE ledger of deposit_ids already consumed by a prior release through
   * this bridge_id. This is verifier-controlled state (NOT supplied by the evidence
   * object), because the producer cannot be trusted to disclose a deposit it intends
   * to replay. A deposit_id present here that equals this release's deposit means the
   * deposit is being DOUBLE-confirmed / double-spent → fail.
   *
   * If this is OMITTED, the verifier cannot assert the not-already-consumed
   * guarantee and MUST return decision='indeterminate' (never 'pass'). Supply an
   * empty array to assert "the authoritative ledger is known and this deposit has
   * not been consumed".
   */
  consumedDepositLedger?: readonly string[];
}

/** VerifyResult-style outcome (sibling to types/verify-result.ts + cross-vps-attest.ts). */
export interface VerifyResult {
  ok: boolean;
  decision: 'pass' | 'fail' | 'indeterminate';
  reason: string;
}

/* -------------------------------------------------------------------------- */
/*  Commitment                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * The deterministic tuple every shard signs. Binding all four fields means a
 * signature authorising release R for amount A through bridge B against deposit D
 * cannot be replayed to authorise any release that differs in ANY of those.
 */
export interface ReleaseCommitment {
  bridge_id: string;
  /** Canonical decimal amount string + asset (finding #27). */
  amount: { amount: string; asset: string };
  deposit_id: string;
  release_tx: string;
}

/** Build the canonical commitment for an evidence object (price re-normalised). */
export function buildReleaseCommitment(evidence: BridgeReleaseEvidence): ReleaseCommitment {
  return {
    bridge_id: evidence.bridge_id,
    amount: { amount: canonicalPrice(evidence.amount), asset: evidence.amount.asset },
    deposit_id: evidence.source_chain_deposit_proof.deposit_id,
    release_tx: evidence.release_tx.release_tx,
  };
}

/** signed_bytes body = utf8( sha256-hex( JCS(commitment) ) ) — same audit-trail discipline as htlc-evidence.ts. */
function commitmentBody(commitment: ReleaseCommitment): Uint8Array {
  return new TextEncoder().encode(jcsHashHex(commitment));
}

/* -------------------------------------------------------------------------- */
/*  Verify                                                                     */
/* -------------------------------------------------------------------------- */

/** Compare two PriceTerms by canonical amount + asset (finding #27 — no float drift). */
function priceEqual(a: PriceTerm, b: PriceTerm): boolean {
  if (a.asset !== b.asset) return false;
  try {
    return canonicalPrice(a) === canonicalPrice(b);
  } catch {
    return false;
  }
}

/** ISO-8601 strict-before. Returns null on an unparseable timestamp (caller treats as reject). */
function strictlyBefore(a: string, b: string): boolean | null {
  const ta = Date.parse(a);
  const tb = Date.parse(b);
  if (Number.isNaN(ta) || Number.isNaN(tb)) return null;
  return ta < tb;
}

/**
 * Verify a bridge release under negative-evidence rules. REJECTS unless:
 *   (a) a CONFIRMED source-chain deposit proof is present AND binds to the
 *       release's bridge_id + amount, is not double-confirmed, and did not
 *       confirm in an expire-then-confirm race; AND
 *   (b) ≥ requiredQuorum DISTINCT valid shard signers signed the release
 *       commitment (majority-of-shard).
 *
 * Returns { ok:false, decision:'fail', reason } on the FIRST failed guarantee so
 * the caller sees exactly which negative-evidence check rejected the release.
 *
 * If `options.consumedDepositLedger` is omitted, the double-spend guarantee cannot
 * be asserted and the verifier returns { ok:false, decision:'indeterminate' } —
 * never 'pass'. Pass an empty array to assert a known, empty authoritative ledger.
 */
export function verifyBridgeRelease(
  evidence: BridgeReleaseEvidence,
  options: VerifyBridgeReleaseOptions
): VerifyResult {
  const fail = (reason: string): VerifyResult => ({ ok: false, decision: 'fail', reason });
  const indeterminate = (reason: string): VerifyResult => ({ ok: false, decision: 'indeterminate', reason });

  const { requiredQuorum, shardSetSize, consumedDepositLedger, authorizedShardSet } = options;

  // Normalise the authorized shard pubkey set once (lower-cased hex). undefined ⇒
  // the caller did not declare a shard set; we cannot establish that signers are
  // authorised shards (see the indeterminate guard in guarantee (b)).
  let authorizedShards: Set<string> | undefined;
  if (authorizedShardSet !== undefined) {
    authorizedShards = new Set<string>();
    for (const k of authorizedShardSet) {
      const norm = k.toLowerCase().replace(/^0x/, '');
      if (norm.length > 0) authorizedShards.add(norm);
    }
  }

  // Guard: a non-positive quorum would vacuously "pass" the majority check — reject the config.
  if (!Number.isInteger(requiredQuorum) || requiredQuorum < 1) {
    return fail(`requiredQuorum must be a positive integer (got ${requiredQuorum}) — a release cannot be authorised by zero shards`);
  }
  // If the shard-set size is known, requiredQuorum MUST be a strict majority of it.
  if (shardSetSize !== undefined) {
    const majority = Math.floor(shardSetSize / 2) + 1;
    if (requiredQuorum < majority) {
      return fail(`requiredQuorum=${requiredQuorum} is not a majority of shardSetSize=${shardSetSize} (need >= ${majority})`);
    }
  }

  const proof = evidence.source_chain_deposit_proof;

  /* ---- Guarantee (a): confirmed deposit that binds to bridge_id + amount ---- */

  if (!proof) {
    return fail('no source_chain_deposit_proof — a release with no inbound deposit mints value');
  }
  if (!proof.confirmed || !proof.confirmedAt) {
    return fail(
      `source-chain deposit is not confirmed (confirmed=${proof.confirmed}, confirmedAt=${proof.confirmedAt ?? 'absent'}) ` +
      `— an unconfirmed deposit MUST NOT back a release`
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
      `deposit proof bridge_id="${proof.bridge_id}" does not bind to release bridge_id="${evidence.bridge_id}"`
    );
  }
  if (!priceEqual(proof.amount, evidence.amount)) {
    return fail(
      `deposit amount (${proof.amount.amount} ${proof.amount.asset}) does not match release amount ` +
      `(${evidence.amount.amount} ${evidence.amount.asset})`
    );
  }

  // Double-confirm / double-spend: this deposit was already consumed by a prior
  // release through this same bridge_id. The ledger is AUTHORITATIVE (verifier-
  // supplied via options), never read from the evidence object — a producer cannot
  // be trusted to disclose a deposit it intends to replay. With no authoritative
  // ledger we cannot assert the not-already-consumed guarantee → indeterminate
  // (§7.5.1: NEVER coerce a missing-evidence state to 'pass').
  if (consumedDepositLedger === undefined) {
    return indeterminate(
      `no authoritative consumedDepositLedger supplied for bridge_id="${evidence.bridge_id}" ` +
      `— cannot assert deposit_id="${proof.deposit_id}" was not already consumed (double-spend guarantee unprovable)`
    );
  }
  if (consumedDepositLedger.includes(proof.deposit_id)) {
    return fail(
      `deposit_id="${proof.deposit_id}" is already in the authoritative consumed ledger for bridge_id="${evidence.bridge_id}" ` +
      `— double-confirm / double-spend`
    );
  }

  // Expire-then-confirm race: the confirmation landed at/after the deposit window
  // closed, so the source side may already treat the deposit as refund-eligible.
  if (proof.depositWindowExpiry !== undefined) {
    const before = strictlyBefore(proof.confirmedAt, proof.depositWindowExpiry);
    if (before === null) {
      return fail(
        `unparseable timestamp in deposit window check (confirmedAt="${proof.confirmedAt}", ` +
        `depositWindowExpiry="${proof.depositWindowExpiry}")`
      );
    }
    if (!before) {
      return fail(
        `expire-then-confirm race: deposit confirmedAt=${proof.confirmedAt} is not strictly before ` +
        `depositWindowExpiry=${proof.depositWindowExpiry} — release would pay out a refund-eligible deposit`
      );
    }
  }

  /* ---- Guarantee (b): majority-of-shard distinct valid signatures ---- */

  const sigs = evidence.shard_quorum_signatures;
  if (!sigs || sigs.length === 0) {
    return fail('shard_quorum_signatures is empty — no shard authorised the release');
  }

  // The authorized shard set is the trust anchor for quorum: a signature is only
  // authorising if it BOTH verifies AND comes from a registered shard. With no
  // declared set we cannot establish that any signer is an authorised shard, so the
  // majority-of-shard guarantee is unprovable → indeterminate (§7.5.1: an unprovable
  // trust property is NEVER coerced to 'pass'). This closes the Codex-flagged hole
  // where an attacker could mint a quorum from N fresh, self-generated keys.
  if (authorizedShards === undefined) {
    return indeterminate(
      `no authorizedShardSet supplied for bridge_id="${evidence.bridge_id}" — cannot establish that signers ` +
      `are registered shards (majority-of-shard guarantee unprovable; a valid signature is not an authorised one)`
    );
  }

  const commitment = buildReleaseCommitment(evidence);
  const body = commitmentBody(commitment);

  const validSigners = new Set<string>();
  let rejectedNonMembers = 0;
  for (const s of sigs) {
    let pubKey: Uint8Array;
    try {
      pubKey = hexToBytes(s.signer);
    } catch {
      // A malformed signer key is not a valid signer; skip it (negative-evidence:
      // do NOT count toward quorum). Continue so one bad entry can't mask others.
      continue;
    }
    if (pubKey.length !== 32) continue; // ed25519 pubkeys are 32 bytes
    let sig: Uint8Array;
    try {
      sig = hexToBytes(s.signature);
    } catch {
      continue;
    }
    if (sig.length !== 64) continue; // ed25519 signatures are 64 bytes
    const ok = edVerify(PATHOS_EXTENSION_SEPARATORS.BRIDGE_RELEASE_ATTESTATION, sig, body, pubKey);
    if (!ok) continue;
    const normSigner = bytesToHex(pubKey).toLowerCase();
    // AUTHORIZATION: a cryptographically valid signature from a NON-member shard is
    // rejected — it does NOT count toward quorum (defeats forge-N-fresh-keys).
    if (!authorizedShards.has(normSigner)) {
      rejectedNonMembers++;
      continue;
    }
    // DISTINCTness keyed on the normalised signer hex — the same authorised signer
    // signing twice counts ONCE (defeats sub-quorum-via-duplication).
    validSigners.add(normSigner);
  }

  if (validSigners.size < requiredQuorum) {
    return fail(
      `sub-quorum: ${validSigners.size} distinct AUTHORIZED valid shard signer(s) over the release commitment ` +
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
      `${commitment.amount.amount} ${commitment.amount.asset}; ` +
      `${validSigners.size}-of-${sigs.length} distinct AUTHORIZED valid shard signatures (>= ${requiredQuorum} required)`,
  };
}

/* -------------------------------------------------------------------------- */
/*  Helper for producers / tests — sign the commitment with a shard key.       */
/* -------------------------------------------------------------------------- */

/**
 * Produce one shard's hex signature over a release commitment with `shardPrivKey`,
 * recording `shardPubKey` (hex) as the signer. Mirrors the producer side a real
 * bridge shard runs; tests use it to mint valid (and, by withholding signers,
 * sub-quorum) attestation sets.
 */
export function signReleaseCommitment(
  commitment: ReleaseCommitment,
  shardPrivKey: Uint8Array,
  shardPubKey: Uint8Array
): ShardSignature {
  const sig = edSign(PATHOS_EXTENSION_SEPARATORS.BRIDGE_RELEASE_ATTESTATION, commitmentBody(commitment), shardPrivKey);
  return { signer: bytesToHex(shardPubKey), signature: bytesToHex(sig) };
}
