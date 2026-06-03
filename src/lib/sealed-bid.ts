/**
 * DACS-3 Negotiate — sealed-envelope SealedBid commitment scheme
 *
 * Spec source: DACS v0.7 §8 (Negotiate) + DACS-1..5 v0.1.
 * Backs PR #10 (define the SealedBid body) and finding #19 (salt / commitment).
 *
 * THE PROBLEM (finding #19). A sealed-bid auction needs a commitment that:
 *   - hides the bid until reveal (hiding), and
 *   - cannot be opened to a different bid later (binding).
 * A bare sha256(JCS(bid)) is binding but NOT hiding: the bid space is small and
 * low-entropy (round prices, a handful of deliverables), so an adversary can
 * brute-force the preimage and read the sealed bid before reveal. The fix is a
 * salted commitment — a high-entropy nonce mixed into the hash so the preimage
 * space is computationally unsearchable.
 *
 * COMMITMENT CONSTRUCTION (this module is the normative reference for §8 sealed bids):
 *
 *   bidHash := sha256-hex(  JCS(bid)  ||  0x00  ||  salt  )
 *
 * where:
 *   - JCS(bid)  is the RFC 8785 canonical UTF-8 byte serialization of the SealedBid
 *               (via src/jcs.ts — the same canonicalizer every other DACS artifact uses).
 *   - 0x00      is a single explicit domain/separator byte between message and salt.
 *               Without it, (JCS="ab", salt="c") and (JCS="abc", salt="") would collide.
 *               The separator byte makes the encoding injective in (JCS(bid), salt).
 *   - salt      is the raw salt bytes, REQUIRED to be >= 16 bytes (128 bits) of entropy
 *               per finding #19. Shorter salts are rejected — a weak salt re-opens the
 *               brute-force hole this scheme exists to close.
 *
 * This is NOT an ed25519 signature, so it does not go through src/lib/sign.ts or the
 * §7.7 domain-separator registry. It is a hash commitment. The eventual on-chain OPEN
 * of the envelope IS signed (DOMAIN_SEPARATORS.SEALED_ENVELOPE_OPEN over the
 * envelopeContentHash, i.e. over this bidHash) — but that signing step lives in the
 * channel-message layer, not here. This module's job is solely commit + verifyReveal.
 *
 * Determinism: JCS canonicalization + a fixed salt encoding means (same bid, same salt)
 * always yields the same bidHash on every implementation. That determinism is what the
 * test vectors lock in for the independent third-party conformance check.
 */

import { sha256 } from '@noble/hashes/sha2';
import { jcsCanonical } from '../jcs.js';

/**
 * A price term on a SealedBid.
 *
 * src/types/settle.ts does not exist in this reference impl yet, so we define a
 * minimal local PriceTerm matching the DACS v0.1 shape. When the DACS-4 Settle
 * types land, this should be re-exported from there and this local copy removed.
 */
export interface PriceTerm {
  /** Numeric amount as a decimal string to avoid float drift in canonical form (e.g. "1000.00"). */
  amount: string;
  /** Currency / unit code (e.g. "USDC", "USD", "DEM"). */
  currency: string;
  /** Optional payment substrate hint (e.g. "demos", "evm:8453"). */
  substrate?: string;
}

/**
 * A sealed bid body, per PR #10. The committed object.
 *
 * Only the fields here are part of the commitment — whatever is JCS-canonicalized
 * is what the bidHash binds to. Extra negotiation context that should NOT be hidden
 * (e.g. the auction id) belongs in the channel envelope, not in the SealedBid.
 */
export interface SealedBid {
  /** The bid price. */
  price: PriceTerm;
  /** Optional free-form description of what is being offered/delivered. */
  deliverable?: string;
  /** Optional structured terms (SLAs, deadlines, etc.). */
  terms?: Record<string, unknown>;
}

/** Minimum salt length in bytes (128 bits) per finding #19. */
export const MIN_SALT_BYTES = 16;

/** The single separator byte between JCS(bid) and salt. Makes the encoding injective. */
const SALT_SEPARATOR_BYTE = 0x00;

/**
 * A sealed-bid commitment. `bidHash` is published during the commit phase;
 * `saltHex` + the revealed bid are published during the reveal phase.
 *
 * `saltHex` is included here so the committer can persist the salt alongside the
 * commitment it must later reveal. It MUST NOT be transmitted during the commit
 * phase — doing so defeats hiding. It is revealed only at open time.
 */
export interface SealedBidCommitment {
  v: 'dacs-3-sealed-bid:0.1';
  /** sha256-hex( JCS(bid) || 0x00 || salt ) — the public commitment. */
  bidHash: string;
  /** Hex-encoded salt, >= 16 bytes. Held private until reveal. */
  saltHex: string;
}

/** Bytes → lowercase hex (no 0x prefix). */
function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

/** Lowercase-hex → bytes. Strict: rejects odd length and non-hex characters. */
function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error(`invalid salt hex length: ${clean.length}`);
  if (!/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error('invalid salt hex: non-[0-9a-fA-F] character in input');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Build the exact preimage bytes the commitment hashes over:
 *
 *   JCS(bid) || 0x00 || salt
 *
 * Pulled out so commit and verifyReveal hash identical bytes and tests can assert
 * the construction directly.
 */
function buildCommitmentPreimage(jcsBytes: Uint8Array, salt: Uint8Array): Uint8Array {
  const out = new Uint8Array(jcsBytes.length + 1 + salt.length);
  out.set(jcsBytes, 0);
  out[jcsBytes.length] = SALT_SEPARATOR_BYTE;
  out.set(salt, jcsBytes.length + 1);
  return out;
}

/**
 * JCS-canonicalize a SealedBid to UTF-8 bytes.
 *
 * Delegates to the shared §7.2-conformant canonicalizer (`src/jcs.ts`) so sealed-bid
 * commitments match the rest of the codebase byte-for-byte — NFC normalisation,
 * safe-integer enforcement, and JSON value-omission all apply. An NFC/decomposed bid
 * MUST produce the same bidHash as its precomposed twin.
 */
function jcsBid(bid: SealedBid): Uint8Array {
  return jcsCanonicalLocal(bid);
}

function jcsCanonicalLocal(value: unknown): Uint8Array {
  return jcsCanonical(value);
}

/**
 * Commit to a SealedBid with a caller-supplied salt.
 *
 * @param bid   the SealedBid body to commit to.
 * @param salt  >= 16 bytes of cryptographically random salt. The caller is
 *              responsible for generating it from a CSPRNG; this function only
 *              enforces the length floor (finding #19).
 * @returns the commitment { bidHash, saltHex }. Publish ONLY bidHash at commit time.
 *
 * Throws if salt is shorter than MIN_SALT_BYTES.
 */
export function commitSealedBid(bid: SealedBid, salt: Uint8Array): SealedBidCommitment {
  if (salt.length < MIN_SALT_BYTES) {
    throw new Error(
      `salt too short: ${salt.length} bytes; finding #19 requires >= ${MIN_SALT_BYTES} bytes (128 bits) of entropy`
    );
  }
  const jcsBytes = jcsBid(bid);
  const preimage = buildCommitmentPreimage(jcsBytes, salt);
  const bidHash = bytesToHex(sha256(preimage));
  return {
    v: 'dacs-3-sealed-bid:0.1',
    bidHash,
    saltHex: bytesToHex(salt),
  };
}

/**
 * Verify a reveal against a prior commitment.
 *
 * Recomputes sha256-hex( JCS(revealedBid) || 0x00 || salt ) and compares it to the
 * committed bidHash in constant-ish time (length-checked exact string compare on hex).
 *
 * Returns true iff the revealed bid + salt reproduce the committed hash exactly.
 * A mutated bid, a wrong salt, or a too-short salt all return false.
 *
 * @param commitment   the bidHash committed earlier (hex string, with or without 0x).
 *                     Either a SealedBidCommitment or the raw bidHash hex is accepted.
 * @param revealedBid  the bid the committer now claims they committed to.
 * @param salt         the salt the committer now reveals. Accepts Uint8Array or hex string.
 */
export function verifyReveal(
  commitment: SealedBidCommitment | string,
  revealedBid: SealedBid,
  salt: Uint8Array | string
): boolean {
  const committedHash = (typeof commitment === 'string' ? commitment : commitment.bidHash)
    .replace(/^0x/, '')
    .toLowerCase();

  let saltBytes: Uint8Array;
  try {
    saltBytes = typeof salt === 'string' ? hexToBytes(salt) : salt;
  } catch {
    return false;
  }

  // A salt below the floor could never have produced a valid commitment from
  // commitSealedBid, so reject it rather than computing a hash that can't match
  // an honestly-generated commitment.
  if (saltBytes.length < MIN_SALT_BYTES) return false;

  let recomputed: string;
  try {
    const jcsBytes = jcsBid(revealedBid);
    const preimage = buildCommitmentPreimage(jcsBytes, saltBytes);
    recomputed = bytesToHex(sha256(preimage));
  } catch {
    return false;
  }

  // Exact, length-guarded comparison. Hex strings of equal length compared char-wise.
  if (recomputed.length !== committedHash.length) return false;
  let diff = 0;
  for (let i = 0; i < recomputed.length; i++) {
    diff |= recomputed.charCodeAt(i) ^ committedHash.charCodeAt(i);
  }
  return diff === 0;
}
