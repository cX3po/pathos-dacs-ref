/**
 * dacs-disclose — selective-disclosure CORE (claim commitments + audience-bound reveal).
 *
 * Spec source: `dacs-consent-selective-disclosure-spec-2026-06-07.md` §3 (mechanism),
 * §5 P1. Reference for the named follow-on the base spec disclaims (DACS-1 §11.2.7:
 * "v0.1 provides NO per-claim selective-disclosure mechanism"). PATH-OS Labs extension;
 * NOT part of the normative DACS v0.1 §B.7 closed registry — its two separators live in
 * DACS_X_EXTENSION_SEPARATORS (SIG-4 `dacs-x-` discipline, CORE.md:265).
 *
 * ============================ HONESTY / SCOPE (spec §4) =======================
 * This layer minimises SUPPORTING-claim disclosure ONLY. It does NOT, and MUST NOT be
 * claimed to:
 *   - hide the PRIMARY claim (`presentedBy` stays linkable — DACS-1 §11.2.7 is explicit);
 *   - provide unlinkability of any kind;
 *   - use ZK / L2PS / FHE / bridges / escrow (all on the no-go list — salted-hash +
 *     optional Merkle membership ONLY).
 * What it DOES give: a holder can prove a chosen claim is a MEMBER of an attester-vouched,
 * bundle-signed set (membership) whose plaintext was validated by the DACS-2 attester
 * (truth, via the `verifiedBy` reference that rides alongside — never replacing it), and
 * bind that proof to a SPECIFIC verifier + a fresh challenge so a captured reveal is
 * non-replayable and non-transferable outside its consent scope.
 *
 * ============================ MECHANISM (spec §3) ============================
 * 1. CLAIM COMMITMENT (attester-produced):
 *      commitment_i = sha256( "dacs-x-claim-commit:v1:" || salt_i || JCS(claim_i) )
 *    - salt_i is CSPRNG (crypto.randomBytes), >=128-bit, unique per claim, secret until
 *      reveal. This is what closes offline commitment-grinding on low-entropy claims
 *      (spec §3 salt discipline + Codex Q1).
 *    - the commitment is computed by the DACS-2 attester over the *validated* plaintext,
 *      so a holder cannot forge a commitment over an unvalidated claim (membership AND
 *      truth — spec §3 Codex MEDIUM fix). This module provides the commitment primitive;
 *      pairing it with a real DACS-2 VerifyResult is the caller's job (the bundle carries
 *      both the commitment set/root AND the existing `verifiedBy` refs).
 *
 * 2. BOUND SET (Merkle root over the commitment set):
 *      The bundle's signed canonical form carries a Merkle ROOT over the SORTED, DEDUPED
 *      commitment set — NOT the raw claims. A holder later proves membership of one
 *      commitment via a Merkle audit path against that signed root.
 *
 *      ---- COUNT-HIDING TRADEOFF (spec §3 / Q2) ----
 *      A flat signed set leaks the exact COUNT of claims (every commitment is visible in
 *      the bundle). A Merkle root leaks only the root hash; the verifier sees the count of
 *      DISCLOSED claims plus a tree DEPTH (so an *upper bound* log2(leaves), not the exact
 *      count). We choose the Merkle root: strictly stronger count-hiding for equal verify
 *      cost on the disclosed side, and it is the SD-style pattern §3 apprentices from.
 *      We pad-defend against the classic Merkle second-preimage / leaf-vs-node ambiguity by
 *      DOMAIN-SEPARATING leaf and internal hashes (0x00 / 0x01 prefixes, RFC 6962 style) and
 *      by DUPLICATING the last node on odd levels (documented, deterministic).
 *
 * 3. SELECTIVE REVEAL (audience/challenge-bound — spec §3 Codex HIGH fix):
 *      The verifier first supplies a fresh `nonce`, its `verifier_id`, and the relevant
 *      `consent_receipt_id`. The holder signs, per disclosed claim, with its presentation
 *      key:
 *        reveal_sig = ed25519_sign( presentationKey,
 *            "dacs-x-claim-reveal:v1:" || LEN-DELIMIT(verifier_id, consent_receipt_id,
 *                                                       nonce, expiry, commitment_i) )
 *      Disclosed artifact = (claim_i, salt_i, merkle_path, reveal_sig, challenge-context).
 *      The verifier recomputes commitment_i, checks membership against the signed root,
 *      AND verifies reveal_sig binds to ITS OWN verifier_id + the fresh nonce it issued +
 *      an unexpired window. A captured reveal is therefore bound to that audience and
 *      challenge — non-replayable, non-transferable.
 *
 * Length-delimited encoding (LEN-DELIMIT): every variable-length field in a hash/sign
 * preimage is prefixed by its 4-byte big-endian byte length, so no two distinct field
 * tuples can ever collide on the same concatenated preimage (field-boundary ambiguity is
 * a real signature-confusion vector). Applied to BOTH the reveal preimage AND the
 * commitment preimage (salt is fixed-length-discipline'd but we length-delimit anyway for
 * uniformity and future-proofing).
 */

import { randomBytes } from 'node:crypto';
import { sha256 } from '@noble/hashes/sha2';
import { jcsCanonical } from '../jcs.js';
import { sign as edSign, verify as edVerify } from './sign.js';
import { DACS_X_EXTENSION_SEPARATORS } from '../domain-sep.js';
import { hexToBytes, bytesToHex } from './verify-bundle.js';
import type { ClaimReference } from '../types/identity.js';

/* -------------------------------------------------------------------------- */
/*  Constants                                                                   */
/* -------------------------------------------------------------------------- */

/** Minimum salt entropy. Spec §3: >=128-bit. We default to 256-bit (32 bytes). */
export const MIN_SALT_BYTES = 16; // 128-bit floor (reject anything shorter on reveal)
export const DEFAULT_SALT_BYTES = 32; // 256-bit default for new commitments

const COMMIT_SEP = DACS_X_EXTENSION_SEPARATORS.CLAIM_COMMIT; // 'dacs-x-claim-commit:v1:'
const REVEAL_SEP = DACS_X_EXTENSION_SEPARATORS.CLAIM_REVEAL; // 'dacs-x-claim-reveal:v1:'

// RFC-6962-style Merkle domain separation: leaf hashes prefix 0x00, internal nodes 0x01.
// Prevents a leaf from being passed off as an internal node (second-preimage) and vice versa.
const MERKLE_LEAF_PREFIX = new Uint8Array([0x00]);
const MERKLE_NODE_PREFIX = new Uint8Array([0x01]);

/* -------------------------------------------------------------------------- */
/*  Types                                                                       */
/* -------------------------------------------------------------------------- */

/**
 * A claim plus its commitment, produced by the attester at verification time.
 * The attester KEEPS salt secret and hands `{claim, salt}` to the holder (out of band /
 * inside the bundle's private side); the PUBLIC bundle carries only `commitment` (folded
 * into the Merkle root). `verifiedByRef` is the OPAQUE pointer to the DACS-2 VerifyResult
 * that rides alongside (membership AND truth) — this module does not resolve it; it only
 * carries it so callers keep the two bound.
 */
export interface ClaimCommitment {
  /** The claim reference that was committed (kept by holder; revealed selectively). */
  claim: ClaimReference;
  /** CSPRNG salt, hex (no 0x). Secret until reveal. */
  salt: string;
  /** sha256( COMMIT_SEP || len(salt)||salt || len(JCS(claim))||JCS(claim) ), hex. */
  commitment: string;
  /**
   * Opaque reference to the DACS-2 VerifyResult that validated this claim's plaintext.
   * Rides ALONGSIDE the commitment (spec §3: do not replace verifiedBy). Carried, not
   * resolved, by this layer.
   */
  verifiedByRef?: string;
}

/** A Merkle audit path: sibling hashes (hex) from leaf to root, with each sibling's side. */
export interface MerklePathStep {
  /** Sibling node hash, hex. */
  sibling: string;
  /** Which side the sibling is on relative to the running hash. */
  side: 'left' | 'right';
}

/** The challenge context a verifier issues BEFORE a reveal (audience/challenge binding). */
export interface RevealChallenge {
  /** Stable identifier of the verifier this reveal is FOR (audience binding). */
  verifier_id: string;
  /** The consent record this disclosure happens under (spec §3 / P2 anchor). */
  consent_receipt_id: string;
  /** Fresh, single-use challenge the verifier generated (replay binding). */
  nonce: string;
  /** Absolute unix-ms after which this reveal is no longer valid (freshness window). */
  expiry: number;
}

/** A single disclosed claim — the artifact a holder hands a verifier. */
export interface DisclosedClaim {
  /** The revealed claim plaintext. */
  claim: ClaimReference;
  /** The salt that opens the commitment, hex. */
  salt: string;
  /** Merkle audit path proving `commitment` is a leaf of the signed root. */
  merkle_path: MerklePathStep[];
  /** ed25519 reveal signature over the audience-bound preimage, hex. */
  reveal_sig: string;
  /** The challenge context this reveal is bound to. */
  challenge: RevealChallenge;
}

/** Result of verifying one disclosed claim. Mirrors the repo VerifyResult shape. */
export interface DiscloseVerifyResult {
  ok: boolean;
  decision: 'pass' | 'fail';
  reason: string;
}

/* -------------------------------------------------------------------------- */
/*  Length-delimited preimage encoding                                         */
/* -------------------------------------------------------------------------- */

/** 4-byte big-endian length prefix for `b`. Rejects fields >= 2^32 bytes (not reachable). */
function lenPrefix(b: Uint8Array): Uint8Array {
  const n = b.length;
  if (n > 0xffffffff) throw new Error('disclose: field too long for 4-byte length prefix');
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

/** Concatenate fields, each as len(field)||field, into one unambiguous preimage. */
function lenDelimit(...fields: Uint8Array[]): Uint8Array {
  const parts: Uint8Array[] = [];
  let total = 0;
  for (const f of fields) {
    const lp = lenPrefix(f);
    parts.push(lp, f);
    total += lp.length + f.length;
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/* -------------------------------------------------------------------------- */
/*  1. Claim commitments (attester-produced)                                   */
/* -------------------------------------------------------------------------- */

/**
 * Build the commitment preimage body (the part AFTER the separator):
 *   len(salt)||salt || len(JCS(claim))||JCS(claim)
 * Returned WITHOUT the separator; `computeCommitment` prepends COMMIT_SEP before hashing.
 */
function commitmentPreimageBody(saltBytes: Uint8Array, claim: ClaimReference): Uint8Array {
  return lenDelimit(saltBytes, jcsCanonical(claim));
}

/**
 * commitment_i = sha256( COMMIT_SEP || len(salt)||salt || len(JCS(claim))||JCS(claim) ), hex.
 * The separator is part of the HASH PREIMAGE here (spec §3 form) — this is a commitment
 * hash, not an ed25519 signed_bytes, so we build the preimage directly rather than via
 * sign(). Domain-separating the commitment hash stops cross-protocol preimage reuse.
 */
export function computeCommitment(salt: string, claim: ClaimReference): string {
  const saltBytes = hexToBytes(salt); // strict hex; throws on garbage
  const preimage = new Uint8Array([...utf8(COMMIT_SEP), ...commitmentPreimageBody(saltBytes, claim)]);
  return bytesToHex(sha256(preimage));
}

/**
 * Attester-side: produce a ClaimCommitment over a VALIDATED claim. CSPRNG salt
 * (crypto.randomBytes), >= MIN_SALT_BYTES (default 256-bit). The caller (DACS-2 attester)
 * is responsible for having validated `claim` and for supplying the matching
 * `verifiedByRef`; this function only enforces the salt discipline + commitment math.
 *
 * @param claim          the validated claim reference
 * @param verifiedByRef  opaque DACS-2 VerifyResult reference riding alongside (spec §3)
 * @param saltBytesLen   salt length in bytes (>= MIN_SALT_BYTES; default DEFAULT_SALT_BYTES)
 */
export function attestClaimCommitment(
  claim: ClaimReference,
  verifiedByRef?: string,
  saltBytesLen: number = DEFAULT_SALT_BYTES
): ClaimCommitment {
  if (!Number.isInteger(saltBytesLen) || saltBytesLen < MIN_SALT_BYTES) {
    throw new Error(
      `disclose: salt must be >= ${MIN_SALT_BYTES} bytes (128-bit floor, spec §3) — got ${saltBytesLen}`
    );
  }
  const saltBytes = randomBytes(saltBytesLen); // CSPRNG — node crypto
  const salt = bytesToHex(new Uint8Array(saltBytes));
  const commitment = computeCommitment(salt, claim);
  return { claim, salt, commitment, verifiedByRef };
}

/* -------------------------------------------------------------------------- */
/*  2. Merkle commitment set (membership + count-hiding)                        */
/* -------------------------------------------------------------------------- */

/** sha256( 0x00 || leafHashBytes ) — leaf-domain-separated. Input is a commitment hash (bytes). */
function merkleLeaf(commitmentBytes: Uint8Array): Uint8Array {
  return sha256(new Uint8Array([...MERKLE_LEAF_PREFIX, ...commitmentBytes]));
}

/** sha256( 0x01 || left || right ) — internal-node-domain-separated. */
function merkleParent(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(new Uint8Array([...MERKLE_NODE_PREFIX, ...left, ...right]));
}

/**
 * Sort + dedupe a commitment set (hex) into a canonical leaf ordering. Sorting by the hex
 * string makes the root INDEPENDENT of the order commitments were added, so the same SET
 * always yields the same ROOT (deterministic membership). Dedupe drops exact duplicates.
 */
function canonicalLeaves(commitmentsHex: readonly string[]): Uint8Array[] {
  const uniqueSorted = Array.from(new Set(commitmentsHex.map((c) => c.toLowerCase()))).sort();
  return uniqueSorted.map((c) => merkleLeaf(hexToBytes(c)));
}

/**
 * Compute the Merkle root over a commitment SET. Odd levels duplicate the last node
 * (deterministic, documented). Empty set throws — a bundle with zero supporting-claim
 * commitments should carry no root rather than a degenerate one.
 */
export function computeCommitmentRoot(commitmentsHex: readonly string[]): string {
  let level = canonicalLeaves(commitmentsHex);
  if (level.length === 0) throw new Error('disclose: cannot build a Merkle root over an empty commitment set');
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i]!;
      const right = i + 1 < level.length ? level[i + 1]! : left; // odd: duplicate last
      next.push(merkleParent(left, right));
    }
    level = next;
  }
  return bytesToHex(level[0]!);
}

/**
 * Build the Merkle audit path for `targetHex` within the SET. Returns the sibling steps
 * leaf->root. Throws if the target is not a member of the set (a path can only be built
 * for a real leaf). Caller pairs the path with the commitment to prove membership.
 */
export function buildMerklePath(commitmentsHex: readonly string[], targetHex: string): MerklePathStep[] {
  const uniqueSorted = Array.from(new Set(commitmentsHex.map((c) => c.toLowerCase()))).sort();
  const target = targetHex.toLowerCase();
  let index = uniqueSorted.indexOf(target);
  if (index === -1) {
    throw new Error('disclose: target commitment is not a member of the set — no audit path exists');
  }
  let level = uniqueSorted.map((c) => merkleLeaf(hexToBytes(c)));
  const path: MerklePathStep[] = [];
  while (level.length > 1) {
    const isRightNode = index % 2 === 1;
    const siblingIndex = isRightNode ? index - 1 : index + 1;
    const sibling = siblingIndex < level.length ? level[siblingIndex]! : level[index]!; // odd: self-dup
    path.push({ sibling: bytesToHex(sibling), side: isRightNode ? 'left' : 'right' });
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i]!;
      const right = i + 1 < level.length ? level[i + 1]! : left;
      next.push(merkleParent(left, right));
    }
    level = next;
    index = Math.floor(index / 2);
  }
  return path;
}

/**
 * Verify a Merkle audit path: fold `commitmentHex` (as a leaf) up through `path` and check
 * the result equals `rootHex`. Pure membership check — no signature involved here.
 */
export function verifyMerklePath(commitmentHex: string, path: MerklePathStep[], rootHex: string): boolean {
  let running: Uint8Array;
  try {
    running = merkleLeaf(hexToBytes(commitmentHex));
  } catch {
    return false;
  }
  for (const step of path) {
    let sib: Uint8Array;
    try {
      sib = hexToBytes(step.sibling);
    } catch {
      return false;
    }
    running = step.side === 'left' ? merkleParent(sib, running) : merkleParent(running, sib);
  }
  return bytesToHex(running).toLowerCase() === rootHex.toLowerCase();
}

/* -------------------------------------------------------------------------- */
/*  3. Selective reveal — audience/challenge-bound                              */
/* -------------------------------------------------------------------------- */

/**
 * The reveal preimage BODY (after REVEAL_SEP), length-delimited so no two distinct
 * challenge tuples collide:
 *   len(verifier_id)||verifier_id || len(consent_receipt_id)||consent_receipt_id ||
 *   len(nonce)||nonce || len(expiry-ascii)||expiry-ascii || len(commitment)||commitment
 * `expiry` is encoded as its decimal ASCII (stable, no float/endianness ambiguity).
 */
function revealPreimageBody(challenge: RevealChallenge, commitmentHex: string): Uint8Array {
  return lenDelimit(
    utf8(challenge.verifier_id),
    utf8(challenge.consent_receipt_id),
    utf8(challenge.nonce),
    utf8(String(challenge.expiry)),
    utf8(commitmentHex.toLowerCase())
  );
}

/**
 * Holder-side: produce an audience/challenge-bound reveal for ONE claim.
 * reveal_sig = ed25519_sign( presentationKey, REVEAL_SEP || revealPreimageBody ).
 * The signature binds the disclosure to the verifier's id + the fresh nonce it issued +
 * the consent record + an expiry — so a captured reveal cannot be replayed to a different
 * verifier or after its window (spec §3 Codex HIGH fix). Uses the existing domain-separated
 * sign() (which prepends REVEAL_SEP and enforces emittable-separator discipline).
 *
 * @param commitment      the holder's ClaimCommitment (carries claim + salt + commitment)
 * @param merkle_path     audit path proving commitment ∈ signed root
 * @param challenge       the verifier-issued challenge context
 * @param presentationKey holder's ed25519 presentation private key (bundle presentation key)
 */
export function produceReveal(
  commitment: ClaimCommitment,
  merkle_path: MerklePathStep[],
  challenge: RevealChallenge,
  presentationKey: Uint8Array
): DisclosedClaim {
  const body = revealPreimageBody(challenge, commitment.commitment);
  const sig = edSign(REVEAL_SEP, body, presentationKey);
  return {
    claim: commitment.claim,
    salt: commitment.salt,
    merkle_path,
    reveal_sig: bytesToHex(sig),
    challenge,
  };
}

/** Options the verifier supplies to authoritatively check a disclosed claim. */
export interface VerifyDisclosedOptions {
  /** The bundle-signed Merkle root the commitment set was bound under (authoritative). */
  signedRoot: string;
  /** The holder's presentation PUBLIC key, hex (the key the bundle presentation is under). */
  presentationPubKey: string;
  /**
   * The verifier's OWN id. The reveal MUST bind to THIS id — a reveal carrying a different
   * verifier_id is a transfer attempt and fails (audience binding). Authoritative; never
   * read from the disclosed artifact.
   */
  expectedVerifierId: string;
  /**
   * The exact nonce THIS verifier issued for THIS challenge. The reveal MUST carry it — a
   * reveal under any other nonce is a replay and fails. Authoritative; never trusted from
   * the artifact. (Single-use enforcement — not re-accepting the same nonce twice — is the
   * caller's responsibility; this layer checks the bound nonce matches the issued one.)
   */
  expectedNonce: string;
  /**
   * Optional: the consent_receipt_id THIS verifier is operating under. When supplied, the
   * reveal MUST bind to it (consent-scope check). Omit to skip (membership+audience+freshness
   * still enforced).
   */
  expectedConsentReceiptId?: string;
  /** Current unix-ms (injectable for deterministic tests). Defaults to Date.now(). */
  now?: number;
}

/**
 * Verify ONE disclosed claim under audience/challenge binding. REJECTS unless ALL hold:
 *   (a) recomputed commitment_i == sha256(COMMIT_SEP || len(salt)||salt || len(JCS(claim))||JCS(claim));
 *   (b) commitment_i is a MEMBER of the signed Merkle root (audit-path fold);
 *   (c) the challenge binds to THIS verifier_id (audience) and THIS nonce (replay);
 *   (c2) if expectedConsentReceiptId supplied, the challenge binds to it (consent scope);
 *   (d) the reveal is UNEXPIRED (challenge.expiry > now);
 *   (e) reveal_sig verifies under the holder's presentation pubkey over the audience-bound
 *       preimage (REVEAL_SEP || revealPreimageBody(challenge, commitment_i)).
 *
 * Fails CLOSED on the FIRST failed guarantee. Returns {ok:false, decision:'fail'} — there is
 * no 'indeterminate' here: every input needed for a verdict is verifier-supplied.
 */
export function verifyDisclosedClaim(
  disclosed: DisclosedClaim,
  options: VerifyDisclosedOptions
): DiscloseVerifyResult {
  const fail = (reason: string): DiscloseVerifyResult => ({ ok: false, decision: 'fail', reason });
  const now = options.now ?? Date.now();

  // (c) audience binding — reject a reveal aimed at a different verifier BEFORE crypto work.
  if (disclosed.challenge.verifier_id !== options.expectedVerifierId) {
    return fail(
      `audience mismatch: reveal binds verifier_id="${disclosed.challenge.verifier_id}" ` +
      `but this verifier is "${options.expectedVerifierId}" — a captured reveal is non-transferable`
    );
  }
  // (c) replay binding — the nonce MUST be the one THIS verifier issued.
  if (disclosed.challenge.nonce !== options.expectedNonce) {
    return fail(
      `nonce mismatch: reveal binds nonce="${disclosed.challenge.nonce}" but this challenge issued ` +
      `"${options.expectedNonce}" — a captured reveal is non-replayable`
    );
  }
  // (c2) consent-scope binding — only when the verifier declares the scope.
  if (
    options.expectedConsentReceiptId !== undefined &&
    disclosed.challenge.consent_receipt_id !== options.expectedConsentReceiptId
  ) {
    return fail(
      `consent-scope mismatch: reveal binds consent_receipt_id="${disclosed.challenge.consent_receipt_id}" ` +
      `but this verifier operates under "${options.expectedConsentReceiptId}"`
    );
  }
  // (d) freshness — reject an expired reveal. expiry is an upper bound (exclusive).
  if (!Number.isFinite(disclosed.challenge.expiry) || now >= disclosed.challenge.expiry) {
    return fail(
      `reveal expired: now=${now} >= expiry=${disclosed.challenge.expiry} — outside the freshness window`
    );
  }

  // (a) recompute the commitment from the revealed (claim, salt). A wrong salt or a
  // tampered claim yields a different commitment, breaking membership below.
  if (disclosed.salt.length === 0 || !/^[0-9a-fA-F]+$/.test(disclosed.salt)) {
    return fail('malformed salt — must be non-empty hex');
  }
  let saltLenBytes: number;
  try {
    saltLenBytes = hexToBytes(disclosed.salt).length;
  } catch {
    return fail('malformed salt — not valid hex');
  }
  if (saltLenBytes < MIN_SALT_BYTES) {
    return fail(
      `salt too short: ${saltLenBytes} bytes < ${MIN_SALT_BYTES}-byte floor (128-bit, spec §3) — ` +
      `low-entropy salt is vulnerable to commitment-grinding`
    );
  }
  let recomputed: string;
  try {
    recomputed = computeCommitment(disclosed.salt, disclosed.claim);
  } catch (e) {
    return fail(`commitment recompute failed: ${(e as Error).message}`);
  }

  // (b) membership — the recomputed commitment MUST fold to the signed root via the path.
  // (A tampered claim / wrong salt changes `recomputed` so this fails; a forged commitment
  // that isn't in the set has no valid path.)
  if (!verifyMerklePath(recomputed, disclosed.merkle_path, options.signedRoot)) {
    return fail(
      'membership failure: recomputed commitment does not fold to the bundle-signed Merkle root ' +
      '(wrong salt, tampered claim, forged commitment, or non-member claim)'
    );
  }

  // (e) reveal signature — binds (verifier_id, consent_receipt_id, nonce, expiry, commitment)
  // under the holder's presentation key. We sign over the RECOMPUTED commitment so the
  // signature can never be valid over a commitment that doesn't match the revealed claim.
  let pubKey: Uint8Array;
  try {
    pubKey = hexToBytes(options.presentationPubKey);
  } catch {
    return fail('malformed presentationPubKey — not valid hex');
  }
  if (pubKey.length !== 32) return fail('presentationPubKey is not a 32-byte ed25519 key');
  let sig: Uint8Array;
  try {
    sig = hexToBytes(disclosed.reveal_sig);
  } catch {
    return fail('malformed reveal_sig — not valid hex');
  }
  if (sig.length !== 64) return fail('reveal_sig is not a 64-byte ed25519 signature');

  const body = revealPreimageBody(disclosed.challenge, recomputed);
  if (!edVerify(REVEAL_SEP, sig, body, pubKey)) {
    return fail(
      'reveal_sig does not verify under the presentation key over the audience-bound preimage ' +
      '(forged/tampered reveal, or signed by a non-holder key)'
    );
  }

  return {
    ok: true,
    decision: 'pass',
    reason:
      `claim disclosed and verified: commitment ${recomputed.slice(0, 12)}… is a member of the signed root, ` +
      `reveal bound to verifier_id="${options.expectedVerifierId}" + nonce + unexpired window`,
  };
}
