/**
 * commitment-opening.ts — buyer-side opening of a proof organ's input commitment.
 *
 * The bridge commits to the FULL raw engine record with HMAC-SHA256 keyed by a fresh random nonce
 * (tools/organ_answer.py `_commit`: key = nonce bytes, message = json.dumps(record, sort_keys=True, default=str)).
 * The deliverable anchors only `input_commitment` and `commitment_scheme`; the nonce and the exact record string are
 * retained by the seller off-channel. To audit what the organ was asked, the seller discloses the opening
 * (nonce, commitment_input) over the private channel and the buyer verifies it here: recompute the HMAC over the
 * disclosed bytes and compare constant-time with the anchored commitment. Nothing here re-canonicalises the record:
 * the seller discloses the exact string it hashed, so the buyer audits those bytes and only those bytes.
 */
import { createHmac, timingSafeEqual } from 'node:crypto';

export const COMMITMENT_SCHEME = 'hmac-sha256(nonce, sorted-json-record)';
const NONCE = /^(?:[0-9a-f]{2}){8,64}$/; // even-length hex only: Node's Buffer.from(hex) would silently drop an odd final digit
const HEX64 = /^[0-9a-f]{64}$/;

export interface CommitmentOpening {
  /** Hex nonce the seller drew at commitment time (16 to 128 hex chars; the bridge uses 64). */
  nonce: string;
  /** The exact canonical record string the seller hashed (json.dumps(record, sort_keys=True, default=str)). */
  commitment_input: string;
}

export interface OpeningVerdict {
  ok: boolean;
  reason: 'opened' | 'scheme-unsupported' | 'commitment-malformed' | 'opening-malformed' | 'mismatch' | 'record-not-json-object';
  /** The audited record, parsed from the disclosed bytes, only when the opening verified. */
  record?: Record<string, unknown>;
}

/** Seller side: the opening for a record and nonce the bridge produced; the returned input must be hashed as is. */
export function openCommitment(nonce: string, commitmentInput: string): CommitmentOpening {
  if (!NONCE.test(nonce)) throw new Error('commitment nonce is not a hex string');
  return { nonce, commitment_input: commitmentInput };
}

export function commitmentFor(opening: CommitmentOpening): string {
  return createHmac('sha256', Buffer.from(opening.nonce, 'hex')).update(Buffer.from(opening.commitment_input, 'utf8')).digest('hex');
}

/**
 * Verify that the disclosed record opens the supplied commitment.
 * The caller must authenticate the anchored deliverable and check its jobId and organ.
 * Success does not prove engine execution, freshness, or correctness of the public answer.
 */
export function verifyCommitmentOpening(deliverable: { input_commitment?: unknown; commitment_scheme?: unknown }, opening: unknown): OpeningVerdict {
  if (deliverable.commitment_scheme !== COMMITMENT_SCHEME) return { ok: false, reason: 'scheme-unsupported' };
  if (typeof deliverable.input_commitment !== 'string' || !HEX64.test(deliverable.input_commitment)) return { ok: false, reason: 'commitment-malformed' };
  if (typeof opening !== 'object' || opening === null || Array.isArray(opening)) return { ok: false, reason: 'opening-malformed' };
  const o = opening as Record<string, unknown>;
  if (typeof o.nonce !== 'string' || !NONCE.test(o.nonce) || typeof o.commitment_input !== 'string' || o.commitment_input.length === 0) return { ok: false, reason: 'opening-malformed' };
  const expected = Buffer.from(commitmentFor({ nonce: o.nonce, commitment_input: o.commitment_input }), 'hex');
  const anchored = Buffer.from(deliverable.input_commitment, 'hex');
  if (expected.length !== anchored.length || !timingSafeEqual(expected, anchored)) return { ok: false, reason: 'mismatch' };
  let record: unknown;
  try { record = JSON.parse(o.commitment_input); } catch { return { ok: false, reason: 'record-not-json-object' }; }
  if (typeof record !== 'object' || record === null || Array.isArray(record)) return { ok: false, reason: 'record-not-json-object' };
  return { ok: true, reason: 'opened', record: record as Record<string, unknown> };
}
