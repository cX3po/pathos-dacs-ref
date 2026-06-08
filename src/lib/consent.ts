/**
 * dacs-disclose P2 — consent / revocation records (append-only, supersede-resolved, OFFLINE).
 *
 * Spec source: `dacs-consent-selective-disclosure-spec-2026-06-07.md`
 *   §3  "Consent + revocation: a consent record (who may see which claims, until when) anchored
 *        as a `demos-receipts` entry; revocation = a later append that supersedes."
 *   §5  P2: "consent/revocation records as `demos-receipts` entries (reuse the shipped anchor;
 *        no new on-chain primitive)."
 *
 * This module builds on P1 (`src/lib/disclose.ts`: claim commitments + audience/challenge-bound
 * reveals). It adds the consent LAYER: a grantor signs a record saying *who* (an audience /
 * verifier_id) may see *which* claim commitments, *under which `consent_receipt_id`*, *until when*.
 * A later signed record can REVOKE/supersede an earlier grant. Given an append-only list of such
 * records, this module resolves the EFFECTIVE consent state at a point in time.
 *
 * ============================ OFFLINE DISCIPLINE (mirrors receipt-ledger.ts) =================
 * ⚠️ OFFLINE / DRY-RUN ONLY. Everything here is PURE in-memory logic over an array ledger:
 *   - record construction + grantor signing (offline ed25519, no network);
 *   - append to an in-memory `ConsentAnchor` (no chain write, no DEM, nothing permanent);
 *   - effective-state resolution over the append-only list (pure function of the records + a time).
 * The real `demos-receipts` anchor (src/demos/receipt-ledger.ts) does devnet WRITES (createStorage /
 * writeStorage cost DEM and are PERMANENT). Wiring a `ConsentRecord` to that anchor is a SEPARATE,
 * SUPERVISED integration step — see the `DEFERRED INTEGRATION` block at the bottom of this file. We
 * deliberately ship ONLY the in-memory `InMemoryConsentAnchor` here, matching the receipt-ledger
 * module's "builds the payload but never broadcasts" discipline.
 *
 * ============================ HONESTY / SCOPE (spec §4) =====================================
 * No L2PS / ZK / FHE / bridges / escrow. Salted-hash commitments (from P1) + ed25519 signatures
 * ONLY. No personal identifiers. This is a REFERENCE for the DACS-1 §11.2.7 named follow-on; it
 * does NOT hide the primary claim and provides no unlinkability. Consent enforcement here is
 * LOCAL orchestration (spec §8 "on-chain enforcement of consent — orchestrate locally"), not an
 * on-chain enforcement primitive.
 *
 * ============================ MECHANISM ====================================================
 * 1. ConsentRecord (signed, domain-separated under `dacs-x-consent:v1:` / SIG-4):
 *      { action: 'grant'|'revoke', consent_receipt_id, grantor (pubkey hex), audience (verifier_id),
 *        commitments (the claim-commitment hexes this record authorises), issuedAt, expiresAt,
 *        supersedes?, recordId }  +  grantor signature over JCS of the canonical signable form.
 * 2. Revocation by append-supersede:
 *      A 'revoke' record (referencing an earlier grant via `consent_receipt_id` and/or `supersedes`)
 *      is appended AFTER the grant. A later grant can also supersede an earlier one. Resolution is a
 *      pure fold over the append-ordered list → the EFFECTIVE state per `consent_receipt_id`.
 *      Latest non-revoked grant wins; a revoke after a grant → denied.
 * 3. Anchor (abstract, dry-run only): `ConsentAnchor` interface + `InMemoryConsentAnchor`. The
 *      append-only array IS the ledger; the live demos-receipts anchor is deferred (see bottom).
 * 4. Tie to P1: `verifyDisclosedClaimWithConsent()` bridges P1's `verifyDisclosedClaim` to the P2
 *      effective-state resolver WITHOUT changing P1's fail-closed API — it resolves effective
 *      consent first (grant exists, not revoked, not expired, covers the disclosed commitment,
 *      audience matches), then calls P1 with the consent scope it just proved.
 */

import { sha256 } from '@noble/hashes/sha2';
import { jcsCanonical } from '../jcs.js';
import { sign as edSign, verify as edVerify } from './sign.js';
import { DACS_X_EXTENSION_SEPARATORS } from '../domain-sep.js';
import { hexToBytes, bytesToHex } from './verify-bundle.js';
import {
  computeCommitment,
  verifyDisclosedClaim,
  type DisclosedClaim,
  type DiscloseVerifyResult,
  type VerifyDisclosedOptions,
} from './disclose.js';

const CONSENT_SEP = DACS_X_EXTENSION_SEPARATORS.CONSENT; // 'dacs-x-consent:v1:'

/* -------------------------------------------------------------------------- */
/*  Types                                                                       */
/* -------------------------------------------------------------------------- */

/** What a consent record DOES: extend consent (grant) or withdraw it (revoke). */
export type ConsentAction = 'grant' | 'revoke';

/**
 * The grantor-signed canonical body of a consent record (everything that is SIGNED).
 * `signature` and any transport metadata are NOT part of this — they ride on `ConsentRecord`.
 * Field order here is irrelevant: JCS canonicalises before hashing/signing.
 */
export interface ConsentRecordBody {
  /** Discriminates extend-vs-withdraw. */
  action: ConsentAction;
  /**
   * The stable consent scope id. The SAME id the P1 reveal binds to via `consent_receipt_id`
   * (disclose.ts RevealChallenge.consent_receipt_id). A grant and the revoke that supersedes it
   * share this id (the revoke withdraws THIS scope). A brand-new grant gets a fresh id.
   */
  consent_receipt_id: string;
  /** The grantor's ed25519 PUBLIC key, hex. Records are signed by the matching private key. */
  grantor: string;
  /**
   * The audience this consent is FOR — the verifier_id a P1 reveal must bind to. Consent is
   * audience-scoped: a grant to verifier A does not authorise disclosure to verifier B.
   */
  audience: string;
  /**
   * The set of claim-commitment hexes this record authorises disclosure of (P1 commitments). A
   * disclosed claim is covered iff its recomputed commitment ∈ this set. Sorted+deduped on build
   * so the signed body is canonical regardless of input order. For a 'revoke' this is informational
   * (a revoke withdraws the whole scope); we keep it for symmetry + audit.
   */
  commitments: string[];
  /** Unix-ms the record was issued. Used for append-supersede ordering tie-breaks. */
  issuedAt: number;
  /**
   * Unix-ms after which the grant is no longer effective (exclusive upper bound, mirrors P1
   * RevealChallenge.expiry semantics). For a 'revoke' this is informational.
   */
  expiresAt: number;
  /**
   * Optional explicit pointer to the `recordId` (or `consent_receipt_id`) this record supersedes.
   * A 'revoke' SHOULD set it; resolution also supersedes implicitly by `consent_receipt_id`.
   */
  supersedes?: string;
}

/** A consent record = its signed body + the grantor signature (hex) + a content-addressed id. */
export interface ConsentRecord extends ConsentRecordBody {
  /**
   * Content-addressed record id: sha256(CONSENT_SEP || JCS(body)) hex. Deterministic from the
   * signed body — two byte-identical bodies collide (idempotent append), and any field change
   * yields a new id. Used by `supersedes` and by the anchor for dedupe.
   */
  recordId: string;
  /** ed25519 signature by `grantor` over CONSENT_SEP || JCS(body), hex. */
  signature: string;
}

/** The EFFECTIVE consent state for ONE `consent_receipt_id` at a given time. */
export interface EffectiveConsent {
  consent_receipt_id: string;
  /** 'granted' = an unexpired, non-revoked grant is in force; 'revoked'/'expired'/'none' otherwise. */
  status: 'granted' | 'revoked' | 'expired' | 'none';
  /** The grant record currently in force (only when status==='granted'). */
  grant?: ConsentRecord;
  /** The revoke record that withdrew consent (only when status==='revoked'). */
  revokedBy?: ConsentRecord;
  /** Human-readable explanation of how this state was reached. */
  reason: string;
}

/* -------------------------------------------------------------------------- */
/*  1. Record construction + signing (offline)                                 */
/* -------------------------------------------------------------------------- */

/** Sort+dedupe commitment hexes so the signed body is order-independent + canonical. */
function canonicalCommitments(commitments: readonly string[]): string[] {
  return Array.from(new Set(commitments.map((c) => c.toLowerCase()))).sort();
}

/**
 * Build the canonical SIGNABLE body (sorted commitments; `supersedes` omitted when undefined so it
 * never JCS-encodes as `null`). Pure — no signing, no id.
 */
function canonicalBody(body: ConsentRecordBody): ConsentRecordBody {
  const out: ConsentRecordBody = {
    action: body.action,
    consent_receipt_id: body.consent_receipt_id,
    grantor: body.grantor.toLowerCase(),
    audience: body.audience,
    commitments: canonicalCommitments(body.commitments),
    issuedAt: body.issuedAt,
    expiresAt: body.expiresAt,
  };
  if (body.supersedes !== undefined) out.supersedes = body.supersedes;
  return out;
}

/** Content-addressed record id over the canonical body: sha256(CONSENT_SEP || JCS(body)), hex. */
export function computeConsentRecordId(body: ConsentRecordBody): string {
  const cb = canonicalBody(body);
  const preimage = new Uint8Array([
    ...new TextEncoder().encode(CONSENT_SEP),
    ...jcsCanonical(cb),
  ]);
  return bytesToHex(sha256(preimage));
}

/**
 * Sign a consent record. The grantor signs CONSENT_SEP || JCS(canonical body) with its ed25519
 * private key (domain-separated via the existing sign(), which enforces SIG-4 emittable discipline).
 * Returns a fully-formed, content-addressed, signed `ConsentRecord`. OFFLINE — no network.
 *
 * @param body         the consent record body (action, scope id, audience, commitments, window)
 * @param grantorPriv  the grantor's ed25519 private key (its pubkey MUST equal body.grantor)
 */
export function signConsentRecord(body: ConsentRecordBody, grantorPriv: Uint8Array): ConsentRecord {
  const cb = canonicalBody(body);
  const recordId = computeConsentRecordId(cb);
  const sig = edSign(CONSENT_SEP, jcsCanonical(cb), grantorPriv);
  return { ...cb, recordId, signature: bytesToHex(sig) };
}

/**
 * Verify a consent record's grantor signature (and that recordId is the honest content hash).
 * Pure / offline. Returns true iff: recordId == content hash of the canonical body AND the
 * signature verifies under `grantor` over CONSENT_SEP || JCS(canonical body).
 *
 * NOTE: this checks AUTHENTICITY of one record only. Effectiveness (revoked? expired? covers a
 * commitment? right audience?) is resolved by `resolveEffectiveConsent` over the whole list.
 */
export function verifyConsentRecord(record: ConsentRecord): boolean {
  // FIX 3 — reject unknown `action` values at RUNTIME, fail-closed, BEFORE the record can affect
  // resolution. TS narrows `action` to 'grant'|'revoke' only at COMPILE time; chain/read JSON is
  // UNTRUSTED, so a hostile record can carry action:'foo' (or a missing action). The resolver
  // (resolveEffectiveConsent) treats any non-'grant' action as a revoke — so without this gate an
  // attacker could revoke a victim's grant with a bogus action string. An authentic record MUST
  // carry exactly 'grant' or 'revoke'. (Defence in depth: canonicalBody also copies `action`
  // verbatim into the signed body, so a tampered action breaks the content-hash/sig check below —
  // but we reject explicitly here so an unknown action can NEVER reach the resolver intake.)
  if (record.action !== 'grant' && record.action !== 'revoke') return false;
  // Re-derive the canonical body from the record's fields and check the content-addressed id.
  const cb = canonicalBody(record);
  if (computeConsentRecordId(cb) !== record.recordId.toLowerCase()) return false;
  let pub: Uint8Array;
  let sig: Uint8Array;
  try {
    pub = hexToBytes(record.grantor);
    sig = hexToBytes(record.signature);
  } catch {
    return false;
  }
  if (pub.length !== 32) return false; // ed25519 pubkey width
  if (sig.length !== 64) return false; // ed25519 sig width
  return edVerify(CONSENT_SEP, sig, jcsCanonical(cb), pub);
}

/* -------------------------------------------------------------------------- */
/*  2. Effective-state resolution (pure fold over the append-only list)         */
/* -------------------------------------------------------------------------- */

/** Options for resolving effective consent. */
export interface ResolveOptions {
  /** Current unix-ms (injectable for deterministic tests). Defaults to Date.now(). */
  now?: number;
  /**
   * If true (default), records whose grantor signature / content hash do NOT verify are DROPPED
   * before resolution (fail-closed: an unauthentic record cannot grant OR revoke). Set to false
   * ONLY in tests that deliberately feed pre-validated records.
   */
  requireValidSignatures?: boolean;
}

/**
 * Resolve the EFFECTIVE consent state for ONE `consent_receipt_id` over an append-only list.
 *
 * Append-supersede semantics (spec §3 — "revocation = a later append that supersedes"):
 *   - The list is processed in APPEND ORDER (array order IS the ledger order, mirroring the
 *     demos-receipts append-only chain). `issuedAt` is a documented tie-break ONLY for records at
 *     the same array position would never happen; array order is authoritative.
 *   - A 'revoke' record for this scope withdraws consent: once a revoke appears AFTER a grant, the
 *     scope is REVOKED and stays revoked unless a LATER grant re-establishes it (later append wins).
 *   - The LATEST grant (by append order) that is not subsequently revoked is the one in force.
 *   - Expiry is evaluated against `now` LAST: a grant that would be in force but whose window has
 *     passed resolves to 'expired', not 'granted'.
 *
 * Fail-closed: unauthentic records are dropped (unless requireValidSignatures===false); an empty /
 * all-dropped list → status 'none'.
 *
 * PURE — no network, no mutation of inputs.
 */
export function resolveEffectiveConsent(
  ledger: readonly ConsentRecord[],
  consent_receipt_id: string,
  options: ResolveOptions = {}
): EffectiveConsent {
  const now = options.now ?? Date.now();
  const requireSig = options.requireValidSignatures !== false;

  // Filter to THIS scope, dropping unauthentic records (fail-closed) while preserving append order.
  const scoped = ledger.filter(
    (r) => r.consent_receipt_id === consent_receipt_id && (!requireSig || verifyConsentRecord(r))
  );

  if (scoped.length === 0) {
    return { consent_receipt_id, status: 'none', reason: 'no authentic consent records for this scope' };
  }

  // FIX 1 — AUTHORITY: the FIRST authentic GRANT for a scope establishes the AUTHORITATIVE grantor
  // pubkey for that scope. verifyConsentRecord only proves "signed by the named key" — it does NOT
  // prove the named key is allowed to govern THIS scope. Without this binding, any valid signer can
  // append a (validly self-signed) revoke or grant for someone else's `consent_receipt_id` and
  // revoke/supersede their consent. So: only the establishing grantor may revoke or supersede their
  // own scope. Any later grant/revoke whose `grantor` != the establishing grantor is IGNORED
  // (fail-closed, dropped) — it cannot affect effective state.
  //
  // The establishing grantor is the grantor of the first authentic GRANT (not a revoke): a scope
  // that opens with only revokes has no authority to revoke and remains 'none'.
  let establishingGrantor: string | undefined;

  // Fold in append order: the last grant-not-followed-by-revoke wins.
  let inForceGrant: ConsentRecord | undefined;
  let revokedBy: ConsentRecord | undefined;
  for (const rec of scoped) {
    const recGrantor = rec.grantor.toLowerCase();
    if (rec.action === 'grant') {
      if (establishingGrantor === undefined) {
        // First authentic grant establishes the authoritative grantor for this scope.
        establishingGrantor = recGrantor;
      } else if (recGrantor !== establishingGrantor) {
        // A grant from a DIFFERENT grantor cannot re-establish or supersede someone else's scope.
        continue; // IGNORED — fail-closed
      }
      inForceGrant = rec; // a later grant re-establishes consent (supersedes any prior revoke)
      revokedBy = undefined;
    } else if (rec.action === 'revoke') {
      // 'revoke' withdraws the current grant (later append supersedes the grant — spec §3) — but
      // (explicit 'revoke' guard, Codex note: with requireValidSignatures:false an unknown action
      //  must NOT fall through to the revoke branch — unknown actions are skipped/fail-closed.)
      // ONLY if it comes from the establishing grantor. A revoke before any grant, or from a
      // non-establishing grantor, has no authority over this scope.
      if (establishingGrantor === undefined || recGrantor !== establishingGrantor) {
        continue; // IGNORED — fail-closed (no authority to revoke this scope)
      }
      inForceGrant = undefined;
      revokedBy = rec;
    }
  }

  if (revokedBy && !inForceGrant) {
    return {
      consent_receipt_id,
      status: 'revoked',
      revokedBy,
      reason: `consent revoked by record ${revokedBy.recordId.slice(0, 12)}… (append-supersede)`,
    };
  }
  if (!inForceGrant) {
    return { consent_receipt_id, status: 'none', reason: 'no grant in force for this scope' };
  }
  // A grant is in force structurally — now check the freshness window (expiry is exclusive).
  if (!Number.isFinite(inForceGrant.expiresAt) || now >= inForceGrant.expiresAt) {
    return {
      consent_receipt_id,
      status: 'expired',
      grant: inForceGrant,
      reason: `grant ${inForceGrant.recordId.slice(0, 12)}… expired: now=${now} >= expiresAt=${inForceGrant.expiresAt}`,
    };
  }
  return {
    consent_receipt_id,
    status: 'granted',
    grant: inForceGrant,
    reason: `grant ${inForceGrant.recordId.slice(0, 12)}… in force (unexpired, not revoked)`,
  };
}

/**
 * Does the EFFECTIVE consent for a scope authorise disclosing a SPECIFIC commitment to a SPECIFIC
 * audience at `now`? Pure boolean gate composed from `resolveEffectiveConsent` plus the
 * audience/commitment-coverage checks. Returns a structured verdict so callers can log the reason.
 */
export interface ConsentCoverageResult {
  ok: boolean;
  reason: string;
  /** The resolved effective state (always populated, even on failure, for auditability). */
  effective: EffectiveConsent;
}

export function consentCovers(
  ledger: readonly ConsentRecord[],
  consent_receipt_id: string,
  audience: string,
  commitmentHex: string,
  options: ResolveOptions = {}
): ConsentCoverageResult {
  const effective = resolveEffectiveConsent(ledger, consent_receipt_id, options);
  if (effective.status !== 'granted' || !effective.grant) {
    return { ok: false, reason: `consent not in force: ${effective.status} — ${effective.reason}`, effective };
  }
  const grant = effective.grant;
  if (grant.audience !== audience) {
    return {
      ok: false,
      reason: `audience mismatch: grant is for "${grant.audience}" but disclosure is to "${audience}"`,
      effective,
    };
  }
  const target = commitmentHex.toLowerCase();
  if (!grant.commitments.includes(target)) {
    return {
      ok: false,
      reason: `commitment not covered: ${target.slice(0, 12)}… is not in the granted commitment set`,
      effective,
    };
  }
  return {
    ok: true,
    reason: `consent in force for audience "${audience}" covering commitment ${target.slice(0, 12)}…`,
    effective,
  };
}

/* -------------------------------------------------------------------------- */
/*  3. Anchor interface (ABSTRACT) + in-memory dry-run implementation           */
/* -------------------------------------------------------------------------- */

/** Opaque reference an anchor returns for an appended record (the recordId for the in-memory impl). */
export interface ConsentAnchorRef {
  ref: string;
}

/**
 * Abstract append-only consent anchor. Production wiring binds this to the shipped `demos-receipts`
 * ledger (src/demos/receipt-ledger.ts) — which does DEVNET WRITES. THAT is a separate, supervised
 * integration step (see DEFERRED INTEGRATION at the bottom). Only the in-memory dry-run impl ships
 * here, matching receipt-ledger.ts's "never broadcast" offline discipline.
 */
export interface ConsentAnchor {
  /** Append a (signed) consent record. Returns an opaque ref. MUST preserve append order. */
  append(record: ConsentRecord): Promise<ConsentAnchorRef>;
  /** Read the full append-only list in append order. */
  read(): Promise<ConsentRecord[]>;
}

/**
 * In-memory, OFFLINE consent anchor — the array IS the ledger. NO chain, NO DEM, nothing permanent.
 * Append is idempotent on `recordId` (a byte-identical re-append is a no-op, mirroring the
 * content-addressed receipt-ledger dedupe). Optionally validates signatures on append (default on).
 */
export class InMemoryConsentAnchor implements ConsentAnchor {
  private readonly records: ConsentRecord[] = [];
  private readonly seen = new Set<string>();
  private readonly validateOnAppend: boolean;

  constructor(options: { validateOnAppend?: boolean } = {}) {
    this.validateOnAppend = options.validateOnAppend !== false; // default: validate
  }

  async append(record: ConsentRecord): Promise<ConsentAnchorRef> {
    if (this.validateOnAppend && !verifyConsentRecord(record)) {
      throw new Error(
        `consent-anchor: refusing to append an unauthentic record ${record.recordId.slice(0, 12)}… ` +
        `(bad grantor signature or content-hash mismatch). This anchor is fail-closed on append.`
      );
    }
    const id = record.recordId.toLowerCase();
    if (this.seen.has(id)) {
      // Idempotent: byte-identical re-append is a no-op (content-addressed dedupe).
      return { ref: id };
    }
    this.seen.add(id);
    this.records.push(record);
    return { ref: id };
  }

  async read(): Promise<ConsentRecord[]> {
    return [...this.records]; // copy — callers cannot mutate the ledger
  }
}

/* -------------------------------------------------------------------------- */
/*  4. Bridge P1 ↔ P2: verify a disclosed claim UNDER the effective consent     */
/* -------------------------------------------------------------------------- */

/**
 * Options to verify a disclosed claim against BOTH the P1 cryptographic guarantees AND the P2
 * effective consent state. Reuses P1's `VerifyDisclosedOptions` EXCEPT for the consent fields —
 * those are now DERIVED from the resolved effective state, not supplied by the caller (that is the
 * whole point of the bridge: consent is proven from the ledger, not asserted).
 */
export interface VerifyWithConsentOptions
  extends Omit<VerifyDisclosedOptions, 'expectedConsentReceiptId' | 'allowUnscopedConsent'> {
  /** The append-only consent ledger to resolve effective state from. */
  ledger: readonly ConsentRecord[];
  /**
   * FIX 2 — REQUIRED authority check. The grantor pubkey (hex) this verifier expects to have
   * granted consent — typically the bundle subject / presentation key the disclosure is bound to.
   * The effective grant's `grantor` MUST === this value, else the disclosure is DENIED. Without it,
   * a grant signed by an UNRELATED keypair (any valid signer) could satisfy "consent proven" even
   * though that signer has no authority over the subject's claims.
   *
   * FAIL-CLOSED (mirrors P1's consent config gate): if `expectedGrantor` is not supplied,
   * `verifyDisclosedClaimWithConsent` THROWS — it is a misconfiguration, never a silent skip.
   */
  expectedGrantor: string;
  /** Resolution options (now, requireValidSignatures) — `now` defaults to options.now if set. */
  resolve?: ResolveOptions;
}

/**
 * Bridge P1's consent gate to the P2 effective-state resolver WITHOUT changing P1's fail-closed API.
 *
 * Flow (fail-closed at every step):
 *   1. Read the consent scope the DISCLOSED reveal binds to (disclosed.challenge.consent_receipt_id).
 *   2. Recompute the disclosed commitment from (salt, claim) — the same value P1 binds membership to.
 *   3. Resolve EFFECTIVE consent for that scope from the ledger and check coverage:
 *        grant in force (not revoked, not expired) ∧ audience matches the verifier ∧ commitment covered.
 *      If not covered → FAIL here (we never even call P1 — consent is denied).
 *   4. If covered, delegate to P1's `verifyDisclosedClaim`, passing the SCOPE WE JUST PROVED as
 *      `expectedConsentReceiptId`. P1 then re-checks audience/nonce/consent-scope/expiry/membership/sig
 *      independently. Both layers must agree → defence in depth, P1's API untouched.
 *
 * This NEVER weakens P1: P1 still does its own consent-scope binding (the reveal must carry the same
 * id we resolved), so a forged reveal that names a scope it isn't bound to still fails inside P1.
 */
export function verifyDisclosedClaimWithConsent(
  disclosed: DisclosedClaim,
  options: VerifyWithConsentOptions
): DiscloseVerifyResult {
  const fail = (reason: string): DiscloseVerifyResult => ({ ok: false, decision: 'fail', reason });

  // FIX 2 — authority is FAIL-CLOSED at config time (mirrors P1's expectedConsentReceiptId gate):
  // the verifier MUST declare WHICH grantor it expects to have authorised this disclosure. Omitting
  // it is a misconfiguration (the caller forgot to bind authority), not a per-reveal verdict — so we
  // THROW rather than silently accepting a grant from any signer.
  if (typeof options.expectedGrantor !== 'string' || options.expectedGrantor.length === 0) {
    throw new Error(
      'consent bridge: expectedGrantor is REQUIRED (fail-closed authority check, FIX 2) — supply ' +
      'the grantor pubkey the verifier expects to have granted (typically the bundle subject / ' +
      'presentation key). A consent grant from an unrelated key is not meaningful authority.'
    );
  }
  const expectedGrantor = options.expectedGrantor.toLowerCase();

  const scope = disclosed.challenge.consent_receipt_id;
  const resolveOpts: ResolveOptions = {
    now: options.resolve?.now ?? options.now,
    requireValidSignatures: options.resolve?.requireValidSignatures,
  };

  // Recompute the commitment the disclosed claim opens to — coverage is checked against THIS, the
  // same value P1 will bind membership to. A malformed salt/claim is rejected by P1 anyway; here we
  // guard so a recompute failure becomes a consent-DENY rather than an exception.
  let commitmentHex: string;
  try {
    commitmentHex = computeCommitment(disclosed.salt, disclosed.claim);
  } catch (e) {
    return fail(`consent bridge: cannot recompute commitment from disclosed (salt, claim): ${(e as Error).message}`);
  }

  const coverage = consentCovers(
    options.ledger,
    scope,
    options.expectedVerifierId, // consent audience MUST match the verifier P1 binds to
    commitmentHex,
    resolveOpts
  );
  if (!coverage.ok) {
    return fail(`consent denied: ${coverage.reason}`);
  }

  // FIX 2 — AUTHORITY: the in-force grant must have been issued by the grantor the verifier expects.
  // coverage.ok guarantees coverage.effective.grant is populated (status==='granted'). A grant from
  // any OTHER key is not meaningful authority over this subject's claims → DENY.
  const grant = coverage.effective.grant!;
  if (grant.grantor.toLowerCase() !== expectedGrantor) {
    return fail(
      `consent denied: grantor authority mismatch — grant signed by "${grant.grantor.slice(0, 12)}…" ` +
      `but verifier expects grantor "${expectedGrantor.slice(0, 12)}…" (a grant by an unrelated key ` +
      `is not authority over this disclosure)`
    );
  }

  // Consent proven — now run P1's full cryptographic verification, binding it to the SAME scope.
  // P1 stays fail-closed and re-checks everything independently (defence in depth).
  return verifyDisclosedClaim(disclosed, {
    signedRoot: options.signedRoot,
    presentationPubKey: options.presentationPubKey,
    expectedVerifierId: options.expectedVerifierId,
    expectedNonce: options.expectedNonce,
    expectedConsentReceiptId: scope, // the scope we just proved is in force
    now: options.now,
  });
}

/* ===========================================================================
 * DEFERRED INTEGRATION — wiring to the REAL demos-receipts anchor (SUPERVISED)
 * ===========================================================================
 *
 * The in-memory `InMemoryConsentAnchor` above is the OFFLINE substitute for the shipped
 * `demos-receipts` ledger (src/demos/receipt-ledger.ts). To anchor consent records on-chain in a
 * SEPARATE, SUPERVISED session, implement a `DemosReceiptsConsentAnchor implements ConsentAnchor`:
 *
 *   append(record):
 *     1. Map the ConsentRecord → a receipt-ledger ReceiptEntry, e.g. via receipt-mappers.ts:
 *          fromArtifact('consent-record', record.recordId, record, {
 *            outcome: record.action, at: new Date(record.issuedAt).toISOString(),
 *            detail: { consent_receipt_id, audience, expiresAt }
 *          })
 *        The record's grantor SIGNATURE travels inside the entry's content (contentHash anchors it).
 *     2. Call receipt-ledger.ts::planAppend(handle, rpc, 'pathos-consent', entry, { knownAddress }).
 *        planAppend is DRY-RUN — it returns the StorageProgram payload + cost but DOES NOT broadcast.
 *     3. *** The owner-gated broadcast (storage.ts::anchor → confirm → broadcastAndWait, costs DEM,
 *        PERMANENT) is the ONLY remaining step. It is INTENTIONALLY NOT IMPLEMENTED in this lane. ***
 *        That single broadcast call is the entire scope of the supervised integration session.
 *
 *   read():
 *     receipt-ledger.ts::readLedger(rpc, storageAddress) → filter kind==='consent-record' →
 *     reconstruct ConsentRecord[] in append order. Pure read; safe; but still requires a live RPC,
 *     hence deferred out of this OFFLINE lane.
 *
 * Why deferred: per the spec §5 P2 "reuse the shipped anchor; no new on-chain primitive" AND the
 * OFFLINE mandate, the on-chain path touches devnet (DEM spend, permanence) and must be run under
 * supervision. The ConsentAnchor interface is deliberately shaped so this drop-in needs NO change
 * to the resolver, the bridge, or the record format — only the two methods above.
 */
