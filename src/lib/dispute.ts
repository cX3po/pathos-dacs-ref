/**
 * dacs-disclose P3 — DISPUTE-EVIDENCE BUNDLE (spec §3 dispute evidence; §5 P3).
 *
 * The artifact a holder presents to a dispute RESOLVER to prove, *with consent*, a selected set of
 * facts drawn from a larger private record — without leaking the rest. P3 is a thin composition
 * layer ON TOP of P1 (selective disclosure, `disclose.ts`) and P2 (consent/revocation, `consent.ts`).
 * It introduces NO new crypto primitive; it binds the two together under ONE presenting identity and
 * closes the two gaps the binding review flagged on P2:
 *
 *  ── OPTION A (presenter === grantor, enforced IN-LAYER) ──────────────────────────────────────────
 *     P2's `verifyDisclosedClaimWithConsent` takes `expectedGrantor` AND `presentationPubKey` as
 *     SEPARATE caller-supplied values, and never asserts they are the same key. So a caller could
 *     (by misconfiguration or malice) accept evidence where the consent was granted by key A but the
 *     disclosure is presented under key B — splitting AUTHORITY from PRESENTATION. In a dispute that
 *     is exactly the forgery you must not accept: "someone consented" is meaningless unless it is the
 *     SAME someone who is presenting the evidence. P3 FORCES `expectedGrantor := presentationPubKey`
 *     inside `verifyDisputeBundle` — the caller CANNOT set them apart. One identity signs the Merkle
 *     root, every reveal, AND every consent grant. (The two alternatives — a separate signed
 *     grantor↔subject link, or keeping it caller-configured — were rejected: option A is the
 *     simplest binding that cannot be misconfigured, because there is nothing to configure.)
 *
 *  ── consent_receipt_id: FRESH · UNGUESSABLE · SINGLE-USE ────────────────────────────────────────
 *     Under trust-on-first-use, a GUESSABLE consent_receipt_id is a denial vector: an attacker who
 *     can predict a victim's scope id can squat or pre-consume it. P3 (a) mints scope ids from a
 *     CSPRNG with a 128-bit floor (`mintConsentReceiptId`), (b) REJECTS at verify any scope id below
 *     the unguessability floor, and (c) enforces SINGLE-USE of the resolver's challenge via a caller-
 *     supplied `ConsumptionStore` — a captured bundle cannot be replayed, and the store is only
 *     written AFTER a bundle fully verifies (a failed bundle never burns the scope → no griefing).
 *
 * Scope discipline (anti-FOMO, mirrors P1/P2): NO ZK, NO L2PS, NO FHE, NO on-chain action. This is an
 * OFFLINE artifact layer — assembling and verifying a bundle touches no network. (Anchoring the
 * consent ledger on demos-receipts is the same SUPERVISED, deferred step documented in consent.ts.)
 *
 * SIG-4: the bundle-root binding signs under `DACS_X_EXTENSION_SEPARATORS.DISPUTE_BUNDLE`
 * (`dacs-x-dispute-bundle:v1:`) — a dedicated separator so a bundle-root signature can never be
 * confused with a reveal, a consent record, or a DACS-1 bundle presentation.
 */

import { randomBytes } from 'node:crypto';
import { sign as edSign, verify as edVerify } from './sign.js';
import { DACS_X_EXTENSION_SEPARATORS } from '../domain-sep.js';
import { hexToBytes, bytesToHex } from './verify-bundle.js';
import {
  type DisclosedClaim,
  type DiscloseVerifyResult,
} from './disclose.js';
import {
  type ConsentRecord,
  verifyDisclosedClaimWithConsent,
} from './consent.js';

const DISPUTE_BUNDLE_SEP = DACS_X_EXTENSION_SEPARATORS.DISPUTE_BUNDLE; // 'dacs-x-dispute-bundle:v1:'

/** 128-bit floor for an unguessable consent_receipt_id (hex chars = bytes*2). */
export const MIN_RECEIPT_ID_BYTES = 16;
/** 256-bit default when minting a fresh scope id. */
export const DEFAULT_RECEIPT_ID_BYTES = 32;
/** Minimum hex length a verifier accepts for a consent_receipt_id (unguessability gate). */
export const MIN_RECEIPT_ID_HEX_LEN = MIN_RECEIPT_ID_BYTES * 2;

/* -------------------------------------------------------------------------- */
/*  Types                                                                       */
/* -------------------------------------------------------------------------- */

/**
 * A self-contained dispute-evidence bundle. Everything in it is bound to ONE presenting identity
 * (`presentationPubKey`): that key signs `signedRoot` (→ `rootSig`), signs every reveal in
 * `disclosures`, and is the `grantor` of every consent grant in `consentLedger` that authorises
 * them. The resolver needs only to know WHO it expects to be presenting (the dispute counterparty)
 * — every internal cross-binding is checked by `verifyDisputeBundle`.
 */
export interface DisputeEvidenceBundle {
  /** The single identity presenting the evidence. ed25519 public key, hex (no 0x). */
  presentationPubKey: string;
  /** The Merkle root over the sorted/deduped commitment SET the disclosures prove membership in, hex. */
  signedRoot: string;
  /** ed25519 signature over (DISPUTE_BUNDLE_SEP || utf8(signedRoot)) by `presentationPubKey`, hex. */
  rootSig: string;
  /** The selectively disclosed claims presented as evidence (all under ONE shared challenge). */
  disclosures: DisclosedClaim[];
  /** The append-only consent ledger that authorises the disclosures (grants signed by the presenter). */
  consentLedger: ConsentRecord[];
}

/**
 * A single-use ledger for resolver challenges. Production supplies a durable implementation; an
 * in-memory default is provided for tests / single-process resolvers. Keys are opaque strings.
 *
 * ATOMICITY (Codex finding 1, 2026-06-08): the API is a single compare-and-set, NOT a separate
 * check-then-write. A naive `has()` then `add()` is a TOCTOU race — two concurrent resolver workers
 * could both observe "absent", both verify, both write, and a captured bundle would pass twice. A
 * durable store MUST implement this as one atomic op (e.g. `INSERT … ON CONFLICT DO NOTHING` and
 * report whether the row was inserted). `verifyDisputeBundle` calls it EXACTLY once, as the final
 * step after full crypto verification, so a failed bundle never consumes (no griefing).
 */
export interface ConsumptionStore {
  /**
   * Atomically consume `key` iff absent. Returns true iff THIS call performed the insert (caller may
   * treat the bundle as accepted); false iff `key` was already present (→ replay; reject). MUST be
   * atomic — no observable window between the membership test and the insert.
   */
  consumeIfAbsent(key: string): boolean;
}

/** In-memory `ConsumptionStore` — process-lifetime single-use. Not durable across restarts. JS is
 *  single-threaded so the test-and-set below is atomic within a process; a durable cross-process
 *  store MUST use a real CAS primitive. */
export class InMemoryConsumptionStore implements ConsumptionStore {
  private readonly seen = new Set<string>();
  consumeIfAbsent(key: string): boolean {
    if (this.seen.has(key)) return false;
    this.seen.add(key);
    return true;
  }
}

/** Options a resolver supplies to verify a dispute-evidence bundle. */
export interface VerifyDisputeBundleOptions {
  /** The resolver's OWN id. Every reveal must bind to it (audience). Authoritative; never read from the bundle. */
  expectedVerifierId: string;
  /** The exact nonce THIS resolver issued for THIS dispute challenge. Every reveal must carry it (replay binding). */
  expectedNonce: string;
  /** Single-use store for the resolver's challenge. Rejects a bundle whose challenge was already consumed. */
  consumption: ConsumptionStore;
  /** Minimum hex length accepted for the consent_receipt_id (unguessability gate). Default `MIN_RECEIPT_ID_HEX_LEN`. */
  minReceiptIdHexLen?: number;
  /** Current unix-ms (injectable for deterministic tests). Defaults to Date.now(). */
  now?: number;
  // NOTE (Codex finding 2, 2026-06-08): there is deliberately NO `resolve` passthrough. P3's whole
  // guarantee is that ONE identity signed everything — so consent-signature validation is FORCED ON
  // in-layer (`requireValidSignatures: true`), and a caller cannot pass a resolution mode that would
  // accept unverified/invalid consent signatures. Authority is non-negotiable at the dispute layer.
}

/** Result of verifying a dispute-evidence bundle. */
export interface DisputeBundleVerifyResult {
  ok: boolean;
  decision: 'pass' | 'fail';
  reason: string;
  /** Per-disclosure verdicts in bundle order (populated whether or not the bundle passes overall). */
  perDisclosure: DiscloseVerifyResult[];
}

/* -------------------------------------------------------------------------- */
/*  1. Mint a fresh, unguessable consent_receipt_id                             */
/* -------------------------------------------------------------------------- */

/**
 * Mint a CSPRNG consent_receipt_id with a 128-bit floor (default 256-bit). Use this rather than a
 * human-/counter-derived id: a guessable scope id is a front-run-denial vector under TOFU.
 * @throws if `bytes` is below the `MIN_RECEIPT_ID_BYTES` floor (a short id is not unguessable).
 */
export function mintConsentReceiptId(bytes: number = DEFAULT_RECEIPT_ID_BYTES): string {
  if (!Number.isInteger(bytes) || bytes < MIN_RECEIPT_ID_BYTES) {
    throw new Error(
      `dispute: consent_receipt_id must be >= ${MIN_RECEIPT_ID_BYTES} bytes (128-bit unguessability ` +
      `floor) — got ${bytes}. A guessable scope id is a front-run-denial vector under TOFU.`
    );
  }
  return bytesToHex(new Uint8Array(randomBytes(bytes)));
}

/* -------------------------------------------------------------------------- */
/*  2. Sign / verify the bundle-root binding (presenter → root)                 */
/* -------------------------------------------------------------------------- */

/** The signable body for the bundle-root binding: the root hex as UTF-8 bytes. */
function rootBindingBody(signedRoot: string): Uint8Array {
  return new TextEncoder().encode(signedRoot.toLowerCase());
}

/**
 * Sign a bundle root under the presenter's key (the binding that makes a bundle the presenter's).
 * Pure helper — `assembleDisputeBundle` uses it; exposed for callers that build bundles by hand.
 */
export function signBundleRoot(signedRoot: string, presenterPriv: Uint8Array): string {
  if (typeof signedRoot !== 'string' || !/^[0-9a-fA-F]+$/.test(signedRoot) || signedRoot.length === 0) {
    throw new Error('dispute: signBundleRoot — signedRoot must be non-empty hex');
  }
  return bytesToHex(edSign(DISPUTE_BUNDLE_SEP, rootBindingBody(signedRoot), presenterPriv));
}

/* -------------------------------------------------------------------------- */
/*  3. Assemble a dispute-evidence bundle (offline)                            */
/* -------------------------------------------------------------------------- */

/** Inputs to assemble a bundle. The caller has already produced the P1 reveals + P2 consent ledger. */
export interface AssembleDisputeBundleArgs {
  /** The presenter's PUBLIC key, hex. MUST be the key that signed every reveal AND every grant. */
  presentationPubKey: string;
  /** The presenter's PRIVATE key — used ONLY to sign the bundle-root binding here. */
  presenterPriv: Uint8Array;
  /** The Merkle root the disclosures prove membership in, hex. */
  signedRoot: string;
  /** The selectively disclosed claims (all under ONE shared challenge). */
  disclosures: DisclosedClaim[];
  /** The consent ledger authorising the disclosures. */
  consentLedger: ConsentRecord[];
}

/**
 * Assemble a dispute-evidence bundle. Pure/offline. This signs the root-binding and shapes the
 * artifact; it does NOT re-run full verification (that is `verifyDisputeBundle`'s job, fail-closed).
 * It DOES assert the cheap structural invariant that makes option A meaningful: there is at least one
 * disclosure, and all disclosures share ONE challenge (a mixed-challenge bundle is malformed).
 */
export function assembleDisputeBundle(args: AssembleDisputeBundleArgs): DisputeEvidenceBundle {
  if (!Array.isArray(args.disclosures) || args.disclosures.length === 0) {
    throw new Error('dispute: assembleDisputeBundle — a bundle MUST carry >= 1 disclosure');
  }
  assertSingleChallenge(args.disclosures); // throws on a mixed-challenge bundle
  return {
    presentationPubKey: args.presentationPubKey.toLowerCase(),
    signedRoot: args.signedRoot.toLowerCase(),
    rootSig: signBundleRoot(args.signedRoot, args.presenterPriv),
    disclosures: args.disclosures,
    consentLedger: args.consentLedger,
  };
}

/* -------------------------------------------------------------------------- */
/*  4. Verify a dispute-evidence bundle — OPTION A enforced in-layer            */
/* -------------------------------------------------------------------------- */

/**
 * Verify a dispute-evidence bundle, fail-closed at every step:
 *
 *   1. Shape: >= 1 disclosure; presentationPubKey + signedRoot are hex.
 *   2. ROOT BINDING: rootSig verifies under presentationPubKey over (DISPUTE_BUNDLE_SEP || root).
 *      → proves THIS presenter committed to THIS root. Without it, anyone could wrap someone else's
 *        reveals around their own root.
 *   3. SHARED CHALLENGE: every disclosure carries the IDENTICAL challenge (verifier_id,
 *      consent_receipt_id, nonce, expiry). A mixed-challenge bundle is malformed → FAIL.
 *   4. UNGUESSABILITY: the shared consent_receipt_id is hex and >= the unguessability floor.
 *   5. SINGLE-USE: the resolver challenge key was not already consumed (replay). (Consumed only on
 *      full success — step 8 — so a failing bundle never burns the scope.)
 *   6. AUDIENCE / NONCE at the bundle layer: shared challenge binds expectedVerifierId + expectedNonce.
 *   7. PER-DISCLOSURE (OPTION A): each disclosure is verified by P2's consent bridge with
 *      `expectedGrantor` FORCED to presentationPubKey — authority cannot be split from presentation.
 *      The bridge re-checks consent coverage AND P1 crypto (membership against THIS bundle's root,
 *      reveal sig under presentationPubKey, audience/nonce/consent/expiry) — defence in depth.
 *   8. If ALL disclosures pass → consume the challenge → PASS.
 *
 * @throws only on resolver MISCONFIGURATION (missing expectedVerifierId/expectedNonce/consumption) —
 *         never as a per-bundle verdict. Every bundle-content failure returns {ok:false}.
 */
export function verifyDisputeBundle(
  bundle: DisputeEvidenceBundle,
  options: VerifyDisputeBundleOptions
): DisputeBundleVerifyResult {
  const fail = (reason: string): DisputeBundleVerifyResult => ({
    ok: false,
    decision: 'fail',
    reason,
    perDisclosure: [],
  });

  // ---- resolver-config gate (misconfiguration → throw, not a verdict) -------------------------
  if (typeof options.expectedVerifierId !== 'string' || options.expectedVerifierId.length === 0) {
    throw new Error('dispute: verifyDisputeBundle — expectedVerifierId is REQUIRED (audience binding).');
  }
  if (typeof options.expectedNonce !== 'string' || options.expectedNonce.length === 0) {
    throw new Error('dispute: verifyDisputeBundle — expectedNonce is REQUIRED (replay binding).');
  }
  if (!options.consumption || typeof options.consumption.consumeIfAbsent !== 'function') {
    throw new Error('dispute: verifyDisputeBundle — a ConsumptionStore (atomic consumeIfAbsent) is REQUIRED (single-use enforcement).');
  }
  const now = options.now ?? Date.now();
  const minHexLen = options.minReceiptIdHexLen ?? MIN_RECEIPT_ID_HEX_LEN;

  // ---- 1. shape ------------------------------------------------------------------------------
  if (!Array.isArray(bundle.disclosures) || bundle.disclosures.length === 0) {
    return fail('empty bundle: a dispute-evidence bundle MUST carry >= 1 disclosure');
  }
  const presenter = bundle.presentationPubKey?.toLowerCase();
  if (typeof presenter !== 'string' || !/^[0-9a-f]+$/.test(presenter)) {
    return fail('malformed presentationPubKey — must be non-empty hex');
  }
  if (typeof bundle.signedRoot !== 'string' || !/^[0-9a-fA-F]+$/.test(bundle.signedRoot) || bundle.signedRoot.length === 0) {
    return fail('malformed signedRoot — must be non-empty hex');
  }

  // ---- 2. ROOT BINDING (presenter committed to this root) ------------------------------------
  let rootSigOk = false;
  try {
    rootSigOk = edVerify(
      DISPUTE_BUNDLE_SEP,
      hexToBytes(bundle.rootSig),
      rootBindingBody(bundle.signedRoot),
      hexToBytes(presenter)
    );
  } catch {
    return fail('malformed rootSig or presentationPubKey — cannot verify root binding');
  }
  if (!rootSigOk) {
    return fail('root binding failed: rootSig does not verify under presentationPubKey — the presenter did not commit to this root');
  }

  // ---- 3. SHARED CHALLENGE -------------------------------------------------------------------
  const mixed = firstChallengeDivergence(bundle.disclosures);
  if (mixed) {
    return fail(`mixed-challenge bundle: ${mixed} — all disclosures must share ONE resolver challenge`);
  }
  const first = bundle.disclosures[0];
  if (!first) return fail('empty bundle: no disclosures'); // unreachable after the length guard; satisfies the checker
  const challenge = first.challenge;
  const scope = challenge.consent_receipt_id;

  // ---- 4. UNGUESSABILITY of the consent scope id --------------------------------------------
  if (typeof scope !== 'string' || !/^[0-9a-fA-F]+$/.test(scope)) {
    return fail('consent_receipt_id must be hex (mint it via mintConsentReceiptId) — non-hex scope ids are not unguessability-gated');
  }
  if (scope.length < minHexLen) {
    return fail(
      `consent_receipt_id too short: ${scope.length} hex chars < ${minHexLen} floor ` +
      `(${minHexLen / 2}-byte unguessability floor) — a guessable scope id is a front-run-denial vector`
    );
  }
  // byte-alignment (Codex finding 4): a minted id is byte-derived hex (even length). An odd-length
  // value is non-canonical — not a CSPRNG receipt id — so reject it rather than count half a byte.
  if (scope.length % 2 !== 0) {
    return fail('consent_receipt_id is non-canonical: odd hex length (not byte-aligned) — mint it via mintConsentReceiptId');
  }

  // ---- 5. SINGLE-USE: deferred to step 8 (atomic consumeIfAbsent AFTER full crypto verification).
  //         Computing the key here; the burn happens once, atomically, only on full success. -------
  const challengeKey = consumptionKey(options.expectedVerifierId, scope, challenge.nonce);

  // ---- 6. AUDIENCE / NONCE at the bundle layer (defence in depth; P1 also checks) ------------
  if (challenge.verifier_id !== options.expectedVerifierId) {
    return fail(
      `audience mismatch: challenge binds verifier_id="${challenge.verifier_id}" but this resolver is "${options.expectedVerifierId}"`
    );
  }
  if (challenge.nonce !== options.expectedNonce) {
    return fail(
      `nonce mismatch: challenge binds nonce="${challenge.nonce}" but this resolver issued "${options.expectedNonce}"`
    );
  }

  // ---- 7. PER-DISCLOSURE — OPTION A: expectedGrantor FORCED to the presenter ------------------
  const perDisclosure: DiscloseVerifyResult[] = [];
  for (let i = 0; i < bundle.disclosures.length; i++) {
    const d = bundle.disclosures[i];
    if (!d) continue; // unreachable; satisfies noUncheckedIndexedAccess
    const r = verifyDisclosedClaimWithConsent(d, {
      signedRoot: bundle.signedRoot,
      presentationPubKey: presenter,
      expectedVerifierId: options.expectedVerifierId,
      expectedNonce: options.expectedNonce,
      // OPTION A — the whole point of P3: authority MUST be the presenter. Not caller-configurable.
      expectedGrantor: presenter,
      ledger: bundle.consentLedger,
      now,
      // Consent-signature validation is FORCED ON (Codex finding 2) — not caller-overridable.
      resolve: { now, requireValidSignatures: true },
    });
    perDisclosure.push(r);
    if (!r.ok) {
      return { ok: false, decision: 'fail', reason: `disclosure[${i}] rejected: ${r.reason}`, perDisclosure };
    }
  }

  // ---- 8. all disclosures passed → ATOMICALLY burn the challenge (single-use). consumeIfAbsent is
  //         the compare-and-set: if a concurrent worker already burned this exact challenge, we lose
  //         the race and reject as replay — closing the has()/add() TOCTOU (Codex finding 1). -------
  if (!options.consumption.consumeIfAbsent(challengeKey)) {
    return { ok: false, decision: 'fail', reason: 'replay: this resolver challenge (verifier|scope|nonce) was already consumed — single-use', perDisclosure };
  }
  return { ok: true, decision: 'pass', reason: `bundle verified: ${perDisclosure.length} disclosure(s) under presenter authority`, perDisclosure };
}

/* -------------------------------------------------------------------------- */
/*  helpers                                                                     */
/* -------------------------------------------------------------------------- */

/** Composite single-use key. The unit of replay is the RESOLVER CHALLENGE, not the consent scope's
 *  lifetime — so the same consented claims can be re-presented under a NEW (fresh-nonce) challenge,
 *  but a captured bundle cannot be replayed. \x1f is a non-hex, non-id separator (unambiguous join). */
function consumptionKey(verifierId: string, scope: string, nonce: string): string {
  return `${verifierId}\x1f${scope.toLowerCase()}\x1f${nonce}`;
}

/** Return a human-readable description of the FIRST field where disclosures' challenges diverge, or
 *  null if every disclosure carries the identical challenge tuple. */
function firstChallengeDivergence(disclosures: readonly DisclosedClaim[]): string | null {
  const c0 = disclosures[0]?.challenge;
  if (!c0) return 'first disclosure has no challenge';
  for (let i = 1; i < disclosures.length; i++) {
    const di = disclosures[i];
    if (!di || !di.challenge) return `disclosure[${i}] is missing its challenge`; // never throw on untrusted input (Codex finding 3)
    const c = di.challenge;
    if (c.verifier_id !== c0.verifier_id) return `disclosure[${i}].verifier_id differs`;
    if (c.consent_receipt_id !== c0.consent_receipt_id) return `disclosure[${i}].consent_receipt_id differs`;
    if (c.nonce !== c0.nonce) return `disclosure[${i}].nonce differs`;
    if (c.expiry !== c0.expiry) return `disclosure[${i}].expiry differs`;
  }
  return null;
}

/** Throw if disclosures do not share ONE challenge (used at assemble time). */
function assertSingleChallenge(disclosures: readonly DisclosedClaim[]): void {
  const d = firstChallengeDivergence(disclosures);
  if (d) {
    throw new Error(`dispute: assembleDisputeBundle — mixed-challenge bundle (${d}); all disclosures must share ONE challenge`);
  }
}
