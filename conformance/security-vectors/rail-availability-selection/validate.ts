/**
 * DACS §9.4.4 — RAIL-AVAILABILITY selection + poisoning defence. GAP vector #13 (issue #158).
 *
 * THREAT (availability-field poisoning, RAV-R5): a tampered/unauthenticated pre-pin read of a rail's
 * `availability` could steer an orchestrator onto a disabled/failed rail, or away from a live one. The
 * pinned, steward-SIGNED `dacs-rail:v1:` definition is the ONLY trusted source.
 *
 * Normative rules exercised:
 *   • RAV-R2 — MUST NOT select rails with availability `disabled` or `failed`.
 *   • RAV-R1 — MUST NOT treat non-`live` (e.g. `mocked`) as `live`.
 *   • RAV-R3 — MAY select `operator_gated` / `closed_data` / `bilateral` ONLY if the operator-side
 *     preflight is satisfied (a runtime check, not a static property).
 *   • RAV-R5 — MUST read `availability` from the authoritative signed+anchored rail definition; MUST
 *     NOT trust an unsigned / counterparty-supplied / cached copy.
 *
 * Decision = "may the orchestrator SELECT this rail for settlement?" §7.5.1 4-value, never collapsed:
 *   pass (selectable) · fail (MUST-NOT-select: poisoned/unauthenticated, disabled/failed/mocked, or
 *   gated-without-preflight) · indeterminate (steward key unresolvable → cannot authenticate the def)
 *   · error (malformed rail def / unknown availability value).
 *
 * Pure, offline, deterministic, dep-free (ed25519 via node:crypto raw-key DER wrappers). The rail-def
 * signing separator `dacs-rail:v1:` is the spec's (RAV-R5 / §9.4.3).
 */
import { createPublicKey, createPrivateKey, sign as nodeSign, verify as nodeVerify, createHash } from 'node:crypto';

const SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const RAIL_SEP = 'dacs-rail:v1:';
const isHex = (s: unknown, bytes: number): s is string => typeof s === 'string' && new RegExp(`^[0-9a-fA-F]{${bytes * 2}}$`).test(s);

export function privKeyObj(seedHex: string) { return createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.from(seedHex, 'hex')]), format: 'der', type: 'pkcs8' }); }
export function pubKeyObj(rawHex: string) { return createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(rawHex, 'hex')]), format: 'der', type: 'spki' }); }
export function pubRawFromSeed(seedHex: string): string { const der = createPublicKey(privKeyObj(seedHex)).export({ format: 'der', type: 'spki' }); return Buffer.from(der.subarray(der.length - 32)).toString('hex'); }
export function edSign(msg: Buffer, seedHex: string): string { return nodeSign(null, msg, privKeyObj(seedHex)).toString('hex'); }
function edVerify(msg: Buffer, sigHex: string, pubHex: string): boolean {
  if (!isHex(sigHex, 64) || !isHex(pubHex, 32)) return false;
  try { return nodeVerify(null, msg, pubKeyObj(pubHex), Buffer.from(sigHex, 'hex')); } catch { return false; }
}

export const RAIL_AVAILABILITY = ['live', 'operator_gated', 'closed_data', 'bilateral', 'mocked', 'disabled', 'failed'] as const;
export type RailAvailability = (typeof RAIL_AVAILABILITY)[number];
const GATED = new Set<RailAvailability>(['operator_gated', 'closed_data', 'bilateral']);

export interface RailDefinition { railId: string; availability: string; railVersion?: number; stewardSig?: string }
export interface RailCtx {
  stewardPub?: string | null;        // null/absent → steward key unresolvable
  operatorPreflightOk?: boolean;     // RAV-R3 runtime preflight result for gated availabilities
  pinnedRailDigest?: string;         // RAV-R5: digest of the def ANCHORED+PINNED at session start
}

/** Content digest of a rail definition's signed scope — the identity used to confirm a presented def
 *  IS the one pinned at session start (a valid signature on a stale/cached copy is not enough). */
export function railDigest(r: RailDefinition): string {
  return createHash('sha256').update(railSignedBytes(r)).digest('hex');
}
export interface Check { id: string; ok: boolean | null; detail: string }
export interface RailVerdict { decision: 'pass' | 'fail' | 'indeterminate' | 'error'; checks: Check[] }

/** The rail body the steward signs (everything except the signature). */
function railSignedBytes(r: RailDefinition): Buffer {
  return Buffer.from(RAIL_SEP + JSON.stringify({ railId: r.railId, availability: r.availability, railVersion: r.railVersion ?? null }), 'utf8');
}

export function checkRailSelection(rail: RailDefinition, ctx: RailCtx): RailVerdict {
  const checks: Check[] = [];
  const out = (d: RailVerdict['decision']): RailVerdict => ({ decision: d, checks });
  // [0] structural — malformed def / unknown availability value is a verifier-side ERROR
  if (!rail || typeof rail !== 'object' || typeof rail.railId !== 'string' || typeof rail.availability !== 'string' || !ctx || typeof ctx !== 'object') {
    checks.push({ id: 'structural', ok: false, detail: 'malformed rail definition / ctx' });
    return out('error');
  }
  if (!(RAIL_AVAILABILITY as readonly string[]).includes(rail.availability)) {
    checks.push({ id: 'availability-enum', ok: false, detail: `unknown availability value: ${String(rail.availability)}` });
    return out('error');
  }
  checks.push({ id: 'structural', ok: true, detail: 'well-formed' });

  // [1] RAV-R5 — authoritative read: the def MUST be steward-signed; trust no unsigned/cached copy
  if (ctx.stewardPub == null) {
    checks.push({ id: 'steward-key', ok: null, detail: 'steward key unresolvable — cannot authenticate the rail definition' });
    return out('indeterminate');                                  // do-not-collapse: undecidable ≠ fail
  }
  const authentic = typeof rail.stewardSig === 'string' && edVerify(railSignedBytes(rail), rail.stewardSig, ctx.stewardPub);
  checks.push({ id: 'authoritative-def', ok: authentic, detail: authentic ? 'rail def is steward-signed (authoritative)' : 'unsigned/invalid steward signature — unauthenticated copy (RAV-R5 poisoning)' });
  if (!authentic) return out('fail');                             // poisoned/counterparty copy → MUST NOT select

  // [1b] RAV-R5 (pin binding) — a VALID signature is NOT enough: the def MUST be the one anchored +
  // pinned at session start. This check is REQUIRED, not optional: with no pinned reference the consumer
  // cannot confirm the def is authoritative (undecidable → indeterminate, never a silent pass); a
  // stale/cached but validly-signed copy (old "live" superseded by a newer "failed") MUST NOT steer.
  if (ctx.pinnedRailDigest == null) {
    checks.push({ id: 'pinned-def', ok: null, detail: 'no pinned/anchored reference to compare — cannot confirm this is the authoritative def (RAV-R5)' });
    return out('indeterminate');
  }
  const pinnedOk = railDigest(rail) === ctx.pinnedRailDigest;
  checks.push({ id: 'pinned-def', ok: pinnedOk, detail: pinnedOk ? 'matches the definition pinned at session start' : 'signed but NOT the pinned/anchored definition — stale or cached copy (RAV-R5)' });
  if (!pinnedOk) return out('fail');

  // [2] RAV-R2 — never select disabled / failed
  const a = rail.availability as RailAvailability;
  if (a === 'disabled' || a === 'failed') {
    checks.push({ id: 'rav-r2', ok: false, detail: `availability ${a} — MUST NOT select (RAV-R2)` });
    return out('fail');
  }
  // [3] RAV-R1 — mocked is not a production rail; MUST NOT treat as live
  if (a === 'mocked') {
    checks.push({ id: 'rav-r1', ok: false, detail: 'availability mocked — stub, not a production rail (RAV-R1)' });
    return out('fail');
  }
  // [4] RAV-R3 — gated availabilities selectable only with operator preflight satisfied
  if (GATED.has(a)) {
    const ok = ctx.operatorPreflightOk === true;
    checks.push({ id: 'rav-r3', ok, detail: ok ? `${a} with operator preflight satisfied` : `${a} requires operator-side preflight (RAV-R3) — not satisfied` });
    return out(ok ? 'pass' : 'fail');
  }
  // [5] live, signed → selectable
  checks.push({ id: 'selectable', ok: true, detail: 'live, authoritative — selectable' });
  return out('pass');
}
