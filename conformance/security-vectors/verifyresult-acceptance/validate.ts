/**
 * DACS §7.12 — VerifyResult ACCEPTANCE checks (consumer side). GAP vectors #6 / #7 / #17 (issue #158).
 *
 * Three §7.12 threats, one consumer-side surface (a consumer deciding whether to ACCEPT a VerifyResult
 * presented to it against a recipe + the claim actually under verification):
 *   • Method substitution (#6): VerifyResult.method MUST be the method actually run; the consumer
 *     compares it to the recipe's defaultMethod ∪ alternatives and REJECTS an unaccepted method.
 *   • Recipe poisoning (#7): recipes are steward-signed and recipeVersion is monotonic + pinned per
 *     session; the consumer MUST verify the steward signature and the pinned version.
 *   • VerifyResult replay across sessions (#17): VerifyResult.identifier MUST match the claim under
 *     verification canonically (CF-3); bundleHash binds the result to a specific bundle. CROSS-SESSION
 *     reuse within validUntil is EXPLICITLY PERMITTED and safe (same identifier still verifies).
 *
 * Decision (§7.5.1, never collapsed): pass · fail (substitution / poisoned / replayed / expired /
 * bundle-mismatch) · indeterminate (undecidable: steward key unresolvable) · error (malformed input).
 *
 * Pure, offline, deterministic, dep-free (ed25519 via node:crypto raw-key DER wrappers; vectors carry
 * raw hex). The recipe-signing separator `dacs-recipe:v1:` is illustrative for the test — what §7.12
 * makes normative is the BEHAVIOUR (consumer MUST verify the steward sig + pinned version), exercised here.
 */
import { createPublicKey, createPrivateKey, sign as nodeSign, verify as nodeVerify } from 'node:crypto';

const SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const RECIPE_SEP = 'dacs-recipe:v1:';
const isHex = (s: unknown, bytes: number): s is string => typeof s === 'string' && new RegExp(`^[0-9a-fA-F]{${bytes * 2}}$`).test(s);

export function pubKeyObj(rawHex: string) { return createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(rawHex, 'hex')]), format: 'der', type: 'spki' }); }
export function privKeyObj(seedHex: string) { return createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.from(seedHex, 'hex')]), format: 'der', type: 'pkcs8' }); }
export function pubRawFromSeed(seedHex: string): string { const der = createPublicKey(privKeyObj(seedHex)).export({ format: 'der', type: 'spki' }); return Buffer.from(der.subarray(der.length - 32)).toString('hex'); }
export function edSign(msg: Buffer, seedHex: string): string { return nodeSign(null, msg, privKeyObj(seedHex)).toString('hex'); }
function edVerify(msg: Buffer, sigHex: string, pubHex: string): boolean {
  if (!isHex(sigHex, 64) || !isHex(pubHex, 32)) return false;
  try { return nodeVerify(null, msg, pubKeyObj(pubHex), Buffer.from(sigHex, 'hex')); } catch { return false; }
}

/** CF-3 canonical identity: scheme + identifier, parameters excluded, CF-1 (NFC) normalised; cci hex
 *  lower-cased with 0x stripped so two forms of the same key don't split (the canonicalisation gap). */
export function canonIdentity(ref: { scheme: string; identifier: string } | string): string {
  let scheme: string, ident: string;
  if (typeof ref === 'string') { const i = ref.indexOf(':'); scheme = ref.slice(0, i); ident = ref.slice(i + 1); }
  else { scheme = ref.scheme; ident = ref.identifier; }
  scheme = scheme.normalize('NFC').trim().toLowerCase();
  ident = ident.normalize('NFC').trim();
  if (scheme === 'cci') ident = ident.replace(/^0x/i, '').toLowerCase();   // per-scheme cci rule
  return `${scheme}:${ident}`;
}

/** A well-formed identifier is a non-empty `scheme:identifier` string OR an object with non-empty
 *  string `scheme` + `identifier`. Anything else is malformed → the consumer returns `error`, never a
 *  crash (canonIdentity assumes this shape). */
export function isValidIdentifier(x: unknown): boolean {
  if (typeof x === 'string') { const i = x.indexOf(':'); return i > 0 && i < x.length - 1; }
  return !!x && typeof x === 'object'
    && typeof (x as { scheme?: unknown }).scheme === 'string' && (x as { scheme: string }).scheme.length > 0
    && typeof (x as { identifier?: unknown }).identifier === 'string' && (x as { identifier: string }).identifier.length > 0;
}

export interface Recipe { method: string; alternatives?: string[]; recipeVersion: number; stewardSig?: string }
export interface VerifyResult { identifier: { scheme: string; identifier: string } | string; method: string; bundleHash?: string; validUntil?: number }
export interface Ctx {
  claimUnderVerification: { scheme: string; identifier: string } | string;
  pinnedRecipeVersion: number;
  expectedBundleHash?: string;
  stewardPub?: string | null;        // null/absent → steward key unresolvable
  now?: number;
}
export interface Check { id: string; ok: boolean | null; detail: string }
export interface AcceptVerdict { decision: 'pass' | 'fail' | 'indeterminate' | 'error'; checks: Check[] }

/** The recipe body that the steward signs (everything except the signature itself), canonical-ish. */
function recipeSignedBytes(r: Recipe): Buffer {
  const body = { method: r.method, alternatives: r.alternatives ?? [], recipeVersion: r.recipeVersion };
  return Buffer.from(RECIPE_SEP + JSON.stringify(body), 'utf8');
}

export function checkVerifyResultAcceptance(vr: VerifyResult, recipe: Recipe, ctx: Ctx): AcceptVerdict {
  const checks: Check[] = [];
  const out = (decision: AcceptVerdict['decision']): AcceptVerdict => ({ decision, checks });
  // [0] structural — malformed input is a verifier-side ERROR (retryable), never a fail/pass
  if (!vr || typeof vr !== 'object' || typeof vr.method !== 'string' || !isValidIdentifier(vr.identifier) ||
      !recipe || typeof recipe !== 'object' || typeof recipe.method !== 'string' || typeof recipe.recipeVersion !== 'number' ||
      !ctx || !isValidIdentifier(ctx.claimUnderVerification) || typeof ctx.pinnedRecipeVersion !== 'number') {
    checks.push({ id: 'structural', ok: false, detail: 'malformed VerifyResult / recipe / ctx' });
    return out('error');
  }
  checks.push({ id: 'structural', ok: true, detail: 'well-formed' });

  // [1] recipe poisoning (#7): steward sig MUST verify; recipeVersion MUST equal the pinned version
  if (ctx.stewardPub == null) {
    checks.push({ id: 'steward-key', ok: null, detail: 'steward key unresolvable — cannot verify recipe signature' });
    return out('indeterminate');                                  // do-not-collapse: undecidable ≠ fail
  }
  const sigOk = typeof recipe.stewardSig === 'string' && edVerify(recipeSignedBytes(recipe), recipe.stewardSig, ctx.stewardPub);
  checks.push({ id: 'recipe-steward-sig', ok: sigOk, detail: sigOk ? 'steward signature valid' : 'steward signature missing/invalid (recipe poisoning)' });
  if (!sigOk) return out('fail');
  const versionOk = recipe.recipeVersion === ctx.pinnedRecipeVersion;
  checks.push({ id: 'recipe-version-pin', ok: versionOk, detail: versionOk ? 'recipeVersion matches pinned' : `recipeVersion ${recipe.recipeVersion} != pinned ${ctx.pinnedRecipeVersion}` });
  if (!versionOk) return out('fail');

  // [2] method substitution (#6): vr.method ∈ recipe.method ∪ alternatives
  const accepted = new Set<string>([recipe.method, ...(recipe.alternatives ?? [])]);
  const methodOk = accepted.has(vr.method);
  checks.push({ id: 'method-accepted', ok: methodOk, detail: methodOk ? `method ${vr.method} accepted` : `method ${vr.method} not in {${[...accepted].join(', ')}}` });
  if (!methodOk) return out('fail');

  // [3] replay (#17): identifier MUST match the claim under verification (CF-3 canonical)
  const idOk = canonIdentity(vr.identifier) === canonIdentity(ctx.claimUnderVerification);
  checks.push({ id: 'identifier-binding', ok: idOk, detail: idOk ? 'identifier matches claim under verification' : 'identifier mismatch — stale/relifted VerifyResult (replay)' });
  if (!idOk) return out('fail');

  // [4] bundle binding: if a bundleHash is expected, it MUST match
  if (ctx.expectedBundleHash != null) {
    const bundleOk = vr.bundleHash === ctx.expectedBundleHash;
    checks.push({ id: 'bundle-binding', ok: bundleOk, detail: bundleOk ? 'bundleHash matches' : 'bundleHash mismatch — result bound to a different bundle' });
    if (!bundleOk) return out('fail');
  }

  // [5] freshness: cross-session reuse WITHIN validUntil is PERMITTED (safe); past validUntil is stale
  if (typeof vr.validUntil === 'number' && typeof ctx.now === 'number') {
    const fresh = ctx.now <= vr.validUntil;
    checks.push({ id: 'freshness', ok: fresh, detail: fresh ? 'within validUntil (cross-session reuse permitted)' : 'past validUntil — stale' });
    if (!fresh) return out('fail');
  }

  return out('pass');
}
