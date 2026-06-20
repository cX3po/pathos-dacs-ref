/**
 * DACS §7.3.2 — Verifiable-presentation HOLDER-BINDING (GAP vector #11: VP-replay).
 *
 * THREAT: a genuine, issuer-signed VC captured from one party is re-presented by a NON-HOLDER, or
 * replayed ACROSS SESSIONS. Verifying the issuer signature alone proves the credential is genuine —
 * NOT that the presenter holds it. §7.3.2 step 6 defense: the VerifiablePresentation MUST be signed by
 * the key controlling the credential subject (holder), over a challenge that includes the bundle's
 * session nonce. Reject if the holder proof is absent or does not verify.
 *
 * SCOPE (read before trusting): this validator implements §7.3.2 **step 1 (issuer genuineness)** +
 * **step 6 (holder-binding / session-nonce)** + the §7.5.1/§7.3.2 decision semantics. It DELIBERATELY
 * does NOT implement step 3 (issuer allow-list), step 4 (expiry/revocation), or step 5 (subject↔claim
 * identifier match) — those are separate conformance surfaces, out of scope for this anti-replay vector.
 *
 * Pure, offline, deterministic, DEP-FREE (ed25519 via node:crypto raw-key DER wrappers → vectors carry
 * raw hex keys/sigs + stay portable). `canon` is a minimal injective serialiser hardened to throw on
 * non-JSON values; a production verifier SHOULD use a full RFC 8785 canonicaliser (cf. the sibling
 * conformance/canonical-form module) — the signed scope here is a flat challenge so the minimal form suffices.
 *
 * Decision (§7.5.1): pass · fail (holder-binding / issuer-sig) · error (verifier-side parse/schema
 * failure — retryable, never `fail`) · indeterminate (undecidable: issuer key unresolvable, or the
 * verifier was handed no session nonce to bind against).
 */
import { createPublicKey, createPrivateKey, sign as nodeSign, verify as nodeVerify } from 'node:crypto';

const SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const HOLDER_SEP = 'dacs-vp-holder:v1:';
const ISSUER_SEP = 'dacs-vc-issue:v1:';
const isHex = (s: unknown, bytes: number): s is string => typeof s === 'string' && new RegExp(`^[0-9a-fA-F]{${bytes * 2}}$`).test(s);

export function pubKeyObj(rawHex: string) { return createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(rawHex, 'hex')]), format: 'der', type: 'spki' }); }
export function privKeyObj(seedHex: string) { return createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.from(seedHex, 'hex')]), format: 'der', type: 'pkcs8' }); }
export function pubRawFromSeed(seedHex: string): string { const der = createPublicKey(privKeyObj(seedHex)).export({ format: 'der', type: 'spki' }); return Buffer.from(der.subarray(der.length - 32)).toString('hex'); }
export function edSign(msg: Buffer, seedHex: string): string { return nodeSign(null, msg, privKeyObj(seedHex)).toString('hex'); }
function edVerify(msg: Buffer, sigHex: string, pubHex: string): boolean {
  if (!isHex(sigHex, 64) || !isHex(pubHex, 32)) return false;
  try { return nodeVerify(null, msg, pubKeyObj(pubHex), Buffer.from(sigHex, 'hex')); } catch { return false; }
}
/** Deterministic, INJECTIVE canonical JSON (recursively sorted keys) over JSON-parsed values.
 *  Throws on anything not representable as a JSON value — undefined / non-finite number / function /
 *  symbol / non-plain-prototype object (Date/Map/RegExp/boxed/class) / sparse array hole / symbol or
 *  non-enumerable key — so two distinct JSON inputs can never collide via silent coercion.
 *  CONTRACT NOTE (RFC 8785 / JSON): `-0` canonicalises to "0" — `-0` and `0` are the SAME JSON number
 *  value (only JS `Object.is` distinguishes them); mapping them identically is correct, by design. */
export function canon(v: unknown): string {
  if (v === undefined || typeof v === 'function' || typeof v === 'symbol') throw new Error('canon: non-JSON value');
  if (typeof v === 'number' && !Number.isFinite(v)) throw new Error('canon: non-finite number');
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) {
    for (let i = 0; i < v.length; i++) if (!(i in v)) throw new Error('canon: sparse array hole'); // [] vs new Array(1) collision
    return `[${v.map((e) => canon(e)).join(',')}]`;
  }
  // Only PLAIN, DENSE, string-keyed objects are JSON-canonicalizable. Reject non-plain prototypes
  // (Date/Map/RegExp/boxed/class → would collapse to {}), symbol keys, and non-enumerable keys
  // (Object.keys ignores them → collision). Input contract = JSON-parsed values; vectors satisfy it.
  const proto = Object.getPrototypeOf(v);
  if (proto !== Object.prototype && proto !== null) throw new Error('canon: non-plain object (Date/Map/class/boxed not representable)');
  if (Object.getOwnPropertySymbols(v).length) throw new Error('canon: symbol keys not representable');
  if (Object.getOwnPropertyNames(v).length !== Object.keys(v).length) throw new Error('canon: non-enumerable keys not representable');
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canon(o[k])}`).join(',')}}`;
}
export const holderSignedBytes = (challenge: unknown) => Buffer.from(HOLDER_SEP + canon(challenge), 'utf8');
export const issuerSignedBytes = (credBody: unknown) => Buffer.from(ISSUER_SEP + canon(credBody), 'utf8');

export interface Presentation {
  credential: { subject: string; issuer: string; claims: Record<string, unknown>; issuerSig: string };
  holderProof?: { challenge: { sessionNonce?: string; audience?: string }; signature: string };
}
export interface Check { id: string; ok: boolean | null; detail: string }
export interface VpVerdict { decision: 'pass' | 'fail' | 'indeterminate' | 'error'; checks: Check[] }

export function verifyHolderBinding(
  presentation: Presentation,
  expectedSessionNonce: string,
  resolveIssuerKey: (issuer: string) => string | null,
): VpVerdict {
  const err = (d: string): VpVerdict => ({ decision: 'error', checks: [{ id: 'parse', ok: false, detail: `${d} (verifier-side error, retryable — §7.3.2 / §7.5.1)` }] });

  // ── strict schema gate → `error` (a malformed presentation is never a `fail`) ──
  const c = presentation?.credential;
  if (!c || typeof c !== 'object') return err('missing credential');
  if (!isHex(c.subject, 32)) return err('credential.subject is not a 32-byte ed25519 key');
  if (!isHex(c.issuer, 32)) return err('credential.issuer is not a 32-byte ed25519 key');
  if (!isHex(c.issuerSig, 64)) return err('credential.issuerSig is not a 64-byte ed25519 signature');
  if (!c.claims || typeof c.claims !== 'object') return err('credential.claims missing');
  let credBytes: Buffer;
  try { credBytes = issuerSignedBytes({ subject: c.subject, issuer: c.issuer, claims: c.claims }); } catch { return err('credential not canonicalizable'); }
  if (presentation.holderProof !== undefined) {
    const hp = presentation.holderProof;
    if (!hp || typeof hp !== 'object' || !hp.challenge || typeof hp.challenge !== 'object') return err('malformed holderProof.challenge');
    if (!isHex(hp.signature, 64)) return err('holderProof.signature is not a 64-byte ed25519 signature');
    try { canon(hp.challenge); } catch { return err('holderProof.challenge not canonicalizable'); }
  }

  const checks: Check[] = [];
  const add = (id: string, ok: boolean | null, detail: string) => { checks.push({ id, ok, detail }); };

  // 1. issuer signature — genuineness. Unresolvable issuer key → indeterminate (undecidable).
  const issuerKey = resolveIssuerKey(c.issuer);
  if (issuerKey === null) add('1-issuer', null, `issuer key for "${c.issuer.slice(0, 12)}…" unresolvable — genuineness undecidable`);
  else { const ok = edVerify(credBytes, c.issuerSig, issuerKey); add('1-issuer', ok, ok ? 'issuer signature verifies (credential genuine)' : 'issuer signature does not verify — credential tampered/not genuine'); }

  // 2. holder-binding proof present? (the core §7.3.2 anti-replay requirement)
  if (!presentation.holderProof) {
    add('2-holder-proof-present', false, 'holder-binding proof ABSENT — issuer-genuine ≠ holder-presents (§7.3.2 step 6)');
  } else {
    add('2-holder-proof-present', true, 'holder-binding proof present');
    // 3. session-nonce binding. Both the expected nonce AND the challenge nonce MUST be non-empty strings,
    //    and equal. An absent/empty expected nonce is a verifier misconfiguration → indeterminate, NEVER pass
    //    (a vacuous nonce must not silently clear the replay guard — §7.3.2 SIWD-note reachable case).
    const cn = presentation.holderProof.challenge.sessionNonce;
    if (typeof expectedSessionNonce !== 'string' || expectedSessionNonce.length === 0) {
      add('3-session-nonce', null, 'expected session nonce absent/empty — cannot bind (verifier misconfiguration → indeterminate, never pass)');
    } else {
      const ok = typeof cn === 'string' && cn.length > 0 && cn === expectedSessionNonce;
      add('3-session-nonce', ok, ok ? `challenge bound to session nonce ${expectedSessionNonce}` : `challenge nonce ${JSON.stringify(cn)} ≠ session nonce ${expectedSessionNonce} — captured VP replayed (wrong/absent/empty session nonce)`);
    }
    // 4. holder proof verifies under the credential SUBJECT key (the presenter controls the credential).
    const ok4 = edVerify(holderSignedBytes(presentation.holderProof.challenge), presentation.holderProof.signature, c.subject);
    add('4-holder-controls-subject', ok4, ok4 ? 'holder proof verifies under credential subject key (presenter is the holder)' : 'holder proof does NOT verify under subject key — non-holder presenter (replay)');
  }

  const anyFail = checks.some((k) => k.ok === false);
  const anyIndet = checks.some((k) => k.ok === null);
  const decision = anyFail ? 'fail' : anyIndet ? 'indeterminate' : 'pass';
  return { decision, checks };
}
