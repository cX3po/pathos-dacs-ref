/**
 * §10.4 AttestationBundle (v0.1) acceptance verifier.
 *
 * Consumes a current-spec `AttestationBundleV1` (the §10.4 shape a reference-impl contributor pinned as the
 * cross-impl fixture, DACS-Standard #117/#99) — distinct from the legacy verify-bundle.ts
 * path. Performs the §10.4.1 checks that don't require a chain:
 *   - structural validation of the §10.4 shape (incl. outcome ∈ enum, party/signature shapes);
 *   - bundleHash = sha256(JCS(bundle with `signatures` omitted)), hex (the signed scope);
 *   - required-signer rule (§10.4.1): non-abort outcomes require buyer + seller (+ a
 *     distinct orchestrator if present) AND no unlisted signers; aborted-by-* outcomes MAY
 *     be single-signed (§10.11) but every signer must still be a listed party;
 *   - signature verification over "dacs-bundle:v1:" || bundleHash, *when* algorithm is
 *     ed25519 AND the signer's claim identifier resolves to a 32-byte key. Illustrative
 *     fixtures using placeholder DIDs (or non-ed25519 labels) are `unverifiable`, not `fail`.
 *
 * Two-sided anchoring / divergence (§10.4.2/§10.4.3) is a cross-bundle concern handled by
 * the caller comparing two single-side verdicts; this function verifies ONE bundle.
 */
import type { AttestationBundleV1, BundleOutcome, BundleParty, BundleSignature } from '../types/bundle.js';
import type { ClaimRef } from '../types/identity.js';
import { verify } from './sign.js';
import { DOMAIN_SEPARATORS } from '../domain-sep.js';
import { jcsHashHex } from '../jcs.js';

const enc = new TextEncoder();

const NON_ABORT: ReadonlySet<string> = new Set(['completed', 'failed-perm', 'failed-counterparty', 'failed-substrate']);
const ABORT: ReadonlySet<string> = new Set(['aborted-by-self', 'aborted-by-other']);
const KNOWN_OUTCOMES: ReadonlySet<string> = new Set([...NON_ABORT, ...ABORT]);
const KNOWN_ROLES: ReadonlySet<string> = new Set(['buyer', 'seller', 'orchestrator']);
// §6.3.1 closed scheme registry.
const KNOWN_SCHEMES: ReadonlySet<string> = new Set([
  'cci', 'evm-key', 'sol-key', 'did', 'erc8004', 'lei', 'finra-crd', 'sam-uei', 'fedramp', 'naics', 'cmmc', 'stor-cred',
]);
const ED25519_SIG_BYTES = 64;

/** Normalise a cci identifier (hex key): strip 0x, lowercase — same key compares equal. */
function normCci(identifier: string): string {
  return identifier.replace(/^0x/i, '').toLowerCase();
}

const HEX64 = /^[0-9a-f]{64}$/;
const DID_GRAMMAR = /^did:[a-z0-9]+:[A-Za-z0-9._:-]+$/; // did:<lowercase-method>:<idchars>
/** A sha256 content/bundle hash: 64 hex chars, optionally a "sha256:" prefix. */
function isHash(h: unknown): boolean {
  return typeof h === 'string' && /^(sha256:)?[0-9a-fA-F]{64}$/.test(h);
}

export type SigCheck = { party: string; decision: 'pass' | 'fail' | 'unverifiable'; reason?: string };
export type BundleV1Verdict = {
  decision: 'accept' | 'reject';
  bundleHash: string;
  structurallyValid: boolean;
  signerRuleSatisfied: boolean;
  /** True iff there is >=1 signature and EVERY signature cryptographically verified. */
  cryptographicallyVerified: boolean;
  signatureChecks: SigCheck[];
  reasons: string[];
};

/**
 * A ClaimReference is either a non-empty bare-DID string or { scheme, identifier, params? }.
 * The key includes canonicalised params so two claims that differ only in params don't collide.
 */
function claimKey(c: unknown): string | null {
  // Keys are namespaced by representation ("str:" vs "obj:") so a bare-string claim can never
  // collide with a structured claim that stringifies to the same text (impersonation guard).
  if (typeof c === 'string') return DID_GRAMMAR.test(c) ? `str:${c}` : null; // bare claims must be DIDs
  if (c && typeof c === 'object') {
    const o = c as Partial<ClaimRef>;
    if (typeof o.scheme === 'string' && KNOWN_SCHEMES.has(o.scheme) && typeof o.identifier === 'string' && o.identifier.length > 0) {
      // cci identifiers are raw ed25519 keys → must be 64-hex (case/0x-insensitive).
      const id = o.scheme === 'cci' ? normCci(o.identifier) : o.identifier;
      if (o.scheme === 'cci' && !HEX64.test(id)) return null;
      const base = `obj:${o.scheme}:${id}`;
      if (o.params !== undefined) {
        // params, if present, MUST be a non-array object whose own values are all strings.
        if (!o.params || typeof o.params !== 'object' || Array.isArray(o.params)) return null;
        const entries = Object.entries(o.params as Record<string, unknown>);
        if (!entries.every(([, val]) => typeof val === 'string')) return null;
        const ps = entries
          .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
          .map(([k, val]) => `${encodeURIComponent(k)}=${encodeURIComponent(val as string)}`)
          .join('&');
        return ps ? `${base}?${ps}` : base;
      }
      return base;
    }
  }
  return null;
}

/**
 * Resolve a claim to a 32-byte ed25519 key — ONLY for scheme `cci` (a raw ed25519 key).
 * Other schemes (evm-key, lei, did, …) are not ed25519 raw keys and are not resolved here,
 * so a 64-hex value under a non-cci scheme is NOT treated as a verifiable key (no scheme confusion).
 */
function keyBytes(c: unknown): Uint8Array | null {
  if (!c || typeof c !== 'object') return null; // bare-DID string claims are not raw keys
  const o = c as Partial<ClaimRef>;
  if (o.scheme !== 'cci' || typeof o.identifier !== 'string') return null;
  const m = /^([0-9a-fA-F]{64})$/.exec(normCci(o.identifier));
  return m ? Uint8Array.from(m[1]!.match(/../g)!.map((b) => parseInt(b, 16))) : null;
}

/**
 * Decode a 64-byte ed25519 signature from canonical base64 OR base64url (separate grammars).
 * A 64-byte payload is exactly 86 significant chars: canonical base64 ends "==", base64url has
 * no padding. Anything else (mixed alphabet, wrong padding, wrong length) → null.
 */
function decodeEd25519Sig(v: unknown): Uint8Array | null {
  if (typeof v !== 'string') return null;
  if (!/^[A-Za-z0-9+/]{86}==$/.test(v) && !/^[A-Za-z0-9_-]{86}$/.test(v)) return null;
  let out: Uint8Array;
  try {
    const b64 = v.replace(/-/g, '+').replace(/_/g, '/');
    out = new Uint8Array(Buffer.from(b64.endsWith('==') ? b64 : b64 + '==', 'base64'));
  } catch {
    return null;
  }
  if (out.length !== ED25519_SIG_BYTES) return null;
  // Canonical-form guard: the input MUST equal the canonical re-encoding. This rejects
  // non-canonical encodings (the 64-byte payload's final base64 char has 4 unused bits that
  // a permissive decoder would accept as non-zero and silently fold to the same bytes).
  const canonB64 = Buffer.from(out).toString('base64'); // 88 chars, "==" padded
  const canonB64url = canonB64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); // 86, no pad
  return v === canonB64 || v === canonB64url ? out : null;
}

function structuralErrors(b: unknown): string[] {
  if (!b || typeof b !== 'object' || Array.isArray(b)) return ['bundle is not a JSON object'];
  const e: string[] = [];
  const x = b as Record<string, unknown>;
  const intGe0 = (n: unknown) => typeof n === 'number' && Number.isInteger(n) && n >= 0;
  if (x.bundleVersion !== '1') e.push('bundleVersion must be "1"');
  if (typeof x.jobId !== 'string' || !x.jobId) e.push('jobId missing');
  if (typeof x.outcome !== 'string' || !KNOWN_OUTCOMES.has(x.outcome)) e.push(`unknown outcome "${String(x.outcome)}" (§10.4)`);
  const lr = x.listingRef as Record<string, unknown> | undefined;
  if (!lr || typeof lr !== 'object' || typeof lr.listingId !== 'string' || !lr.listingId || !intGe0(lr.version) || !isHash(lr.contentHash)) e.push('listingRef malformed');
  if (!intGe0(x.recipeRegistryVersion) || !intGe0(x.railRegistryVersion)) e.push('registry versions must be non-negative integers');
  if (!intGe0(x.finalisedAt)) e.push('finalisedAt must be a non-negative integer (unix ms)');
  // Cross-impl AttestationRef: the spec defines { anchor:{kind,locator}, contentHash, signer? },
  // but the two reference impls diverge on the anchor wrapper (ours adds substrate/type/producedAt;
  // the contributor impl is flat {kind,id,contentHash}). We validate the minimal common contract that
  // every form shares — a non-null object carrying a string `contentHash` — so cross-impl fixtures
  // are accepted while null/primitive entries are still rejected. (Shape divergence flagged in #99.)
  const isRef = (r: unknown): boolean =>
    !!r && typeof r === 'object' && !Array.isArray(r) && isHash((r as Record<string, unknown>).contentHash);
  const isPhase = (p: unknown): boolean => {
    if (!p || typeof p !== 'object' || Array.isArray(p)) return false;
    const o = p as Record<string, unknown>;
    return intGe0(o.index) && typeof o.kind === 'string' && o.kind.length > 0 && (o.outcome === 'ok' || o.outcome === 'fail');
  };
  if (!Array.isArray(x.phaseSummary) || !x.phaseSummary.every(isPhase)) e.push('phaseSummary entries malformed');
  for (const arr of ['vetRecords', 'settlementEvidence']) if (!Array.isArray(x[arr]) || !(x[arr] as unknown[]).every(isRef)) e.push(`${arr} entries must be AttestationRefs`);
  for (const arr of ['amendments', 'ratingRefs']) if (x[arr] !== undefined && (!Array.isArray(x[arr]) || !(x[arr] as unknown[]).every(isRef))) e.push(`${arr} entries must be AttestationRefs`);
  if (x.agreementRef !== undefined && !isRef(x.agreementRef)) e.push('agreementRef malformed');
  const parties = x.parties;
  if (!Array.isArray(parties) || parties.length === 0) {
    e.push('parties missing');
  } else {
    parties.forEach((p: Partial<BundleParty> | null, i: number) => {
      if (!p || typeof p !== 'object' || typeof p.role !== 'string' || !KNOWN_ROLES.has(p.role)) e.push(`party[${i}].role invalid`);
      if (claimKey(p?.primaryClaim) === null) e.push(`party[${i}].primaryClaim invalid`);
      if (!isHash(p?.bundleHash)) e.push(`party[${i}].bundleHash invalid`);
    });
  }
  const sigs = x.signatures;
  if (!Array.isArray(sigs) || sigs.length === 0) {
    e.push('signatures missing');
  } else {
    sigs.forEach((s: Partial<BundleSignature> | null, i: number) => {
      if (claimKey(s?.party) === null) e.push(`signatures[${i}].party invalid`);
      if (typeof s?.algorithm !== 'string' || !s.algorithm) e.push(`signatures[${i}].algorithm invalid`);
      if (typeof s?.value !== 'string' || !s.value) e.push(`signatures[${i}].value invalid`);
    });
  }
  return e;
}

/**
 * Verify a single §10.4 AttestationBundleV1.
 *
 * `requireSignatures` (default true, ENFORCING): every signature must cryptographically
 * verify for `accept`. Pass `false` (FIXTURE mode) for non-normative illustrative fixtures
 * whose signers are placeholder DIDs (or non-ed25519) that can't be crypto-verified — there
 * `accept` means structurally valid + signer-set rule satisfied + no hard signature failure;
 * `cryptographicallyVerified` reports the real crypto status regardless of mode.
 */
export function verifyBundleV1(
  bundle: AttestationBundleV1,
  opts: { requireSignatures?: boolean } = {},
): BundleV1Verdict {
  const requireSignatures = opts.requireSignatures ?? true;
  const reasons: string[] = [];
  const structErrs = structuralErrors(bundle);
  if (structErrs.length) {
    return { decision: 'reject', bundleHash: '', structurallyValid: false, signerRuleSatisfied: false, cryptographicallyVerified: false, signatureChecks: [], reasons: structErrs };
  }

  const { signatures, ...unsigned } = bundle;
  const bundleHash = jcsHashHex(unsigned); // signed scope = bundle without `signatures` (§10.4.1)

  // Listed-party claim set; required signers = EVERY distinct party claim (buyer + seller +
  // each distinct orchestrator) — covers multiple/shared-claim orchestrators correctly. §10.4.1
  const partyClaims = new Set(bundle.parties.map((p) => claimKey(p.primaryClaim)!));
  const requiredClaims = partyClaims; // every distinct party is a required signer for non-abort
  const hasBuyer = bundle.parties.some((p) => p.role === 'buyer');
  const hasSeller = bundle.parties.some((p) => p.role === 'seller');

  const signerKeys = signatures.map((s: BundleSignature) => claimKey(s.party)!);
  const signerSet = new Set(signerKeys);
  const unlistedSigners = signerKeys.filter((k) => !partyClaims.has(k));

  let signerRuleSatisfied = true;
  if (unlistedSigners.length) { signerRuleSatisfied = false; reasons.push(`signature(s) from unlisted parties: ${unlistedSigners.join(', ')}`); }

  if (NON_ABORT.has(bundle.outcome)) {
    if (!hasBuyer || !hasSeller) { signerRuleSatisfied = false; reasons.push('non-abort bundle must list buyer + seller parties (§10.4.1)'); }
    const missing = [...requiredClaims].filter((k) => !signerSet.has(k));
    if (missing.length) { signerRuleSatisfied = false; reasons.push(`missing required signer(s): ${missing.join(', ')} (§10.4.1)`); }
  } else {
    // aborted-by-*: MAY be single-signed (§10.11), but >=1 signature (from a listed party, checked above).
    if (signatures.length < 1) { signerRuleSatisfied = false; reasons.push('abort bundle must carry >=1 signature (§10.11)'); }
  }

  // Signature verification — only attempt ed25519 verify for ed25519-labelled sigs over a resolvable key.
  const signatureChecks: SigCheck[] = signatures.map((s: BundleSignature): SigCheck => {
    const party = claimKey(s.party)!;
    if (s.algorithm !== 'ed25519') return { party, decision: 'unverifiable', reason: `unsupported algorithm "${s.algorithm}"` };
    // Encoding validity is independent of key resolution — reject a malformed value even for a DID signer.
    const sig = decodeEd25519Sig(s.value);
    if (!sig) return { party, decision: 'fail', reason: 'signature value is not a valid 64-byte base64/base64url ed25519 signature' };
    const kb = keyBytes(s.party);
    if (!kb) return { party, decision: 'unverifiable', reason: 'claim identifier is not a 32-byte ed25519 key (e.g. placeholder DID)' };
    let ok = false;
    try { ok = verify(DOMAIN_SEPARATORS.BUNDLE, sig, enc.encode(bundleHash), kb); } catch { ok = false; }
    return { party, decision: ok ? 'pass' : 'fail', reason: ok ? undefined : 'does not verify over dacs-bundle:v1: || bundleHash' };
  });

  const anyHardFail = signatureChecks.some((c) => c.decision === 'fail');
  const cryptographicallyVerified = signatureChecks.length > 0 && signatureChecks.every((c) => c.decision === 'pass');
  if (anyHardFail) reasons.push('one or more resolvable signatures failed verification');

  let decision: 'accept' | 'reject';
  if (!signerRuleSatisfied || anyHardFail) {
    decision = 'reject';
  } else if (requireSignatures && !cryptographicallyVerified) {
    decision = 'reject';
    reasons.push('enforcing mode: not every signature cryptographically verified (e.g. placeholder DID / unsupported algorithm) — pass requireSignatures:false for illustrative fixtures');
  } else {
    decision = 'accept';
  }
  return { decision, bundleHash, structurallyValid: true, signerRuleSatisfied, cryptographicallyVerified, signatureChecks, reasons };
}
