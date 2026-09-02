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
import type { AttestationRef } from '../types/verify-result.js';
import { verify } from './sign.js';
import { DOMAIN_SEPARATORS } from '../domain-sep.js';
import { jcsCanonical } from '../jcs.js';
import { bundleSignedScopeHashV1 } from './bundle-signed-scope-v1.js';
import { sha256 } from '@noble/hashes/sha2';
import { fetchAnchored, unwrapTextAnchor } from '../demos/storage.js';

const enc = new TextEncoder();

const bytesToHexLocal = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/**
 * §10.4.2 two-sided anchor derivation for a v0.1 bundle's jobId — identical contract to the
 * legacy `computeAnchorPair` in verify-bundle.ts:
 *   buyer  := stor-{sha256(jobId + "-bundle-buyer")}
 *   seller := stor-{sha256(jobId + "-bundle-seller")}
 */
export function computeAnchorPairV1(jobId: string): { buyer: string; seller: string } {
  return {
    buyer: 'stor-' + bytesToHexLocal(sha256(enc.encode(jobId + '-bundle-buyer'))),
    seller: 'stor-' + bytesToHexLocal(sha256(enc.encode(jobId + '-bundle-seller'))),
  };
}

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
// Spec §B.1: a ClaimReference is the STRING "Scheme:Identifier". The legacy object form
// { scheme, identifier } is this impl's own drift (surfaced cross-impl in #145/#146). We accept
// the spec string form for the `cci` raw-key scheme — its identifier is an ed25519 key the verifier
// resolves — and converge it to the SAME canonical key as the object form, so a string-form claim
// and the equivalent object claim are ONE logical signer. DID/other-scheme claims keep their handling
// (a generic scheme split would mis-route did:method:id, since `did` is itself a known scheme).
const CCI_STRING = /^cci:(?:0x)?([0-9a-fA-F]{64})$/;
/** A sha256 content/bundle hash: 64 hex chars, optionally a "sha256:" prefix. */
function isHash(h: unknown): boolean {
  return typeof h === 'string' && /^(sha256:)?[0-9a-fA-F]{64}$/.test(h);
}

export type SigCheck = { party: string; decision: 'pass' | 'fail' | 'unverifiable'; reason?: string };
export type BundleV1Verdict = {
  /**
   * CONSUMER CONTRACT (§7.5.1, do-not-collapse): ONLY `accept` is success. Treat BOTH `reject`
   * (hard failure — invalid signature / structural / unlisted signer) AND `indeterminate`
   * (undecidable — unresolvable key / placeholder DID / unsupported algorithm) as NOT-accepted.
   * Never write `decision !== 'reject'` to mean success — that would wrongly accept `indeterminate`.
   */
  decision: 'accept' | 'reject' | 'indeterminate';
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
export function claimKey(c: unknown): string | null {
  // Keys are namespaced by representation ("str:" vs "obj:") so a bare-string claim can never
  // collide with a structured claim that stringifies to the same text (impersonation guard).
  if (typeof c === 'string') {
    // Spec string-form cci ("cci:<hex>") canonicalises to the SAME "obj:cci:<hex>" key as the
    // object form — it IS the same logical claim, not an impersonation of a different one.
    const m = CCI_STRING.exec(c);
    if (m) return `obj:cci:${m[1]!.toLowerCase()}`;
    return DID_GRAMMAR.test(c) ? `str:${c}` : null; // other bare claims must be DIDs
  }
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
  // Spec string-form cci ("cci:<hex>") resolves to the same ed25519 key as the object form.
  if (typeof c === 'string') {
    const sm = CCI_STRING.exec(c);
    return sm ? Uint8Array.from(sm[1]!.toLowerCase().match(/../g)!.map((b) => parseInt(b, 16))) : null;
  }
  if (!c || typeof c !== 'object') return null; // other bare-DID string claims are not raw keys
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
export function decodeEd25519Sig(v: unknown): Uint8Array | null {
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
  // §10.4 (R4-B): anchoredByRole is required, a known role, and must match a listed party's role.
  if (typeof x.anchoredByRole !== 'string' || !KNOWN_ROLES.has(x.anchoredByRole)) {
    e.push('anchoredByRole missing/invalid (§10.4)');
  } else if (Array.isArray(x.parties) && !(x.parties as Array<{ role?: unknown }>).some((p) => p && p.role === x.anchoredByRole)) {
    e.push(`anchoredByRole "${x.anchoredByRole}" is not a listed party role (§10.4)`);
  }
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
  // Signed scope = bundle WITHOUT `signatures` AND WITHOUT `anchoredByRole` (§10.4.1 + R5-1).
  //
  // anchoredByRole is EXCLUDED from the hashed canonical form (DACS-Standard v0.1, CHANGELOG R5-1):
  // it is per-copy (buyer/seller/orchestrator), so excluding it makes the two two-sided copies hash
  // EQUAL in the happy path (keeping it in-hash mis-routed every happy-path session to "disputed").
  // Re-pin 2026-06-11 converged this impl to upstream: the prior in-hash choice (which preserved the
  // old cross-impl fixture hash 98d7b565) is superseded. Integrity of anchoredByRole is now restored
  // by the anchor-address ↔ anchoredByRole cross-check in verifyV1TwoSided (§10.4.2/§248) — the copy
  // at the buyer address MUST declare "buyer", the seller address "seller" — NOT by the signature.
  const bundleHash = bundleSignedScopeHashV1(unsigned);

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

  let decision: 'accept' | 'reject' | 'indeterminate';
  if (!signerRuleSatisfied || anyHardFail) {
    decision = 'reject';
  } else if (requireSignatures && !cryptographicallyVerified) {
    // §7.5.1 DO-NOT-COLLAPSE: there is no hard signature FAILURE (that path is `anyHardFail` → reject
    // above), but >=1 signature is UNVERIFIABLE — its key could not be resolved (placeholder DID), or the
    // algorithm is unsupported. We cannot decide, so the honest verdict is INDETERMINATE, not reject.
    // (Surfaced by the cross-impl convergence harness 2026-06-19: dacs-verify returns `indeterminate`
    // here; we were collapsing it to `reject`, conflating "can't decide" with "signature is invalid".)
    decision = 'indeterminate';
    reasons.push('indeterminate: not every signature could be cryptographically verified (unresolvable key / placeholder DID / unsupported algorithm) — no hard failure, but undecidable. Pass requireSignatures:false for illustrative fixtures.');
  } else {
    decision = 'accept';
  }
  return { decision, bundleHash, structurallyValid: true, signerRuleSatisfied, cryptographicallyVerified, signatureChecks, reasons };
}

// ───────────────────────────────────────────────────────────────────────────
// Chain-side v0.1 verification: §7.5.2 AttestationRef walk + §10.4.2/§10.4.3
// two-sided anchoring. The single-bundle `verifyBundleV1` above does NOT touch the
// chain; this layer adds the checks the legacy verifyBundle has always done so the
// v0.1 CLI path has the SAME contract (Codex BLOCKERs 1 + 2, 2026-06-07).
// ───────────────────────────────────────────────────────────────────────────

/** Three-valued outcome for one §7.5.2 step / the two-sided anchoring step. */
type ChainOutcome = 'pass' | 'fail' | 'indeterminate';

export interface VerifyBundleV1Options {
  /** Demos RPC URL for fetching anchored bundles + attestation refs. */
  rpc?: string;
  /**
   * Skip the §10.4.2/§10.4.3 two-sided anchor lookup. EXACTLY like legacy verifyBundle's
   * `skipTwoSidedLookup`: only set this when the caller has deliberately opted into offline
   * verification (e.g. receipt-archive audit). When false (default), an UNANCHORED bundle is
   * `indeterminate`, NEVER a silent pass.
   */
  skipTwoSidedLookup?: boolean;
  /** Inject a custom fetchAnchored — tests use this to mock the chain. */
  fetchAnchoredImpl?: typeof fetchAnchored;
  /**
   * Enforcing vs fixture mode for the structural+signature stage of BOTH the local bundle AND
   * the two chain-anchored counterparty copies (see verifyBundleV1).
   *
   * DEFAULT = undefined ⇒ ENFORCING (requireSignatures:true) everywhere. The two-sided check
   * (FIX 3) NO LONGER hardcodes fixture mode for the anchored copies — a counterparty anchor with
   * placeholder/unverifiable signatures is `fail` unless the CALLER explicitly opted into fixture
   * mode by passing `requireSignatures:false`. This flag is threaded to verifyV1TwoSided so the
   * anchored copies are verified under the SAME mode the caller chose for the local bundle.
   */
  requireSignatures?: boolean;
}

/** The full v0.1 verdict: the single-bundle verdict PLUS the chain-side results. */
export interface BundleV1FullVerdict extends BundleV1Verdict {
  /** §10.4.2/§10.4.3 — null when skipped. */
  twoSided: { outcome: ChainOutcome | 'skipped'; detail: string };
  /** §7.5.2 — REAL fetched-and-content-hashed counts (no longer hardcoded). */
  attestationsVerified: number;
  attestationsFailed: number;
  /** Per-ref §7.5.2 step log. */
  attestationSteps: { ref: string; outcome: ChainOutcome; detail: string }[];
  /** Final rollup across structural+sig, two-sided, and the attestation walk (§7.5.1). */
  rollup: ChainOutcome;
}

/** Collect every AttestationRef-bearing field of a v0.1 bundle into a flat list. */
function collectV1Refs(b: AttestationBundleV1): AttestationRef[] {
  const out: AttestationRef[] = [];
  const push = (r: unknown) => { if (r && typeof r === 'object') out.push(r as AttestationRef); };
  if (b.agreementRef) push(b.agreementRef);
  for (const r of b.vetRecords ?? []) push(r);
  for (const r of b.settlementEvidence ?? []) push(r);
  for (const r of b.amendments ?? []) push(r);
  for (const r of b.ratingRefs ?? []) push(r);
  for (const p of b.phaseSummary ?? []) if (p && (p as { attestationRef?: unknown }).attestationRef) push((p as { attestationRef: unknown }).attestationRef);
  return out;
}

type ArtifactSignature = { algorithm?: unknown; signer?: unknown; party?: unknown; value?: unknown };

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function authorizedArtifactSigners(
  artifact: Record<string, unknown>, ref: AttestationRef, bundle: AttestationBundleV1,
  kind: 'listing' | 'agreement' | 'evidence' | 'vet',
): Set<string> | null {
  const refSigner = claimKey(ref.signer);
  if (refSigner) return new Set([refSigner]);
  if (kind === 'listing') {
    const seller = asRecord(artifact.seller);
    const identity = asRecord(seller?.identity);
    const primary = identity?.primary ?? identity?.presentedBy ?? seller?.primaryClaim ?? artifact.sellerClaim;
    const key = claimKey(primary);
    return key ? new Set([key]) : null;
  }
  if (kind === 'agreement') {
    const parties = Array.isArray(artifact.parties)
      ? artifact.parties.map((p) => claimKey(asRecord(p)?.primaryClaim)).filter((k): k is string => k !== null)
      : [claimKey(artifact.buyer), claimKey(artifact.seller)].filter((k): k is string => k !== null);
    return parties.length > 0 ? new Set(parties) : null;
  }
  if (kind === 'evidence') {
    // A fresh attacker key must not become authorized merely by self-signing the evidence.
    return new Set(bundle.parties.map((p) => claimKey(p.primaryClaim)!));
  }
  // Vet-record issuers are not necessarily deal parties, so the AttestationRef must pin one.
  return null;
}

function classifyArtifact(artifact: Record<string, unknown>): 'listing' | 'agreement' | 'evidence' | 'vet' | null {
  if (artifact.listingVersion !== undefined || (typeof artifact.v === 'string' && artifact.v.includes('listing'))) return 'listing';
  if (artifact.agreementVersion !== undefined || (typeof artifact.v === 'string' && artifact.v.includes('agreement'))) return 'agreement';
  if (artifact.evidenceVersion !== undefined || (typeof artifact.v === 'string' && artifact.v.includes('settlement-evidence'))) return 'evidence';
  if (artifact.recordVersion !== undefined || (typeof artifact.v === 'string' && (artifact.v.includes('verify') || artifact.v.includes('attestation')))) return 'vet';
  return null;
}

/** Hash binding is necessary but insufficient: authenticate the fetched artifact's author. */
function verifyReferencedArtifact(
  data: string, ref: AttestationRef, bundle: AttestationBundleV1,
): { outcome: ChainOutcome; detail: string } {
  let artifact: Record<string, unknown>;
  try {
    const obj = asRecord(JSON.parse(data));
    if (!obj) return { outcome: 'fail', detail: 'referenced artifact is not a signed JSON object' };
    artifact = obj;
  } catch {
    return { outcome: 'fail', detail: 'referenced artifact is not parseable signed JSON (unsigned/unverifiable)' };
  }
  const kind = classifyArtifact(artifact);
  if (!kind) return { outcome: 'indeterminate', detail: 'referenced artifact kind is unknown; signer authorization cannot be established' };
  const separator = kind === 'listing' ? DOMAIN_SEPARATORS.LISTING
    : kind === 'agreement' ? DOMAIN_SEPARATORS.AGREEMENT
      : kind === 'evidence' ? DOMAIN_SEPARATORS.SETTLEMENT_EVIDENCE : DOMAIN_SEPARATORS.COMPOSITE_VERIFY;
  const rawSignatures: ArtifactSignature[] = Array.isArray(artifact.signatures)
    ? artifact.signatures.map((s) => (asRecord(s) ?? {}) as ArtifactSignature)
    : artifact.signature !== undefined ? [(asRecord(artifact.signature) ?? {}) as ArtifactSignature] : [];
  if (rawSignatures.length === 0) {
    return { outcome: 'fail', detail: `${kind} artifact is unsigned — contentHash proves integrity, not authorship` };
  }
  const authorized = authorizedArtifactSigners(artifact, ref, bundle, kind);
  if (!authorized || authorized.size === 0) {
    return { outcome: 'indeterminate', detail: `${kind} artifact signer authority is not resolvable/pinned` };
  }
  const { signature: _signature, signatures: _signatures, ...unsigned } = artifact;
  void _signature; void _signatures;
  let artifactHash: string;
  try { artifactHash = bytesToHexLocal(sha256(jcsCanonical(unsigned))); }
  catch (e) { return { outcome: 'fail', detail: `${kind} artifact signed scope is not canonicalizable: ${(e as Error).message}` }; }
  const verified = new Set<string>();
  for (const sigRecord of rawSignatures) {
    const signer = sigRecord.signer ?? sigRecord.party;
    const signerKey = claimKey(signer);
    if (!signerKey) return { outcome: 'fail', detail: `${kind} artifact signature has no valid signer claim` };
    if (!authorized.has(signerKey)) return { outcome: 'fail', detail: `${kind} artifact signer ${signerKey} is not authorized` };
    if (sigRecord.algorithm !== 'ed25519') return { outcome: 'indeterminate', detail: `${kind} artifact uses unsupported signature algorithm "${String(sigRecord.algorithm)}"` };
    const sig = decodeEd25519Sig(sigRecord.value);
    if (!sig) return { outcome: 'fail', detail: `${kind} artifact has a malformed ed25519 signature` };
    const pub = keyBytes(signer);
    if (!pub) return { outcome: 'indeterminate', detail: `${kind} artifact signer key is unresolvable` };
    if (!verify(separator, sig, enc.encode(artifactHash), pub)) return { outcome: 'fail', detail: `${kind} artifact signature does not verify over its canonical artifact hash` };
    verified.add(signerKey);
  }
  if (kind === 'agreement') {
    const missing = [...authorized].filter((claim) => !verified.has(claim));
    if (missing.length > 0) return { outcome: 'fail', detail: `agreement artifact is missing authorized party signature(s): ${missing.join(', ')}` };
  }
  return { outcome: 'pass', detail: `${kind} artifact signature(s) verified from authorized signer(s)` };
}

/**
 * §7.5.2 — walk every AttestationRef: fetch the anchored bytes, recompute sha256, compare to
 * `contentHash`. Mismatch ⇒ fail. Missing ⇒ fail (the bundle cites evidence that does not exist
 * — that is a content-integrity failure, not a transient absence: a finalised bundle's evidence
 * MUST be retrievable). Unreachable RPC / unsupported substrate ⇒ indeterminate.
 *
 * Mirrors the legacy walkAttestationRefs contract (string-anchored only; object-anchored → v0.3).
 */
async function walkV1AttestationRefs(
  bundle: AttestationBundleV1,
  rpc: string,
  fetchImpl: typeof fetchAnchored,
): Promise<{ verified: number; failed: number; steps: BundleV1FullVerdict['attestationSteps'] }> {
  const refs = collectV1Refs(bundle);
  const steps: BundleV1FullVerdict['attestationSteps'] = [];
  let verified = 0;
  let failed = 0;

  for (let i = 0; i < refs.length; i++) {
    const ref = refs[i]!;
    const anchor = (ref as { anchor?: { substrate?: string; locator?: string } }).anchor;
    const contentHash = (ref as { contentHash?: string }).contentHash;
    const label = `attestation[${i}]${(ref as { type?: string }).type ? ` type=${(ref as { type?: string }).type}` : ''}`;

    if (typeof contentHash !== 'string' || !/^(sha256:)?[0-9a-fA-F]{64}$/.test(contentHash)) {
      steps.push({ ref: label, outcome: 'fail', detail: `AttestationRef has no valid sha256 contentHash — cannot satisfy §7.5.2` });
      failed++;
      continue;
    }
    const wantHash = contentHash.replace(/^sha256:/, '').toLowerCase();

    // Locator must be present + on a substrate we can fetch. No locator / non-demos substrate ⇒
    // verifier cannot reach the bytes → indeterminate (NOT a pass — §7.5.1 never coerces).
    if (!anchor || anchor.substrate !== 'demos' || typeof anchor.locator !== 'string' || !anchor.locator) {
      steps.push({ ref: label, outcome: 'indeterminate',
        detail: `anchor not fetchable (substrate="${anchor?.substrate ?? 'none'}", locator="${anchor?.locator ?? 'none'}") — only string-anchored demos refs are walked in v0.2` });
      continue;
    }

    let fetched;
    try {
      fetched = await fetchImpl(rpc, anchor.locator);
    } catch (e) {
      steps.push({ ref: label, outcome: 'indeterminate', detail: `fetch ${anchor.locator} from ${rpc} failed (RPC error): ${(e as Error).message}` });
      continue;
    }
    if (!fetched) {
      // The bundle cites this evidence by content hash; if it cannot be retrieved at the locator
      // the citation is unverifiable. §7.5.2 normative MUST: a non-resolvable cited ref fails.
      steps.push({ ref: label, outcome: 'fail', detail: `${anchor.locator} not found at ${rpc} — cited evidence does not exist (§7.5.2)` });
      failed++;
      continue;
    }
    const fetchedData = unwrapTextAnchor(fetched.data) ?? fetched.data;
    if (typeof fetchedData !== 'string') {
      steps.push({ ref: label, outcome: 'indeterminate',
        detail: `anchored data is not a string (type=${typeof fetchedData}); v0.2 walks string-anchored refs only` });
      continue;
    }
    const actualHash = bytesToHexLocal(sha256(enc.encode(fetchedData)));
    if (actualHash !== wantHash) {
      steps.push({ ref: label, outcome: 'fail',
        detail: `content-hash mismatch at ${anchor.locator}: want ${wantHash.slice(0, 16)}…, got ${actualHash.slice(0, 16)}… — §7.5.2 MUST reject` });
      failed++;
      continue;
    }
    const authorship = verifyReferencedArtifact(fetchedData, ref, bundle);
    if (authorship.outcome === 'pass') {
      steps.push({ ref: label, outcome: 'pass', detail: `content-hash matches (${actualHash.slice(0, 16)}…); ${authorship.detail}; anchor=${anchor.locator}` });
      verified++;
    } else {
      steps.push({ ref: label, outcome: authorship.outcome,
        detail: `content-hash matches (${actualHash.slice(0, 16)}…) but ${authorship.detail} — fail-closed (§7.5.2/§10.4)` });
      if (authorship.outcome === 'fail') failed++;
    }
  }

  return { verified, failed, steps };
}

/**
 * Detect §10.4.3(d) divergence between two same-jobId v0.1 bundles, per the normative
 * "canonically diverge" definition: the copies differ in `outcome`, or in a SHARED
 * `phaseSummary` entry's `outcome`/`errorClass`. (errorClass added to match the spec
 * definition — a same-outcome phase blamed on different error classes is a
 * contradiction about what happened, not an advisory skew.)
 */
function v1Divergence(a: AttestationBundleV1, b: AttestationBundleV1): string | null {
  if (a.outcome !== b.outcome) return `outcome contradiction: "${a.outcome}" vs "${b.outcome}"`;
  // §10.4.3 ruling #224 (carve-out-free): phaseSummary INDEX-SET mismatch is a divergence — a phase
  // present in only one copy is a contradiction (the entry set feeds ST-10 / §10.5.1), closing the
  // phantom-entry gaming vector. Then shared indices must agree on outcome/errorClass.
  const aIdx = new Map(a.phaseSummary.map((p) => [p.index, p]));
  const bIdx = new Map(b.phaseSummary.map((p) => [p.index, p]));
  for (const idx of aIdx.keys()) if (!bIdx.has(idx)) return `phaseSummary index-set divergence: index ${idx} present only in one copy`;
  for (const idx of bIdx.keys()) if (!aIdx.has(idx)) return `phaseSummary index-set divergence: index ${idx} present only in one copy`;
  for (const p of a.phaseSummary) {
    const other = bIdx.get(p.index)!;
    if (other.outcome !== p.outcome) return `phaseSummary contradiction at index ${p.index}: "${p.outcome}" vs "${other.outcome}"`;
    if ((p.errorClass ?? null) !== (other.errorClass ?? null)) {
      return `phaseSummary contradiction at index ${p.index}: errorClass "${String(p.errorClass ?? null)}" vs "${String(other.errorClass ?? null)}"`;
    }
  }
  return null;
}

type AnchorFetch = { status: 'present'; data: unknown } | { status: 'absent' } | { status: 'error'; error: string };
async function fetchV1WithStatus(rpc: string, addr: string, fetchImpl: typeof fetchAnchored): Promise<AnchorFetch> {
  try {
    const r = await fetchImpl(rpc, addr);
    return r ? { status: 'present', data: unwrapTextAnchor(r.data) ?? r.data } : { status: 'absent' };
  } catch (e) {
    return { status: 'error', error: (e as Error).message };
  }
}

/**
 * §10.4.2 + §10.4.3 — two-sided anchoring for a v0.1 bundle. Compute buyer + seller anchors from
 * jobId, fetch BOTH, and:
 *   - neither present              → indeterminate (unanchored — NOT a pass)
 *   - exactly one present          → §10.4.3(b) signature-set classification: fully-signed copy
 *       stands as the unified session bundle (anchoring omission → pass); single-signed ABORT
 *       copy stands per §10.11 suppression (pass); single-signed non-abort copy is rejected per
 *       §10.4.1 → no valid bundle → indeterminate (like unanchored). Local bundle must be
 *       byte-equal to the lone copy and role-integrity holds (FIX 1), else fail.
 *
 *       TRUST ASSUMPTION (Codex review note, 2026-07-07): the one-sided pass depends on an
 *       HONEST ABSENCE SIGNAL from the storage substrate. An attacker who can censor the
 *       counterparty anchor at the fetch layer presents a divergent session as a clean lone
 *       fully-signed pass — byte-equality/role/signature guards protect the PRESENT copy, they
 *       cannot prove the missing copy was honestly absent. Callers on untrusted transports
 *       should fetch through quorum/authenticated storage reads. (Raised upstream on dacs-sdk
 *       #30 as a §10.4.3(b) spec-level observation.)
 *   - both present, RPC error      → indeterminate (transient, not an absence signal)
 *   - both present, jobId mismatch → fail
 *   - both present, anchoredByRole ↔ anchor-address mismatch → fail (FIX 1: integrity cross-check;
 *       the copy fetched from the BUYER address MUST declare anchoredByRole "buyer", the SELLER
 *       address MUST declare "seller"; the LOCAL bundle's anchoredByRole must match whichever side
 *       its bytes are bound to)
 *   - both present, local bundle not byte-equal to either anchored copy → fail (ride-along)
 *   - both present, an anchored copy fails ENFORCING structural+signature verify → fail (FIX 3:
 *       anchored copies are enforcing by default; fixture mode honored ONLY when caller requested it)
 *   - both present, divergent (§10.4.3(d) outcome/phaseSummary contradiction) → fail (dispute)
 *   - both present + consistent + local bound to one side → pass
 */
async function verifyV1TwoSided(
  bundle: AttestationBundleV1,
  rpc: string,
  fetchImpl: typeof fetchAnchored,
  requireSignatures: boolean,
): Promise<{ outcome: ChainOutcome; detail: string }> {
  const pair = computeAnchorPairV1(bundle.jobId);
  const buyer = await fetchV1WithStatus(rpc, pair.buyer, fetchImpl);
  const seller = await fetchV1WithStatus(rpc, pair.seller, fetchImpl);

  if (buyer.status === 'error' || seller.status === 'error') {
    const parts: string[] = [];
    if (buyer.status === 'error') parts.push(`buyer RPC error: ${buyer.error}`);
    if (seller.status === 'error') parts.push(`seller RPC error: ${seller.error}`);
    return { outcome: 'indeterminate', detail: `two-sided anchor fetch failed (not an absence signal): ${parts.join('; ')}` };
  }
  const buyerPresent = buyer.status === 'present';
  const sellerPresent = seller.status === 'present';
  if (!buyerPresent && !sellerPresent) {
    return { outcome: 'indeterminate',
      detail: `neither party anchor present at ${rpc} (buyer=${pair.buyer}, seller=${pair.seller}); bundle may not have been anchored — unanchored local v1 bundle is indeterminate, not a pass` };
  }
  // §10.4.3(b) — exactly one copy present: classify by the present copy's signature set.
  // (Replaces the earlier blanket "unilateral ⇒ aborted-by-self ⇒ fail" reading, which predates
  // the lettered consumer rules: a copy carrying all §10.4.1 required signatures IS the unified
  // session bundle — the missing copy is an anchoring omission, not an abort. A SINGLE-signed
  // copy stands only with an abort outcome (§10.11 bundle-suppression); any other single-signed
  // outcome is rejected per §10.4.1, leaving no valid bundle → indeterminate like unanchored.)
  if (buyerPresent !== sellerPresent) {
    const presentRole: 'buyer' | 'seller' = buyerPresent ? 'buyer' : 'seller';
    const fetched = (buyerPresent ? buyer : seller) as { data: unknown };
    let loneBundle: AttestationBundleV1;
    try {
      const raw = fetched.data;
      loneBundle = JSON.parse(typeof raw === 'string' ? raw : JSON.stringify(raw)) as AttestationBundleV1;
    } catch (e) {
      return { outcome: 'indeterminate', detail: `failed to parse the lone ${presentRole}-anchored v0.1 bundle: ${(e as Error).message}` };
    }
    if (loneBundle.jobId !== bundle.jobId) {
      return { outcome: 'fail', detail: `jobId mismatch: ${presentRole}-anchor=${loneBundle.jobId}, local=${bundle.jobId}` };
    }
    // FIX 1 — anchor-address ↔ anchoredByRole integrity applies to the lone copy too.
    if (loneBundle.anchoredByRole !== presentRole) {
      return { outcome: 'fail',
        detail: `anchor-address ↔ anchoredByRole mismatch: lone copy at ${presentRole} address declares anchoredByRole="${loneBundle.anchoredByRole}", expected "${presentRole}" (CORE.md:477)` };
    }
    // The LOCAL bundle must be byte-equal to the lone anchored copy (ride-along guard).
    const localH = bytesToHexLocal(sha256(jcsCanonical(bundle)));
    const loneH = bytesToHexLocal(sha256(jcsCanonical(loneBundle)));
    if (localH !== loneH) {
      return { outcome: 'fail', detail: `local bundle is not byte-equal to the lone ${presentRole}-anchored bundle (shared jobId, different content — likely a third bundle riding along)` };
    }
    // Single-bundle structural+signature verify, enforcing by default (FIX 3 discipline). Our
    // single-bundle verifier already implements §10.4.1's abort exception, so a single-signed
    // ABORT copy verifies while a single-signed non-abort copy rejects — exactly the (b) split.
    const lv = verifyBundleV1(loneBundle, { requireSignatures });
    if (lv.decision === 'reject') {
      return { outcome: 'indeterminate',
        detail: `lone ${presentRole}-anchored copy rejected by §10.4.1 signature rules (${lv.reasons.join('; ')}) — no valid bundle for the session (§10.4.3(b)); like unanchored, this is indeterminate, not a pass` };
    }
    if (lv.decision === 'indeterminate') {
      return { outcome: 'indeterminate', detail: `lone ${presentRole}-anchored copy undecidable (unresolvable key / placeholder DID): ${lv.reasons.join('; ')}` };
    }
    const sigCount = Array.isArray(loneBundle.signatures) ? loneBundle.signatures.length : 0;
    const standing = sigCount >= 2
      ? 'carries all §10.4.1 required signatures — it IS the unified session bundle; the missing copy is an anchoring omission, not an abort'
      : `single-signed with abort outcome "${loneBundle.outcome}" — stands per the §10.11 bundle-suppression rule`;
    return { outcome: 'pass',
      detail: `one-sided (§10.4.3(b)): lone ${presentRole} anchor ${standing} (present=${(buyerPresent ? pair.buyer : pair.seller).slice(0, 16)}…)` };
  }

  // Both present — parse + cross-check.
  let buyerBundle: AttestationBundleV1, sellerBundle: AttestationBundleV1;
  try {
    const bData = (buyer as { data: unknown }).data;
    const sData = (seller as { data: unknown }).data;
    buyerBundle = JSON.parse(typeof bData === 'string' ? bData : JSON.stringify(bData)) as AttestationBundleV1;
    sellerBundle = JSON.parse(typeof sData === 'string' ? sData : JSON.stringify(sData)) as AttestationBundleV1;
  } catch (e) {
    return { outcome: 'indeterminate', detail: `failed to parse one or both anchored v0.1 bundles: ${(e as Error).message}` };
  }

  if (buyerBundle.jobId !== bundle.jobId || sellerBundle.jobId !== bundle.jobId) {
    return { outcome: 'fail', detail: `jobId mismatch: buyer-anchor=${buyerBundle.jobId}, seller-anchor=${sellerBundle.jobId}, local=${bundle.jobId}` };
  }

  // FIX 1 — anchor-address ↔ anchoredByRole integrity cross-check (CORE.md:477, §10.4.1/§10.4.2).
  // `anchoredByRole` names the role that anchored a copy; it is integrity-checked against the
  // anchor ADDRESS the copy was fetched from. The bundle at the BUYER address MUST declare
  // anchoredByRole === "buyer"; the SELLER address MUST declare "seller". A buyer-address anchor
  // claiming anchoredByRole "seller" (or vice versa) is a forged/mislabeled copy → reject.
  if (buyerBundle.anchoredByRole !== 'buyer') {
    return { outcome: 'fail',
      detail: `anchor-address ↔ anchoredByRole mismatch: copy at buyer address ${pair.buyer.slice(0, 16)}… declares anchoredByRole="${buyerBundle.anchoredByRole}", expected "buyer" (CORE.md:477)` };
  }
  if (sellerBundle.anchoredByRole !== 'seller') {
    return { outcome: 'fail',
      detail: `anchor-address ↔ anchoredByRole mismatch: copy at seller address ${pair.seller.slice(0, 16)}… declares anchoredByRole="${sellerBundle.anchoredByRole}", expected "seller" (CORE.md:477)` };
  }

  // Bind the LOCAL bundle to one of the two anchored copies via full byte-equality (signatures
  // included). A local bundle that is not byte-equal to EITHER anchored side is a third bundle
  // riding along the jobId — reject.
  const localHash = bytesToHexLocal(sha256(jcsCanonical(bundle)));
  const matchesBuyer = localHash === bytesToHexLocal(sha256(jcsCanonical(buyerBundle)));
  const matchesSeller = localHash === bytesToHexLocal(sha256(jcsCanonical(sellerBundle)));
  if (!matchesBuyer && !matchesSeller) {
    return { outcome: 'fail', detail: `local bundle is not byte-equal to EITHER party-anchored bundle (shared jobId, different content — likely a third bundle riding along)` };
  }

  // FIX 1 (local-side) — the LOCAL bundle's own anchoredByRole must match the side its bytes are
  // bound to. Since byte-equality includes anchoredByRole, matchesBuyer ⇒ local anchoredByRole
  // already equals the (validated) buyer copy's "buyer", and matchesSeller ⇒ "seller". This guard
  // is defence-in-depth: it makes the local binding's role-integrity explicit (and survives any
  // future change to the byte-equality scope, e.g. excluding anchoredByRole per CORE.md:612).
  const boundRole: 'buyer' | 'seller' = matchesBuyer ? 'buyer' : 'seller';
  if (bundle.anchoredByRole !== boundRole) {
    return { outcome: 'fail',
      detail: `local bundle bound to ${boundRole} anchor but declares anchoredByRole="${bundle.anchoredByRole}" — address↔role integrity violation (CORE.md:477)` };
  }

  // FIX 3 — both anchored copies must pass the single-bundle structural+signature check ENFORCING
  // by default. Previously this hardcoded requireSignatures:false, so a counterparty anchor with
  // placeholder/unverifiable signatures could be accepted. We now thread the caller's chosen mode:
  // fixture mode (requireSignatures:false) is honored ONLY when the caller explicitly requested it.
  const bv = verifyBundleV1(buyerBundle, { requireSignatures });
  const sv = verifyBundleV1(sellerBundle, { requireSignatures });
  // §7.5.1 propagation: a REJECT anchored copy is a hard fail; an INDETERMINATE copy (unresolvable key /
  // placeholder DID) is undecidable, not a failure — propagate it as indeterminate, never collapse to fail.
  if (bv.decision === 'reject') return { outcome: 'fail', detail: `buyer-anchor bundle failed single-bundle verify: ${bv.reasons.join('; ')}` };
  if (sv.decision === 'reject') return { outcome: 'fail', detail: `seller-anchor bundle failed single-bundle verify: ${sv.reasons.join('; ')}` };
  if (bv.decision === 'indeterminate' || sv.decision === 'indeterminate')
    return { outcome: 'indeterminate', detail: `anchored copy undecidable (unresolvable key / placeholder DID): ${[...bv.reasons, ...sv.reasons].join('; ')}` };

  // §10.4.3(d) divergence detection.
  const div = v1Divergence(buyerBundle, sellerBundle);
  if (div) return { outcome: 'fail', detail: `two-sided divergence (dispute signal, §10.4.3(d)): ${div}` };

  return { outcome: 'pass', detail: `both party anchors present, jobId + content consistent, local bound to ${matchesBuyer ? 'buyer' : 'seller'} side (buyer=${pair.buyer.slice(0, 16)}…, seller=${pair.seller.slice(0, 16)}…)` };
}

/**
 * Full v0.1 verification — the contract the CLI MUST use for `bundleVersion:"1"` bundles.
 * Runs the single-bundle structural+signature check, the §10.4.2/§10.4.3 two-sided anchoring
 * (unless explicitly skipped via `skipTwoSidedLookup`), and the §7.5.2 AttestationRef walk, then
 * rolls them up with §7.5.1 precedence (any fail → fail; else any indeterminate → indeterminate;
 * else pass). This brings the v0.1 path to parity with the legacy verifyBundle path.
 */
export async function verifyBundleV1Full(
  bundle: AttestationBundleV1,
  options: VerifyBundleV1Options = {},
): Promise<BundleV1FullVerdict> {
  const rpc = options.rpc ?? 'https://demosnode.discus.sh/';
  const fetchImpl = options.fetchAnchoredImpl ?? fetchAnchored;
  // ENFORCING by default everywhere — the local bundle AND the anchored counterparty copies.
  const requireSignatures = options.requireSignatures ?? true;
  const base = verifyBundleV1(bundle, { requireSignatures });

  // Structural reject short-circuits — no jobId / refs to trust.
  if (!base.structurallyValid) {
    return { ...base, twoSided: { outcome: 'skipped', detail: 'structural reject — chain checks not run' }, attestationsVerified: 0, attestationsFailed: 0, attestationSteps: [], rollup: 'fail' };
  }

  let twoSided: BundleV1FullVerdict['twoSided'];
  if (options.skipTwoSidedLookup) {
    twoSided = { outcome: 'skipped',
      detail: 'skipTwoSidedLookup=true — offline verification; §10.4.3 unilateral/divergence detection not enforced (caller-accepted scope limit)' };
  } else {
    twoSided = await verifyV1TwoSided(bundle, rpc, fetchImpl, requireSignatures);
  }

  const walk = await walkV1AttestationRefs(bundle, rpc, fetchImpl);

  // §7.5.1 rollup. `skipped` two-sided is informational (does not block), exactly like legacy.
  const baseDecision: ChainOutcome = base.decision === 'accept' ? 'pass' : base.decision === 'indeterminate' ? 'indeterminate' : 'fail';
  const outcomes: ChainOutcome[] = [baseDecision];
  if (twoSided.outcome !== 'skipped') outcomes.push(twoSided.outcome);
  outcomes.push(...walk.steps.map((s) => s.outcome));
  const rollup: ChainOutcome = outcomes.includes('fail') ? 'fail' : outcomes.includes('indeterminate') ? 'indeterminate' : 'pass';

  return {
    ...base,
    twoSided,
    attestationsVerified: walk.verified,
    attestationsFailed: walk.failed,
    attestationSteps: walk.steps,
    rollup,
  };
}
