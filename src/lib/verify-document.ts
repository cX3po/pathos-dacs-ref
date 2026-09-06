/**
 * verify-document — the one place a raw bundle document becomes a structured verdict.
 *
 * `src/cli/verify.ts` (the repository CLI) and `packages/verifier` (the packaged CLI, HTTP
 * service and MCP tool) all call `verifyDocument()`. Classification (v0.1 `bundleVersion:"1"`
 * versus legacy `v:"dacs-5-bundle:0.1"`), the v0.1 verdict normalisation, and the exit-code
 * mapping live here so no surface carries its own copy.
 *
 * Verdict semantics are unchanged from the CLI: pass / fail / indeterminate, never coerced
 * (§7.5.1); an unanchored bundle is indeterminate unless the caller opted into offline
 * verification; a bundle that cannot be classified or loaded is indeterminate.
 */

import type { AttestationBundle, VerifyVerdict } from '../types/index.js';
import type { AttestationBundleV1 } from '../types/bundle.js';
import { computeAnchorPair, verifyBundle } from './verify-bundle.js';
import { verifyBundleV1Full, type BundleV1FullVerdict } from './verify-bundle-v1.js';
import { fetchAnchored as liveFetchAnchored } from '../demos/storage.js';
type FetchAnchored = typeof liveFetchAnchored;

/** Version of the structured result shape returned by verifyDocument. */
export const VERIFIER_API_VERSION = 'pathos-dacs-verifier:1';

export type LoadedBundle =
  | { kind: 'v1'; bundle: AttestationBundleV1 }
  | { kind: 'legacy'; bundle: AttestationBundle };

export type BundleKind = LoadedBundle['kind'] | 'unrecognised';

export interface VerifyDocumentOptions {
  /** Demos RPC URL for the two-sided anchor lookup and the §7.5.2 attestation walk. */
  rpc?: string;
  /** Skip the §10.4.2/§10.4.3 two-sided anchor lookup (receipt-archive audit only). */
  offline?: boolean;
  /** v0.1 only: enforcing (default true) or fixture mode for signatures. */
  requireSignatures?: boolean;
  /** Inject the chain reader; tests use this so nothing touches the network. */
  fetchAnchoredImpl?: FetchAnchored;
  /** Fallback jobId for verdicts about documents that carry none. */
  jobId?: string;
}

export interface VerifyDocumentResult {
  apiVersion: typeof VERIFIER_API_VERSION;
  bundleKind: BundleKind;
  verdict: VerifyVerdict;
  /** 0 = pass, 1 = fail, 2 = indeterminate (the CLI's exit codes). */
  exitCode: 0 | 1 | 2;
}

type VerifyStepLite = VerifyVerdict['steps'][number];

/**
 * Dual-accept dispatch (§10.4.2 backwards-compat). The DEFAULT verify path is the v0.1
 * AttestationBundleV1 verifier; legacy `dacs-5-bundle:0.1` bundles are still READ via the
 * legacy verifyBundle walk. Discriminated on the bundle's version field.
 */
export function classifyBundle(raw: unknown): LoadedBundle | { error: string } {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { error: 'bundle is not a JSON object' };
  const o = raw as Record<string, unknown>;
  // The v0.1 verifier owns all three current discriminators: the AttestationBundle, the DACS-5 §10.4
  // FaultAttestationBundle and the additive evidence-bound form the live coordinator finalizes (LIVE
  // attempt 6, 2026-09-06: the published CLI could not read its own two-sided bundles).
  if (o.bundleVersion === '1' || o.faultBundleVersion === '1' || o.evidenceBoundFaultBundleVersion === '1') return { kind: 'v1', bundle: raw as AttestationBundleV1 };
  if (o.v === 'dacs-5-bundle:0.1') return { kind: 'legacy', bundle: raw as AttestationBundle };
  return {
    error: `unrecognised bundle shape — expected a v0.1 bundle (bundleVersion, faultBundleVersion or evidenceBoundFaultBundleVersion equal to "1") ` +
      `or a legacy bundle (v:"dacs-5-bundle:0.1"); got bundleVersion=${String(o.bundleVersion)} faultBundleVersion=${String(o.faultBundleVersion)} evidenceBoundFaultBundleVersion=${String(o.evidenceBoundFaultBundleVersion)} v=${String(o.v)}`,
  };
}

/** Normalise the full v0.1 verdict (structural+sig + two-sided + §7.5.2 walk) into the VerifyVerdict shape. */
export function normaliseV1Verdict(jobId: string, v: BundleV1FullVerdict): VerifyVerdict {
  const steps: VerifyStepLite[] = [
    { step: 'structural', outcome: v.structurallyValid ? 'pass' : 'fail', detail: v.structurallyValid ? 'v0.1 §10.4 shape valid' : v.reasons.join('; ') },
    { step: 'signer-rule', outcome: v.signerRuleSatisfied ? 'pass' : 'fail', detail: v.signerRuleSatisfied ? 'required-signer rule satisfied (§10.4.1)' : v.reasons.join('; ') },
    { step: 'signatures', outcome: v.cryptographicallyVerified ? 'pass' : (v.decision === 'reject' ? 'fail' : 'indeterminate'),
      detail: v.signatureChecks.map((c) => `${c.party.slice(0, 18)}…:${c.decision}${c.reason ? ` (${c.reason})` : ''}`).join('; ') || 'no signatures' },
    // §10.4.2/§10.4.3 two-sided anchoring — `skipped` only when offline was requested (informational).
    { step: 'two-sided-anchoring',
      outcome: v.twoSided.outcome === 'skipped' ? 'skipped' : v.twoSided.outcome,
      detail: v.twoSided.detail },
    // §7.5.2 AttestationRef walk — the real per-ref outcomes.
    ...v.attestationSteps.map((s): VerifyStepLite => ({ step: s.ref, outcome: s.outcome, detail: s.detail })),
  ];
  return {
    // §7.5.1 — the verdict is the FULL rollup (any fail → fail; else any indeterminate →
    // indeterminate; else pass). An unanchored / unwalkable v1 bundle is NOT a default pass.
    decision: v.rollup,
    jobId,
    steps,
    canonicalBundleHash: v.bundleHash,
    signersVerified: v.signatureChecks.filter((c) => c.decision === 'pass').map((c) => c.party),
    attestationsVerified: v.attestationsVerified,
    attestationsFailed: v.attestationsFailed,
  };
}

/** A verdict for a document the verifier could not evaluate: always indeterminate, never fail. */
export function indeterminateVerdict(step: string, detail: string, jobId = 'unknown'): VerifyVerdict {
  return {
    decision: 'indeterminate',
    jobId,
    steps: [{ step, outcome: 'indeterminate', detail }],
    canonicalBundleHash: '',
    signersVerified: [],
    attestationsVerified: 0,
    attestationsFailed: 0,
  };
}

export function exitCodeFor(decision: VerifyVerdict['decision']): 0 | 1 | 2 {
  return decision === 'pass' ? 0 : decision === 'fail' ? 1 : 2;
}

/** Verify one already-parsed bundle document. Never throws on document content; RPC errors propagate. */
export async function verifyDocument(raw: unknown, options: VerifyDocumentOptions = {}): Promise<VerifyDocumentResult> {
  const fallbackJobId = options.jobId ?? 'unknown';
  const classified = classifyBundle(raw);
  if ('error' in classified) {
    const verdict = indeterminateVerdict('classify', classified.error, fallbackJobId);
    return { apiVersion: VERIFIER_API_VERSION, bundleKind: 'unrecognised', verdict, exitCode: 2 };
  }
  let verdict: VerifyVerdict;
  if (classified.kind === 'v1') {
    const v1 = await verifyBundleV1Full(classified.bundle, {
      rpc: options.rpc,
      skipTwoSidedLookup: options.offline ?? false,
      requireSignatures: options.requireSignatures,
      fetchAnchoredImpl: options.fetchAnchoredImpl,
    });
    verdict = normaliseV1Verdict(classified.bundle.jobId ?? fallbackJobId, v1);
  } else {
    verdict = await verifyBundle(classified.bundle, {
      rpc: options.rpc,
      skipTwoSidedLookup: options.offline ?? false,
      fetchAnchoredImpl: options.fetchAnchoredImpl,
    });
  }
  return { apiVersion: VERIFIER_API_VERSION, bundleKind: classified.kind, verdict, exitCode: exitCodeFor(verdict.decision) };
}

export interface BundleSource {
  /** Path of a local bundle JSON file. */
  file?: string;
  /** Already-read bundle JSON text (stdin, HTTP body). */
  text?: string;
  /** stor-<hex> anchor address to fetch from the chain. */
  anchor?: string;
  /** jobId: both party-specific anchors are computed and fetched; the first present wins. */
  jobId?: string;
  rpc?: string;
  fetchAnchoredImpl?: FetchAnchored;
  /** Injected file reader (tests). */
  readFileImpl?: (path: string) => string;
}

/**
 * Resolve a bundle document from one of the supported sources. Returns `{ error }` (never
 * throws) when the source cannot be read; the caller turns that into an indeterminate verdict.
 * RPC exceptions surface as errors too, distinguished from absence in the message.
 */
export async function loadBundleSource(source: BundleSource): Promise<unknown | { error: string }> {
  const rpc = source.rpc ?? 'https://demosnode.discus.sh/';
  const fetchImpl = source.fetchAnchoredImpl ?? liveFetchAnchored;
  const parse = (raw: string, where: string): unknown | { error: string } => {
    try { return JSON.parse(raw); } catch (e) { return { error: `bundle at ${where} is not valid JSON: ${(e as Error).message}` }; }
  };
  if (source.file !== undefined) {
    let raw: string;
    try {
      raw = source.readFileImpl ? source.readFileImpl(source.file) : (await import('node:fs')).readFileSync(source.file, 'utf-8');
    } catch (e) {
      return { error: `failed to load bundle from ${source.file}: ${(e as Error).message}` };
    }
    try { return JSON.parse(raw); } catch (e) { return { error: `failed to load bundle from ${source.file}: ${(e as Error).message}` }; }
  }
  if (source.text !== undefined) return parse(source.text, 'input');
  if (source.anchor !== undefined) {
    let fetched;
    try {
      fetched = await fetchImpl(rpc, source.anchor);
    } catch (e) {
      return { error: `bundle anchor fetch failed (RPC error): ${(e as Error).message}` };
    }
    if (!fetched) return { error: `bundle anchor ${source.anchor} not found at ${rpc}` };
    return parse(typeof fetched.data === 'string' ? fetched.data : JSON.stringify(fetched.data), source.anchor);
  }
  if (source.jobId !== undefined) {
    const pair = computeAnchorPair(source.jobId);
    let buyer, seller;
    let buyerErr: string | undefined;
    let sellerErr: string | undefined;
    try { buyer = await fetchImpl(rpc, pair.buyer); } catch (e) { buyerErr = (e as Error).message; }
    try { seller = await fetchImpl(rpc, pair.seller); } catch (e) { sellerErr = (e as Error).message; }
    const winner = buyer ?? seller;
    if (!winner) {
      if (buyerErr || sellerErr) {
        const parts: string[] = [];
        if (buyerErr) parts.push(`buyer fetch RPC error: ${buyerErr}`); else parts.push(`buyer anchor absent at ${pair.buyer}`);
        if (sellerErr) parts.push(`seller fetch RPC error: ${sellerErr}`); else parts.push(`seller anchor absent at ${pair.seller}`);
        return { error: `bundle-load failed for jobId=${source.jobId} at ${rpc}: ${parts.join('; ')}` };
      }
      return { error: `neither party anchor present at ${rpc} (buyer=${pair.buyer}, seller=${pair.seller})` };
    }
    return parse(typeof winner.data === 'string' ? winner.data : JSON.stringify(winner.data), `${pair.buyer}/${pair.seller}`);
  }
  return { error: 'no bundle source given (file, text, anchor or jobId)' };
}

/** True when a loadBundleSource result is the error shape. */
export function isLoadError(x: unknown): x is { error: string } {
  return !!x && typeof x === 'object' && 'error' in x && typeof (x as { error: unknown }).error === 'string';
}
