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
import { type BundleV1FullVerdict } from './verify-bundle-v1.js';
import { fetchAnchored as liveFetchAnchored } from '../demos/storage.js';
type FetchAnchored = typeof liveFetchAnchored;
/** Version of the structured result shape returned by verifyDocument. */
export declare const VERIFIER_API_VERSION = "pathos-dacs-verifier:1";
export type LoadedBundle = {
    kind: 'v1';
    bundle: AttestationBundleV1;
} | {
    kind: 'legacy';
    bundle: AttestationBundle;
};
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
/**
 * Dual-accept dispatch (§10.4.2 backwards-compat). The DEFAULT verify path is the v0.1
 * AttestationBundleV1 verifier; legacy `dacs-5-bundle:0.1` bundles are still READ via the
 * legacy verifyBundle walk. Discriminated on the bundle's version field.
 */
export declare function classifyBundle(raw: unknown): LoadedBundle | {
    error: string;
};
/** Normalise the full v0.1 verdict (structural+sig + two-sided + §7.5.2 walk) into the VerifyVerdict shape. */
export declare function normaliseV1Verdict(jobId: string, v: BundleV1FullVerdict): VerifyVerdict;
/** A verdict for a document the verifier could not evaluate: always indeterminate, never fail. */
export declare function indeterminateVerdict(step: string, detail: string, jobId?: string): VerifyVerdict;
export declare function exitCodeFor(decision: VerifyVerdict['decision']): 0 | 1 | 2;
/** Verify one already-parsed bundle document. Never throws on document content; RPC errors propagate. */
export declare function verifyDocument(raw: unknown, options?: VerifyDocumentOptions): Promise<VerifyDocumentResult>;
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
export declare function loadBundleSource(source: BundleSource): Promise<unknown | {
    error: string;
}>;
/** True when a loadBundleSource result is the error shape. */
export declare function isLoadError(x: unknown): x is {
    error: string;
};
export {};
