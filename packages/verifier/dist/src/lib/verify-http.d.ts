/**
 * verify-http — the one request handler behind every HTTP-shaped verify surface.
 *
 * `packages/verifier/src/http.ts` (the packaged service) and `src/live/verify-endpoint.mts`
 * (the d402-gated endpoint) both call `handleVerifyRequest()`: body validation, the `rpc`
 * refusal, the indeterminate-on-failure rule and the result shape live here once.
 */
import { type VerifyDocumentOptions, type VerifyDocumentResult } from './verify-document.js';
export declare const MAX_VERIFY_BODY_BYTES = 1048576;
export interface VerifyHttpConfig {
    rpc?: string;
    fetchAnchoredImpl?: VerifyDocumentOptions['fetchAnchoredImpl'];
    /** Deployment-wide: skip the two-sided anchor lookup for every request (receipt-archive audit only). */
    forceOffline?: boolean;
    /** Ignore the request's own `offline` / `requireSignatures`: the deployment decides what a verification is (paid endpoints). */
    lockRequestOptions?: boolean;
}
export type VerifyHttpResult = {
    status: 200;
    body: VerifyDocumentResult;
    incomplete?: string;
} | {
    status: 400;
    body: {
        error: string;
    };
};
/** Parse and validate a verify request body; returns the 400 problem or the parsed request. */
export declare function parseVerifyRequest(bodyText: string): {
    ok: true;
    bundle: object;
    offline?: boolean;
    requireSignatures?: boolean;
} | {
    ok: false;
    error: string;
};
/** Validate the body and verify. A well-formed request always yields 200 with a verdict, never coerced. */
export declare function handleVerifyRequest(bodyText: string, config?: VerifyHttpConfig): Promise<VerifyHttpResult>;
