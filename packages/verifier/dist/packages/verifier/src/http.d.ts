#!/usr/bin/env node
/**
 * dacs-verifier-http — the verifier as a small HTTP service.
 *
 *   POST /verify                     body {bundle, offline?, requireSignatures?} → VerifyDocumentResult
 *   GET  /healthz                    {ok, name, version, apiVersion}
 *   GET  /schemas/verify-request.json, /schemas/verify-verdict.json
 *
 * A well-formed request always answers 200 with a verdict (pass / fail / indeterminate, never
 * coerced). Caller-side problems answer 4xx with {error}. The Demos RPC used for anchor
 * lookups is server configuration (DACS_VERIFIER_RPC or --rpc), never taken from the request.
 * Binds 127.0.0.1 unless DACS_VERIFIER_HOST / --host says otherwise; there is no
 * authentication, so expose it only behind something that provides it.
 */
import { type IncomingMessage, type ServerResponse } from 'node:http';
import { type VerifyDocumentOptions } from '../../../src/lib/verify-document.js';
export declare const MAX_BODY_BYTES = 1048576;
export interface ServiceConfig {
    rpc?: string;
    fetchAnchoredImpl?: VerifyDocumentOptions['fetchAnchoredImpl'];
    /** Where the JSON schemas live (defaults to the package's schemas directory). */
    schemasDir?: string;
}
export interface RouteResult {
    status: number;
    body: unknown;
}
/** Pure request handler: (method, path, body text) → (status, JSON body). Used by the server and by tests. */
export declare function route(method: string, path: string, bodyText: string, config?: ServiceConfig): Promise<RouteResult>;
export declare function createVerifierServer(config?: ServiceConfig): import("http").Server<typeof IncomingMessage, typeof ServerResponse>;
export declare function main(argv?: string[]): void;
