#!/usr/bin/env node
import { type VerifyDocumentOptions } from '../../../src/lib/verify-document.js';
export declare const MCP_PROTOCOL_VERSION = "2024-11-05";
/** Largest accepted stdio frame (one JSON-RPC line); the HTTP service has the same body budget. */
export declare const MAX_FRAME_BYTES = 1048576;
export interface McpConfig {
    rpc?: string;
    fetchAnchoredImpl?: VerifyDocumentOptions['fetchAnchoredImpl'];
}
type Json = Record<string, unknown>;
export declare function tools(config: McpConfig): {
    readonly verify_bundle: {
        readonly description: "Verify a DACS attestation bundle (v0.1 bundleVersion \"1\" or legacy dacs-5-bundle:0.1). Returns the structured verdict: pass, fail or indeterminate, never coerced; offline=true skips the two-sided anchor lookup (audit only).";
        readonly inputSchema: {
            readonly type: "object";
            readonly properties: {
                readonly bundle: {
                    readonly type: "object";
                    readonly description: "the AttestationBundle document";
                };
                readonly offline: {
                    readonly type: "boolean";
                    readonly description: "skip the two-sided anchor lookup (receipt-archive audit only)";
                };
                readonly requireSignatures: {
                    readonly type: "boolean";
                    readonly description: "v0.1 only: false = fixture mode";
                };
            };
            readonly required: readonly ["bundle"];
        };
        readonly handler: (args: Json) => Promise<string>;
    };
    readonly verifier_info: {
        readonly description: "Name, version, API version and the configured Demos RPC of this verifier.";
        readonly inputSchema: {
            readonly type: "object";
            readonly properties: {};
            readonly required: readonly [];
        };
        readonly handler: () => Promise<string>;
    };
};
export declare function handleRequest(request: unknown, config?: McpConfig): Promise<Json | null>;
export declare function serve(config?: McpConfig, input?: NodeJS.ReadableStream, output?: NodeJS.WritableStream): Promise<void>;
export {};
