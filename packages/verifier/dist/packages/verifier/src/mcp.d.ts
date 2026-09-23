#!/usr/bin/env node
import { type VerifyDocumentOptions } from '../../../src/lib/verify-document.js';
export declare const MCP_PROTOCOL_VERSION = "2024-11-05";
/** Largest accepted stdio frame (one JSON-RPC line); the HTTP service has the same body budget. */
export declare const MAX_FRAME_BYTES = 1048576;
export declare const MCP_VERIFICATION_POLICIES: readonly ["live-enforcing", "offline-enforcing", "offline-fixture"];
export type McpVerificationPolicy = typeof MCP_VERIFICATION_POLICIES[number];
export interface McpConfig {
    rpc?: string;
    fetchAnchoredImpl?: VerifyDocumentOptions['fetchAnchoredImpl'];
    /**
     * Server-owned policy. Clients may echo the effective booleans for compatibility but cannot
     * weaken them. `offline-fixture` is deliberately explicit: it is the only mode that disables
     * cryptographic signature enforcement, and it never claims live anchoring.
     */
    verificationPolicy?: McpVerificationPolicy;
}
type Json = Record<string, unknown>;
export declare function tools(config: McpConfig): {
    readonly verify_bundle: {
        readonly description: "Verify a DACS attestation bundle (v0.1 bundleVersion \"1\" or legacy dacs-5-bundle:0.1) under server policy live-enforcing. Returns pass, fail or indeterminate, never coerced. Offline modes do not claim two-sided anchoring." | "Verify a DACS attestation bundle (v0.1 bundleVersion \"1\" or legacy dacs-5-bundle:0.1) under server policy offline-enforcing. Returns pass, fail or indeterminate, never coerced. Offline modes do not claim two-sided anchoring." | "Verify a DACS attestation bundle (v0.1 bundleVersion \"1\" or legacy dacs-5-bundle:0.1) under server policy offline-fixture. Returns pass, fail or indeterminate, never coerced. Offline modes do not claim two-sided anchoring.";
        readonly inputSchema: {
            readonly type: "object";
            readonly properties: {
                readonly bundle: {
                    readonly type: "object";
                    readonly description: "the AttestationBundle document";
                };
                readonly offline: {
                    readonly type: "boolean";
                    readonly description: `compatibility echo only; server policy requires ${string}`;
                };
                readonly requireSignatures: {
                    readonly type: "boolean";
                    readonly description: `compatibility echo only; server policy requires ${string}`;
                };
            };
            readonly required: readonly ["bundle"];
            readonly additionalProperties: false;
        };
        readonly handler: (args: Json) => Promise<string>;
    };
    readonly verifier_info: {
        readonly description: "Name, version, API version, configured Demos RPC and effective server-owned verification policy.";
        readonly inputSchema: {
            readonly type: "object";
            readonly properties: {};
            readonly required: readonly [];
            readonly additionalProperties: false;
        };
        readonly handler: (args: Json) => Promise<string>;
    };
};
export declare function handleRequest(request: unknown, config?: McpConfig): Promise<Json | null>;
export declare function serve(config?: McpConfig, input?: NodeJS.ReadableStream, output?: NodeJS.WritableStream): Promise<void>;
export {};
