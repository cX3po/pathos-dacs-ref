/**
 * verify-http — the one request handler behind every HTTP-shaped verify surface.
 *
 * `packages/verifier/src/http.ts` (the packaged service) and `src/live/verify-endpoint.mts`
 * (the d402-gated endpoint) both call `handleVerifyRequest()`: body validation, the `rpc`
 * refusal, the indeterminate-on-failure rule and the result shape live here once.
 */
import { VERIFIER_API_VERSION, indeterminateVerdict, verifyDocument } from './verify-document.js';
export const MAX_VERIFY_BODY_BYTES = 1_048_576;
/** Parse and validate a verify request body; returns the 400 problem or the parsed request. */
export function parseVerifyRequest(bodyText) {
    let parsed;
    try {
        parsed = JSON.parse(bodyText);
    }
    catch (e) {
        return { ok: false, error: `request body is not valid JSON: ${e.message}` };
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed))
        return { ok: false, error: 'request body must be a JSON object' };
    const req = parsed;
    if (!req.bundle || typeof req.bundle !== 'object' || Array.isArray(req.bundle))
        return { ok: false, error: 'bundle must be a JSON object' };
    for (const flag of ['offline', 'requireSignatures']) {
        if (req[flag] !== undefined && typeof req[flag] !== 'boolean')
            return { ok: false, error: `${flag} must be a boolean` };
    }
    if (req.rpc !== undefined)
        return { ok: false, error: 'rpc is server configuration, not a request field' };
    return { ok: true, bundle: req.bundle, offline: req.offline, requireSignatures: req.requireSignatures };
}
/** Validate the body and verify. A well-formed request always yields 200 with a verdict, never coerced. */
export async function handleVerifyRequest(bodyText, config = {}) {
    const req = parseVerifyRequest(bodyText);
    if (!req.ok)
        return { status: 400, body: { error: req.error } };
    try {
        const result = await verifyDocument(req.bundle, {
            rpc: config.rpc,
            offline: config.forceOffline === true ? true : (config.lockRequestOptions ? false : req.offline),
            requireSignatures: config.lockRequestOptions ? undefined : req.requireSignatures,
            fetchAnchoredImpl: config.fetchAnchoredImpl,
        });
        return { status: 200, body: result };
    }
    catch (e) {
        // An RPC or internal failure is "could not reach a verdict": indeterminate, never fail or pass.
        // `incomplete` tells a caller that this is the verifier's own failure, not a verdict about the bundle;
        // the payment gate keys on it rather than on the step name, which a real verdict is free to use.
        const detail = `verification did not complete: ${e.message}`;
        const verdict = indeterminateVerdict('verifier', detail);
        return { status: 200, body: { apiVersion: VERIFIER_API_VERSION, bundleKind: 'unrecognised', verdict, exitCode: 2 }, incomplete: detail };
    }
}
