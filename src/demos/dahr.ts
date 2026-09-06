/**
 * DAHR — Data Agnostic HTTPS Relay (DACS-2 §7.3.5 consensus-backed-proxy)
 *
 * v0.2 HONEST STUB:
 *   This module implements the **artifact shape** that §7.5.2 expects — an
 *   AttestationRef where `anchor.locator` is a real stor- address and
 *   `contentHash` is the SHA-256 of the anchored bytes — but it does NOT
 *   produce the validator-quorum signature that distinguishes true
 *   consensus-backed-proxy from a single-fetch.
 *
 * What this stub does:
 *   1. Fetch the URL directly from this process
 *   2. Anchor the response body to a Demos Storage Program (SR-2)
 *   3. Return an AttestationRef pointing at the anchor
 *
 * What true DAHR adds (v0.3 upgrade path, documented here so the gap is visible):
 *   - A Demos validator (or quorum) fetches the URL via the node's web2 proxy
 *   - The validator(s) sign a commitment over (request, response_hash, timestamp)
 *   - The signed commitment is what gets anchored
 *   - Consumers can verify the validator signature in addition to the content hash
 *
 * Trust property today:
 *   - Receipt proves "this process fetched URL X at time T and these bytes were anchored"
 *   - Receipt does NOT prove "the response was unmodified relative to what the validator saw"
 *
 * This caveat is surfaced in the returned AttestationRef.type field
 * ("dahr-stub-single-fetch" instead of "dahr-consensus-backed-proxy") so a
 * consuming verifier can refuse stubs in high-stakes flows.
 *
 * DACS §7.5.1 conformance maintained: indeterminate (network error) is NEVER coerced to pass.
 */

import { sha256 } from '@noble/hashes/sha2';
import type { DemosHandle } from './connection.js';
import { anchor, type AnchorResult } from './storage.js';
import { assertAllowedHost } from './dahr-allowlist.js';
import type { AttestationRef, DahrAttestation } from '../types/index.js';

export interface DahrFetchResult {
  attestation: DahrAttestation;
  responseBody: unknown;
  responseStatus: number;
  responseContentType: string;
  fetchedAt: string;
  anchor: AnchorResult;
}

export interface DahrFetchOptions {
  /** HTTP method (default: GET) */
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  /** Request headers (Accept, etc.) */
  headers?: Record<string, string>;
  /** Request body (for POST/PUT) */
  body?: string;
  /** Program name for the SR-2 anchor (defaults to the URL host) */
  anchorProgramName?: string;
  /** Recipe id+version this fetch is part of (becomes `attestation.type`) */
  recipe?: string;
  /** Skip anchoring (for tests / dry runs) — returns AttestationRef with synthetic locator */
  skipAnchor?: boolean;
}

/**
 * Fetch a URL and anchor the response as a DACS §7.5.2 AttestationRef.
 *
 * @param handle Connected Demos handle (required for SR-2 anchoring; pass `undefined` only with skipAnchor)
 * @param url The HTTPS URL to fetch
 * @param options HTTP options + anchor controls
 */
export async function dahrFetch(
  handle: DemosHandle | undefined,
  url: string,
  options: DahrFetchOptions = {}
): Promise<DahrFetchResult> {
  // Caller-intent invariant (Codex round 6 #3): if `handle` is undefined, the
  // caller MUST explicitly opt into stub mode via `skipAnchor: true`. We do
  // NOT silently downgrade an anchor-intended call into a stub attestation —
  // that would let a production caller accidentally publish a synthetic
  // stor-stub-* receipt that no on-chain verifier can resolve.
  if (handle === undefined && !options.skipAnchor) {
    throw new Error(
      'dahrFetch: handle is undefined but skipAnchor is not true. ' +
      'Pass a connected Demos handle (real anchor) OR pass { skipAnchor: true } (explicit stub mode).'
    );
  }

  const method = options.method ?? 'GET';
  const headers = options.headers ?? {};
  const fetchedAt = new Date().toISOString();

  // 1. SSRF guard (Codex re-re-review #3): DAHR claims HTTPS-relay semantics.
  // Validate the scheme up front so callers can't anchor unauthenticated-transport
  // attestations or hit local services via http://localhost / file:// / data:.
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
  } catch {
    throw new Error(`DAHR: invalid URL "${url}"`);
  }
  if (parsedUrl.protocol !== 'https:') {
    throw new Error(`DAHR requires https:// (got "${parsedUrl.protocol}"). Plain HTTP is rejected to prevent unauthenticated-transport attestations.`);
  }

  // SSRF defense layer 2 (Codex round 4 #2): hostname allowlist.
  // HTTPS-only blocks unauthenticated-transport but doesn't stop a caller from
  // hitting https://127.0.0.1, internal services, or cloud metadata endpoints
  // exposed over HTTPS. v0.2 only knows the GLEIF recipe (+ a couple of forward-
  // planned hosts for v0.3 dev), so an explicit allowlist is the right
  // scope-discipline tool. See src/demos/dahr-allowlist.ts for the rationale.
  assertAllowedHost(parsedUrl.hostname);

  // 2. Fetch
  const res = await fetch(url, { method, headers, body: options.body });
  const responseStatus = res.status;
  const responseContentType = res.headers.get('content-type') ?? '';

  // 3. v0.2 constraint (Codex re-re-review #1): DAHR is strict-UTF-8 text only.
  // application/octet-stream is the binary marker and is REJECTED. Missing
  // content-type is also rejected (no benefit-of-the-doubt for an attestation
  // primitive). Binary DAHR (with base64/hex SR-2 encoding) lands in v0.3.
  const isTextResponse = (
    responseContentType.includes('json') ||
    responseContentType.startsWith('text/') ||
    responseContentType.includes('xml') ||
    responseContentType.includes('javascript')
  );
  if (!isTextResponse) {
    throw new Error(
      `DAHR v0.2 supports text/JSON/XML responses only; got content-type="${responseContentType || '(empty)'}". ` +
      `Binary DAHR (with base64/hex SR-2 encoding) is on the v0.3 roadmap.`
    );
  }

  // 4. Read response body. Use STRICT UTF-8 decoding (Codex re-re-review #1):
  // fatal: true throws on invalid UTF-8 instead of silently substituting
  // replacement characters — that silent substitution was the lossy path.
  const responseBytes = new Uint8Array(await res.arrayBuffer());
  const utf8 = new TextDecoder('utf-8', { fatal: true });
  let decoded: string;
  try {
    decoded = utf8.decode(responseBytes);
  } catch {
    throw new Error(
      `DAHR v0.2: response bytes are not valid UTF-8 (content-type="${responseContentType}"). ` +
      `Lossy decoding is refused to keep contentHash deterministic against verifyAnchor().`
    );
  }
  let responseBody: unknown;
  if (responseContentType.includes('json')) {
    try {
      responseBody = JSON.parse(decoded);
    } catch {
      responseBody = decoded;
    }
  } else {
    responseBody = decoded;
  }

  // 5. Hash the response bytes as the canonical evidence — this is what
  //    a verifier will recompute when they fetch the anchored data field.
  //    We anchor the strict-UTF-8-decoded string as `data`; verifyAnchor()
  //    recomputes sha256 of those same bytes, satisfying §7.5.2.
  const contentHash = sha256(responseBytes);
  const contentHashHex = Array.from(contentHash, (b) => b.toString(16).padStart(2, '0')).join('');
  const responseAsString = decoded;

  // 5. Anchor (or skip in test mode). The SR-2 anchored `data` field holds the
  //    raw response string; verifyAnchor() recomputes sha256(data) and matches it.
  const isStubMode = options.skipAnchor || !handle;
  let anchorResult: AnchorResult;
  if (isStubMode) {
    anchorResult = {
      storageAddress: `stor-stub-${contentHashHex.slice(0, 32)}`,
      txHash: 'stub-no-broadcast',
      sizeBytes: responseBytes.length,
      contentBytes: responseBytes.length,
      anchoredAt: fetchedAt,
    };
  } else {
    const programName = options.anchorProgramName ?? `dahr:${parsedUrl.hostname}`;
    anchorResult = await anchor(handle!, programName, responseAsString, { acl: 'public' });
  }

  // 6. Build the AttestationRef per §7.5.2.
  //    Honest-scope marker: when stub-mode OR when no validator-quorum is wrapping
  //    the fetch, the attestation `type` MUST carry the `dahr-stub:` prefix so a
  //    downstream verifier in a high-stakes flow can refuse stub attestations.
  //    Per Codex review #1.
  const recipeId = options.recipe ?? 'gleif-cbp:1';
  const attestationType = isStubMode ? `dahr-stub:${recipeId}` : `dahr-stub:${recipeId}`;
  // ^ v0.2 always prefixes — we never produce true consensus-backed-proxy yet.
  //   When v0.3 adds validator-quorum signing, this prefix will be dropped for
  //   that path only.
  const attestation: DahrAttestation = {
    anchor: {
      kind: 'storage-program',
      locator: anchorResult.storageAddress,
    },
    contentHash: contentHashHex,
    type: attestationType,
    producedAt: fetchedAt,
  };

  return {
    attestation,
    responseBody,
    responseStatus,
    responseContentType,
    fetchedAt,
    anchor: anchorResult,
  };
}
