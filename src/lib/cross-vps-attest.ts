/**
 * Cross-VPS multi-attestation harness — DAHR single-node-relay trust-gap closure
 *
 * Spec source: DACS v0.7 §7.3.5 (consensus-backed-proxy) + §7.5 (VerifyResult).
 * PATH-OS Labs extension — NOT part of the normative DACS v1 spec list.
 *
 * The gap this closes:
 *   src/demos/dahr.ts (the v0.2 DAHR stub) issues a web2 request from a SINGLE
 *   process and anchors the response. Its own header is explicit about the limit:
 *   "Receipt does NOT prove the response was unmodified relative to what the
 *   validator saw." A single node can be MITM'd, geo-fenced, or serve a doctored
 *   response and the receipt would still verify against itself.
 *
 *   This harness issues the SAME request from N independent nodes (PATH-OS Labs'
 *   three Contabo VPS: R1 NA, R2/R3 EU), hashes each node's normalised response
 *   with JCS+SHA-256, has each node sign its own response hash with its own
 *   ed25519 key, then produces an n-of-m SIGNED agreement receipt on the agreed
 *   response hash — plus a divergence report naming every node that disagreed.
 *
 * Trust property gained:
 *   "≥ threshold independent nodes, in distinct regions, each cryptographically
 *    attests they saw the SAME response bytes." A doctored response now has to
 *    fool a quorum of geographically-separated nodes simultaneously.
 *
 * Conformance maintained:
 *   - Every signature uses the §7.7 domain-separated ed25519 pattern via src/lib/sign.ts.
 *   - Response hashes are JCS-canonical (RFC 8785) via src/jcs.ts — same canonical
 *     form every node and every verifier computes.
 *   - decision ∈ {'agreed','no-quorum'} is never coerced (sibling to §7.5.1).
 *
 * Testability:
 *   The fan-out takes injectable NodeAttestor functions, so tests pass mocked
 *   per-node responses. A real deployment wires each NodeAttestor to one VPS over
 *   HTTPS (e.g. POST the request spec to a small relay endpoint on R1/R2/R3).
 */

import { jcsHashHex } from '../jcs.js';
import { sign, verify as edVerify } from './sign.js';
import { PATHOS_EXTENSION_SEPARATORS } from '../domain-sep.js';
import { bytesToHex, hexToBytes } from './verify-bundle.js';

/** The web2 request, replicated verbatim to every node. Caller-defined shape. */
export interface CrossVpsRequest {
  /** HTTPS URL every node fetches. */
  url: string;
  /** HTTP method (default GET at the node). */
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  /** Request headers replicated to every node. */
  headers?: Record<string, string>;
  /** Request body (POST/PUT). */
  body?: string;
}

/**
 * Per-node fetch function — injectable so tests mock the fleet.
 *
 * A real deployment wires this to one VPS: it POSTs the CrossVpsRequest to a
 * relay endpoint on R1/R2/R3 over HTTPS and returns the node's raw response.
 * `rawResponse` is whatever the node fetched (parsed JSON object, string, etc.);
 * normalisation + hashing happen here, identically for every node.
 */
export type NodeAttestor = (
  request: CrossVpsRequest
) => Promise<{ nodeId: string; region: string; rawResponse: unknown }>;

/**
 * The ed25519 signing material for one node. nodeId binds a signer to the
 * NodeAttestor that produced the response; pubkeyId is the public-key reference
 * a verifier resolves to re-check the signature.
 */
export interface NodeSigner {
  nodeId: string;
  /** 32-byte ed25519 private key. */
  privKey: Uint8Array;
  /** 32-byte ed25519 public key. */
  pubKey: Uint8Array;
  /** Stable public-key reference recorded in the attestation (e.g. hex pubkey or a key id). */
  pubkeyId: string;
}

/** One node's signed attestation that it saw a particular response. */
export interface NodeAttestation {
  nodeId: string;
  region: string;
  /** sha256-hex of JCS(normalised response). */
  responseHash: string;
  /** ed25519 signature (hex) over the domain-separated responseHash. */
  signature: string;
  /** Public-key reference a verifier resolves to re-check `signature`. */
  pubkeyId: string;
}

/** The n-of-m signed agreement receipt over a response hash, with a divergence report. */
export interface CrossVpsAgreementReceipt {
  v: 'pathos-cross-vps-agreement:0.1';
  /** Caller-supplied reference identifying the request this receipt is about. */
  requestRef: string;
  /** The response hash the quorum agreed on (empty string when 'no-quorum'). */
  agreedResponseHash: string;
  /** n = matching attestations on the agreed hash; m = total attestations collected. */
  quorum: { n: number; m: number };
  /** Threshold required to declare agreement (n-of-m). */
  threshold: number;
  /** Every node's attestation (agreeing + divergent). */
  attestations: NodeAttestation[];
  decision: 'agreed' | 'no-quorum';
  /** Nodes whose responseHash differs from the agreed (majority) hash. */
  divergences: { nodeId: string; responseHash: string }[];
}

/** VerifyResult-style outcome for a receipt re-verification (sibling to types/verify-result.ts). */
export interface CrossVpsVerifyResult {
  ok: boolean;
  decision: 'agreed' | 'no-quorum';
  reason: string;
}

/**
 * Normalise a node's raw response into the canonical value that gets hashed.
 *
 * The JCS canonicalizer (src/jcs.ts) already orders object keys and normalises
 * number/string forms per RFC 8785, so for objects this is the identity — JCS
 * does the work. We keep this seam explicit so a deployment can strip volatile
 * fields (server timestamps, request-ids) BEFORE hashing if a given endpoint
 * embeds them; otherwise every node would diverge on noise. v0.1 passes the
 * value through unchanged.
 */
export function normaliseResponse(rawResponse: unknown): unknown {
  return rawResponse;
}

/** Domain-separated signed bytes body for a response hash: utf8(responseHashHex). */
function responseHashBody(responseHash: string): Uint8Array {
  return new TextEncoder().encode(responseHash);
}

/** Compute the JCS+SHA-256 hex response hash for a node's raw response. */
export function hashResponse(rawResponse: unknown): string {
  return jcsHashHex(normaliseResponse(rawResponse));
}

/**
 * Pick the majority response hash and its match count.
 *
 * Groups attestations by responseHash, returns the hash with the most matches.
 * Deterministic tie-break: when two hashes have equal counts, the
 * lexicographically-smaller hex hash wins, so every verifier picks the same
 * majority hash from the same attestation set.
 */
function pickMajority(attestations: NodeAttestation[]): { hash: string; count: number } {
  const counts = new Map<string, number>();
  for (const a of attestations) {
    counts.set(a.responseHash, (counts.get(a.responseHash) ?? 0) + 1);
  }
  let bestHash = '';
  let bestCount = 0;
  for (const [hash, count] of counts) {
    if (count > bestCount || (count === bestCount && hash < bestHash)) {
      bestHash = hash;
      bestCount = count;
    }
  }
  return { hash: bestHash, count: bestCount };
}

/**
 * Fan out `request` to every NodeAttestor, hash + sign each response, group by
 * hash, and emit an n-of-m signed agreement receipt.
 *
 * @param request    The web2 request replicated verbatim to every node.
 * @param requestRef Caller reference recorded in the receipt.
 * @param attestors  Per-node fetch functions (mocked in tests; one-per-VPS in prod).
 * @param signers    ed25519 signing material keyed by nodeId — every attestor's
 *                   nodeId MUST have a matching signer.
 * @param threshold  n-of-m matching attestations required to declare 'agreed'.
 */
export async function buildCrossVpsAttestation(
  request: CrossVpsRequest,
  requestRef: string,
  attestors: NodeAttestor[],
  signers: NodeSigner[],
  threshold: number
): Promise<CrossVpsAgreementReceipt> {
  if (attestors.length === 0) {
    throw new Error('buildCrossVpsAttestation: at least one NodeAttestor is required');
  }
  if (threshold < 1) {
    throw new Error(`buildCrossVpsAttestation: threshold must be >= 1 (got ${threshold})`);
  }

  const signerByNode = new Map<string, NodeSigner>();
  for (const s of signers) signerByNode.set(s.nodeId, s);

  // Fan out concurrently — every node fetches the same request independently.
  const responses = await Promise.all(attestors.map((attest) => attest(request)));

  const attestations: NodeAttestation[] = responses.map(({ nodeId, region, rawResponse }) => {
    const signer = signerByNode.get(nodeId);
    if (!signer) {
      throw new Error(
        `buildCrossVpsAttestation: no signer registered for nodeId="${nodeId}" — ` +
        `every attestor's nodeId must have a matching NodeSigner`
      );
    }
    const responseHash = hashResponse(rawResponse);
    // Each node signs its OWN response hash with its OWN key (domain-separated).
    const sig = sign(PATHOS_EXTENSION_SEPARATORS.CROSS_VPS_ATTESTATION, responseHashBody(responseHash), signer.privKey);
    return {
      nodeId,
      region,
      responseHash,
      signature: bytesToHex(sig),
      pubkeyId: signer.pubkeyId,
    };
  });

  const majority = pickMajority(attestations);
  const agreed = majority.count >= threshold;
  const agreedResponseHash = agreed ? majority.hash : '';

  // Divergences: every node NOT on the agreed hash. When no quorum, the "agreed"
  // hash is empty, so every node is a divergence (the report names them all).
  const divergences = attestations
    .filter((a) => a.responseHash !== agreedResponseHash)
    .map((a) => ({ nodeId: a.nodeId, responseHash: a.responseHash }));

  return {
    v: 'pathos-cross-vps-agreement:0.1',
    requestRef,
    agreedResponseHash,
    quorum: { n: agreed ? majority.count : 0, m: attestations.length },
    threshold,
    attestations,
    decision: agreed ? 'agreed' : 'no-quorum',
    divergences,
  };
}

/**
 * Re-verify a CrossVpsAgreementReceipt independently of who produced it.
 *
 * Walk:
 *   1. Re-verify every attestation's ed25519 signature over its own responseHash.
 *   2. Recompute the majority hash + count from the attestations.
 *   3. Confirm the receipt's decision + agreedResponseHash + quorum.n + divergences
 *      are consistent with that independent recomputation.
 *
 * Returns a VerifyResult-style {ok, decision, reason}. ok=false on ANY
 * inconsistency (bad signature, miscounted quorum, wrong agreed hash, wrong
 * divergence set, or a decision that contradicts the threshold).
 */
export function verifyCrossVpsAgreementReceipt(receipt: CrossVpsAgreementReceipt): CrossVpsVerifyResult {
  const { attestations, threshold } = receipt;

  if (attestations.length === 0) {
    return { ok: false, decision: receipt.decision, reason: 'receipt has no attestations' };
  }
  if (receipt.quorum.m !== attestations.length) {
    return {
      ok: false,
      decision: receipt.decision,
      reason: `quorum.m=${receipt.quorum.m} does not equal attestation count ${attestations.length}`,
    };
  }

  // 1. Re-verify every attestation signature.
  for (const a of attestations) {
    let pubKey: Uint8Array;
    try {
      pubKey = hexToBytes(a.pubkeyId);
    } catch (e) {
      return {
        ok: false,
        decision: receipt.decision,
        reason: `node "${a.nodeId}" pubkeyId is not valid hex: ${(e as Error).message}`,
      };
    }
    let sig: Uint8Array;
    try {
      sig = hexToBytes(a.signature);
    } catch (e) {
      return {
        ok: false,
        decision: receipt.decision,
        reason: `node "${a.nodeId}" signature is not valid hex: ${(e as Error).message}`,
      };
    }
    const sigOk = edVerify(
      PATHOS_EXTENSION_SEPARATORS.CROSS_VPS_ATTESTATION,
      sig,
      responseHashBody(a.responseHash),
      pubKey
    );
    if (!sigOk) {
      return {
        ok: false,
        decision: receipt.decision,
        reason: `node "${a.nodeId}" signature did NOT verify over its responseHash (separator="${PATHOS_EXTENSION_SEPARATORS.CROSS_VPS_ATTESTATION}")`,
      };
    }
  }

  // 2. Recompute the majority independently.
  const majority = pickMajority(attestations);
  const agreed = majority.count >= threshold;
  const expectedHash = agreed ? majority.hash : '';
  const expectedDecision: 'agreed' | 'no-quorum' = agreed ? 'agreed' : 'no-quorum';

  // 3. Consistency checks against the receipt's recorded values.
  if (receipt.decision !== expectedDecision) {
    return {
      ok: false,
      decision: expectedDecision,
      reason: `decision="${receipt.decision}" contradicts recomputed quorum (count=${majority.count}, threshold=${threshold} ⇒ "${expectedDecision}")`,
    };
  }
  if (receipt.agreedResponseHash !== expectedHash) {
    return {
      ok: false,
      decision: expectedDecision,
      reason: `agreedResponseHash="${receipt.agreedResponseHash.slice(0, 16)}…" does not match recomputed majority hash "${expectedHash.slice(0, 16)}…"`,
    };
  }
  if (agreed && receipt.quorum.n !== majority.count) {
    return {
      ok: false,
      decision: expectedDecision,
      reason: `quorum.n=${receipt.quorum.n} does not match recomputed match count ${majority.count}`,
    };
  }
  if (!agreed && receipt.quorum.n !== 0) {
    return {
      ok: false,
      decision: expectedDecision,
      reason: `no-quorum receipt must record quorum.n=0 (got ${receipt.quorum.n})`,
    };
  }

  // Divergence set must be exactly the nodes NOT on the agreed hash.
  const expectedDivergent = attestations
    .filter((a) => a.responseHash !== expectedHash)
    .map((a) => a.nodeId)
    .sort();
  const recordedDivergent = receipt.divergences.map((d) => d.nodeId).sort();
  if (expectedDivergent.length !== recordedDivergent.length ||
      expectedDivergent.some((id, i) => id !== recordedDivergent[i])) {
    return {
      ok: false,
      decision: expectedDecision,
      reason: `divergence set mismatch: recorded [${recordedDivergent.join(', ')}], expected [${expectedDivergent.join(', ')}]`,
    };
  }
  // Each recorded divergence hash must match that node's actual attestation hash.
  for (const d of receipt.divergences) {
    const att = attestations.find((a) => a.nodeId === d.nodeId);
    if (!att || att.responseHash !== d.responseHash) {
      return {
        ok: false,
        decision: expectedDecision,
        reason: `divergence record for "${d.nodeId}" has responseHash inconsistent with its attestation`,
      };
    }
  }

  return {
    ok: true,
    decision: expectedDecision,
    reason: agreed
      ? `${majority.count}-of-${attestations.length} nodes agreed on ${expectedHash.slice(0, 16)}… (threshold ${threshold}); all signatures verified`
      : `no quorum: best match ${majority.count}-of-${attestations.length} < threshold ${threshold}; all signatures verified`,
  };
}
