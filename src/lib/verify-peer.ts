/**
 * verifyPeer() — a DACS peer-trust primitive + A2A middleware.
 *
 * THE A2A SEAM (#194 composition-precision doctrine, made concrete):
 * -----------------------------------------------------------------
 * The A2A ecosystem's unsolved problem is TRUSTING A STRANGER'S AGENT. Before an agent accepts a
 * task from a peer it has never seen, it has an AgentCard (the peer's `.well-known/agent.json`
 * discovery surface: a name + an identity claim + an optional self-signature). An AgentCard is
 * DISCOVERY EVIDENCE — it says who the peer *claims* to be. It is NOT trust: a stranger can put
 * any name and any identity in their own card, and even self-sign it. Trust has to be EARNED
 * against something the peer cannot forge.
 *
 * DACS is that something. `verifyPeer()` runs the §10.4.1 acceptance verifier (`verifyBundleV1`)
 * over the peer's AttestationBundle, then BINDS the card's claimed identity to the identity the
 * bundle CRYPTOGRAPHICALLY PROVES signed. The bundle is the evidence DACS binds; the AgentCard is
 * merely the reference being resolved. This is the #194 rule: **an A2A AgentCard is evidence DACS
 * binds, not trust it inherits.** DACS records its OWN verifier act — it never borrows the card's
 * self-assertion as a pass.
 *
 * THE DO-NOT-COLLAPSE INVARIANT (§7.5.1, the load-bearing rule):
 *   trusted === (decision === 'accept' && identityBound)
 *   Anything else — reject, indeterminate, error, or an unbound identity — is trusted=false.
 *   An UNRESOLVABLE or AMBIGUOUS reference is `indeterminate`, NEVER a borrowed `pass`.
 *   "Can't decide" is NOT "trusted". This module NEVER returns trusted=true on an indeterminate.
 *
 * The AgentCard's optional `agentCardSignature` is DELIBERATELY NOT a trust input here: a
 * self-signature over one's own card proves only that the card-holder holds the card-key — it is
 * discovery-layer provenance, not a third-party-verifiable trust act. Trust flows solely from the
 * DACS bundle binding. (Recording it as untrusted metadata is itself the #194 discipline.)
 *
 * DEFENSIVE, non-adversarial: this proves a peer IS who a verifiable bundle says it is, or honestly
 * declines. No network, no funds, no deployed identities — the verifier it wraps is offline crypto.
 */
import type { AttestationBundleV1, BundleParty } from '../types/bundle.js';
import { verifyBundleV1, claimKey, type BundleV1Verdict, type SigCheck } from './verify-bundle-v1.js';

/**
 * The A2A `.well-known/agent.json` discovery surface (minimal shape we bind against). `identity`
 * is the peer's claimed DACS claim reference (scheme:identifier). `agentCardSignature` is the
 * peer's optional self-signature over its own card — carried for completeness but NOT trusted
 * (see module header: discovery ≠ trust).
 */
export interface A2AAgentCard {
  name: string;
  identity: { scheme: string; identifier: string };
  agentCardSignature?: string;
}

/** What `verifyPeer()` returns — a closed, do-not-collapse-safe trust verdict. */
export interface PeerTrustResult {
  /** The ONLY success flag. True IFF decision==='accept' AND identityBound. Never true otherwise. */
  trusted: boolean;
  /**
   * The four-value §7.5.1 decision this peer-trust act resolved to:
   *   - 'accept'        : the bundle verified AND the card's identity is bound to a proven signer.
   *   - 'reject'        : hard failure — invalid bundle, OR impersonation (card claims an identity
   *                       the bundle does not prove).
   *   - 'indeterminate' : undecidable — unresolvable peer identity, or the bundle could not be
   *                       cryptographically decided (placeholder DID / unsupported algorithm).
   *                       NEVER collapse this to a pass.
   *   - 'error'         : the trust check itself could not complete (unexpected exception).
   */
  decision: 'accept' | 'reject' | 'indeterminate' | 'error';
  /** True IFF the card's claimed identity matches an identity the bundle cryptographically proves. */
  identityBound: boolean;
  /** Human-readable reason for the verdict (always populated). */
  reason: string;
  /** The single decisive check that denied trust (absent on accept). */
  killedBy?: { check: string; detail: string };
}

export interface VerifyPeerOptions {
  /**
   * Enforcing (default true) vs fixture mode, threaded straight to `verifyBundleV1`. Enforcing =
   * every signature must cryptographically verify for the bundle to `accept`. Only pass `false`
   * for non-normative illustrative fixtures whose signers are placeholder DIDs.
   */
  requireSignatures?: boolean;
}

// ── canonical claim-key — IMPORTED from the verifier (single source of truth, zero drift) ────────
// verify-bundle-v1.ts now EXPORTS `claimKey`; we bind the AgentCard identity with the verifier's
// OWN canonicalisation instead of a copy, so the two can never silently diverge. (2026-07-01:
// Fable + DeepSeek-R1 flagged the prior in-file replication as a drift hazard — this removes it.)

/** Short, human-safe rendering of a canonical key for reasons/logs. */
function shortKey(k: string): string {
  return k.length > 30 ? `${k.slice(0, 30)}…` : k;
}

/**
 * Which single check DECISIVELY denied trust, in the verifier's own precedence order
 * (structural → signer-rule → hard signature failure → indeterminate). Mirrors the sibling
 * gauntlet's `decisiveReason` so the two showcases speak the same language.
 */
function bundleKilledBy(v: BundleV1Verdict): { check: string; detail: string } | null {
  if (v.decision === 'accept') return null;
  if (!v.structurallyValid) {
    return { check: 'structurallyValid=false', detail: v.reasons[0] ?? 'structural validation failed' };
  }
  if (!v.signerRuleSatisfied) {
    const r = v.reasons.find((x) => /unlisted|required signer|buyer \+ seller/.test(x));
    return { check: 'signerRuleSatisfied=false', detail: r ?? 'required-signer rule violated (§10.4.1)' };
  }
  const hardFail: SigCheck | undefined = v.signatureChecks.find((c) => c.decision === 'fail');
  if (hardFail) {
    return { check: 'signature-invalid', detail: `signer ${hardFail.party.slice(0, 22)}… — ${hardFail.reason ?? 'signature failed verification'}` };
  }
  const r = v.reasons.find((x) => /indeterminate/.test(x));
  return { check: 'bundle-indeterminate', detail: r ?? v.reasons[0] ?? 'undecidable (unresolvable key / placeholder DID)' };
}

/**
 * verifyPeer — DACS-verify a stranger's identity + attestation bundle → a trust verdict.
 *
 * Steps:
 *   1. Resolve the peer's AgentCard identity. Absent / malformed / unresolvable → INDETERMINATE
 *      ("cannot resolve peer identity — not a borrowed pass"), trusted=false. Never throws.
 *   2. Run `verifyBundleV1` → the 4-value §10.4.1 acceptance decision.
 *   3. IDENTITY BINDING (the #194 core): the card's claimed identity MUST match an identity the
 *      bundle cryptographically PROVES signed (a signer whose signatureCheck passed). If the bundle
 *      accepts but proves a DIFFERENT identity than the card claims → REJECT (impersonation: the
 *      card claims to be someone the bundle doesn't prove). If the bundle itself is reject/
 *      indeterminate, that bundle-level verdict dominates (trusted=false with the bundle's reason).
 *   4. trusted = (decision==='accept' && identityBound). Anything else → trusted=false.
 */
export function verifyPeer(
  peer: { agentCard: A2AAgentCard; bundle: AttestationBundleV1 },
  opts: VerifyPeerOptions = {},
): PeerTrustResult {
  try {
    // ── Step 1: resolve the peer's claimed identity (discovery surface). ──────────────────────
    const card = peer?.agentCard;
    const identity = card?.identity;
    if (!card || !identity || typeof identity.scheme !== 'string' || typeof identity.identifier !== 'string') {
      return {
        trusted: false,
        decision: 'indeterminate',
        identityBound: false,
        reason: 'cannot resolve peer identity — AgentCard absent or missing a scheme:identifier claim; not a borrowed pass (§7.5.1 do-not-collapse)',
        killedBy: { check: 'peer-identity-unresolvable', detail: 'AgentCard has no usable identity claim' },
      };
    }
    const cardKey = claimKey(identity);
    if (cardKey === null) {
      return {
        trusted: false,
        decision: 'indeterminate',
        identityBound: false,
        reason: `cannot resolve peer identity — AgentCard claim "${identity.scheme}:${identity.identifier}" is not a canonical DACS claim reference (§6.3.1); not a borrowed pass`,
        killedBy: { check: 'peer-identity-unresolvable', detail: `claim "${identity.scheme}:${identity.identifier}" does not canonicalise` },
      };
    }

    // ── Step 2: run the §10.4.1 acceptance verifier over the peer's bundle. ───────────────────
    const verdict = verifyBundleV1(peer.bundle, { requireSignatures: opts.requireSignatures ?? true });

    // Identities the bundle CRYPTOGRAPHICALLY PROVES = signers whose signature check passed.
    // signatureChecks[].party is already the verifier's own claimKey string — same namespace as cardKey.
    const provenSigners = new Set(verdict.signatureChecks.filter((c) => c.decision === 'pass').map((c) => c.party));
    // Identities the bundle merely LISTS as parties (not necessarily proven).
    const listedParties = new Map<string, BundleParty['role']>();
    for (const p of peer.bundle.parties ?? []) {
      const k = claimKey(p.primaryClaim);
      if (k) listedParties.set(k, p.role);
    }
    const identityBound = provenSigners.has(cardKey);

    // ── Step 4: resolve the trust verdict with §7.5.1 precedence. ─────────────────────────────
    if (verdict.decision === 'accept') {
      if (identityBound) {
        const role = listedParties.get(cardKey);
        return {
          trusted: true,
          decision: 'accept',
          identityBound: true,
          reason: `peer trusted: DACS bundle accepts (§10.4.1) and cryptographically proves the AgentCard identity ${shortKey(cardKey)}${role ? ` (bound as ${role})` : ''} signed it`,
        };
      }
      // Bundle is valid and proves identities — but NOT the one the card claims. Impersonation.
      const proven = [...provenSigners].map(shortKey).join(', ') || '(none)';
      return {
        trusted: false,
        decision: 'reject',
        identityBound: false,
        reason: `identity-mismatch: AgentCard claims ${shortKey(cardKey)} but the accepted DACS bundle proves a different identity set {${proven}} — the card claims to be someone the bundle does not prove (#194: discovery ≠ trust)`,
        killedBy: { check: 'identity-mismatch', detail: `card=${shortKey(cardKey)} ∉ proven signers {${proven}}` },
      };
    }

    // Bundle-level reject or indeterminate dominates — the peer's evidence itself did not verify.
    const killedBy = bundleKilledBy(verdict) ?? undefined;
    return {
      trusted: false,
      decision: verdict.decision, // 'reject' | 'indeterminate' — never collapsed to accept
      identityBound, // may be false; on a non-accept bundle we could not prove the binding
      reason:
        verdict.decision === 'indeterminate'
          ? `peer NOT trusted — DACS bundle is indeterminate (undecidable, not a pass): ${verdict.reasons.join('; ') || 'unresolvable signatures'}`
          : `peer NOT trusted — DACS bundle rejected (§10.4.1): ${verdict.reasons.join('; ') || 'bundle failed verification'}`,
      killedBy,
    };
  } catch (e) {
    // Never throw at a trust boundary — an internal failure is `error`, distinct from indeterminate,
    // and (like all non-accept values) trusted=false.
    return {
      trusted: false,
      decision: 'error',
      identityBound: false,
      reason: `peer-trust check could not complete: ${(e as Error).message}`,
      killedBy: { check: 'verifier-error', detail: (e as Error).message },
    };
  }
}

// ── A2A middleware ───────────────────────────────────────────────────────────────────────────────

/** The structured outcome of a trust-gated task handler. */
export type DacsTrustOutcome<R> =
  | { accepted: true; result: R; peerTrust: PeerTrustResult }
  | { accepted: false; peerTrust: PeerTrustResult };

/**
 * withDacsTrust — wrap an A2A task handler so it only runs for a DACS-trusted peer.
 *
 * The returned function, on an incoming `(task, peer)`, first runs `verifyPeer(peer)`. If the peer
 * is NOT trusted (reject / indeterminate / error / unbound) the handler is NEVER called and a
 * structured refusal `{ accepted:false, peerTrust }` is returned. An `indeterminate` peer is
 * DECLINED with its reason — do-not-collapse: "can't decide" is never promoted to "trusted".
 * Only a genuinely trusted peer reaches the handler → `{ accepted:true, result, peerTrust }`.
 */
export function withDacsTrust<Task, Peer extends { agentCard: A2AAgentCard; bundle: AttestationBundleV1 }, R>(
  handler: (task: Task, peer: Peer) => R | Promise<R>,
  opts: VerifyPeerOptions = {},
): (task: Task, peer: Peer) => Promise<DacsTrustOutcome<R>> {
  return async (task: Task, peer: Peer): Promise<DacsTrustOutcome<R>> => {
    const peerTrust = verifyPeer(peer, opts);
    if (!peerTrust.trusted) {
      return { accepted: false, peerTrust };
    }
    const result = await handler(task, peer);
    return { accepted: true, result, peerTrust };
  };
}
