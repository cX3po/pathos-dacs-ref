// DACS-2 Governance — §14.7 conformance surface (GOV-1..GOV-3) over the
// progressive-anchoring scheme (§7.4.4 PA-1..PA-3) and the steward-disclosure
// rules (§12 / §11.1.1). Read-only: this module reasons about how a consumer
// reads governance metadata, not how a registry writes it. No key handling,
// no anchoring — recipe signature verification and pinning stay in DACS-2 vet.

// §7.4.1/§7.4.4 — the closed set of `governance.anchoring` phases. Each maps to
// a progressive-anchoring phase: in-code = PA-1 (bootstrap), single-signer =
// PA-2 (current single-steward), multisig = PA-3 (constituted body).
export type AnchoringPhase = "in-code" | "single-signer" | "multisig";
export const ANCHORING_PHASES: readonly AnchoringPhase[] = ["in-code", "single-signer", "multisig"];

export type GovResult = { ok: true } | { ok: false; reason: string };

/** GOV-2: classify a raw `governance.anchoring` string against the closed §7.4.1 set; throws on anything else. */
export function classifyAnchoringPhase(raw: string): AnchoringPhase {
  if ((ANCHORING_PHASES as readonly string[]).includes(raw)) return raw as AnchoringPhase;
  throw new Error(`§7.4.4 GOV-2: anchoring phase must be one of ${ANCHORING_PHASES.join("/")}, got ${JSON.stringify(raw)}`);
}

/**
 * §7.4.4: a recipe marked `in-code` (PA-1 bootstrap) MUST NOT be presented as
 * canonically anchored. `single-signer` (PA-2) and `multisig` (PA-3) ARE
 * canonically anchored. This is the GOV-3 "in-code ≠ canonically anchored"
 * predicate, isolated so both the eval path and callers can reuse it.
 */
export function isCanonicallyAnchored(phase: AnchoringPhase): boolean {
  return phase !== "in-code";
}

// ── GOV-1: steward disclosure (ADVISORY — see note) ─────────────────────────
// §12 / §11.1.1 / §14.7: a registry consumer MUST (a) surface which signing key
// it treats as authoritative, and (b) MUST NOT misrepresent the current single
// steward (PA-2) as a constituted multi-party body.
//
// IMPORTANT (non-normative): GOV-1 is a behavioural obligation on the consumer's
// own UX/disclosure, not a wire-format rule. DACS v0.1 defines NO wire field for
// "how a consumer presents the steward". The `represents` value below is a
// verifier-internal disclosure HINT this reference uses to make the obligation
// mechanically checkable — it is NOT a DACS wire-field and MUST NOT be read as
// one. GOV-1 is therefore enforced ADVISORILY here, pending any steward-defined
// authoritative representation. The steward owns that normative call.

/** Verifier-internal disclosure hint (NOT a DACS wire-field; see GOV-1 note). */
export type StewardRepresentationHint = "single-steward" | "constituted-body";

export interface StewardDisclosure {
  /** The signing key the consumer surfaces to its users as authoritative (§14.7). */
  authoritativeSigningKey?: string;
  /** How the consumer presents the steward to its users (advisory hint, not a spec wire-field). */
  represents?: StewardRepresentationHint;
  /** The registry's actual operating phase — only `multisig` (PA-3) is a constituted body. */
  actualPhase: AnchoringPhase;
}

/**
 * GOV-1 (advisory): pass iff (a) the consumer surfaces a non-empty authoritative
 * signing key, AND (b) it does not present the steward as a constituted
 * multi-party body unless the registry is actually in the `multisig` phase
 * (PA-3). Claiming `constituted-body` while the registry is `in-code`/
 * `single-signer` is the misrepresentation §12 forbids. The `represents` input
 * is a verifier-internal hint, not a spec wire-field (see the section note).
 */
export function validateStewardDisclosure(d: StewardDisclosure): GovResult {
  // GOV-2 gate: actualPhase is resolved governance metadata crossing a trust
  // boundary — reclassify through the closed §7.4.1 set so a malformed phase is
  // rejected (throws), never trusted. (A JS/parsed caller can defeat the TS type.)
  const actualPhase = classifyAnchoringPhase(d.actualPhase);
  if (typeof d.authoritativeSigningKey !== "string" || d.authoritativeSigningKey.length === 0) {
    return { ok: false, reason: "GOV-1: consumer must surface a non-empty authoritative signing key (§14.7)" };
  }
  if (d.represents === "constituted-body" && actualPhase !== "multisig") {
    return { ok: false, reason: `GOV-1: must not present a ${actualPhase} steward as a constituted multi-party body (§12)` };
  }
  return { ok: true };
}

// ── GOV-3: pin-time anchoring-phase verification ─────────────────────────────
// §7.4.4 + §7.12/§12.4: a VerifyResult pins a recipeVersion. Re-anchoring is
// append-only — the constituted body (PA-3) re-anchors prior recipes only as NEW
// recipeVersions and MUST NOT mutate the signer/content-hash of an
// already-published recipeVersion. So a consumer MUST evaluate a pinned
// recipeVersion against the phase recorded AT PIN TIME, never the current
// registry phase: a single-signer (PA-2) pin stays single-signer even after the
// registry transitions to multisig (PA-3).
//
// Boundary (non-normative): GOV-3 here evaluates the pin-time ANCHORING PHASE
// only. Recipe revocation and steward-key compromise are a SEPARATE mechanism
// (revocation markers + emergency-revision discipline, §7.4.4 / recipe-poisoning
// mitigation) — NOT a phase downgrade — so a later weakening of the registry
// does not flow through this function. Trusting pin-time here is the spec's
// monotonic-pinning guarantee, not a durability claim across revocation; a
// consumer needing revocation-awareness checks the revocation surface separately.

const PHASE_RANK: Record<AnchoringPhase, number> = { "in-code": 0, "single-signer": 1, "multisig": 2 };

export interface PinnedRecipeEval {
  recipeVersion: number;
  /** `governance.anchoring` recorded when this recipeVersion was anchored / pinned. */
  pinTimePhase: AnchoringPhase;
  /** Current registry phase. Informational only — MUST NOT override pin-time (append-only re-anchoring). */
  currentPhase?: AnchoringPhase;
  /** The consumer's own trust floor; a pin-time phase below it fails GOV-3. */
  requiredMinPhase?: AnchoringPhase;
}

export interface GovEvalDecision {
  recipeVersion: number;
  /** Always equals `pinTimePhase` — proves pin-time, not current registry state, governs. */
  evaluatedPhase: AnchoringPhase;
  canonicallyAnchored: boolean;
  ok: boolean;
  reason?: string;
}

/**
 * GOV-3: evaluate a pinned recipeVersion. The evaluated phase is ALWAYS the
 * pin-time phase (a later PA-3 re-anchoring MUST NOT retro-upgrade an
 * already-pinned PA-2 recipeVersion). An `in-code` pin is reported as not
 * canonically anchored. If the consumer set a `requiredMinPhase`, a pin-time
 * phase below it fails.
 */
export function evaluatePinnedRecipe(p: PinnedRecipeEval): GovEvalDecision {
  // GOV-2 gate: pinTimePhase / requiredMinPhase are resolved recipe metadata
  // crossing a trust boundary — reclassify through the closed §7.4.1 set before
  // any anchoring/trust decision, so an unrecognised phase is rejected (throws)
  // rather than defaulting to "anchored" or a `undefined` rank that skips the
  // trust floor (fail-closed). pin-time governs — currentPhase is never consulted.
  const evaluatedPhase = classifyAnchoringPhase(p.pinTimePhase);
  const minPhase = p.requiredMinPhase === undefined ? undefined : classifyAnchoringPhase(p.requiredMinPhase);
  const canonicallyAnchored = isCanonicallyAnchored(evaluatedPhase);
  if (minPhase && PHASE_RANK[evaluatedPhase] < PHASE_RANK[minPhase]) {
    return {
      recipeVersion: p.recipeVersion,
      evaluatedPhase,
      canonicallyAnchored,
      ok: false,
      reason: `GOV-3: pin-time phase ${evaluatedPhase} below consumer trust floor ${minPhase} (§7.4.4)`,
    };
  }
  return { recipeVersion: p.recipeVersion, evaluatedPhase, canonicallyAnchored, ok: true };
}
