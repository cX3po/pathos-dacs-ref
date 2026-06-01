/**
 * DACS-2 recipe.availability preflight (§7.4.5)
 *
 * Spec source: DACS v0.7 + DACS-1..5 v0.1, §7.4.5 (now-normative `recipe.availability` field)
 *
 * **LOAD-BEARING NORMATIVE RULE (§7.4.5 / RAV — Recipe Availability Vetting):**
 *   A verifier MUST refuse to run a recipe whose declared availability is
 *   `disabled` or `failed` (the recipe cannot produce a trustworthy result).
 *   Such a refusal is a hard preflight error (decision = 'error'), NOT a
 *   verification verdict — the recipe never ran, so it cannot pass / fail /
 *   indeterminate per §7.5.1.
 *
 *   A verifier MUST treat an ABSENT availability field as `mocked` (fail-safe):
 *   a recipe that does not declare its availability is assumed to be a mock /
 *   stub, so high-stakes consumers can refuse it on policy grounds while
 *   low-stakes flows may proceed knowing the result is not authoritative.
 *
 * Relationship to §7.5.1: the three VerifyDecision values (pass/fail/indeterminate)
 * describe the OUTCOME of running a recipe. RAV runs strictly BEFORE that — it
 * decides whether the recipe is even allowed to run. A blocked preflight yields
 * `decision = 'error'`, a distinct band that callers MUST NOT fold into a
 * verification verdict (in particular MUST NOT coerce to 'pass').
 *
 * This module is self-contained: it defines the §7.4.5 enum + preflight result
 * shape itself (matching DACS v0.1) and has no external dependencies.
 */

/**
 * §7.4.5 RecipeAvailability — the declared operational state of a verification recipe.
 *
 *   - 'available' : recipe is live and authoritative; safe to run.
 *   - 'mocked'    : recipe returns canned / stubbed output; runnable but NOT authoritative.
 *                   Also the fail-safe value assumed when the field is ABSENT.
 *   - 'degraded'  : recipe is live but operating below full fidelity (e.g. a fallback
 *                   data source). Runnable; the verifier SHOULD downgrade confidence.
 *   - 'disabled'  : recipe is intentionally turned off. MUST refuse to run (decision='error').
 *   - 'failed'    : recipe's backing service is broken / erroring. MUST refuse to run (decision='error').
 */
export enum RecipeAvailability {
  Available = 'available',
  Mocked = 'mocked',
  Degraded = 'degraded',
  Disabled = 'disabled',
  Failed = 'failed',
}

/**
 * Minimal recipe shape RAV inspects. Self-contained (matches the §7.4.5 field
 * on the larger DACS-2 recipe descriptor) so this module needn't import the
 * full recipe type.
 *
 * `availability` is optional precisely so the absent-field fail-safe is
 * expressible at the type level.
 */
export interface RecipeAvailabilityDescriptor {
  /** Recipe id@version, for diagnostics in the preflight reason string. */
  recipe?: string;
  /** §7.4.5 declared availability. ABSENT ⇒ treated as 'mocked' (fail-safe). */
  availability?: RecipeAvailability | `${RecipeAvailability}`;
}

/**
 * Structured RAV preflight result.
 *
 *   - proceed=true  : the recipe is allowed to run. `effectiveAvailability` is
 *                     the value the caller should act on (the absent field is
 *                     resolved to 'mocked' here so the caller never re-derives it).
 *   - proceed=false : the recipe MUST NOT run. `decision` is always 'error' in
 *                     this band (a preflight block is not a verification verdict).
 */
export interface PreflightResult {
  /** Whether the verifier may run the recipe. */
  proceed: boolean;
  /**
   * Preflight error band. Present (and always 'error') iff proceed=false.
   * Distinct from VerifyDecision (§7.5.1) — a blocked recipe never ran, so it
   * has no pass/fail/indeterminate verdict; callers MUST NOT coerce to 'pass'.
   */
  decision?: 'error';
  /** Human-readable reason, structured-where-possible. */
  reason: string;
  /**
   * The availability the caller should act on. Equals the declared value, or
   * 'mocked' when the field was absent (fail-safe resolution). Always set.
   */
  effectiveAvailability: RecipeAvailability;
}

/** Set of availability values that MUST block the recipe from running (§7.4.5). */
const BLOCKING: ReadonlySet<RecipeAvailability> = new Set<RecipeAvailability>([
  RecipeAvailability.Disabled,
  RecipeAvailability.Failed,
]);

/** All known availability string values, for validation of unknown inputs. */
const KNOWN_AVAILABILITY: ReadonlySet<string> = new Set<string>(
  Object.values(RecipeAvailability),
);

/**
 * RAV preflight for a single recipe (§7.4.5).
 *
 * Rules:
 *   1. ABSENT availability  → treat as 'mocked' (fail-safe), proceed=true.
 *   2. 'disabled' | 'failed' → MUST refuse: proceed=false, decision='error'.
 *   3. 'available' | 'mocked' | 'degraded' → proceed=true.
 *   4. Any unrecognized string → fail-safe to refusal: a value the verifier
 *      does not understand is treated as un-runnable (proceed=false,
 *      decision='error') rather than silently assumed safe.
 *
 * @param recipe the recipe descriptor carrying the §7.4.5 availability field.
 * @returns a structured {proceed, decision?, reason, effectiveAvailability}.
 */
export function preflightRecipe(recipe: RecipeAvailabilityDescriptor): PreflightResult {
  const label = recipe.recipe ? `recipe "${recipe.recipe}"` : 'recipe';
  const raw = recipe.availability;

  // Rule 1 — absent field is the fail-safe 'mocked'.
  if (raw === undefined || raw === null) {
    return {
      proceed: true,
      reason:
        `${label}: availability field absent — §7.4.5 fail-safe treats absent availability as ` +
        `'mocked' (runnable but NOT authoritative; high-stakes consumers SHOULD refuse).`,
      effectiveAvailability: RecipeAvailability.Mocked,
    };
  }

  // Rule 4 — unrecognized value is treated as un-runnable (fail-safe to refusal).
  if (!KNOWN_AVAILABILITY.has(raw)) {
    return {
      proceed: false,
      decision: 'error',
      reason:
        `${label}: unrecognized availability="${String(raw)}" — not in the §7.4.5 enum ` +
        `(available|mocked|degraded|disabled|failed). Verifier refuses to run an availability ` +
        `state it does not understand.`,
      // Surface the safest interpretation for callers that still want a value.
      effectiveAvailability: RecipeAvailability.Disabled,
    };
  }

  const availability = raw as RecipeAvailability;

  // Rule 2 — disabled | failed MUST block.
  if (BLOCKING.has(availability)) {
    return {
      proceed: false,
      decision: 'error',
      reason:
        `${label}: availability="${availability}" — §7.4.5 verifier MUST refuse to run a ` +
        `${availability} recipe (a blocked preflight is decision='error', NOT a verification ` +
        `verdict; MUST NOT be coerced to 'pass' per §7.5.1).`,
      effectiveAvailability: availability,
    };
  }

  // Rule 3 — available | mocked | degraded are runnable.
  const note =
    availability === RecipeAvailability.Available
      ? 'live and authoritative.'
      : availability === RecipeAvailability.Degraded
        ? 'live but degraded — caller SHOULD downgrade confidence.'
        : 'mocked — runnable but NOT authoritative; high-stakes consumers SHOULD refuse.';
  return {
    proceed: true,
    reason: `${label}: availability="${availability}" — ${note}`,
    effectiveAvailability: availability,
  };
}
