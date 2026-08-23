import { isRegisteredSeparator } from "../signing.ts";

// DACS-X — PROPOSED dispute / execution-verification extension (§11.2.1).
//
// NOT part of DACS v0.1. The spec's §7.7 domain-separator registry is declared
// CLOSED; SIG-4 mandates that any artifact kind OUTSIDE that registry use a
// "dacs-x-..." domain separator. These separators therefore live in a SEPARATE
// registry so they never pollute the spec's frozen set — which (a) keeps the
// provenance of every signature honest (a verifier can tell a spec-native
// artifact from a proposed-extension artifact by its separator alone) and
// (b) demonstrates §7.7's own extension mechanism working exactly as written.

export const DACS_X_SEPARATORS = Object.freeze({
  "dacs-x-dispute-record": "dacs-x-dispute-record:v1:",
  "dacs-x-dispute-outcome": "dacs-x-dispute-outcome:v1:",
  // step 3 — §8.7 arbitrator-disclosure authorization (DP-1). The disclosed
  // transcript itself is a NATIVE §8.7 artifact (registered "dacs-transcript:v1:");
  // only the grant that authorizes its disclosure is a dacs-x extension.
  "dacs-x-disclosure-grant": "dacs-x-disclosure-grant:v1:",
} as const);

export type DacsXArtifactKind = keyof typeof DACS_X_SEPARATORS;

// Collision / namespace guard (ISC-19/39), evaluated at module load so a future
// careless edit fails loudly rather than silently shadowing a spec separator.
for (const sep of Object.values(DACS_X_SEPARATORS)) {
  if (!sep.startsWith("dacs-x-")) {
    throw new Error(`DACS-X separator must use the SIG-4 "dacs-x-" namespace: ${sep}`);
  }
  if (isRegisteredSeparator(sep)) {
    throw new Error(`DACS-X separator collides with the §7.7 closed registry: ${sep}`);
  }
}

export function dacsXSeparator(kind: DacsXArtifactKind): string {
  return DACS_X_SEPARATORS[kind];
}
