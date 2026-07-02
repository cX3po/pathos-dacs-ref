// DACS-2 (Vet + Governance) — the verifier-side read surface of §7.4/§7.5/§7.6,
// the §6.3.3 match algorithm, and the §7.4.4 progressive-anchoring governance
// checks (§14.2 + §14.7). No name collisions between the two modules.
export * from "./vet.ts";
export * from "./governance.ts";
