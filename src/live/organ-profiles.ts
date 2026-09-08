/**
 * organ-profiles.ts — the one table that names each sellable proof organ's listing profile.
 *
 * The coordinator (src/live/dacs-testnet-run.mts, `--organ` / ORGAN) and the organ gateway (src/live/organ-gateway.mts,
 * ORGAN) read this table; the public answer projections in the coordinator decide what an organ may anchor, this
 * table decides how it is offered. Every profile sells at the same CD-1 canonical price behind the same pipeline; an
 * organ absent here is a config refusal before any credential read or network call. Queries are the buyer's
 * committed input (a point, a medication name); they are committed by the bridge, never disclosed.
 */

export interface OrganProfile {
  /** Listing offering title (DACS-1 offering.title). */
  title: string;
  /** Listing tags: the organ name first. */
  tags: readonly string[];
  /** What the deliverable discloses and what stays committed. */
  description: string;
  /** Default query when none is supplied (ORGAN_QUERY). */
  defaultQuery: string;
  /** What the query is, for operators and buyers. */
  queryKind: 'lat,lon point' | 'medication name';
  /** The seller identity that offers this organ (config/demos_cci_identity.json principal on the PATH-OS side). */
  sellerPrincipal: string;
  /** The environment variable holding that seller's mnemonic; never the buyer's DEMOS_MNEMONIC. */
  sellerMnemonicEnv: string;
}

/** The buyer's mnemonic variable; no organ may sell with it. */
export const BUYER_MNEMONIC_ENV = 'DEMOS_MNEMONIC';

export const ORGAN_PROFILES: Readonly<Record<string, OrganProfile>> = {
  nws_alerts: {
    title: 'proof-organ:nws_alerts severity band', tags: ['nws_alerts', 'severe-weather'],
    description: 'severe-weather severity band near a committed point (raw feed + location committed, never disclosed)',
    defaultQuery: '35.2271,-80.8431', queryKind: 'lat,lon point',
    sellerPrincipal: 'seller-nws', sellerMnemonicEnv: 'DEMOS_SELLER_MNEMONIC',
  },
  air_quality: {
    title: 'proof-organ:air_quality EPA category', tags: ['air_quality', 'aqi', 'epa'],
    description: 'EPA air-quality category and vendored guidance near a committed point (exact reading + location committed, never disclosed)',
    defaultQuery: '35.2271,-80.8431', queryKind: 'lat,lon point',
    sellerPrincipal: 'seller-air', sellerMnemonicEnv: 'DEMOS_SELLER_AIR_MNEMONIC',
  },
  drug_info: {
    title: 'proof-organ:drug_info label safety flags', tags: ['drug_info', 'medication', 'label'],
    description: 'derived label flags for a committed medication: whether boxed-warning, interactions and pregnancy sections are present, plus prescription-required status (true, false or unknown); based on a supplied, unattested label record (medication name + label record committed, never disclosed)',
    defaultQuery: 'ibuprofen', queryKind: 'medication name',
    sellerPrincipal: 'seller-drug', sellerMnemonicEnv: 'DEMOS_SELLER_DRUG_MNEMONIC',
  },
};

export function organProfile(organ: string): OrganProfile | undefined {
  return Object.hasOwn(ORGAN_PROFILES, organ) ? ORGAN_PROFILES[organ] : undefined;
}

export function profiledOrgans(): string[] { return Object.keys(ORGAN_PROFILES); }

/** The seller (principal + mnemonic env) for a profiled organ; undefined for an unprofiled one. */
export function organSeller(organ: string): { principal: string; mnemonicEnv: string } | undefined {
  const profile = organProfile(organ);
  return profile ? { principal: profile.sellerPrincipal, mnemonicEnv: profile.sellerMnemonicEnv } : undefined;
}

/** Every seller mnemonic env named by a profile, in profile order, each once. */
export function sellerMnemonicEnvs(): string[] {
  return [...new Set(Object.values(ORGAN_PROFILES).map((p) => p.sellerMnemonicEnv))];
}
