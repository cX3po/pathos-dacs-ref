export type JsonRecord = Record<string, unknown>;

export interface UnboundPayStep {
  index: number;
  step: JsonRecord;
  rail: string | null;
}

export interface PayBindingsResult {
  ok: boolean;
  acceptedRailIds: string[];
  payStepCount: number;
  unboundPaySteps: UnboundPayStep[];
}

const record = (value: unknown): JsonRecord | null =>
  value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as JsonRecord
    : null;

/**
 * Mirrors the directory RI's `payBindingsOk` predicate: every `pay-*` pipeline
 * step must name an accepted rail through `parameters.rail`.
 */
export function checkPayBindings(listingValue: unknown): PayBindingsResult {
  const listing = record(listingValue);
  if (!listing) throw new TypeError('Listing must be a JSON object');

  const pipeline = Array.isArray(listing.pipeline)
    ? listing.pipeline.map(record).filter((step): step is JsonRecord => step !== null)
    : [];
  const rails = Array.isArray(listing.acceptedRails)
    ? listing.acceptedRails.map(record).filter((rail): rail is JsonRecord => rail !== null)
    : [];
  const acceptedRailIds = rails
    .map((rail) => rail.railId)
    .filter((railId): railId is string => typeof railId === 'string');
  const railIds = new Set(acceptedRailIds);

  const unboundPaySteps: UnboundPayStep[] = [];
  let payStepCount = 0;
  pipeline.forEach((step, index) => {
    if (typeof step.kind !== 'string' || !step.kind.startsWith('pay-')) return;

    payStepCount += 1;
    const parameters = record(step.parameters);
    const rail = typeof parameters?.rail === 'string' ? parameters.rail : null;
    if (rail === null || !railIds.has(rail)) unboundPaySteps.push({ index, step, rail });
  });

  return {
    ok: unboundPaySteps.length === 0,
    acceptedRailIds,
    payStepCount,
    unboundPaySteps,
  };
}

/** Select the Listing artifact from the DACS-Standard lifecycle vector. */
export function listingFromVector(vectorValue: unknown): JsonRecord {
  const vector = record(vectorValue);
  if (!vector || !Array.isArray(vector.artifacts)) {
    throw new TypeError('Conformance vector must contain an artifacts array');
  }

  for (const artifactValue of vector.artifacts) {
    const entry = record(artifactValue);
    const artifact = record(entry?.artifact);
    if (entry?.kind === 'Listing' && artifact) return artifact;
  }

  throw new TypeError('Conformance vector contains no Listing artifact');
}
