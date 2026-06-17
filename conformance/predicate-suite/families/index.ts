/** The registry of conformance families the suite enumerates + runs. */
import type { Family } from '../types.js';
import { bundleFamily } from './bundle.js';
import { consentFamily } from './consent.js';
import { discloseFamily } from './disclose.js';

export const FAMILIES: Family[] = [bundleFamily, consentFamily, discloseFamily];

/** Look up a family by name (set name). */
export function familyByName(name: string): Family | undefined {
  return FAMILIES.find((f) => f.name === name);
}
