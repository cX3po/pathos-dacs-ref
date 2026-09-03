/**
 * DACS reference implementation — type barrel
 *
 * Re-exports every DACS type used across the codebase, anchored to spec sections.
 *
 * Import from this file rather than the individual modules so the spec
 * section references are co-located here.
 */
export { isPass, isFail, isIndeterminate, isError } from './verify-result.js';
