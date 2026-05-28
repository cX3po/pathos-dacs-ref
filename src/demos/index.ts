/**
 * Demos bridge layer barrel
 *
 * Imports here are how the rest of the codebase touches the SDK.
 * Keep this file as the single point of substrate dependency — easier to
 * mock for tests, easier to swap when the §11.3 second-substrate work happens.
 */

export { connectDemos, newMnemonic, mnemonicFromEnv, type DemosHandle } from './connection.js';
export { anchor, fetchAnchored, verifyAnchor, type AnchorResult, type FetchResult } from './storage.js';
export { dahrFetch, type DahrFetchResult, type DahrFetchOptions } from './dahr.js';
