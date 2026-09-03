/**
 * DACS-1 Listing document — TypeScript types
 *
 * Spec source: DACS v0.7 + DACS-1..5 v0.1, §6.3.4
 *
 * Normative requirements (LP-1..LP-4, LR-1..LR-3):
 *   LP-1: Listing publishers MUST anchor via SR-2 before indexing
 *   LP-2: Sign with a key referenced in `seller.identity.claims`
 *   LP-3: Maintain monotonically increasing `version` for the same `id`
 *   LP-4: Publish revocation markers (separate stor- address) when listing is withdrawn
 *
 *   LR-1: Readers MUST pin the (id, version, contentHash) tuple per session
 *   LR-2: 9-step validation order, halt-on-first-failure
 *   LR-3: Refuse revoked listings
 *
 * Size cap: 16 KB JCS-canonical (enforced in listing-pub CLI before anchoring).
 */
export {};
