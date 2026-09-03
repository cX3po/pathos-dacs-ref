/**
 * §10.4.1 + R5-1 — the signed canonical scope of a v0.1 AttestationBundle.
 *
 * The hashed canonical form OMITS both `signatures` AND `anchoredByRole`. `anchoredByRole` is
 * per-copy (buyer / seller / orchestrator); excluding it from the hash is what makes the two
 * two-sided copies hash EQUAL in the happy path. DACS-Standard CHANGELOG R5-1 (Critical) records
 * why: while it was IN the hash (added R4-B), the two copies always differed, so every happy-path
 * session mis-routed to "disputed". v0.1 resolves to EXCLUDE (DACS-5 §10.4.1 / §227 / §231 / §248,
 * GLOSSARY, CONFORMANCE-PLAN — all agree). Its integrity is restored NOT by the signature but by
 * the anchor-address ↔ anchoredByRole cross-check on the two-sided path (§10.4.2 / §248): the copy
 * at the buyer address MUST declare anchoredByRole "buyer", the seller address "seller".
 *
 * emit (emit-bundle-v1.ts) and verify (verify-bundle-v1.ts) MUST share this ONE definition so the
 * signed scope can never drift between producer and consumer. (Re-pin 2026-06-11: converges
 * pathos-dacs-ref to upstream v0.1; supersedes the prior in-hash-plus-address-cross-check choice.)
 */
import { jcsHashHex } from '../jcs.js';
/**
 * Compute the v0.1 bundle signed-scope hash (hex). Strips BOTH `signatures` and `anchoredByRole`
 * itself, so it is safe to call on a full bundle OR a signature-less one (misuse-proof — a caller
 * that passes a full bundle still gets the correct signed scope). `signatures` is the §10.4.1
 * exclusion; `anchoredByRole` is the R5-1 exclusion.
 */
export function bundleSignedScopeHashV1(bundle) {
    const { signatures: _omitSigs, anchoredByRole: _omitRole, ...scope } = bundle;
    void _omitSigs; // §10.4.1 — signatures never in the signed scope
    void _omitRole; // R5-1 — excluded from the hashed canonical form; integrity via anchor-address cross-check
    return jcsHashHex(scope);
}
