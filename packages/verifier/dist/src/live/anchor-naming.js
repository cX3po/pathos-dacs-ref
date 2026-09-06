/**
 * anchor-naming.ts — Demos substrate-equivalent DACS anchor addressing.
 *
 * The spec's two-sided bundle addresses are `stor-{sha256(jobId + "-bundle-buyer")}`
 * "**or substrate-equivalent two-sided addressing**" (§10.4.3). On Demos, a
 * StorageProgram address derives from (owner, programName, nonce, salt) — a writer
 * cannot claim an arbitrary jobId-derived address, and a consumer cannot know the
 * writer's nonce. The substrate-equivalent is NAME-based addressing:
 *
 *   - writers anchor under a canonical, jobId-derived PROGRAM NAME (below);
 *   - consumers resolve by exact-name search (`searchStoragePrograms`) and then
 *     REQUIRE the returned program's `owner` to equal the expected party address —
 *     the (owner, name) pair is exactly as collision-safe as the spec's
 *     jobId-derived address, because an attacker can publish the same NAME but
 *     never as the expected OWNER.
 *
 * Canonical program names (mirroring the spec's address schemes):
 *   listing            dacs1listing-{sha256(logical_address)}           (§6.3.4 opaque/colon-free)
 *   agreement          dacs3:agreement:{jobId}                        (signed both-party terms)
 *   payment evidence   dacs4:payment:{jobId}:{railId}:{phaseIndex}   (PC-2; railId %-encoded)
 *   deliverable        dacs4:deliverable:{jobId}                      (§9.6.1)
 *   delivery evidence  dacs4:delivery:{jobId}:{phaseIndex}
 *   bundle copies      dacs5:bundle:{jobId}:buyer | :seller           (§10.4.2 equivalent)
 */
import { fetchAnchored } from '../demos/storage.js';
import { opaqueListingProgramName } from '../dacs1/addressing.js';
import { deriveBundleLogicalAddress } from '../lib/bundle-binding-v1.js';
/** PC-2: railId is a CF-4 variable segment — percent-encode internal colons. */
export function encodeRailSegment(railId) {
    return railId.replaceAll(':', '%3A');
}
/**
 * Which party's wallet writes an anchor. The two-sided bundle copies are named in the spec's
 * hashed form (`stor-{sha256(jobId-bundle-role)}`, see deriveBundleLogicalAddress), so a suffix
 * test on the logical address cannot see the role; resolve it from the job id instead. Every
 * other anchor (listing, agreement, commitment, evidence, deliverable) is the orchestrator's.
 */
export function anchorWriterRole(jobId, logicalAddress) {
    if (logicalAddress === deriveBundleLogicalAddress(jobId, 'buyer') || logicalAddress.endsWith(':buyer'))
        return 'buyer';
    if (logicalAddress === deriveBundleLogicalAddress(jobId, 'seller') || logicalAddress.endsWith(':seller'))
        return 'seller';
    return 'orchestrator';
}
export const anchorNames = {
    listing: (logicalAddress) => opaqueListingProgramName(logicalAddress),
    agreement: (jobId) => `dacs3:agreement:${jobId}`,
    paymentEvidence: (jobId, railId, phaseIndex) => `dacs4:payment:${jobId}:${encodeRailSegment(railId)}:${phaseIndex}`,
    deliverable: (jobId) => `dacs4:deliverable:${jobId}`,
    deliveryEvidence: (jobId, phaseIndex) => `dacs4:delivery:${jobId}:${phaseIndex}`,
    bundle: (jobId, role) => `dacs5:bundle:${jobId}:${role}`,
};
/**
 * Resolve an anchored program by (expected owner, canonical name) via exact-name
 * search. Returns null when absent. THROWS on RPC failure (callers must treat a
 * throw as indeterminate, never as absence — §10.4.2 discipline). A name match
 * with the WRONG owner is treated as absent-for-this-party (it is some other
 * publisher's program, not the party's anchor).
 */
export async function resolveByName(rpc, expectedOwner, programName, options = {}) {
    const requestedRetries = Number.isFinite(options.retries) && (options.retries ?? 0) > 0
        ? Math.floor(options.retries)
        : 0;
    const delayMs = Number.isFinite(options.delayMs) && (options.delayMs ?? 0) >= 0
        ? Math.floor(options.delayMs)
        : 0;
    const retryBudget = delayMs === 0 ? 100 : Math.floor(60_000 / delayMs);
    const retries = Math.min(requestedRetries, retryBudget, 100);
    const searchFetch = options.fetchImpl ?? fetch;
    const addressFetch = options.fetchAnchoredImpl
        ?? ((addressRpc, storageAddress) => fetchAnchored(addressRpc, storageAddress, { fetchImpl: options.fetchImpl }));
    const retryLog = options.retryLog ?? ((message) => console.log(`[SR-2] ${message}`));
    for (let attempt = 0; attempt <= retries; attempt++) {
        const result = await resolveByNameOnce();
        if (result)
            return result;
        if (attempt === retries)
            return null;
        retryLog(`name index has not listed "${programName}"; retry ${attempt + 1}/${retries} in ${delayMs}ms`);
        if (delayMs > 0)
            await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
    return null;
    async function resolveByNameOnce() {
        // Raw nodeCall (NOT StorageProgram.searchByName, which swallows every error into [])
        // so an RPC failure THROWS and can never be mistaken for honest absence (§10.4.2
        // discipline). nodeCall is private on the SDK class, so we speak the same wire shape
        // directly — one POST, same envelope.
        const httpRes = await searchFetch(rpc, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                method: 'nodeCall',
                params: [{
                        message: 'searchStoragePrograms',
                        data: { query: programName, options: { exactMatch: true, limit: 25 } },
                        muid: `dacs-anchor-${programName.length}-${programName.slice(0, 24)}`,
                    }],
            }),
        });
        if (!httpRes.ok)
            throw new Error(`searchStoragePrograms HTTP ${httpRes.status} for "${programName}"`);
        const envelope = (await httpRes.json());
        if (envelope?.result !== 200) {
            throw new Error(`searchStoragePrograms RPC returned result=${String(envelope?.result)} for "${programName}"`);
        }
        const results = envelope.response;
        if (!Array.isArray(results))
            return null;
        const norm = (a) => a.replace(/^0x/i, '').toLowerCase();
        for (const r of results) {
            const owner = String(r['owner'] ?? '');
            const name = String(r['name'] ?? r['programName'] ?? '');
            if (name !== programName || norm(owner) !== norm(expectedOwner))
                continue;
            const storageAddress = String(r['storageAddress'] ?? r['address'] ?? '');
            if (!storageAddress)
                continue;
            return addressFetch(rpc, storageAddress);
        }
        return null;
    }
}
/** Read a just-created program by its known address before consulting the lagging name index. */
export async function fetchAddressFirst(rpc, storageAddress, expectedOwner, programName, options = {}) {
    const addressFetch = options.fetchAnchoredImpl
        ?? ((addressRpc, address) => fetchAnchored(addressRpc, address, { fetchImpl: options.fetchImpl }));
    const byAddress = await addressFetch(rpc, storageAddress);
    if (byAddress)
        return byAddress;
    return resolveByName(rpc, expectedOwner, programName, options);
}
