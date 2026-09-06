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
 *   listing            logical address with ':' → '%3A'                 (§6.3.4 leaves the name implementation-defined; this is the pinned dacs-sdk's form, so its Agent resolves it)
 *   agreement          dacs3:agreement:{jobId}                        (signed both-party terms)
 *   payment evidence   dacs4:payment:{jobId}:{railId}:{phaseIndex}   (PC-2; railId %-encoded)
 *   deliverable        dacs4:deliverable:{jobId}                      (§9.6.1)
 *   delivery evidence  dacs4:delivery:{jobId}:{phaseIndex}
 *   bundle copies      dacs5:bundle:{jobId}:buyer | :seller           (§10.4.2 equivalent)
 */
import { fetchAnchored, type FetchResult } from '../demos/storage.js';
export interface ResolveByNameOptions {
    /** Additional searches after the first absent result. Default: 0. */
    retries?: number;
    /** Delay between absent-result retries. The total delay is capped at 60 seconds. */
    delayMs?: number;
    /** Test seam for raw nodeCall search and address-read transports. */
    fetchImpl?: typeof fetch;
    /** Test/substrate seam for the address read. */
    fetchAnchoredImpl?: typeof fetchAnchored;
    /** Retry observer; defaults to a concise console message. */
    retryLog?: (message: string) => void;
}
/** PC-2: railId is a CF-4 variable segment — percent-encode internal colons. */
export declare function encodeRailSegment(railId: string): string;
/**
 * Which party's wallet writes an anchor. The two-sided bundle copies are named in the spec's
 * hashed form (`stor-{sha256(jobId-bundle-role)}`, see deriveBundleLogicalAddress), so a suffix
 * test on the logical address cannot see the role; resolve it from the job id instead. Every
 * other anchor (listing, agreement, commitment, evidence, deliverable) is the orchestrator's.
 */
export declare function anchorWriterRole(jobId: string, logicalAddress: string): 'buyer' | 'seller' | 'orchestrator';
export declare const anchorNames: {
    readonly listing: (logicalAddress: string) => string;
    readonly agreement: (jobId: string) => string;
    readonly paymentEvidence: (jobId: string, railId: string, phaseIndex: number) => string;
    readonly deliverable: (jobId: string) => string;
    readonly deliveryEvidence: (jobId: string, phaseIndex: number) => string;
    readonly bundle: (jobId: string, role: "buyer" | "seller") => string;
};
/**
 * Resolve an anchored program by (expected owner, canonical name) via exact-name
 * search. Returns null when absent. THROWS on RPC failure (callers must treat a
 * throw as indeterminate, never as absence — §10.4.2 discipline). A name match
 * with the WRONG owner is treated as absent-for-this-party (it is some other
 * publisher's program, not the party's anchor).
 */
export declare function resolveByName(rpc: string, expectedOwner: string, programName: string, options?: ResolveByNameOptions): Promise<FetchResult | null>;
/** Read a just-created program by its known address before consulting the lagging name index. */
export declare function fetchAddressFirst(rpc: string, storageAddress: string, expectedOwner: string, programName: string, options?: ResolveByNameOptions): Promise<FetchResult | null>;
