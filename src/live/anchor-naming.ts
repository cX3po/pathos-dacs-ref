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

import type { FetchResult } from '../demos/storage.js';
import { opaqueListingProgramName } from '../dacs1/addressing.js';

/** PC-2: railId is a CF-4 variable segment — percent-encode internal colons. */
export function encodeRailSegment(railId: string): string {
  return railId.replaceAll(':', '%3A');
}

export const anchorNames = {
  listing: (logicalAddress: string) => opaqueListingProgramName(logicalAddress),
  agreement: (jobId: string) => `dacs3:agreement:${jobId}`,
  paymentEvidence: (jobId: string, railId: string, phaseIndex: number) =>
    `dacs4:payment:${jobId}:${encodeRailSegment(railId)}:${phaseIndex}`,
  deliverable: (jobId: string) => `dacs4:deliverable:${jobId}`,
  deliveryEvidence: (jobId: string, phaseIndex: number) => `dacs4:delivery:${jobId}:${phaseIndex}`,
  bundle: (jobId: string, role: 'buyer' | 'seller') => `dacs5:bundle:${jobId}:${role}`,
} as const;

/**
 * Resolve an anchored program by (expected owner, canonical name) via exact-name
 * search. Returns null when absent. THROWS on RPC failure (callers must treat a
 * throw as indeterminate, never as absence — §10.4.2 discipline). A name match
 * with the WRONG owner is treated as absent-for-this-party (it is some other
 * publisher's program, not the party's anchor).
 */
export async function resolveByName(
  rpc: string,
  expectedOwner: string,
  programName: string,
): Promise<FetchResult | null> {
  // Raw nodeCall (NOT StorageProgram.searchByName, which swallows every error into [])
  // so an RPC failure THROWS and can never be mistaken for honest absence (§10.4.2
  // discipline). nodeCall is private on the SDK class, so we speak the same wire shape
  // directly — one POST, same envelope.
  const httpRes = await fetch(rpc, {
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
  if (!httpRes.ok) throw new Error(`searchStoragePrograms HTTP ${httpRes.status} for "${programName}"`);
  const envelope = (await httpRes.json()) as { result?: number; response?: unknown };
  if (envelope?.result !== 200) {
    throw new Error(`searchStoragePrograms RPC returned result=${String(envelope?.result)} for "${programName}"`);
  }
  const results = envelope.response;
  if (!Array.isArray(results)) return null;
  const norm = (a: string) => a.replace(/^0x/i, '').toLowerCase();
  for (const r of results as Array<Record<string, unknown>>) {
    const owner = String(r['owner'] ?? '');
    const name = String(r['name'] ?? r['programName'] ?? '');
    if (name !== programName || norm(owner) !== norm(expectedOwner)) continue;
    return {
      storageAddress: String(r['storageAddress'] ?? r['address'] ?? ''),
      owner,
      data: r['data'] ?? null,
      sizeBytes: Number(r['sizeBytes'] ?? 0),
      createdByTx: r['createdByTx'] ? String(r['createdByTx']) : undefined,
      createdAt: String(r['createdAt'] ?? ''),
    };
  }
  return null;
}
