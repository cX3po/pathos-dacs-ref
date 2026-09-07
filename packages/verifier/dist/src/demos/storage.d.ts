/**
 * SR-2 Storage Program — anchor write + read
 *
 * Spec context: DACS §5 SR-2 ("anchored storage") — bytes anchored at a content-derived
 * locator, retrievable by any verifier. Used by:
 *   - DACS-1 Listings (§6.3.4 LP-1: MUST anchor via SR-2 before indexing)
 *   - DACS-5 AttestationBundle two-sided anchoring (§10.4.2)
 *   - DACS-2 attestation refs (§7.5.2 — anchor.locator is the SR-2 address)
 *
 * Demos substrate provides this via the StorageProgram primitive.
 * The wrapper here keeps the SDK call shape out of the CLIs.
 */
import { type StorageProgramData } from '@kynesyslabs/demosdk/storage';
import type { DemosHandle } from './connection.js';
export interface AnchorResult {
    /** stor- prefixed storage address (the SR-2 locator) */
    storageAddress: string;
    /** Transaction hash that created the storage program */
    txHash: string;
    /** Stored byte length, including the JSON text-envelope overhead when present */
    sizeBytes: number;
    /** Original content byte length before adding a text envelope */
    contentBytes: number;
    /** When anchored (ISO 8601) */
    anchoredAt: string;
    /** Wallet nonce bound into the create transaction, when available. */
    nonce?: string;
}
export interface FetchResult {
    /** stor- prefixed storage address */
    storageAddress: string;
    /** Owner address (the publisher) */
    owner: string;
    /** Raw data field — JSON object or string depending on encoding */
    data: unknown;
    /** True when a wrapped-text JSON anchor was transparently unwrapped */
    wrapped?: true;
    /** Bytes size */
    sizeBytes: number;
    /** Transaction that created this storage */
    createdByTx?: string;
    /** When created (ISO 8601 per SDK) */
    createdAt: string;
}
export interface FetchAnchoredOptions {
    /** Test/substrate seam for the raw nodeCall transport. */
    fetchImpl?: typeof fetch;
}
export declare function wrapTextAnchor(text: string): {
    v: 'dacs-ref-text:1';
    text: string;
};
export declare function unwrapTextAnchor(data: unknown): string | null;
export declare function storedAnchorPayload(data: Record<string, unknown> | string, encoding: 'json' | 'binary'): Record<string, unknown> | string;
/**
 * Read a Storage Program without the SDK's error-to-null conversion.
 * Only a dedicated not-found response or an empty successful response is absence.
 */
export declare function getStorageProgram(rpc: string, storageAddress: string, options?: FetchAnchoredOptions): Promise<StorageProgramData | null>;
/**
 * Anchor `data` to SR-2 (Demos Storage Program).
 *
 * @param handle Connected Demos handle
 * @param programName Human-readable identifier (used in deterministic address derivation)
 * @param data JSON-encodable object or raw string. JCS canonical form recommended for hash-stable artifacts.
 * @param options Optional ACL (defaults to public-read) + nonce (defaults to wallet's next nonce)
 *
 * Returns the storage address (`stor-...`) — this becomes the `AttestationRef.anchor.locator`
 * in §7.5.2 / §10.4.2.
 *
 * Throws on broadcast failure, insufficient DEM balance, or RPC error.
 */
/** The SR-2 anchor path's failure classes. Finite by construction; the run record may name them. */
export type Sr2AnchorFailureClass = 'anchor-nonce-unavailable' | 'anchor-size-limit' | 'anchor-unsigned' | 'anchor-wrong-wallet' | 'anchor-failed-on-chain' | 'anchor-not-confirmed' | 'anchor-not-included' | 'anchor-readback-missing' | 'anchor-facts-mismatch';
export declare const SR2_ANCHOR_STATES: Set<string>;
export interface Sr2AnchorDiagnostics {
    class: Sr2AnchorFailureClass;
    /** The signed or broadcast transaction hash, when the failure has one (64 lowercase hex). */
    txHash?: string;
    /** The confirmation window that elapsed, in milliseconds. */
    waitMs?: number;
    /** The node's reported transaction state, allowlisted; anything else becomes 'unknown'. */
    state?: 'pending' | 'included' | 'failed' | 'missing' | 'unknown';
}
/**
 * An anchor failure that carries its diagnostics as typed fields. The live coordinator's run record reports
 * ONLY these fields (never the message): provenance is the class, not a pattern found in text.
 */
export declare class Sr2AnchorError extends Error {
    readonly diagnostics: Sr2AnchorDiagnostics;
    constructor(failureClass: Sr2AnchorFailureClass, fields: {
        txHash?: unknown;
        waitMs?: unknown;
        state?: unknown;
    }, message: string);
}
export declare function anchor(handle: DemosHandle, programName: string, data: Record<string, unknown> | string, options?: {
    acl?: 'public' | 'private';
    salt?: string;
    encoding?: 'binary';
    fetchImpl?: typeof fetch;
    readBackAttempts?: number;
    readBackDelayMs?: number;
}): Promise<AnchorResult>;
/** A node record that exists but contradicts itself or the request; never retried. */
export declare class AnchorFactsContradiction extends Error {
    constructor(message: string);
}
/**
 * The facts a receipt is checked against, read from the node after inclusion: the storage program's
 * creating transaction and the nonce that transaction carries. Returns null only when the record or its
 * transaction is not (yet) available; a record that is present but contradictory (foreign address, malformed
 * or foreign creating transaction, signer not the owner, unusable nonce) throws AnchorFactsContradiction.
 */
export declare function anchorFactsFromNode(rpc: string, storageAddress: string, options?: {
    fetchImpl?: typeof fetch;
}): Promise<{
    txHash: string;
    nonce: string;
    owner: string;
} | null>;
/**
 * Fetch a previously anchored Storage Program by its address.
 *
 * @param rpc Demos node RPC URL
 * @param storageAddress stor- prefixed address
 * @returns FetchResult, or null if not found
 */
/** Programs listed for one owner beyond this count are not proven complete: a missing name is then an error, never absence. */
export declare const OWNER_LISTING_COMPLETENESS_BOUND = 100;
/**
 * Resolve a party's program by listing the programs the owner has written (`getStorageProgramsByOwner`)
 * and matching the exact program name, then reading the record at the node-assigned address. This is the
 * owner-bound resolution the verifier uses for two-sided bundle copies: on Demos the node assigns the
 * native address and the derived DACS-5 address is the program NAME (the name index has been observed
 * not to list a fresh program while the owner listing did, 2026-09-06). Discipline: a malformed listing,
 * two same-owner records of that name, or a listing at or beyond the completeness bound without the
 * name all THROW (indeterminate for the caller); null means the owner has no program of that name.
 */
export declare function resolveByOwnerListing(rpc: string, expectedOwner: string, programName: string, options?: {
    fetchImpl?: typeof fetch;
    fetchAnchoredImpl?: typeof fetchAnchored;
}): Promise<FetchResult | null>;
export declare function fetchAnchored(rpc: string, storageAddress: string, options?: FetchAnchoredOptions): Promise<FetchResult | null>;
/**
 * Verify that the bytes anchored at `storageAddress` match an expected SHA-256.
 *
 * Used by DACS §7.5.2: "consumer MUST hash the fetched bytes and compare to AttestationRef.contentHash"
 *
 * Returns:
 *   - 'pass'          — fetched + hash matched
 *   - 'fail'          — fetched but hash mismatched
 *   - 'indeterminate' — anchor unreachable / not found
 */
export declare function verifyAnchor(rpc: string, storageAddress: string, expectedContentHashHex: string, options?: {
    fetchAnchoredImpl?: typeof fetchAnchored;
}): Promise<{
    outcome: 'pass' | 'fail' | 'indeterminate';
    detail: string;
    actualHashHex?: string;
}>;
