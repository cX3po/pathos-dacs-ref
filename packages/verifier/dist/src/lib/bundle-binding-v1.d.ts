export type BundleBindingRole = 'buyer' | 'seller' | 'orchestrator';
export interface BundleBindingV1 {
    bindingVersion: string;
    jobId: string;
    role: BundleBindingRole;
    logicalAddress: string;
    nativeAddress: string;
    bundleContentHash: string;
    anchorTx?: string;
    signer: unknown;
    signature: {
        algorithm: string;
        signer: unknown;
        value: string;
    };
}
export interface BundleBindingRequest {
    jobId: string;
    role: BundleBindingRole;
    /** Authenticated claim -> raw Ed25519 public key (base64url/base64 or 32 bytes). */
    publicKeys?: Readonly<Record<string, string | Uint8Array>>;
    /** Authenticated co-signed claim -> role map, when one is available. */
    partyMap?: Readonly<Record<string, BundleBindingRole>>;
    /** Per-authenticated-signer fetch cap.  Normative default: N=8. */
    budget?: number;
}
export interface BundleBindingResolution {
    disposition: 'present' | 'fail' | 'indeterminate';
    detail: string;
    resolvedRole?: BundleBindingRole;
    resolvedNativeAddress?: string;
    bundle?: unknown;
}
type JsonObject = Record<string, unknown>;
/** BB-2 logical address derivation. */
export declare function deriveBundleLogicalAddress(jobId: string, role: BundleBindingRole): string;
/** Resolve one requested logical side through BB-1..BB-8. */
export declare function resolveBundleBinding(request: BundleBindingRequest, bindings: readonly BundleBindingV1[], fetchBundle: (nativeAddress: string, binding: BundleBindingV1) => unknown): BundleBindingResolution;
export interface FaultBundlePointerRequest {
    publicKeys?: Readonly<Record<string, string | Uint8Array>>;
    /** The FaultBundleExtendedPointer record at the resolved nativeAddress. */
    pointer: JsonObject;
    /** The full FaultAttestationBundle the pointer dereferences to. */
    dereferenced: JsonObject;
    /** The BundleBinding anchoring the pointer. */
    binding: JsonObject;
}
/**
 * §10.4.2 extended-pointer + §10.4.1 triple-identity (E7).
 *
 * `present` iff triple-identity holds: binding.bundleContentHash ==
 * pointer.fullBundleContentHash == the recomputed §10.4.1 hash of the DEREFERENCED bundle,
 * AND the pointer signature (dacs-fault-bundle-pointer:v1:) and every dereferenced-bundle
 * signature (dacs-fault-bundle:v1:) verify.  A pointer/binding that agree with each other
 * but not with the recomputed dereferenced hash is rejected content (BB-7), not absence —
 * this is the case a compare-the-pointer's-own-hash shortcut would wrongly accept.
 */
export declare function resolveFaultBundlePointer(request: FaultBundlePointerRequest): BundleBindingResolution;
export interface FaultBundlePairRequest {
    publicKeys?: Readonly<Record<string, string | Uint8Array>>;
    /** role -> FAB copy.  A single-copy map exercises the §10.4.1 permissible-set rule. */
    copies: Readonly<Record<string, unknown>>;
}
/**
 * §10.4.3 FaultAttestationBundle-pair rule + §10.4.1 permissible set.
 *
 * A single invalid/out-of-set copy is rejected content -> `fail`.  A pair `present`
 * iff both copies are valid AND name the same absolute faultedParty and the same outcome
 * class (perspective spellings such as aborted-by-self vs aborted-by-other reconcile).
 * A pair that names different absolute faultedParty or different outcome class diverges
 * -> `fail`.
 */
export declare function resolveFaultBundlePair(request: FaultBundlePairRequest): BundleBindingResolution;
/**
 * §10.4.3 mixed-version rule + §10.5.1 authoritative selection.
 *
 * Reconcile a pair of copies where at least one is a FAB and at least one is a legacy
 * AttestationBundle (or two legacy copies, the perspective-flip control).  Each copy's
 * §10.4.1 implied absolute-fault SET is computed (FAB -> singleton, legacy -> derived from
 * outcome+anchoredByRole).  The pair is non-divergent iff:
 *   - all copies share the same outcome class,
 *   - every pairwise implied-fault-set intersection is non-empty (no contradiction — a FAB
 *     faultedParty outside the legacy implied set, or two legacy copies whose flips disagree,
 *     is a contradiction), and
 *   - shared-index phaseSummary limbs agree.
 * A non-divergent pair is `present` (unified); the FAB is authoritative for derivation when
 * present, else the legacy copy (§10.5.1).  Contradiction -> `fail` (excluded from all metrics).
 */
export declare function resolveMixedVersionPair(request: FaultBundlePairRequest): BundleBindingResolution;
export {};
