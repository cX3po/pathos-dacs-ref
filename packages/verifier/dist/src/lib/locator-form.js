/**
 * locator-form.ts — the two forms an AttestationRef locator takes on Demos, and the owner behind a claim.
 *
 * A NATIVE locator is the storage address the node assigned (`stor-<40 hex>`); it reads directly. A LOGICAL
 * locator is the DACS logical address (`dacs4:payment:{jobId}:{railId}:{phaseIndex}`, `dacs4:delivery:…`,
 * `dacs3:…`); the node cannot read it, so a consumer resolves it by exact program NAME plus the expected
 * OWNER and reads the resolved address. The pinned dacs-sdk requires the logical form for settlement
 * evidence (DACS-4 PC-2: `expectedPaymentEvidenceLocator`) and names its programs with ':' encoded as
 * '%3A'; this module carries no imports so the verifier, the finalizer and the coordinator can share it.
 */
const LOGICAL_LOCATOR = /^(?:dacs[0-9]+|pathos):/;
const OWNER_CLAIM = /^(?:did:demos:agent:|cci:(?:0x)?)([0-9a-fA-F]{64})$/;
/** A DACS logical address (`dacs1:`…`dacs5:`, `pathos:` namespaces): the node cannot read it; it resolves by name plus owner. */
export function isLogicalLocator(value) {
    return typeof value === 'string' && LOGICAL_LOCATOR.test(value);
}
/** Anything that is not a logical address reads as given: the node-assigned `stor-<40 hex>` address, or the spec's derived `stor-<sha256>` two-sided address a fetch layer maps. */
export function isNativeLocator(value) {
    return typeof value === 'string' && value.length > 0 && !LOGICAL_LOCATOR.test(value);
}
/** The pinned dacs-sdk's implementation-defined StorageProgram NAME for a logical address (':' → '%3A'); idempotent. */
export function sdkProgramName(logicalAddress) {
    return logicalAddress.replace(/:/g, '%3A');
}
/** The Demos owner address behind a party or signer claim: `did:demos:agent:<hex>` or `cci:<hex>` → `0x<hex>`; anything else is unknown. */
export function ownerAddressOfClaim(claim) {
    if (typeof claim !== 'string')
        return null;
    const m = OWNER_CLAIM.exec(claim);
    return m ? `0x${m[1].toLowerCase()}` : null;
}
