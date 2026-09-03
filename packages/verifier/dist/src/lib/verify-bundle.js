/**
 * DACS-5 envelope-receipt verifier — core logic
 *
 * Spec source: DACS v0.7 + DACS-1..5 v0.1 §10.4
 *
 * Pulled out of cli/verify.ts so the verifier can be unit-tested without going
 * through process.argv + process.exit. The CLI is a thin wrapper.
 *
 * Normative invariants enforced here:
 *   §7.5.1 — decision ∈ {pass, fail, indeterminate}; NEVER coerced
 *   §7.5.2 — every AttestationRef MUST have its anchored bytes re-hashed and matched
 *   §10.4.1 — verifier MUST recompute canonical form + bundleHash + signed_bytes; verify signatures
 *   §10.4.2 — bundle is anchored at TWO addresses (buyer + seller); compute deterministically
 *   §10.4.3 — consumer queries BOTH party-specific addresses; unilateral ⇒ aborted-by-self
 */
import { sha256 } from '@noble/hashes/sha2';
import { jcsCanonical, jcsHash } from '../jcs.js';
import { verify as edVerify } from './sign.js';
import { DOMAIN_SEPARATORS, LEGACY_READ_SEPARATORS } from '../domain-sep.js';
import { fetchAnchored, unwrapTextAnchor } from '../demos/storage.js';
/** Step recorder — accumulates the verify walk for the final verdict. */
export class StepLog {
    steps = [];
    add(step, outcome, detail) {
        this.steps.push({ step, outcome, detail });
    }
    hasFailure() { return this.steps.some(s => s.outcome === 'fail'); }
    hasIndeterminate() { return this.steps.some(s => s.outcome === 'indeterminate'); }
    rollupDecision() {
        // §7.5.1 — decision precedence: any fail → fail; else any indeterminate → indeterminate; else pass.
        // NEVER coerce indeterminate to pass. `skipped` outcomes are informational and do not affect rollup.
        if (this.hasFailure())
            return 'fail';
        if (this.hasIndeterminate())
            return 'indeterminate';
        return 'pass';
    }
}
/** Convert hex (with optional 0x prefix) to a Uint8Array. Strict — rejects non-hex chars. */
export function hexToBytes(hex) {
    const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
    if (clean.length % 2 !== 0)
        throw new Error(`invalid hex length: ${clean.length}`);
    // Codex M2 #1: parseInt(non-hex, 16) returns NaN which becomes 0 in Uint8Array assignment.
    // Validate format BEFORE parsing so a 64-char "zz"-string isn't accepted as a zeroed pubkey.
    if (!/^[0-9a-fA-F]*$/.test(clean)) {
        throw new Error(`invalid hex: non-[0-9a-fA-F] character in input`);
    }
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}
/** Convert bytes to hex (no 0x prefix). */
export function bytesToHex(b) {
    return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}
/** Standard base64 decode (binary string → bytes). Node provides Buffer; browser provides atob. */
function b64decode(s) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    if (typeof globalThis.Buffer !== 'undefined') {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        return new Uint8Array(globalThis.Buffer.from(s, 'base64'));
    }
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++)
        out[i] = bin.charCodeAt(i);
    return out;
}
/**
 * Compute the §10.4.2 two-sided anchors from a jobId.
 *
 *   buyer  := stor-{sha256(jobId + "-bundle-buyer")}
 *   seller := stor-{sha256(jobId + "-bundle-seller")}
 *
 * The derivation is pure — given the same jobId, every verifier produces the same pair.
 */
export function computeAnchorPair(jobId) {
    return {
        buyer: 'stor-' + bytesToHex(sha256(new TextEncoder().encode(jobId + '-bundle-buyer'))),
        seller: 'stor-' + bytesToHex(sha256(new TextEncoder().encode(jobId + '-bundle-seller'))),
    };
}
/**
 * Resolve the ed25519 public key for a DACS-1 IdentityBundle's primary claim.
 *
 * v0.2 supports `scheme: 'cci'` only. On Demos, the CCI primary-claim identifier
 * IS the ed25519 public key as 64 hex chars (with optional 0x prefix). For other
 * schemes (ERC-8004, LEI, etc.) we return null — the caller marks signature
 * verification as `indeterminate` with reason "scheme not supported in v0.2".
 */
export function resolvePrimaryClaimPubkey(bundle) {
    const primary = bundle.party.primary;
    if (primary.scheme === 'cci') {
        const hex = primary.identifier.startsWith('0x') ? primary.identifier.slice(2) : primary.identifier;
        if (hex.length !== 64)
            return null;
        try {
            return { pubkey: hexToBytes(primary.identifier), source: `cci:${primary.identifier.slice(0, 12)}…` };
        }
        catch {
            return null;
        }
    }
    return null;
}
/** Verify the bundle's primary signature. */
function verifySignature(bundle, log) {
    if (!bundle.signature) {
        log.add('verify-signature', 'fail', 'bundle.signature is absent (§10.4 requires the bundle author to sign)');
        return { ok: false, signerPubkeyHex: null };
    }
    const resolved = resolvePrimaryClaimPubkey(bundle);
    if (!resolved) {
        log.add('verify-signature', 'indeterminate', `bundle.party.primary.scheme="${bundle.party.primary.scheme}" — only "cci" is supported in v0.2 ` +
            `(ERC-8004 + other schemes land in v0.3 once CCI→pubkey resolution ships).`);
        return { ok: false, signerPubkeyHex: null };
    }
    // Recompute the canonical bundle bytes (sans signatures) and the bundleHash.
    const unsigned = { ...bundle, signature: undefined, orchestratorSignature: undefined };
    const canonical = jcsCanonical(unsigned);
    const bundleHash = jcsHash(unsigned);
    // signed_bytes = <separator> || bundleHash || JCS(payload)  per §10.4.2 + sign.ts contract.
    // Post-cutover bundles seal under the canonical `dacs-bundle:v1:`. GENUINE pre-cutover legacy
    // bundles were sealed under `dacs5-bundle:v1:` (now LEGACY_READ_SEPARATORS) — the verify below
    // tries the canonical separator first, then falls back to the legacy one for backwards-compat
    // READS (§10.4.2). New emission is canonical-only; the legacy separator is never emitted.
    // Codex M2 #3: Buffer.from(..., 'base64') is permissive — garbage input decodes to whatever
    // happens to be base64-decodable, then edVerify gets a wrong-length signature. Validate the
    // decoded length is exactly 64 bytes (ed25519 signature length) before passing to edVerify.
    let sig;
    try {
        sig = b64decode(bundle.signature);
    }
    catch (e) {
        log.add('verify-signature', 'fail', `bundle.signature is not valid base64: ${e.message}`);
        return { ok: false, signerPubkeyHex: null };
    }
    if (sig.length !== 64) {
        log.add('verify-signature', 'fail', `malformed signature length: decoded to ${sig.length} bytes; ed25519 requires exactly 64.`);
        return { ok: false, signerPubkeyHex: null };
    }
    // §10.4.2 backwards-compat reads: try the canonical EMISSION separator first
    // (`dacs-bundle:v1:` — what every post-cutover bundle is sealed under), then fall back to
    // the READ-ONLY legacy separator (`dacs5-bundle:v1:`) so genuine PRE-cutover artifacts —
    // signed before the §B.7 fold — still verify. New code never emits under the legacy string;
    // this fallback is purely a read-path concession (Codex BLOCKER 3, 2026-06-07).
    if (edVerify(DOMAIN_SEPARATORS.BUNDLE, sig, canonical, resolved.pubkey, bundleHash)) {
        log.add('verify-signature', 'pass', `ed25519 verified against ${resolved.source} (separator="${DOMAIN_SEPARATORS.BUNDLE}")`);
        return { ok: true, signerPubkeyHex: bytesToHex(resolved.pubkey) };
    }
    if (edVerify(LEGACY_READ_SEPARATORS.BUNDLE_DACS5, sig, canonical, resolved.pubkey, bundleHash)) {
        log.add('verify-signature', 'pass', `ed25519 verified against ${resolved.source} under the read-only legacy separator ` +
            `"${LEGACY_READ_SEPARATORS.BUNDLE_DACS5}" (pre-cutover artifact, §10.4.2 backwards-compat read)`);
        return { ok: true, signerPubkeyHex: bytesToHex(resolved.pubkey) };
    }
    log.add('verify-signature', 'fail', `ed25519 verification failed against ${resolved.source} ` +
        `(tried separators "${DOMAIN_SEPARATORS.BUNDLE}" + read-only legacy "${LEGACY_READ_SEPARATORS.BUNDLE_DACS5}", ` +
        `bundleHash=${bytesToHex(bundleHash).slice(0, 16)}…)`);
    return { ok: false, signerPubkeyHex: null };
}
/**
 * §10.4.2 + §10.4.3 — two-sided anchor lookup.
 *
 * Computes the buyer + seller anchor addresses from bundle.jobId and queries BOTH.
 * Outcomes:
 *   - both present + canonical hashes equal           → pass with detail
 *   - both present + canonical hashes differ          → fail (dispute signal)
 *   - exactly one present                             → fail with `aborted-by-self` for the absent role
 *   - neither present                                 → indeterminate (network or never-anchored)
 */
async function verifyTwoSidedAnchoring(bundle, rpc, log, counterparty, fetchImpl = fetchAnchored) {
    const pair = computeAnchorPair(bundle.jobId);
    log.add('two-sided-anchors-derived', 'pass', `jobId=${bundle.jobId} → buyer=${pair.buyer}, seller=${pair.seller}`);
    if (counterparty) {
        if (counterparty.jobId !== bundle.jobId) {
            log.add('two-sided-anchoring', 'fail', `counterparty bundle jobId=${counterparty.jobId} does not match local bundle jobId=${bundle.jobId}`);
            return;
        }
        if (counterparty.role === bundle.role) {
            log.add('two-sided-anchoring', 'fail', `counterparty bundle has same role="${counterparty.role}" — expected the OTHER side per §10.4.2`);
            return;
        }
        // Codex M2 round-4 #2: the counterparty bundle's signature MUST also verify.
        // A tampered counterparty bundle that satisfies relational checks should NOT pass.
        const counterpartySigLog = new StepLog();
        const counterpartySigResult = verifySignature(counterparty, counterpartySigLog);
        if (!counterpartySigResult.ok) {
            log.add('two-sided-anchoring', 'fail', `counterparty bundle signature did NOT verify: ${counterpartySigLog.steps.map(s => s.detail).join('; ')}`);
            return;
        }
        if (!claimRefEqual(bundle.counterparty.primary, counterparty.party.primary) ||
            !claimRefEqual(bundle.party.primary, counterparty.counterparty.primary)) {
            log.add('two-sided-anchoring', 'fail', `counterparty bundle refers to a different deal — cross-party primary claims (scheme+identifier) don't match (dispute signal per §10.4.2)`);
            return;
        }
        if (bundle.state !== counterparty.state) {
            log.add('two-sided-anchoring', 'fail', `state mismatch between party bundles: local="${bundle.state}" counterparty="${counterparty.state}"`);
            return;
        }
        log.add('two-sided-anchoring', 'pass', `counterparty bundle supplied inline (role=${counterparty.role}); signature verified, jobId + cross-party claims + state all match`);
        return;
    }
    // Codex M2 round-3 #3: distinguish "not found" (real absence → unilateral)
    // from "fetch threw" (RPC error → indeterminate). The previous .catch(() => null)
    // collapsed both into "absent," producing false unilateral / dispute signals on
    // transient RPC failures.
    const buyerResult = await fetchAnchoredWithStatus(rpc, pair.buyer, fetchImpl);
    const sellerResult = await fetchAnchoredWithStatus(rpc, pair.seller, fetchImpl);
    // If either side errored, we cannot make a definitive verdict
    if (buyerResult.status === 'error' || sellerResult.status === 'error') {
        const buyerErr = buyerResult.status === 'error' ? buyerResult.error : null;
        const sellerErr = sellerResult.status === 'error' ? sellerResult.error : null;
        log.add('two-sided-anchoring', 'indeterminate', `anchor fetch failed (RPC error, not an absence signal): ` +
            `${buyerErr ? `buyer error: ${buyerErr}` : ''} ` +
            `${sellerErr ? `seller error: ${sellerErr}` : ''}`.trim());
        return;
    }
    const buyerPresent = buyerResult.status === 'present';
    const sellerPresent = sellerResult.status === 'present';
    if (!buyerPresent && !sellerPresent) {
        log.add('two-sided-anchoring', 'indeterminate', `neither anchor present at ${rpc} (buyer=${pair.buyer} seller=${pair.seller}); bundle may not have been anchored`);
        return;
    }
    if (buyerPresent && !sellerPresent) {
        log.add('two-sided-anchoring', 'fail', `seller anchor absent at ${pair.seller} — per §10.4.3, unilateral ⇒ aborted-by-self for seller`);
        return;
    }
    if (!buyerPresent && sellerPresent) {
        log.add('two-sided-anchoring', 'fail', `buyer anchor absent at ${pair.buyer} — per §10.4.3, unilateral ⇒ aborted-by-self for buyer`);
        return;
    }
    // Both present — parse and verify cross-party identifier match + state match.
    // Narrow the union explicitly so TS sees `.data`.
    if (buyerResult.status !== 'present' || sellerResult.status !== 'present') {
        // Unreachable given the checks above, but tells TS the narrowing
        log.add('two-sided-anchoring', 'indeterminate', 'internal: unexpected status after presence checks');
        return;
    }
    try {
        const buyerData = buyerResult.data;
        const sellerData = sellerResult.data;
        const buyerBundle = JSON.parse(typeof buyerData === 'string' ? buyerData : JSON.stringify(buyerData));
        const sellerBundle = JSON.parse(typeof sellerData === 'string' ? sellerData : JSON.stringify(sellerData));
        // Codex M2 round-4 #1: enforce role tags on the anchored bundles.
        // Anchored at the buyer-anchor address: MUST declare role 'buyer'. Same for seller.
        if (buyerBundle.role !== 'buyer') {
            log.add('two-sided-anchoring', 'fail', `bundle at buyer-anchor declares role="${buyerBundle.role}", expected "buyer" per §10.4.2`);
            return;
        }
        if (sellerBundle.role !== 'seller') {
            log.add('two-sided-anchoring', 'fail', `bundle at seller-anchor declares role="${sellerBundle.role}", expected "seller" per §10.4.2`);
            return;
        }
        // Codex M2 round-5 #1 + round-6 #1: bind the local bundle to one of the two
        // anchored sides via FULL byte-equality (including signatures). A local bundle
        // that differs only in signature from its claimed anchor MUST NOT be accepted.
        // The local bundle IS the anchored bundle on its own side — same signature, same canonical bytes.
        const localFullCanonical = jcsCanonical(bundle);
        const buyerFullCanonical = jcsCanonical(buyerBundle);
        const sellerFullCanonical = jcsCanonical(sellerBundle);
        const matchesBuyer = bytesToHex(sha256(localFullCanonical)) === bytesToHex(sha256(buyerFullCanonical));
        const matchesSeller = bytesToHex(sha256(localFullCanonical)) === bytesToHex(sha256(sellerFullCanonical));
        if (!matchesBuyer && !matchesSeller) {
            log.add('two-sided-anchoring', 'fail', `the bundle being verified is not byte-equal to EITHER party-anchored bundle (jobId shared but content differs — likely a third bundle riding along the jobId)`);
            return;
        }
        // Also enforce that the local bundle's declared role matches whichever anchor it's bound to
        if (matchesBuyer && bundle.role !== 'buyer') {
            log.add('two-sided-anchoring', 'fail', `local bundle is byte-equal to buyer-anchor bundle but declares role="${bundle.role}"`);
            return;
        }
        if (matchesSeller && bundle.role !== 'seller') {
            log.add('two-sided-anchoring', 'fail', `local bundle is byte-equal to seller-anchor bundle but declares role="${bundle.role}"`);
            return;
        }
        if (buyerBundle.jobId !== sellerBundle.jobId || buyerBundle.jobId !== bundle.jobId) {
            log.add('two-sided-anchoring', 'fail', `jobId mismatch: buyer-anchor=${buyerBundle.jobId}, seller-anchor=${sellerBundle.jobId}, local=${bundle.jobId}`);
            return;
        }
        // Codex M2 round-4 #2: anchored bundles MUST cryptographically verify too.
        // Tampered anchors must NOT pass relational checks alone.
        const buyerSigLog = new StepLog();
        if (!verifySignature(buyerBundle, buyerSigLog).ok) {
            log.add('two-sided-anchoring', 'fail', `buyer-anchor bundle signature did NOT verify: ${buyerSigLog.steps.map(s => s.detail).join('; ')}`);
            return;
        }
        const sellerSigLog = new StepLog();
        if (!verifySignature(sellerBundle, sellerSigLog).ok) {
            log.add('two-sided-anchoring', 'fail', `seller-anchor bundle signature did NOT verify: ${sellerSigLog.steps.map(s => s.detail).join('; ')}`);
            return;
        }
        if (!claimRefEqual(buyerBundle.counterparty.primary, sellerBundle.party.primary) ||
            !claimRefEqual(sellerBundle.counterparty.primary, buyerBundle.party.primary)) {
            log.add('two-sided-anchoring', 'fail', `cross-party primary-claim mismatch — buyer and seller anchors describe different deals (dispute signal per §10.4.2)`);
            return;
        }
        if (buyerBundle.state !== sellerBundle.state) {
            log.add('two-sided-anchoring', 'fail', `state mismatch between party bundles: buyer="${buyerBundle.state}" seller="${sellerBundle.state}"`);
            return;
        }
    }
    catch (e) {
        log.add('two-sided-anchoring', 'indeterminate', `failed to parse one or both anchored bundles for content comparison: ${e.message}`);
        return;
    }
    log.add('two-sided-anchoring', 'pass', `both party anchors present + content cross-checked (buyer ${pair.buyer.slice(0, 16)}…, seller ${pair.seller.slice(0, 16)}…)`);
}
async function fetchAnchoredWithStatus(rpc, addr, fetchImpl = fetchAnchored) {
    try {
        const result = await fetchImpl(rpc, addr);
        if (!result)
            return { status: 'absent' };
        return { status: 'present', data: unwrapTextAnchor(result.data) ?? result.data };
    }
    catch (e) {
        return { status: 'error', error: e.message };
    }
}
/**
 * Tuple equality for ClaimRef. Scheme MUST match exactly. Identifier comparison
 * is scheme-specific: cci identifiers are hex (case-insensitive). Other schemes
 * are case-sensitive — silent case-flattening would mask real identifier-differing-by-case
 * bugs (Codex M2 round-4 #3).
 */
function claimRefEqual(a, b) {
    if (a.scheme !== b.scheme)
        return false;
    if (a.scheme === 'cci') {
        return a.identifier.toLowerCase() === b.identifier.toLowerCase();
    }
    return a.identifier === b.identifier;
}
/**
 * §7.5.2 — walk every AttestationRef in the bundle.
 *
 * For each ref:
 *   1. Fetch from ref.anchor.locator via SR-2 (only `substrate: 'demos'` supported in v0.2)
 *   2. Recompute sha256(fetched bytes)
 *   3. Compare to ref.contentHash
 *
 * Mismatch ⇒ §7.5.2 normative MUST cause rejection.
 * Unreachable ⇒ indeterminate (verifier could not produce a definitive verdict).
 */
async function walkAttestationRefs(bundle, rpc, log, fetchImpl = fetchAnchored) {
    const refs = bundle.phases.flatMap(p => p.attestations);
    if (refs.length === 0) {
        log.add('attestation-refs', 'pass', 'bundle has no AttestationRefs (vacuously satisfied)');
        return { verified: 0, failed: 0 };
    }
    let verified = 0;
    let failed = 0;
    for (let i = 0; i < refs.length; i++) {
        const ref = refs[i];
        const label = `attestation[${i}] type=${ref.type}`;
        if (ref.anchor.substrate !== 'demos') {
            log.add(label, 'indeterminate', `anchor.substrate="${ref.anchor.substrate}" — only "demos" is supported in v0.2`);
            continue;
        }
        // dahr-stub: prefix means the attestation is NOT a real consensus-backed-proxy receipt.
        // We still verify the bytes-vs-hash, but mark as indeterminate at the type level so
        // a high-stakes consumer can refuse stub attestations on policy grounds.
        const isStubType = ref.type.startsWith('dahr-stub:');
        const isStubLocator = ref.anchor.locator.startsWith('stor-stub-');
        if (isStubLocator) {
            // No chain to fetch from — the stub locator is content-addressed by the prefix.
            // Sanity-check: the prefix MUST equal the first 32 hex chars of contentHash.
            const expectedPrefix = `stor-stub-${ref.contentHash.slice(0, 32)}`;
            if (ref.anchor.locator !== expectedPrefix) {
                log.add(label, 'fail', `stub locator "${ref.anchor.locator}" does not match contentHash prefix "${expectedPrefix}"`);
                failed++;
                continue;
            }
            // Bytes are not retrievable from a stub locator; mark as indeterminate per stub semantics
            log.add(label, 'indeterminate', `stub locator (no chain fetch); contentHash prefix matches but bytes not anchored. ` +
                `Type "${ref.type}" — high-stakes verifiers SHOULD refuse stub attestations.`);
            continue;
        }
        // Real anchor — fetch from chain and verify
        let fetched;
        try {
            fetched = await fetchImpl(rpc, ref.anchor.locator);
        }
        catch (e) {
            log.add(label, 'indeterminate', `failed to fetch ${ref.anchor.locator} from ${rpc}: ${e.message}`);
            continue;
        }
        if (!fetched) {
            log.add(label, 'indeterminate', `${ref.anchor.locator} not found at ${rpc}`);
            continue;
        }
        // Codex M2 #4: the verifier MUST hash the same bytes the writer hashed. dahrFetch()
        // anchors a string (decoded raw response body); fetched.data should round-trip back as
        // a string. If StorageProgram returned an object (json encoding), the SDK may have
        // re-serialized with a different canonical form than what was originally written, so
        // re-encoding via JSON.stringify(object) is NOT byte-equivalent to the original anchor.
        // v0.2 verifier accepts ONLY string-anchored attestations to keep the hash chain honest;
        // object-anchored attestations resolve to indeterminate until v0.3 wires the canonical-
        // bytes API the SDK exposes for that case.
        const fetchedData = unwrapTextAnchor(fetched.data) ?? fetched.data;
        if (typeof fetchedData !== 'string') {
            log.add(label, 'indeterminate', `anchored data is not a string (type=${typeof fetchedData}). v0.2 verifier only ` +
                `handles string-anchored attestations (DAHR shape); object-anchored attestations land in v0.3.`);
            continue;
        }
        const bytes = new TextEncoder().encode(fetchedData);
        const actualHash = bytesToHex(sha256(bytes));
        if (actualHash !== ref.contentHash.toLowerCase()) {
            log.add(label, 'fail', `content-hash mismatch at ${ref.anchor.locator}: expected ${ref.contentHash.slice(0, 16)}…, ` +
                `got ${actualHash.slice(0, 16)}… — §7.5.2 normative MUST cause rejection`);
            failed++;
            continue;
        }
        if (isStubType) {
            log.add(label, 'indeterminate', `content-hash matches but type carries dahr-stub: prefix — no validator-quorum signature wraps the fetch. ` +
                `High-stakes verifiers SHOULD refuse.`);
            continue;
        }
        log.add(label, 'pass', `content-hash matches (${actualHash.slice(0, 16)}…); type=${ref.type}; anchor=${ref.anchor.locator}`);
        verified++;
    }
    return { verified, failed };
}
/** The full §10.4.1 walk. */
export async function verifyBundle(bundle, options = {}) {
    const log = new StepLog();
    const rpc = options.rpc ?? 'https://demosnode.discus.sh/';
    log.add('parse-bundle', 'pass', `bundle.v=${bundle.v}, jobId=${bundle.jobId}, role=${bundle.role}`);
    // §10.4.1 step 1: canonical form + bundleHash
    const unsigned = { ...bundle, signature: undefined, orchestratorSignature: undefined };
    const canonical = jcsCanonical(unsigned);
    const bundleHash = jcsHash(unsigned);
    const bundleHashHex = bytesToHex(bundleHash);
    log.add('canonicalize', 'pass', `JCS canonical bytes=${canonical.length}, bundleHash=${bundleHashHex.slice(0, 16)}…`);
    // §10.4.1 step 2-3: signature
    const sigResult = verifySignature(bundle, log);
    // §10.4.2 + §10.4.3: two-sided anchoring. When the caller explicitly opts into
    // offline file verification (skipTwoSidedLookup=true), the check is recorded
    // as `skipped` — informational only, not a verdict blocker. The caller has
    // chosen scope and is responsible for understanding that §10.4.3 unilateral
    // detection cannot be enforced offline.
    if (!options.skipTwoSidedLookup) {
        await verifyTwoSidedAnchoring(bundle, rpc, log, options.counterpartyBundle, options.fetchAnchoredImpl);
    }
    else {
        log.add('two-sided-anchoring', 'skipped', 'skipTwoSidedLookup=true — offline file verification; §10.4.3 unilateral detection not enforced. ' +
            'Caller accepts this scope limit (e.g. for receipt-archive auditing where both anchors are not on the chain being queried).');
    }
    // §7.5.2: AttestationRef walk (Codex M2 round-6 #2: also threads the injected fetch impl)
    const attestationResults = await walkAttestationRefs(bundle, rpc, log, options.fetchAnchoredImpl);
    return {
        decision: log.rollupDecision(),
        jobId: bundle.jobId,
        steps: log.steps,
        canonicalBundleHash: bundleHashHex,
        signersVerified: sigResult.signerPubkeyHex ? [sigResult.signerPubkeyHex] : [],
        attestationsVerified: attestationResults.verified,
        attestationsFailed: attestationResults.failed,
    };
}
