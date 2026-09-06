/** SR2-4: cold `pass` means the injected receipt provider attested finalization and every offline-checkable field agrees; it does not mean substrate-proven finality. */
import { DOMAIN_SEPARATORS, ADDITIVE_DOMAIN_SEPARATORS } from '../../domain-sep.js';
import { signatureExcludedHash } from '../../lib/content-hash.js';
import { sha256 } from '@noble/hashes/sha2';
import { jcsCanonical, jcsHashHex } from '../../jcs.js';
import { claimKey } from '../../lib/verify-bundle-v1.js';
export class AgreementCommitmentError extends Error {
    code;
    constructor(code, message) {
        super(message);
        this.code = code;
        this.name = 'AgreementCommitmentError';
    }
}
export class NotSupportedError extends AgreementCommitmentError {
    constructor(message) {
        super('not-supported', message);
        this.name = 'NotSupportedError';
    }
}
function object(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        throw new AgreementCommitmentError('malformed', 'expected a JSON object');
    return value;
}
function hashWithout(value, field) {
    const copy = { ...value };
    delete copy[field];
    return jcsHashHex(copy);
}
function signatureValue(value) {
    const encoded = value instanceof Uint8Array
        ? Buffer.from(value).toString('base64url')
        : value;
    if (!/^[A-Za-z0-9_-]+$/.test(encoded) || encoded.includes('=')) {
        throw new AgreementCommitmentError('signature-encoding', 'signature must use unpadded Base64URL (SIG-6)');
    }
    return encoded;
}
async function signedValue(signer, domain, hash) {
    return signatureValue(await signer.sign(domain, hash));
}
function listingReference(listing, supplied) {
    const listingId = listing.listingId ?? listing.id;
    const version = listing.listingVersion ?? listing.version;
    const unsigned = { ...listing };
    delete unsigned.signature;
    delete unsigned.contentHash;
    const recomputedContentHash = jcsHashHex(unsigned);
    if (listing.contentHash !== undefined && listing.contentHash !== recomputedContentHash) {
        throw new AgreementCommitmentError('listing-ref', 'listing contentHash does not match its signed scope (§8.5.2)');
    }
    const contentHash = recomputedContentHash;
    const actual = { listingId, version, contentHash };
    if (typeof listingId !== 'string' || !Number.isSafeInteger(version) || !/^[0-9a-f]{64}$/.test(contentHash)) {
        throw new AgreementCommitmentError('listing-ref', 'listing cannot produce a complete pinned listing reference');
    }
    if (supplied && jcsHashHex(supplied) !== jcsHashHex(actual)) {
        throw new AgreementCommitmentError('listing-ref', 'supplied listingRef does not match the pinned listing');
    }
    return actual;
}
const PAYMENT = new Set(['pay-evm-erc20', 'pay-solana-spl', 'pay-cross-chain-htlc', 'pay-cross-chain-liquidity-tank', 'pay-ap2', 'pay-x402', 'pay-dem', 'pay-alternative']);
const NEGOTIATION = {
    'negotiate-fixed-price': 'fixed-price',
    'negotiate-rfq': 'rfq',
    'negotiate-sealed-envelope': 'sealed-envelope',
    'negotiate-sealed-envelope-procurement': 'sealed-envelope',
};
function decimalParts(value) {
    if (!/^(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?$/.test(value))
        throw new AgreementCommitmentError('price', `non-canonical CD-1 decimal: ${value}`);
    const [whole, fraction = ''] = value.split('.');
    return { coefficient: BigInt(whole + fraction), scale: fraction.length };
}
function compareDecimal(a, b) {
    const x = decimalParts(a), y = decimalParts(b);
    const scale = Math.max(x.scale, y.scale);
    const ax = x.coefficient * 10n ** BigInt(scale - x.scale);
    const by = y.coefficient * 10n ** BigInt(scale - y.scale);
    return ax < by ? -1 : ax > by ? 1 : 0;
}
function roundedPercent(center, percent, add) {
    if (!Number.isSafeInteger(percent) || percent < 0 || (!add && percent >= 100))
        throw new AgreementCommitmentError('price', 'invalid negotiable percentage');
    const p = decimalParts(center);
    const numerator = p.coefficient * BigInt(add ? 100 + percent : 100 - percent);
    const rounded = (numerator + 50n) / 100n;
    const raw = rounded.toString().padStart(p.scale + 1, '0');
    if (p.scale === 0)
        return raw;
    const result = `${raw.slice(0, -p.scale)}.${raw.slice(-p.scale)}`.replace(/\.0+$/, '').replace(/(\.[0-9]*[1-9])0+$/, '$1');
    return result;
}
function expectedDeliverable(listing) {
    const offering = object(listing.offering);
    const spec = object(offering.deliverable);
    if (typeof spec.deliverableType === 'string' && typeof spec.hash === 'string')
        return spec;
    if (typeof spec.kind !== 'string')
        throw new AgreementCommitmentError('deliverable', 'listing deliverable kind is missing');
    const result = { deliverableType: spec.kind, hash: jcsHashHex(spec) };
    if (typeof spec.schemaUrl === 'string')
        result.schemaUrl = spec.schemaUrl;
    return result;
}
function validateAgreement(listing, agreement, committedAt, provisional) {
    const ref = listingReference(listing);
    if (jcsHashHex(agreement.listingRef) !== jcsHashHex(ref))
        throw new AgreementCommitmentError('listing-ref', 'agreement listingRef mismatch');
    const pipeline = listing.pipeline;
    if (!Array.isArray(pipeline) || pipeline.length === 0)
        throw new AgreementCommitmentError('pipeline', 'listing pipeline must be non-empty');
    const phases = pipeline.map((p) => object(p));
    const commit = phases.filter((p) => p.kind === 'commit-agreement' || p.kind === 'commit-payee-bound-agreement');
    if (commit.length !== 1)
        throw new AgreementCommitmentError('commit-phase', 'pipeline must select exactly one agreement commitment phase');
    if (commit[0].kind === 'commit-payee-bound-agreement')
        throw new NotSupportedError('commit-payee-bound-agreement is out of scope for this adapter');
    const negotiation = phases.filter((p) => typeof p.kind === 'string' && NEGOTIATION[p.kind]);
    if (negotiation.length !== 1 || NEGOTIATION[negotiation[0].kind] !== agreement.derivedFromPattern) {
        throw new AgreementCommitmentError('pattern', 'agreement pattern does not match the listing negotiation phase');
    }
    const pricing = object(listing.pricing);
    const price = agreement.terms.price;
    let listedPrice;
    if (pricing.kind === 'fixed')
        listedPrice = object(pricing.price);
    else if (pricing.kind === 'negotiable')
        listedPrice = object(pricing.bandCenter);
    else if (pricing.kind === 'metered')
        listedPrice = object(pricing.unitPrice);
    else
        throw new AgreementCommitmentError('unrecognized-pricing-kind', 'listing pricing kind is not supported');
    if (price.currency !== listedPrice.currency)
        throw new AgreementCommitmentError('currency', 'agreement and listing currencies differ');
    decimalParts(price.amount);
    if (pricing.kind === 'fixed' || (pricing.kind === 'negotiable' && agreement.derivedFromPattern === 'fixed-price')) {
        if (compareDecimal(price.amount, String(listedPrice.amount)) !== 0)
            throw new AgreementCommitmentError('price', 'agreement price does not equal listed price');
    }
    else if (pricing.kind === 'negotiable') {
        const low = roundedPercent(String(listedPrice.amount), Number(pricing.minPct), false);
        const high = roundedPercent(String(listedPrice.amount), Number(pricing.maxPct), true);
        if (compareDecimal(low, '0') <= 0 || compareDecimal(price.amount, low) < 0 || compareDecimal(price.amount, high) > 0) {
            throw new AgreementCommitmentError('price', 'agreement price is outside the inclusive listing band');
        }
    }
    else {
        const mq = agreement.terms.meteredQuantity;
        if (!mq || mq.unit !== pricing.unit || !/^(?:0|[1-9][0-9]*)$/.test(mq.quantity))
            throw new AgreementCommitmentError('price', 'metered quantity/unit is invalid');
        const unit = decimalParts(String(listedPrice.amount));
        const product = unit.coefficient * BigInt(mq.quantity);
        const raw = product.toString().padStart(unit.scale + 1, '0');
        const productText = unit.scale ? `${raw.slice(0, -unit.scale)}.${raw.slice(-unit.scale)}`.replace(/\.0+$/, '').replace(/(\.[0-9]*[1-9])0+$/, '$1') : raw;
        const minimum = pricing.minTotal ? String(object(pricing.minTotal).amount) : '0';
        const total = compareDecimal(productText, minimum) < 0 ? minimum : productText;
        if (compareDecimal(price.amount, total) !== 0)
            throw new AgreementCommitmentError('price', 'metered total does not match listing');
    }
    const payPhases = phases.filter((p) => PAYMENT.has(String(p.kind)));
    if ((payPhases.length > 0) !== (agreement.terms.rail !== undefined))
        throw new AgreementCommitmentError('rail', 'rail presence does not match pipeline');
    if (agreement.terms.rail) {
        const rail = agreement.terms.rail;
        const alternativePhases = payPhases.filter((p) => p.kind === 'pay-alternative');
        const canonical = jcsHashHex(rail);
        if (alternativePhases.length > 0) {
            const alternatives = alternativePhases.flatMap((p) => {
                const values = object(p.parameters).alternatives;
                return Array.isArray(values) ? values : [];
            });
            if (alternatives.filter((x) => jcsHashHex(x) === canonical).length !== 1) {
                throw new AgreementCommitmentError('rail', 'agreement rail must canonically match exactly one signed alternative (APR-3)');
            }
        }
        else {
            const accepted = Array.isArray(listing.acceptedRails) ? listing.acceptedRails : [];
            if (!accepted.some((x) => typeof x === 'string' ? x === rail.railId : jcsHashHex(x) === canonical)) {
                throw new AgreementCommitmentError('rail', 'agreement rail is not an accepted complete reference');
            }
        }
    }
    if (jcsHashHex(agreement.terms.deliverable) !== jcsHashHex(expectedDeliverable(listing)))
        throw new AgreementCommitmentError('deliverable', 'agreement deliverable does not match listing');
    const sealed = negotiation[0].kind;
    if (sealed === 'negotiate-sealed-envelope-procurement' && object(negotiation[0].parameters).auctionMode !== 'procurement') {
        throw new AgreementCommitmentError('unresolvable-auctionMode', 'procurement auctionMode is missing or invalid');
    }
    if (sealed === 'negotiate-sealed-envelope') {
        const mode = negotiation[0].parameters === undefined ? undefined : object(negotiation[0].parameters).auctionMode;
        if (mode !== undefined && mode !== 'demand')
            throw new AgreementCommitmentError('unresolvable-auctionMode', 'demand auctionMode is invalid');
    }
    if (sealed === 'negotiate-sealed-envelope' || sealed === 'negotiate-sealed-envelope-procurement') {
        const sellerRecord = listing.seller === undefined ? undefined : object(listing.seller);
        const identity = sellerRecord?.identity === undefined ? undefined : object(sellerRecord.identity);
        // DACS-1 §6.3.4: the publisher is the identity bundle's presented claim; older listing shapes named it as seller.primaryClaim,
        // identity.primary or publisher. A sealed pattern without a resolvable publisher cannot establish SE-8 role direction.
        const publisher = (identity?.presentedBy ?? sellerRecord?.primaryClaim ?? identity?.primary ?? listing.publisher);
        if (publisher === undefined)
            throw new AgreementCommitmentError('sealed-envelope-publisher', 'sealed-envelope listing does not name its publisher (SE-8)');
        {
            const publisherRole = agreement.parties.find((party) => claimKey(party.primaryClaim) === claimKey(publisher))?.role;
            const expectedRole = sealed === 'negotiate-sealed-envelope' ? 'seller' : 'buyer';
            if (publisherRole !== expectedRole)
                throw new AgreementCommitmentError('sealed-envelope-role-direction', 'agreement buyer/seller direction contradicts auctionMode (SE-8)');
        }
    }
    if (agreement.terms.priorPaymentDispositionRef !== undefined) {
        throw new NotSupportedError('priorPaymentDispositionRef replacement disposition is not supported (APR-5/APR-6)');
    }
    const deadlineSec = object(listing.terms).deadlineSecAfterCommit;
    if (deadlineSec !== undefined && (!Number.isSafeInteger(deadlineSec) || agreement.terms.deadline > committedAt + Number(deadlineSec) * 1000)) {
        throw new AgreementCommitmentError('deadline', provisional ? 'provisional agreement deadline exceeds listing window' : 'receipt-relative agreement deadline exceeds listing window');
    }
    const notAfter = object(listing.validity).notAfter;
    if (notAfter !== undefined && (typeof notAfter !== 'number' || notAfter < committedAt))
        throw new AgreementCommitmentError('expired', 'listing expired before commitment finality');
}
function receiptBinding(receipt, expected) {
    const a = expected.anchor;
    if (receipt.receiptVersion !== '1' || receipt.observationDisposition !== 'established')
        throw new AgreementCommitmentError('receipt', 'receipt is not an established CORE receipt');
    if (receipt.logicalAddress !== expected.logicalAddress || receipt.contentHash !== expected.contentHash ||
        (a && (receipt.nativeAddress !== a.nativeAddress || receipt.writer !== a.writer || receipt.transactionRef.kind !== a.transactionRef.kind || receipt.transactionRef.value !== a.transactionRef.value || receipt.nonce !== a.nonce))) {
        throw new AgreementCommitmentError('receipt-binding', 'receipt does not bind the submitted logical/native address, hash, transaction, writer, and nonce');
    }
    if (receipt.evidence.kind !== 'stored-bytes-base64url') {
        throw new AgreementCommitmentError('evidence-unverifiable', 'receipt evidence does not carry recoverable stored bytes (SR2-4)');
    }
    if (!/^[A-Za-z0-9_-]*$/.test(receipt.evidence.value) || receipt.evidence.value.includes('=')) {
        throw new AgreementCommitmentError('receipt-evidence', 'receipt evidence stored bytes are not valid unpadded Base64URL');
    }
    const storedBytes = new Uint8Array(Buffer.from(receipt.evidence.value, 'base64url'));
    if (Buffer.from(storedBytes).toString('base64url') !== receipt.evidence.value) {
        throw new AgreementCommitmentError('receipt-evidence', 'receipt evidence stored bytes are not valid unpadded Base64URL');
    }
    const evidenceHash = Buffer.from(sha256(storedBytes)).toString('hex');
    if (evidenceHash !== expected.contentHash || (expected.storedContent !== undefined && !Buffer.from(storedBytes).equals(Buffer.from(jcsCanonical(expected.storedContent))))) {
        throw new AgreementCommitmentError('receipt-evidence', 'receipt evidence bytes do not match the stored contentHash (SR2-4)');
    }
    const { state: lifecycle, } = receipt;
    if (lifecycle !== 'finalized' || !receipt.blockRef || !Number.isSafeInteger(receipt.blockRef.timestamp)) {
        throw new AgreementCommitmentError('finality', 'commitment receipt is not finalized with a consensus timestamp');
    }
    return receipt.blockRef.timestamp;
}
function fetchedObject(value) {
    if (typeof value === 'string')
        return object(JSON.parse(value));
    return object(value);
}
export async function commitAgreement(input, deps) {
    const now = deps.now?.() ?? Date.now();
    if (!input.jobId)
        throw new AgreementCommitmentError('job-id', 'jobId is required');
    const listingRef = listingReference(input.listing, input.listingRef);
    const roles = new Map(input.parties.map((p) => [p.role, p]));
    if (!roles.get('buyer') || !roles.get('seller'))
        throw new AgreementCommitmentError('parties', 'agreement requires buyer and seller parties');
    if (claimKey(roles.get('buyer').primaryClaim) !== claimKey(deps.signers.buyer.claim) || claimKey(roles.get('seller').primaryClaim) !== claimKey(deps.signers.seller.claim)) {
        throw new AgreementCommitmentError('signer', 'agreement signers do not match buyer/seller party claims');
    }
    const pattern = input.derivedFromPattern ?? (() => {
        const pipeline = input.listing.pipeline;
        return pipeline?.map((p) => NEGOTIATION[String(p.kind)]).find(Boolean);
    })();
    if (!pattern)
        throw new AgreementCommitmentError('pattern', 'listing has no recognized negotiation phase');
    const unsigned = {
        agreementVersion: '1', jobId: input.jobId, listingRef, parties: input.parties,
        terms: input.terms, derivedFromPattern: pattern, generatedAt: now,
        ...(input.derivedFromChannel ? { derivedFromChannel: input.derivedFromChannel } : {}),
    };
    validateAgreement(input.listing, unsigned, now, true);
    const agreementHash = jcsHashHex(unsigned);
    const agreement = { ...unsigned, signatures: [
            { party: deps.signers.buyer.claim, algorithm: deps.signers.buyer.algorithm ?? 'ed25519', value: await signedValue(deps.signers.buyer, DOMAIN_SEPARATORS.AGREEMENT, agreementHash) },
            { party: deps.signers.seller.claim, algorithm: deps.signers.seller.algorithm ?? 'ed25519', value: await signedValue(deps.signers.seller, DOMAIN_SEPARATORS.AGREEMENT, agreementHash) },
        ] };
    const agreementLogical = `dacs3:agreement:${input.jobId}`;
    let agreementAnchor;
    if (input.anchorAgreement !== false) {
        agreementAnchor = await deps.anchor({ logicalAddress: agreementLogical, content: agreement, contentHash: jcsHashHex(agreement) });
        const fetched = fetchedObject(await deps.fetchAnchored(agreementAnchor.nativeAddress));
        if (jcsHashHex(fetched) !== jcsHashHex(agreement))
            throw new AgreementCommitmentError('cold-read', 'anchored agreement did not resolve byte-equivalently');
    }
    const commitmentUnsigned = {
        finalityCommitmentVersion: '1', jobId: input.jobId, agreementHash, listingRef,
        parties: [roles.get('buyer').primaryClaim, roles.get('seller').primaryClaim], pattern, createdAt: now,
    };
    const commitmentScopeHash = jcsHashHex(commitmentUnsigned);
    const commitment = { ...commitmentUnsigned, signature: {
            algorithm: deps.signers.orchestrator.algorithm ?? 'ed25519', signer: deps.signers.orchestrator.claim,
            value: await signedValue(deps.signers.orchestrator, ADDITIVE_DOMAIN_SEPARATORS.FINALITY_COMMITMENT, commitmentScopeHash),
        } };
    const commitmentHash = jcsHashHex(commitment);
    const commitmentLogical = `dacs3:commit:${input.jobId}`;
    const commitmentAnchor = await deps.anchor({ logicalAddress: commitmentLogical, content: commitment, contentHash: commitmentHash });
    const fetchedCommitment = fetchedObject(await deps.fetchAnchored(commitmentAnchor.nativeAddress));
    if (jcsHashHex(fetchedCommitment) !== commitmentHash)
        throw new AgreementCommitmentError('cold-read', 'commitment did not independently resolve');
    const receipt = await deps.receiptProvider({ logicalAddress: commitmentLogical, contentHash: commitmentHash, anchor: commitmentAnchor });
    const committedAt = receiptBinding(receipt, { logicalAddress: commitmentLogical, contentHash: commitmentHash, anchor: commitmentAnchor, storedContent: fetchedCommitment });
    validateAgreement(input.listing, unsigned, committedAt, false);
    return {
        agreement, agreementHash,
        agreementRef: { anchor: { kind: 'storage-program', locator: agreementAnchor?.nativeAddress ?? agreementLogical }, contentHash: signatureExcludedHash(agreement) },
        commitment, commitmentHash, receipt, committedAt,
        addresses: { ...(agreementAnchor ? { agreement: { logical: agreementLogical, native: agreementAnchor.nativeAddress } } : {}), commitment: { logical: commitmentLogical, native: commitmentAnchor.nativeAddress } },
    };
}
export async function verifyAgreementCommitmentCold(expected, deps) {
    if (typeof deps.verifySignature !== 'function')
        throw new AgreementCommitmentError('verifier-required', 'verifySignature is required for cold commitment verification (CA-6/CA-7)');
    try {
        let fetched;
        try {
            fetched = fetchedObject(await deps.fetchAnchored(expected.addresses.commitment.native));
        }
        catch {
            return { outcome: 'indeterminate', detail: 'commitment could not be independently resolved' };
        }
        if (jcsHashHex(fetched) !== expected.commitmentHash || jcsHashHex(expected.commitment) !== expected.commitmentHash)
            return { outcome: 'fail', detail: 'commitment content hash mismatch' };
        if (expected.commitment.finalityCommitmentVersion !== '1' || 'dacsVersion' in expected.commitment)
            return { outcome: 'fail', detail: 'unsupported or ambiguous commitment discriminator' };
        if (expected.commitment.jobId !== expected.jobId || expected.commitment.agreementHash !== expected.agreementHash)
            return { outcome: 'fail', detail: 'commitment job/agreement binding mismatch' };
        if (hashWithout(expected.agreement, 'signatures') !== expected.agreementHash)
            return { outcome: 'fail', detail: 'agreement hash mismatch' };
        const scopeHash = hashWithout(expected.commitment, 'signature');
        const valid = await deps.verifySignature({ domain: ADDITIVE_DOMAIN_SEPARATORS.FINALITY_COMMITMENT, hash: scopeHash, ...expected.commitment.signature });
        if (!valid)
            return { outcome: 'fail', detail: 'commitment orchestrator signature invalid' };
        const buyer = expected.agreement.parties.find((party) => party.role === 'buyer');
        const seller = expected.agreement.parties.find((party) => party.role === 'seller');
        if (!buyer || !seller)
            return { outcome: 'fail', detail: 'agreement requires buyer and seller parties' };
        for (const [role, party] of [['buyer', buyer], ['seller', seller]]) {
            const signatures = expected.agreement.signatures.filter((sig) => claimKey(sig.party) === claimKey(party.primaryClaim));
            if (signatures.length !== 1)
                return { outcome: 'fail', detail: `agreement requires exactly one ${role} signature` };
            const sig = signatures[0];
            if (!await deps.verifySignature({ domain: DOMAIN_SEPARATORS.AGREEMENT, hash: expected.agreementHash, signer: sig.party, algorithm: sig.algorithm, value: sig.value }))
                return { outcome: 'fail', detail: `agreement ${role} signature invalid` };
        }
        let receipt;
        try {
            receipt = await deps.receiptProvider({ logicalAddress: expected.addresses.commitment.logical, contentHash: expected.commitmentHash });
        }
        catch {
            return { outcome: 'indeterminate', detail: 'commitment receipt unavailable' };
        }
        let committedAt;
        const prior = expected.receipt;
        const expectedAnchor = prior ? {
            logicalAddress: expected.addresses.commitment.logical,
            nativeAddress: expected.addresses.commitment.native,
            transactionRef: prior.transactionRef,
            writer: prior.writer,
            ...(prior.nonce !== undefined ? { nonce: prior.nonce } : {}),
        } : undefined;
        try {
            committedAt = receiptBinding(receipt, { logicalAddress: expected.addresses.commitment.logical, contentHash: expected.commitmentHash, anchor: expectedAnchor, storedContent: fetched });
        }
        catch (error) {
            if (error instanceof AgreementCommitmentError && error.code === 'finality')
                return { outcome: 'indeterminate', detail: error.message };
            return { outcome: 'fail', detail: error instanceof Error ? error.message : 'invalid receipt' };
        }
        validateAgreement(expected.listing, { ...expected.agreement, signatures: undefined }, committedAt, false);
        return { outcome: 'pass', detail: 'agreement, finality commitment, cold read, and finalized receipt verified' };
    }
    catch (error) {
        return { outcome: 'fail', detail: error instanceof Error ? error.message : 'agreement commitment verification failed' };
    }
}
