/** SR2-4: cold `pass` means the injected receipt provider attested finalization and every offline-checkable field agrees; it does not mean substrate-proven finality. */
import { type DomainSeparator } from '../../domain-sep.js';
import type { AgreementDocumentV1, AgreementPartyV1, AgreementTermsV1, AnchorReceipt, FinalityCommitmentRecord } from '../../types/bundle.js';
import type { ClaimRef } from '../../types/identity.js';
type Claim = ClaimRef | string;
type JsonObject = Record<string, unknown>;
export declare class AgreementCommitmentError extends Error {
    readonly code: string;
    constructor(code: string, message: string);
}
export declare class NotSupportedError extends AgreementCommitmentError {
    constructor(message: string);
}
export interface AdapterSigner {
    claim: Claim;
    algorithm?: 'ed25519' | 'ecdsa-secp256k1' | 'sr1-aggregate';
    sign(domain: DomainSeparator, hash: string): Promise<string | Uint8Array> | string | Uint8Array;
}
export interface AgreementAnchorResult {
    logicalAddress: string;
    nativeAddress: string;
    transactionRef: {
        kind: string;
        value: string;
    };
    writer: string;
    nonce?: string;
}
export interface AgreementCommitmentInput {
    jobId: string;
    listing: JsonObject;
    listingRef?: {
        listingId: string;
        version: number;
        contentHash: string;
    };
    parties: AgreementPartyV1[];
    terms: AgreementTermsV1;
    derivedFromPattern?: 'fixed-price' | 'rfq' | 'sealed-envelope';
    derivedFromChannel?: {
        subnet: string;
        lastMessageHash: string;
    };
    anchorAgreement?: boolean;
}
export interface AgreementCommitmentDependencies {
    signers: {
        buyer: AdapterSigner;
        seller: AdapterSigner;
        orchestrator: AdapterSigner;
    };
    anchor(request: {
        logicalAddress: string;
        content: unknown;
        contentHash: string;
    }): Promise<AgreementAnchorResult>;
    fetchAnchored(address: string): Promise<unknown>;
    receiptProvider(request: {
        logicalAddress: string;
        contentHash: string;
        anchor: AgreementAnchorResult;
    }): Promise<AnchorReceipt>;
    now?: () => number;
}
export interface CommittedAgreement {
    agreement: AgreementDocumentV1;
    agreementHash: string;
    /** The exact DACS-2 §7.5.2 reference to the signed agreement; the unsigned document hash is the sibling `agreementHash`. */
    agreementRef: {
        anchor: {
            kind: 'storage-program';
            locator: string;
        };
        contentHash: string;
    };
    commitment: FinalityCommitmentRecord;
    commitmentHash: string;
    receipt: AnchorReceipt;
    committedAt: number;
    addresses: {
        agreement?: {
            logical: string;
            native: string;
        };
        commitment: {
            logical: string;
            native: string;
        };
    };
}
export interface AgreementCommitmentExpectation {
    jobId: string;
    listing: JsonObject;
    agreement: AgreementDocumentV1;
    agreementHash: string;
    commitment: FinalityCommitmentRecord;
    commitmentHash: string;
    receipt?: AnchorReceipt;
    addresses: CommittedAgreement['addresses'];
}
export interface AgreementCommitmentReadDependencies {
    fetchAnchored(address: string): Promise<unknown>;
    receiptProvider(request: {
        logicalAddress: string;
        contentHash: string;
        anchor?: AgreementAnchorResult;
    }): Promise<AnchorReceipt>;
    verifySignature(request: {
        domain: DomainSeparator;
        hash: string;
        signer: Claim;
        algorithm: string;
        value: string;
    }): Promise<boolean> | boolean;
}
export declare function commitAgreement(input: AgreementCommitmentInput, deps: AgreementCommitmentDependencies): Promise<CommittedAgreement>;
export declare function verifyAgreementCommitmentCold(expected: AgreementCommitmentExpectation, deps: AgreementCommitmentReadDependencies): Promise<{
    outcome: 'pass' | 'fail' | 'indeterminate';
    detail: string;
}>;
export {};
