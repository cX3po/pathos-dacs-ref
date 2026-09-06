/**
 * DACS-2 §7.5.2 (DACS-2-VET.md lines 638-639): `AttestationRef.contentHash` is the sha256 of the cited
 * artifact's signature-excluded RFC 8785 canonical form, the same scope the artifact's own signature
 * covers. The pinned dacs-sdk checks exactly that (checkArtifact: stripSignature, then contentHash).
 * Our anchor receipts keep binding the stored bytes (SR2-4); the two hashes differ for signed documents.
 */
export declare function signatureExcludedHash(artifact: unknown): string;
