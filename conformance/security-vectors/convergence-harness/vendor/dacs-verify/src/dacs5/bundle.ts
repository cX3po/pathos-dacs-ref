import { canonicalize, withoutSignature } from "../canonicalize.ts";
import { sha256Hex } from "../hash.ts";
import { verifyArtifactSignature } from "../signing.ts";
import { schemeOf, type ClaimReference } from "../dacs1.ts";

export type BundleDecision = "pass" | "fail" | "indeterminate" | "error";

export type BundleOutcome =
  | "completed"
  | "failed-perm"
  | "failed-counterparty"
  | "failed-substrate"
  | "aborted-by-self"
  | "aborted-by-other";

export type PhaseType = string;

export interface AttestationRef {
  kind: string;
  id: string;
  contentHash: string;
}

export interface ChainTxRef {
  rail: string;
  txHash: string;
  kind?: string;
  chainId?: number | string;
  cluster?: "mainnet" | "devnet" | "testnet" | string;
  signature?: string;
  logIndex?: number;
  instructionIndex?: number;
}

// §10.4 (L3085): the role of the party that anchored THIS copy. `outcome` is recorded from this party's
// perspective and the value matches the §10.4.2 role-derived anchor address. REQUIRED + signed (inside the
// bundle hash) — added in the Round-4 R4-B fix so §10.5.1 derive() can reconcile two-sided copies per-jobId.
export type AnchoredByRole = "buyer" | "seller" | "orchestrator";

export interface AttestationBundle {
  bundleVersion: "1";
  jobId: string;
  outcome: BundleOutcome;
  anchoredByRole: AnchoredByRole;
  listingRef: { listingId: string; version: number; contentHash: string };
  agreementRef?: AttestationRef;
  parties: BundleParty[];
  phaseSummary: BundlePhaseEntry[];
  vetRecords: AttestationRef[];
  settlementEvidence: AttestationRef[];
  amendments?: AttestationRef[];
  ratingRefs?: AttestationRef[];
  recipeRegistryVersion: number;
  railRegistryVersion: number;
  finalisedAt: number;
  signatures: BundleSignature[];
}

export interface BundleParty {
  role: "buyer" | "seller" | "orchestrator";
  bundleHash: string;
  primaryClaim: ClaimReference;
}

export interface BundlePhaseEntry {
  index: number;
  kind: PhaseType;
  outcome: "ok" | "fail";
  errorClass?: "permanent" | "transient" | "counterparty" | "substrate" | "settlement-atomicity";
  txRefs?: ChainTxRef[];
  attestationRef?: AttestationRef;
}

export interface BundleSignature {
  party: ClaimReference;
  algorithm: "ed25519" | "ecdsa-secp256k1" | "sr1-aggregate";
  value: string;
}

export type BundleKeyResolver = (party: ClaimReference) => Uint8Array | null | undefined;

// §10.6 (L3389) RatingRecord — the rate-phase artifact referenced from a bundle's `ratingRefs`. §10.5.1 derive()
// aggregates these (with de-duplication) into averageBuyerRating / averageSellerRating. The deriver reads jobId,
// rater, target, targetRole, value, ratedAt; the SIGNATURE is verified by the injected fetch_and_verify resolver
// (the §10.5.1 `fetch_and_verify_rating` call), not by derive() itself — mirroring the spec's injection style.
export interface RatingRecord {
  ratingVersion: "1";
  jobId: string;
  rater: ClaimReference;
  target: ClaimReference;
  targetRole: "buyer" | "seller";
  value: number;
  freeText?: string;
  dimensions?: Record<string, number>;
  ratedAt: number;
  signature: { algorithm: "ed25519" | "ecdsa-secp256k1" | "sr1-aggregate"; signer: ClaimReference; value: string };
}

// §10.5.1 injected resolvers (the spec's `fetch_and_verify_*` calls). Each returns the verified artifact, or null
// when the anchor is unreadable / contentHash-mismatched / signature-invalid (the spec's "exclude that bundle/rating"
// path). The crypto + anchor resolution lives in the resolver (caller-supplied); derive() does the spec's binding,
// range, de-dup, and grouping logic. When a resolver is absent, that metric stays null/empty (no signal).
export type RatingResolver = (ref: AttestationRef) => RatingRecord | null;
export type AgreementPriceResolver = (ref: AttestationRef) => { amount: string; currency: string } | null;

const TERMINAL_REQUIRED_OUTCOMES: ReadonlySet<BundleOutcome> = new Set([
  "completed",
  "failed-perm",
  "failed-counterparty",
  "failed-substrate",
]);

const ALLOWED_OUTCOMES: ReadonlySet<string> = new Set([
  "completed",
  "failed-perm",
  "failed-counterparty",
  "failed-substrate",
  "aborted-by-self",
  "aborted-by-other",
]);

const HASH_RE = /^[0-9a-f]{64}$/;
const PARTY_ROLES: ReadonlySet<string> = new Set(["buyer", "seller", "orchestrator"]);
const ANCHORED_BY_ROLES: ReadonlySet<string> = new Set(["buyer", "seller", "orchestrator"]);
const PHASE_OUTCOMES: ReadonlySet<string> = new Set(["ok", "fail"]);
const ERROR_CLASSES: ReadonlySet<string> = new Set(["permanent", "transient", "counterparty", "substrate", "settlement-atomicity"]);
const SIGNATURE_ALGORITHMS: ReadonlySet<string> = new Set(["ed25519", "ecdsa-secp256k1", "sr1-aggregate"]);

// §10.4.1 (R5-1, b26a420): the fields omitted from the bundle's hashed/signed canonical form. `signatures` is the
// signature envelope; `anchoredByRole` is the per-copy field (buyer/seller/orchestrator) excluded since R5-1 so the
// two-sided copies stay canonically EQUAL in the happy path (they differ only in that unhashed field) — fixing R4-B's
// self-inflicted bug where the hashed field forced every happy-path session to the §10.4.3(d) "disputed" branch. This is
// a recognised, specified omission, NOT a SIG-5 silent strip; integrity of the unhashed field is the §10.4.2 anchor-address
// cross-check (see twoSidedLookup), not the signature. SINGLE SOURCE — every bundle signer AND the verifier MUST omit this
// exact set or signatures won't round-trip (the R5-1 multi-site drift trap).
export const BUNDLE_SIGNED_SCOPE_OMIT: readonly string[] = ["signatures", "anchoredByRole"];

export function bundleHash(bundle: AttestationBundle): string {
  return sha256Hex(canonicalize(withoutSignature(bundle as unknown as Record<string, unknown>, ...BUNDLE_SIGNED_SCOPE_OMIT)));
}

export function verifyBundle(bundle: AttestationBundle, resolveKey: BundleKeyResolver): BundleDecision {
  try {
    if (!isStructurallySupported(bundle)) return "fail";
    if (bundle.signatures.length === 0) return "fail";

    const computedHash = bundleHash(bundle);
    if (!HASH_RE.test(computedHash)) return "error";

    const partyClaims = new Set(bundle.parties.map((p) => p.primaryClaim));
    for (const p of bundle.parties) {
      try {
        schemeOf(p.primaryClaim);
      } catch {
        return "fail";
      }
    }

    if (TERMINAL_REQUIRED_OUTCOMES.has(bundle.outcome)) {
      const required = requiredSignerClaims(bundle.parties);
      if (required === null) return "fail";
      const present = new Set(bundle.signatures.map((s) => s.party));
      for (const claim of required) {
        if (!present.has(claim)) return "fail";
      }
    }

    for (const sig of bundle.signatures) {
      if (sig.algorithm !== "ed25519") return "indeterminate";
      if (!partyClaims.has(sig.party)) return "fail";
      const publicKeyRaw = resolveKey(sig.party);
      if (publicKeyRaw === null || publicKeyRaw === undefined) return "indeterminate";
      if (publicKeyRaw.length !== 32) return "error";

      const signatureRaw = new Uint8Array(Buffer.from(sig.value, "base64url"));
      const result = verifyArtifactSignature({
        kind: "dacs-5-bundle",
        doc: bundle as unknown as Record<string, unknown>,
        publicKeyRaw,
        signatureRaw,
        // §10.4.1 (R5-1): the signed scope MUST equal bundleHash()'s canonical form (so result.artifactHash === computedHash).
        signatureFields: [...BUNDLE_SIGNED_SCOPE_OMIT],
      });
      if (result.artifactHash !== computedHash) return "error";
      if (!result.ok) return "fail";
    }

    return "pass";
  } catch {
    return "error";
  }
}

function requiredSignerClaims(parties: BundleParty[]): Set<ClaimReference> | null {
  const buyers = parties.filter((p) => p.role === "buyer").map((p) => p.primaryClaim);
  const sellers = parties.filter((p) => p.role === "seller").map((p) => p.primaryClaim);
  if (buyers.length === 0 || sellers.length === 0) return null;

  const required = new Set<ClaimReference>([...buyers, ...sellers]);
  // §10.4.1: "If the orchestrator is a distinct party (not buyer or seller), the
  // orchestrator signature is also REQUIRED." The !required.has() guard is that
  // "distinct" test — an orchestrator whose primaryClaim is already a buyer/seller
  // claim adds no new required signer; a distinct orchestrator's signature IS required.
  for (const p of parties) {
    if (p.role === "orchestrator" && !required.has(p.primaryClaim)) required.add(p.primaryClaim);
  }
  return required;
}

function isStructurallySupported(bundle: AttestationBundle): boolean {
  if (bundle.bundleVersion !== "1") return false;
  if (!ALLOWED_OUTCOMES.has(bundle.outcome)) return false;
  // §10.4 (L3085): anchoredByRole is REQUIRED and one of the three roles. A bundle missing it (a pre-R4-B
  // producer) or carrying a bad value is structurally unsupported — derive()'s reconciliation depends on it.
  if (!ANCHORED_BY_ROLES.has(bundle.anchoredByRole)) return false;
  if (typeof bundle.jobId !== "string" || bundle.jobId.length === 0) return false;
  if (!bundle.listingRef || typeof bundle.listingRef.listingId !== "string") return false;
  if (!Number.isSafeInteger(bundle.listingRef.version)) return false;
  if (!HASH_RE.test(bundle.listingRef.contentHash)) return false;
  if (!Array.isArray(bundle.parties) || !Array.isArray(bundle.phaseSummary)) return false;
  if (!Array.isArray(bundle.vetRecords) || !Array.isArray(bundle.settlementEvidence)) return false;
  if (!Array.isArray(bundle.signatures)) return false;
  if (bundle.agreementRef !== undefined && !isAttestationRef(bundle.agreementRef)) return false;
  for (const party of bundle.parties) {
    if (!PARTY_ROLES.has(party.role)) return false;
    if (!HASH_RE.test(party.bundleHash)) return false;
    if (typeof party.primaryClaim !== "string" || party.primaryClaim.length === 0) return false;
  }
  for (const phase of bundle.phaseSummary) {
    if (!Number.isSafeInteger(phase.index)) return false;
    if (typeof phase.kind !== "string" || phase.kind.length === 0) return false;
    if (!PHASE_OUTCOMES.has(phase.outcome)) return false;
    if (phase.errorClass !== undefined && !ERROR_CLASSES.has(phase.errorClass)) return false;
    if (phase.attestationRef !== undefined && !isAttestationRef(phase.attestationRef)) return false;
    if (phase.txRefs !== undefined && (!Array.isArray(phase.txRefs) || phase.txRefs.some((tx) => typeof tx.rail !== "string" || typeof tx.txHash !== "string"))) return false;
  }
  if (bundle.vetRecords.some((r) => !isAttestationRef(r))) return false;
  if (bundle.settlementEvidence.some((r) => !isAttestationRef(r))) return false;
  if (bundle.amendments !== undefined && (!Array.isArray(bundle.amendments) || bundle.amendments.some((r) => !isAttestationRef(r)))) return false;
  if (bundle.ratingRefs !== undefined && (!Array.isArray(bundle.ratingRefs) || bundle.ratingRefs.some((r) => !isAttestationRef(r)))) return false;
  for (const sig of bundle.signatures) {
    if (typeof sig.party !== "string" || sig.party.length === 0) return false;
    if (!SIGNATURE_ALGORITHMS.has(sig.algorithm)) return false;
    if (typeof sig.value !== "string" || sig.value.length === 0) return false;
  }
  if (!Number.isSafeInteger(bundle.recipeRegistryVersion)) return false;
  if (!Number.isSafeInteger(bundle.railRegistryVersion)) return false;
  if (!Number.isSafeInteger(bundle.finalisedAt)) return false;
  return true;
}

function isAttestationRef(ref: AttestationRef): boolean {
  return typeof ref.kind === "string" && ref.kind.length > 0
    && typeof ref.id === "string" && ref.id.length > 0
    && HASH_RE.test(ref.contentHash);
}
