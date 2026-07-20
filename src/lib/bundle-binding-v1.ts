/**
 * DACS-5 §10.4.2 BundleBinding resolver (BB-1..BB-8).
 *
 * The resolver is deliberately synchronous and side-effect free.  Callers supply both
 * authenticated public keys and a deterministic native-address fetch function.
 */
import * as ed25519 from '@noble/ed25519';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { jcsCanonical } from '../jcs.js';
import { verify } from './sign.js';
import { claimKey, decodeEd25519Sig } from './verify-bundle-v1.js';

ed25519.etc.sha512Sync = (...messages: Uint8Array[]): Uint8Array =>
  sha512(ed25519.etc.concatBytes(...messages));

const encoder = new TextEncoder();
const BINDING_DOMAIN = 'dacs-bundle-binding:v1:';
const FAULT_BUNDLE_DOMAIN = 'dacs-fault-bundle:v1:';
const DEFAULT_FETCH_BUDGET = 8;
const ROLES = new Set(['buyer', 'seller', 'orchestrator']);
const OUTCOMES = new Set([
  'completed', 'failed-perm', 'failed-counterparty', 'failed-substrate',
  'aborted-by-self', 'aborted-by-other',
]);

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
  signature: { algorithm: string; signer: unknown; value: string };
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
type Candidate = { binding: BundleBindingV1; signerKey: string };
type ValidCopy = Candidate & {
  bundle: JsonObject;
  canonicalScope: string;
  fullySigned: boolean;
};

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}

function hashCanonical(value: unknown): Uint8Array {
  return sha256(jcsCanonical(value));
}

/** BB-2 logical address derivation. */
export function deriveBundleLogicalAddress(jobId: string, role: BundleBindingRole): string {
  return `stor-${hex(sha256(encoder.encode(`${jobId}-bundle-${role}`)))}`;
}

function publicKeyBytes(value: string | Uint8Array | undefined): Uint8Array | null {
  if (value instanceof Uint8Array) return value.length === 32 ? value : null;
  if (typeof value !== 'string') return null;
  try {
    const normal = value.replace(/-/g, '+').replace(/_/g, '/');
    const decoded = new Uint8Array(Buffer.from(normal + '='.repeat((4 - normal.length % 4) % 4), 'base64'));
    return decoded.length === 32 ? decoded : null;
  } catch {
    return null;
  }
}

function publicKeyFor(request: BundleBindingRequest, claim: unknown): Uint8Array | null {
  const key = claimKey(claim);
  if (key === null) return null;
  const direct = request.publicKeys?.[typeof claim === 'string' ? claim : key];
  return publicKeyBytes(direct ?? request.publicKeys?.[key]);
}

/**
 * Use the repository signature wrapper first.  The current shared closed registry predates
 * the two #248 domains, so the narrow fallback verifies the exact same Ed25519 bytes until
 * those domains are exposed there.  No signing path is introduced here.
 */
function verifyHashedDomain(domain: string, signature: Uint8Array, hash: Uint8Array, publicKey: Uint8Array): boolean {
  const hashText = encoder.encode(hex(hash));
  if (verify(domain, signature, hashText, publicKey)) return true;
  const domainBytes = encoder.encode(domain);
  const message = new Uint8Array(domainBytes.length + hashText.length);
  message.set(domainBytes);
  message.set(hashText, domainBytes.length);
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

function isObject(value: unknown): value is JsonObject {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function bindingSignatureValid(request: BundleBindingRequest, binding: BundleBindingV1): string | null {
  if (!isObject(binding) || !isObject(binding.signature)) return null;
  const signerKey = claimKey(binding.signer);
  if (signerKey === null || claimKey(binding.signature.signer) !== signerKey) return null;
  if (binding.signature.algorithm !== 'ed25519') return null;
  const signature = decodeEd25519Sig(binding.signature.value);
  const publicKey = publicKeyFor(request, binding.signer);
  if (signature === null || publicKey === null) return null;
  const { signature: _signature, ...signedTuple } = binding;
  // JCS canonicalisation of an untrusted tuple can throw (e.g. a non-finite number, §7.2). A tuple
  // we cannot canonicalise cannot have been signed under our scheme — fail-closed as invalid, never
  // let the exception escape (property-fuzzer no-throw class, 2026-07).
  let tupleHash: Uint8Array;
  try {
    tupleHash = hashCanonical(signedTuple);
  } catch {
    return null;
  }
  return verifyHashedDomain(BINDING_DOMAIN, signature, tupleHash, publicKey) ? signerKey : null;
}

function bundleScope(bundle: JsonObject): { canonical: string; hash: Uint8Array } {
  const { signatures: _signatures, anchoredByRole: _anchoredByRole, ...signed } = bundle;
  const canonicalBytes = jcsCanonical(signed);
  return { canonical: Buffer.from(canonicalBytes).toString('base64'), hash: sha256(canonicalBytes) };
}

function roleClaims(bundle: JsonObject): Map<string, string> | null {
  if (!Array.isArray(bundle.parties) || bundle.parties.length === 0) return null;
  const result = new Map<string, string>();
  for (const party of bundle.parties) {
    if (!isObject(party) || typeof party.role !== 'string' || !ROLES.has(party.role)) return null;
    const key = claimKey(party.primaryClaim);
    if (key === null) return null;
    result.set(key, party.role);
  }
  return result;
}

function faultedPartyPermitted(bundle: JsonObject, roles: Map<string, string>): boolean {
  const outcome = bundle.outcome;
  const anchoredRole = bundle.anchoredByRole;
  const faulted = bundle.faultedParty;
  if (typeof outcome !== 'string' || !OUTCOMES.has(outcome) ||
      typeof anchoredRole !== 'string' || !ROLES.has(anchoredRole) ||
      typeof faulted !== 'string') return false;
  const partyRoles = new Set(roles.values());
  if (!partyRoles.has(anchoredRole)) return false;
  if (outcome === 'completed' || outcome === 'failed-substrate') return faulted === 'none';
  if (outcome === 'aborted-by-self' || outcome === 'failed-perm') return faulted === anchoredRole;
  if (outcome === 'aborted-by-other' || outcome === 'failed-counterparty') {
    return faulted !== 'none' && faulted !== anchoredRole && partyRoles.has(faulted);
  }
  return false;
}

function verifyBundleSignatures(
  request: BundleBindingRequest,
  bundle: JsonObject,
  hash: Uint8Array,
  roles: Map<string, string>,
): { valid: boolean; fullySigned: boolean } {
  if (!Array.isArray(bundle.signatures) || bundle.signatures.length === 0) return { valid: false, fullySigned: false };
  const signed = new Set<string>();
  for (const entry of bundle.signatures) {
    if (!isObject(entry) || entry.algorithm !== 'ed25519') return { valid: false, fullySigned: false };
    const key = claimKey(entry.party);
    const signature = decodeEd25519Sig(entry.value);
    const publicKey = publicKeyFor(request, entry.party);
    if (key === null || !roles.has(key) || signature === null || publicKey === null ||
        !verifyHashedDomain(FAULT_BUNDLE_DOMAIN, signature, hash, publicKey)) {
      return { valid: false, fullySigned: false };
    }
    signed.add(key);
  }
  const fullySigned = [...roles.keys()].every((key) => signed.has(key));
  const abort = bundle.outcome === 'aborted-by-self' || bundle.outcome === 'aborted-by-other';
  return { valid: abort || fullySigned, fullySigned };
}

function invalid(detail: string): BundleBindingResolution {
  return { disposition: 'fail', detail };
}

/** Resolve one requested logical side through BB-1..BB-8. */
export function resolveBundleBinding(
  request: BundleBindingRequest,
  bindings: readonly BundleBindingV1[],
  fetchBundle: (nativeAddress: string, binding: BundleBindingV1) => unknown,
): BundleBindingResolution {
  if (!request || typeof request.jobId !== 'string' || !request.jobId || !ROLES.has(request.role)) {
    return invalid('BB-1: malformed resolution request');
  }
  // Fail-closed on a malformed binding set (non-array ingress) — symmetric to the request guard
  // above.  Wire input can deliver a non-array here; without this guard the first `.filter` throws
  // instead of returning a deterministic disposition (property-fuzzer no-throw class, 2026-07).
  if (!Array.isArray(bindings)) {
    return invalid('BB-1: malformed binding set');
  }
  const logicalAddress = deriveBundleLogicalAddress(request.jobId, request.role);
  const publishedHere = bindings.filter((binding) => binding?.logicalAddress === logicalAddress);
  if (publishedHere.length === 0) {
    return { disposition: 'indeterminate', detail: 'BB-7: no binding published for the requested logical side' };
  }

  const authenticated: Candidate[] = [];
  let observedInvalid = false;
  for (const binding of publishedHere) {
    const signerKey = bindingSignatureValid(request, binding);
    if (signerKey === null) {
      observedInvalid = true;
      continue;
    }
    // BB-5 is reject-on-any over every authenticated tuple published at this side.
    if (binding.bindingVersion !== '1' || binding.jobId !== request.jobId || binding.role !== request.role ||
        binding.logicalAddress !== deriveBundleLogicalAddress(binding.jobId, binding.role) ||
        typeof binding.nativeAddress !== 'string' || !binding.nativeAddress ||
        !/^[0-9a-f]{64}$/.test(binding.bundleContentHash)) {
      return invalid('BB-5: authenticated binding tuple does not match the requested logical side');
    }
    authenticated.push({ binding, signerKey });
  }
  if (authenticated.length === 0) {
    return observedInvalid
      ? invalid('BB-4: published binding signature or signer is invalid')
      : { disposition: 'indeterminate', detail: 'BB-7: no authenticated binding resolves the side' };
  }

  const mapped = request.partyMap;
  const candidates = mapped
    ? authenticated.filter(({ binding }) => mapped[typeof binding.signer === 'string' ? binding.signer : claimKey(binding.signer)!] === request.role)
    : authenticated;
  if (candidates.length === 0) {
    return { disposition: 'indeterminate', detail: 'BB-7: the authenticated party map authorizes no candidate' };
  }

  const budget = Number.isInteger(request.budget) && request.budget! > 0 ? request.budget! : DEFAULT_FETCH_BUDGET;
  const buckets = new Map<string, Candidate[]>();
  for (const candidate of candidates) {
    const bucket = buckets.get(candidate.signerKey) ?? [];
    bucket.push(candidate);
    buckets.set(candidate.signerKey, bucket);
  }
  for (const bucket of buckets.values()) {
    bucket.sort((left, right) =>
      left.binding.bundleContentHash.localeCompare(right.binding.bundleContentHash) ||
      left.binding.nativeAddress.localeCompare(right.binding.nativeAddress));
    if (bucket.length > budget) {
      return { disposition: 'indeterminate', detail: `BB-7: per-signer fetch budget N=${budget} exhausted` };
    }
  }

  const validCopies: ValidCopy[] = [];
  let presentInvalid = observedInvalid;
  for (const signer of [...buckets.keys()].sort()) {
    for (const candidate of buckets.get(signer)!) {
      const fetched = fetchBundle(candidate.binding.nativeAddress, candidate.binding);
      if (!isObject(fetched)) continue;
      // A fetched bundle we cannot canonicalise (e.g. non-finite number, §7.2) is malformed — treat
      // it as a present-but-invalid copy (fail-closed), never let the JCS exception escape.
      let scope: { canonical: string; hash: Uint8Array };
      try {
        scope = bundleScope(fetched);
      } catch {
        presentInvalid = true;
        continue;
      }
      const roles = roleClaims(fetched);
      const mappedRole = mapped?.[typeof candidate.binding.signer === 'string' ? candidate.binding.signer : candidate.signerKey];
      const bundleRole = roles?.get(candidate.signerKey);
      const authorized = mapped ? mappedRole === request.role : bundleRole === request.role;
      if (!authorized) continue; // Authenticated outsider copies are inert.
      const signatureResult = roles && verifyBundleSignatures(request, fetched, scope.hash, roles);
      if (fetched.jobId !== candidate.binding.jobId || hex(scope.hash) !== candidate.binding.bundleContentHash ||
          roles === null || !faultedPartyPermitted(fetched, roles) || !signatureResult || !signatureResult.valid) {
        presentInvalid = true;
        continue;
      }
      validCopies.push({
        ...candidate,
        bundle: fetched,
        canonicalScope: scope.canonical,
        fullySigned: signatureResult.fullySigned,
      });
    }
  }

  if (validCopies.length === 0) {
    return presentInvalid
      ? invalid('BB-5: a present authenticated/authorized binding or bundle is invalid')
      : { disposition: 'indeterminate', detail: 'BB-7: no authorized copy resolved' };
  }

  const groups = new Map<string, ValidCopy[]>();
  for (const copy of validCopies) {
    const group = groups.get(copy.canonicalScope) ?? [];
    group.push(copy);
    groups.set(copy.canonicalScope, group);
  }
  let standing = [...groups.values()];
  if (standing.length > 1) {
    const full = standing.filter((group) => group.some((copy) => copy.fullySigned));
    if (full.length > 0) standing = full;
  }
  if (standing.length !== 1) {
    return { disposition: 'indeterminate', detail: 'BB-6/BB-7: equal-standing authorized copies diverge' };
  }
  const winner = standing[0]!.slice().sort((left, right) =>
    left.binding.bundleContentHash.localeCompare(right.binding.bundleContentHash) ||
    left.binding.nativeAddress.localeCompare(right.binding.nativeAddress))[0]!;
  return {
    disposition: 'present',
    detail: 'BB-4..BB-6: authenticated, authorized, byte-exact bundle resolved',
    resolvedRole: request.role,
    resolvedNativeAddress: winner.binding.nativeAddress,
    bundle: winner.bundle,
  };
}
