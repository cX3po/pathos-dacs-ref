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
// §10.4.2 extended-pointer path: the FaultBundleExtendedPointer is signed under its own domain;
// legacy AttestationBundle copies (mixed-version reconciliation) sign under dacs-bundle:v1:.
const FAULT_BUNDLE_POINTER_DOMAIN = 'dacs-fault-bundle-pointer:v1:';
const LEGACY_BUNDLE_DOMAIN = 'dacs-bundle:v1:';
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

/*
 * ---------------------------------------------------------------------------
 * DACS-5 §10.4.1 / §10.4.2 / §10.4.3 FaultAttestationBundle reconciliation.
 *
 * These entry points extend the BB-1..BB-8 resolver above to the round-13 #248
 * FaultAttestationBundle (FAB) decision models.  They share the same fail-closed
 * posture: any malformed / unverifiable input yields `fail` (rejected content),
 * never a silent `present`.  They reuse the §10.4.1 permissible-set relation
 * (faultedPartyPermitted) and the §B.7 domain-separated hashed-signature verifier
 * (verifyHashedDomain) rather than reimplementing them.
 * ---------------------------------------------------------------------------
 */

/**
 * §10.4.2/§248 anchor-address ↔ anchoredByRole integrity for the role-keyed FAB/legacy copy
 * maps consumed by resolveFaultBundlePair / resolveMixedVersionPair.
 *
 * `anchoredByRole` is EXCLUDED from a copy's signed scope (bundleScope strips it — R5-1), so a
 * relaying adversary can flip it WITHOUT invalidating the copy signature. Because impliedFaultSet
 * (legacy path) and faultedPartyPermitted (FAB path) derive fault AUTHORITY from anchoredByRole,
 * an unchecked flip can launder a `fail` (implied-fault contradiction) into a `present` (agreement).
 *
 * The trusted signal that re-anchors this unsigned field is the anchor address the copy was
 * published under — carried here as the role KEY of the copies map (the copy at role X's storage
 * address). This mirrors the anchor-address ↔ anchoredByRole cross-check already enforced on the
 * two-sided verify path (verify-bundle-v1.ts FIX 1). The copy at key X MUST declare
 * anchoredByRole === X; anything else is forged/mislabeled → reject (fail-closed).
 *
 * Returns true (mismatch → reject) when: the key is not a known role, the copy is not an object,
 * its anchoredByRole is missing / not a known role, or it disagrees with the key.
 */
function anchorRoleMismatch(anchorKey: string, copy: unknown): boolean {
  if (!ROLES.has(anchorKey)) return true;
  if (!isObject(copy)) return true;
  const declared = copy.anchoredByRole;
  if (typeof declared !== 'string' || !ROLES.has(declared)) return true;
  return declared !== anchorKey;
}

/** §10.4.1 outcome classes used for cross-copy contradiction checks. */
type OutcomeClass = 'success' | 'abort' | 'failure' | 'substrate';
function outcomeClass(outcome: unknown): OutcomeClass | null {
  switch (outcome) {
    case 'completed': return 'success';
    case 'failed-substrate': return 'substrate';
    case 'aborted-by-self':
    case 'aborted-by-other': return 'abort';
    case 'failed-perm':
    case 'failed-counterparty': return 'failure';
    default: return null;
  }
}

/**
 * §10.4.1 implied absolute-fault SET for one copy.
 *
 * A FAB carries an explicit `faultedParty`, so its set is the singleton {faultedParty}
 * (or {'none'} for a no-fault outcome).  A legacy AttestationBundle has no faultedParty;
 * its implied set is derived from (outcome, anchoredByRole) over the party roster:
 *   - none-class (completed / failed-substrate)     -> {'none'}
 *   - self-class (aborted-by-self / failed-perm)    -> {anchoredByRole}
 *   - other-class (aborted-by-other / failed-cp)    -> partyRoles \ {anchoredByRole}
 * Returns null when the copy is malformed or its declared faultedParty is outside the
 * §10.4.1 permissible set (rejected content).
 */
function impliedFaultSet(bundle: JsonObject, roles: Map<string, string>): Set<string> | null {
  const outcome = bundle.outcome;
  const anchoredRole = bundle.anchoredByRole;
  if (typeof outcome !== 'string' || !OUTCOMES.has(outcome) ||
      typeof anchoredRole !== 'string' || !ROLES.has(anchoredRole)) return null;
  const partyRoles = new Set(roles.values());
  if (!partyRoles.has(anchoredRole)) return null;
  const isFab = 'faultBundleVersion' in bundle;
  if (isFab) {
    // A FAB must satisfy §10.4.1 for its explicit faultedParty; reuse the permissible-set relation.
    if (!faultedPartyPermitted(bundle, roles)) return null;
    return new Set([bundle.faultedParty as string]);
  }
  // Legacy AttestationBundle: no explicit faultedParty, derive the implied set.
  if (outcome === 'completed' || outcome === 'failed-substrate') return new Set(['none']);
  if (outcome === 'aborted-by-self' || outcome === 'failed-perm') return new Set([anchoredRole]);
  // other-class: every non-anchoring party role is a candidate absolute fault.
  const others = [...partyRoles].filter((role) => role !== anchoredRole);
  return others.length > 0 ? new Set(others) : null;
}

/** Verify every carried signature on a FAB (dacs-fault-bundle:v1:) or legacy AttestationBundle
 *  (dacs-bundle:v1:) copy over its §10.4.1 scope hash.  All signers must be roster members. */
function copySignaturesValid(
  request: BundleBindingRequest,
  bundle: JsonObject,
  hash: Uint8Array,
  roles: Map<string, string>,
): boolean {
  if (!Array.isArray(bundle.signatures) || bundle.signatures.length === 0) return false;
  const domain = 'faultBundleVersion' in bundle ? FAULT_BUNDLE_DOMAIN : LEGACY_BUNDLE_DOMAIN;
  for (const entry of bundle.signatures) {
    if (!isObject(entry) || entry.algorithm !== 'ed25519') return false;
    const key = claimKey(entry.party);
    const signature = decodeEd25519Sig(entry.value);
    const publicKey = publicKeyFor(request, entry.party);
    if (key === null || !roles.has(key) || signature === null || publicKey === null ||
        !verifyHashedDomain(domain, signature, hash, publicKey)) {
      return false;
    }
  }
  return true;
}

/** Same-index phaseSummary limb (#254): every shared index must agree on kind+outcome. */
function phaseSummaryDiverges(a: JsonObject, b: JsonObject): boolean {
  const pa = Array.isArray(a.phaseSummary) ? a.phaseSummary : [];
  const pb = Array.isArray(b.phaseSummary) ? b.phaseSummary : [];
  const byIndex = new Map<unknown, JsonObject>();
  for (const p of pa) if (isObject(p)) byIndex.set(p.index, p);
  for (const p of pb) {
    if (!isObject(p)) continue;
    const other = byIndex.get(p.index);
    if (other && (other.kind !== p.kind || other.outcome !== p.outcome)) return true;
  }
  return false;
}

/** Validate a single FAB / legacy copy: canonicalisable, roster-consistent, permissible,
 *  and fully signature-verified.  Returns its parsed facts or null (rejected content). */
function validateFaultCopy(
  request: BundleBindingRequest,
  copy: unknown,
): { bundle: JsonObject; roles: Map<string, string>; faultSet: Set<string>; klass: OutcomeClass } | null {
  if (!isObject(copy)) return null;
  const roles = roleClaims(copy);
  if (roles === null) return null;
  const klass = outcomeClass(copy.outcome);
  if (klass === null) return null;
  const faultSet = impliedFaultSet(copy, roles);
  if (faultSet === null) return null;
  let hash: Uint8Array;
  try {
    hash = bundleScope(copy).hash;
  } catch {
    return null;
  }
  if (!copySignaturesValid(request, copy, hash, roles)) return null;
  return { bundle: copy, roles, faultSet, klass };
}

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
export function resolveFaultBundlePointer(request: FaultBundlePointerRequest): BundleBindingResolution {
  const { pointer, dereferenced, binding } = request ?? {};
  if (!isObject(pointer) || !isObject(dereferenced) || !isObject(binding)) {
    return invalid('§10.4.2: malformed extended-pointer input');
  }
  if (pointer.faultBundleVersion !== '1' || pointer.pointerKind !== 'extended' ||
      typeof pointer.fullBundleContentHash !== 'string' ||
      typeof binding.bundleContentHash !== 'string') {
    return invalid('§10.4.2: pointer/binding discriminator or hash field malformed');
  }
  const asRequest: BundleBindingRequest = { jobId: '', role: 'buyer', publicKeys: request.publicKeys };

  // (1) The dereferenced bundle must itself be a valid, fully-signed §10.4.1 FAB.
  const deref = validateFaultCopy(asRequest, dereferenced);
  if (deref === null) return invalid('§10.4.2: dereferenced bundle is not a valid §10.4.1 FAB');

  // (1b) §10.4.2/§248 anchor-address ↔ anchoredByRole integrity — the extended-pointer family.
  //
  // `anchoredByRole` is EXCLUDED from the signed scope (bundleScope strips it, R5-1), so it is
  // tamperable WITHOUT invalidating the FAB signature. Yet validateFaultCopy → impliedFaultSet →
  // faultedPartyPermitted derive fault AUTHORITY from anchoredByRole (e.g. aborted-by-other /
  // failed-counterparty require faulted !== anchoredRole). Flipping the unsigned anchoredByRole
  // therefore launders a permissibility-rejected FAB (fail) into a permitted one (present) — the
  // exact #248 authority-laundering class the pair/mixed families already close via the copies-map
  // anchor key (anchorRoleMismatch). The pointer family has no copies-map key, but it DOES have a
  // trusted anchor signal: the BINDING that anchors the pointer. binding.role is cryptographically
  // bound to binding.logicalAddress = derive(jobId, role); a forged binding.role breaks that
  // derivation. So we re-anchor the unsigned anchoredByRole to binding.role: the FAB dereferenced
  // through the role-X binding MUST declare anchoredByRole === X. A mismatch is forged/mislabeled
  // content (an unsigned-field flip trying to launder fault authority) → fail-closed.
  if (typeof binding.jobId !== 'string' || typeof binding.role !== 'string' || !ROLES.has(binding.role) ||
      binding.logicalAddress !== deriveBundleLogicalAddress(binding.jobId, binding.role as BundleBindingRole)) {
    return invalid('§10.4.2/§248: binding anchor role is not integrity-bound to its logical address (unsigned-field tamper cannot be re-anchored)');
  }
  if (anchorRoleMismatch(binding.role, dereferenced)) {
    return invalid('§10.4.2/§248: anchor-address ↔ anchoredByRole mismatch on the dereferenced FAB (unsigned-field tamper rejected)');
  }

  // (2) Recompute the §10.4.1 hash of the dereferenced bundle and require triple-identity.
  let recomputed: string;
  try {
    recomputed = hex(bundleScope(dereferenced).hash);
  } catch {
    return invalid('§10.4.2: dereferenced bundle is not canonicalisable');
  }
  if (recomputed !== pointer.fullBundleContentHash || recomputed !== binding.bundleContentHash) {
    // Rejected content (BB-7): pointer/binding may agree with each other but neither equals
    // the recomputed dereferenced hash.  Fail, never present.
    return invalid('§10.4.2: triple-identity broken — pointer/binding hash != recomputed dereferenced hash (BB-7 rejected content)');
  }

  // (3) The pointer signs the JCS-canonical hash of its own tuple under the pointer domain.
  const signature = isObject(pointer.signature) ? decodeEd25519Sig(pointer.signature.value) : null;
  const pointerKey = isObject(pointer.signature) ? publicKeyFor(asRequest, pointer.signature.signer) : null;
  if (signature === null || pointerKey === null || (isObject(pointer.signature) && pointer.signature.algorithm !== 'ed25519')) {
    return invalid('§10.4.2: pointer signature or signer key malformed');
  }
  let pointerHash: Uint8Array;
  try {
    const { signature: _sig, ...pointerScope } = pointer;
    pointerHash = hashCanonical(pointerScope);
  } catch {
    return invalid('§10.4.2: pointer tuple is not canonicalisable');
  }
  if (!verifyHashedDomain(FAULT_BUNDLE_POINTER_DOMAIN, signature, pointerHash, pointerKey)) {
    return invalid('§10.4.2: pointer signature does not verify under the pointer domain');
  }

  return {
    disposition: 'present',
    detail: '§10.4.2: extended-pointer triple-identity holds (binding == pointer == recomputed dereferenced hash)',
    bundle: dereferenced,
  };
}

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
export function resolveFaultBundlePair(request: FaultBundlePairRequest): BundleBindingResolution {
  if (!request || !isObject(request.copies)) return invalid('§10.4.3: malformed FAB-pair input');
  const asRequest: BundleBindingRequest = { jobId: '', role: 'buyer', publicKeys: request.publicKeys };
  const parsed: Array<{ bundle: JsonObject; faultSet: Set<string>; klass: OutcomeClass }> = [];
  for (const [anchorKey, copy] of Object.entries(request.copies)) {
    // §10.4.2/§248 anchor-address ↔ anchoredByRole integrity (verify-bundle-v1.ts FIX 1):
    // anchoredByRole is EXCLUDED from the signed scope (bundleScope), so it is tamperable
    // without invalidating the signature. It is re-anchored to the TRUSTED signal — the
    // role-keyed anchor address the copy was published under. A copy fetched from role X's
    // address MUST declare anchoredByRole === X; a mismatch is forged/mislabeled content
    // (an unsigned-field flip trying to launder fault authority) → fail-closed.
    if (anchorRoleMismatch(anchorKey, copy)) {
      return invalid('§10.4.2/§248: anchor-address ↔ anchoredByRole mismatch on a FAB copy (unsigned-field tamper rejected)');
    }
    const validated = validateFaultCopy(asRequest, copy);
    if (validated === null) {
      return invalid('§10.4.1: a FAB copy is malformed or its faultedParty is outside the permissible set (rejected)');
    }
    parsed.push(validated);
  }
  if (parsed.length === 0) return invalid('§10.4.3: no FAB copy present');
  if (parsed.length === 1) {
    // A single valid, in-set copy stands on its own (the permissible-set rule is what this exercises).
    return {
      disposition: 'present',
      detail: '§10.4.1: single FAB copy is valid and within the permissible set',
      bundle: parsed[0]!.bundle,
    };
  }
  // §10.4.3: every copy in the pair must name the SAME absolute faultedParty and outcome class.
  const [first, ...rest] = parsed;
  for (const other of rest) {
    if (other.klass !== first!.klass) {
      return invalid('§10.4.3: FAB-pair outcome classes contradict (divergent)');
    }
    // FAB copies carry singleton fault sets; identity means the singletons match.
    const same = first!.faultSet.size === other.faultSet.size &&
      [...first!.faultSet].every((party) => other.faultSet.has(party));
    if (!same) {
      return invalid('§10.4.3: FAB-pair names non-identical absolute faultedParty (divergent)');
    }
    if (phaseSummaryDiverges(first!.bundle, other.bundle)) {
      return invalid('§10.4.3: FAB-pair shared-index phaseSummary limb diverges');
    }
  }
  return {
    disposition: 'present',
    detail: '§10.4.3: FAB-pair converges (same absolute faultedParty and outcome class)',
    bundle: first!.bundle,
  };
}

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
export function resolveMixedVersionPair(request: FaultBundlePairRequest): BundleBindingResolution {
  if (!request || !isObject(request.copies)) return invalid('§10.4.3: malformed mixed-version input');
  const asRequest: BundleBindingRequest = { jobId: '', role: 'buyer', publicKeys: request.publicKeys };
  const parsed: Array<{ bundle: JsonObject; faultSet: Set<string>; klass: OutcomeClass; isFab: boolean }> = [];
  for (const [anchorKey, copy] of Object.entries(request.copies)) {
    // §10.4.2/§248 anchor-address ↔ anchoredByRole integrity (verify-bundle-v1.ts FIX 1).
    // anchoredByRole is unsigned (excluded from bundleScope) yet drives the legacy implied
    // absolute-fault SET (impliedFaultSet). Re-anchor it to the role-keyed anchor address the
    // copy was published under: the copy at role X's address MUST declare anchoredByRole === X.
    // Without this, flipping the unsigned anchoredByRole launders a contradiction (fail) into an
    // agreement (present) — the #248 authority-laundering class (Codex adversarial review 2026-07).
    if (anchorRoleMismatch(anchorKey, copy)) {
      return invalid('§10.4.2/§248: anchor-address ↔ anchoredByRole mismatch on a mixed-version copy (unsigned-field tamper rejected)');
    }
    const validated = validateFaultCopy(asRequest, copy);
    if (validated === null) {
      return invalid('§10.4.1: a mixed-version copy is malformed or outside the permissible set (rejected)');
    }
    parsed.push({ ...validated, isFab: 'faultBundleVersion' in validated.bundle });
  }
  if (parsed.length < 2) return invalid('§10.4.3: mixed-version reconciliation needs at least two copies');

  const [first, ...rest] = parsed;
  for (const other of rest) {
    // Outcome classes must agree (completed vs abort etc. is an unconditional divergence).
    if (other.klass !== first!.klass) {
      return invalid('§10.4.3: mixed-version outcome classes contradict (divergent)');
    }
    // Implied-fault-set intersection must be non-empty: a FAB faultedParty must be a member
    // of the legacy implied set; two legacy perspective copies must agree after the flip.
    const intersect = [...first!.faultSet].some((party) => other.faultSet.has(party));
    if (!intersect) {
      return invalid('§10.4.3: mixed-version implied absolute-fault sets contradict (divergent)');
    }
    if (phaseSummaryDiverges(first!.bundle, other.bundle)) {
      return invalid('§10.4.3: mixed-version shared-index phaseSummary limb diverges (#254)');
    }
  }
  const authoritative = parsed.find((copy) => copy.isFab) ?? first!;
  return {
    disposition: 'present',
    detail: `§10.4.3/§10.5.1: mixed pair unified; authoritative copy is ${authoritative.isFab ? 'FaultAttestationBundle' : 'AttestationBundle'}`,
    bundle: authoritative.bundle,
  };
}
