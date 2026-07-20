#!/usr/bin/env tsx
/**
 * Property-based differential fuzzer for DACS-5 §10.4.2 BundleBinding resolution (BB-1..BB-8).
 *
 * WHY THIS EXISTS
 * ---------------
 * DACS-Standard PR #248 has churned for 11 review rounds; every defect since round 7 lives in
 * the BB-6 candidate-multiplicity ladder or in malformed-input handling. The recurring failure
 * mode is that tests assert *fixture metadata* (a pinned expected verdict) rather than EXECUTING
 * the predicate against a reference implementation, so semantic bugs pass CI silently. xm33's
 * point: "a suite is authority over the paths it exercises and silent about the rest." Fixed
 * vectors only lock the corners someone thought of.
 *
 * This tool generates randomised, structurally-rich BB scenarios and asserts INVARIANTS that
 * must hold for ANY input — no pinned metadata. Each invariant targets a real round-9/10/11
 * defect class: exception escapes, non-determinism, fail-open, budget truncation, precedence
 * inversion, arbitrary-pick on divergence.
 *
 * DIFFERENTIAL MODE
 * -----------------
 * A *true* second-oracle differential (our resolver vs DACS-Standard's reference) would run each
 * generated input through both implementations and assert agree-or-both-fail-closed. As of this
 * build the DACS-Standard repo ships NO executable BB-1..BB-8 resolver — only schema/structural
 * vector validators (scripts/validate_conformance_vectors.py), i.e. the very metadata-assertion
 * anti-pattern above. There is nothing to run differentially. So this deliverable is the
 * invariant-based ("metamorphic") property fuzzer; the second-oracle mode is a documented
 * follow-up (see README) that needs a runnable reference adapter under the dacs-adapter/1
 * protocol (conformance/shared-suite/ADAPTER-PROTOCOL.md). We do NOT fake a second oracle.
 *
 * Invariants are still differential in spirit: many are metamorphic (permutation invariance,
 * determinism, monotonicity) — they compare the resolver against ITSELF under transformations
 * that must not change the verdict, which is where non-deterministic tie-breaks and order
 * dependence hide.
 *
 * RUN
 * ---
 *   tsx conformance/cross-run-corpus/bb-differential-fuzzer.mts               # 1000 cases, fixed seed
 *   tsx conformance/cross-run-corpus/bb-differential-fuzzer.mts --cases 5000 --seed 42
 *   tsx conformance/cross-run-corpus/bb-differential-fuzzer.mts --case-seed 123456   # replay one case
 *   npm run fuzz:bb-binding
 *
 * Exit code is non-zero iff an invariant violation was found (CI-gateable).
 */
import * as ed25519 from '@noble/ed25519';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { jcsCanonical } from '../../src/jcs.js';
import {
  deriveBundleLogicalAddress,
  resolveBundleBinding,
  type BundleBindingRequest,
  type BundleBindingResolution,
  type BundleBindingRole,
  type BundleBindingV1,
} from '../../src/lib/bundle-binding-v1.js';

ed25519.etc.sha512Sync = (...m: Uint8Array[]): Uint8Array => sha512(ed25519.etc.concatBytes(...m));

const enc = new TextEncoder();
const BINDING_DOMAIN = 'dacs-bundle-binding:v1:';
const FAULT_DOMAIN = 'dacs-fault-bundle:v1:';
const ROLES: BundleBindingRole[] = ['buyer', 'seller', 'orchestrator'];

// --------------------------------------------------------------------------------------------
// primitives
// --------------------------------------------------------------------------------------------
type Json = Record<string, any>;

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (v) => v.toString(16).padStart(2, '0')).join('');
}
function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function hashCanonical(value: unknown): Uint8Array {
  return sha256(jcsCanonical(value));
}
/** Sign `domain || hex(hash)` — the exact message the resolver's verifyHashedDomain reconstructs. */
function signDomainHash(domain: string, hash: Uint8Array, priv: Uint8Array): string {
  const hashText = enc.encode(hex(hash));
  const domainBytes = enc.encode(domain);
  const msg = new Uint8Array(domainBytes.length + hashText.length);
  msg.set(domainBytes);
  msg.set(hashText, domainBytes.length);
  return b64url(ed25519.sign(msg, priv));
}

// --------------------------------------------------------------------------------------------
// seeded PRNG (mulberry32) — fast-check is not a dependency; keep it self-contained + reproducible.
// --------------------------------------------------------------------------------------------
type Rng = {
  next(): number;
  int(nExclusive: number): number;
  pick<T>(arr: readonly T[]): T;
  chance(p: number): boolean;
  bytes(n: number): Uint8Array;
};
function makeRng(seed: number): Rng {
  let a = seed >>> 0;
  const next = (): number => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return {
    next,
    int: (n) => Math.floor(next() * n),
    pick: (arr) => arr[Math.floor(next() * arr.length)]!,
    chance: (p) => next() < p,
    bytes: (n) => {
      const out = new Uint8Array(n);
      for (let i = 0; i < n; i++) out[i] = Math.floor(next() * 256);
      return out;
    },
  };
}

// --------------------------------------------------------------------------------------------
// party keys (derived from the rng so every case is fully reproducible from its case-seed)
// --------------------------------------------------------------------------------------------
type Party = { did: string; priv: Uint8Array; pub: Uint8Array };
function makeParty(rng: Rng, did: string): Party {
  const priv = rng.bytes(32);
  const pub = ed25519.getPublicKey(priv);
  return { did, priv, pub };
}

// --------------------------------------------------------------------------------------------
// well-formed FaultAttestationBundle + BundleBinding builders (produce genuinely valid signatures)
// --------------------------------------------------------------------------------------------
type BuildBundleOpts = {
  jobId: string;
  parties: Party[]; // roster, in role order
  roles: BundleBindingRole[]; // role per party (aligned with parties[])
  signers: Party[]; // who signs the bundle
  outcome: string;
  faultedParty: string;
  anchoredByRole: BundleBindingRole;
  nonce: number; // varies the canonical scope so two bundles can diverge
};
function buildBundle(opts: BuildBundleOpts): { bundle: Json; contentHash: string } {
  const bundle: Json = {
    faultBundleVersion: '1',
    jobId: opts.jobId,
    outcome: opts.outcome,
    faultedParty: opts.faultedParty,
    anchoredByRole: opts.anchoredByRole, // excluded from the signed scope
    parties: opts.parties.map((p, i) => ({
      role: opts.roles[i],
      primaryClaim: p.did,
      bundleHash: hex(sha256(enc.encode(`${opts.jobId}-${opts.roles[i]}-${opts.nonce}`))),
    })),
    phaseSummary: [{ index: 0, kind: 'deliver-storage-program', outcome: 'ok' }],
    finalisedAt: 1780000000000 + opts.nonce,
    nonce: opts.nonce,
  };
  // scope hash = sha256(JCS(bundle minus signatures + anchoredByRole)), matching resolver.bundleScope
  const { signatures: _s, anchoredByRole: _a, ...signed } = bundle;
  const scopeHash = sha256(jcsCanonical(signed));
  bundle.signatures = opts.signers.map((p) => ({
    party: p.did,
    algorithm: 'ed25519',
    value: signDomainHash(FAULT_DOMAIN, scopeHash, p.priv),
  }));
  return { bundle, contentHash: hex(scopeHash) };
}

type BuildBindingOpts = {
  jobId: string;
  role: BundleBindingRole;
  signer: Party;
  nativeAddress: string;
  contentHash: string;
  bindingVersion?: string;
  logicalAddress?: string;
};
function buildBinding(opts: BuildBindingOpts): BundleBindingV1 {
  const tuple: Json = {
    bindingVersion: opts.bindingVersion ?? '1',
    jobId: opts.jobId,
    role: opts.role,
    logicalAddress: opts.logicalAddress ?? deriveBundleLogicalAddress(opts.jobId, opts.role),
    nativeAddress: opts.nativeAddress,
    bundleContentHash: opts.contentHash,
    anchorTx: `demos-testnet:tx-${opts.nativeAddress.slice(5, 21)}`,
    signer: opts.signer.did,
  };
  const value = signDomainHash(BINDING_DOMAIN, hashCanonical(tuple), opts.signer.priv);
  return { ...tuple, signature: { algorithm: 'ed25519', signer: opts.signer.did, value } } as BundleBindingV1;
}

function nativeAddr(rng: Rng): string {
  return `stor-${hex(rng.bytes(20))}`;
}

// --------------------------------------------------------------------------------------------
// malformed value generators. Most values are strict-JSON-reachable (strings, numbers, bools, null,
// arrays, nested objects). A few (NaN, undefined) are NOT RFC-8259-reachable via JSON.parse but ARE
// producible by lenient parsers / upstream numeric computation — we include them because a resolver
// that hashes untrusted input must fail-closed on them, not throw (§7.2). Symbols / BigInt /
// circular refs are neither wire- nor lenient-parser-reachable and are out of scope (see README).
// --------------------------------------------------------------------------------------------
function garbageScalarOrShape(rng: Rng): any {
  return rng.pick([
    null,
    undefined,
    0,
    8,
    -1,
    1.5,
    NaN,
    '8',
    '',
    'not-a-hash',
    true,
    false,
    [],
    [1, 2, 3],
    {},
    { nested: { dict: 'where scalar expected' } },
    { scheme: 'cci', identifier: 'x' },
    { role: {} },
  ]);
}
function malformedBinding(rng: Rng, goodLogical: string, jobId: string, role: BundleBindingRole): any {
  const base: Json = {
    bindingVersion: rng.pick(['1', '2', 1, null, {}, []]),
    jobId: rng.pick([jobId, '', 0, {}, null, ['x']]),
    role: rng.pick([role, 'buyer', 'nope', 42, {}, null]),
    logicalAddress: rng.pick([goodLogical, 'stor-wrong', null, {}, 123]),
    nativeAddress: rng.pick([nativeAddr(rng), '', null, {}, []]),
    bundleContentHash: rng.pick([hex(rng.bytes(32)), 'short', null, {}, 3.14, { dict: 1 }]),
    signer: rng.pick(['did:demos:ghost', { scheme: 'cci', identifier: 'nope' }, 42, null, {}, []]),
    signature: rng.pick([
      { algorithm: 'ed25519', signer: 'did:demos:ghost', value: b64url(rng.bytes(64)) },
      { algorithm: 'rsa', signer: 'did:demos:ghost', value: 'x' },
      { algorithm: 'ed25519', signer: {}, value: {} },
      'not-an-object',
      null,
      42,
      {},
    ]),
  };
  // occasionally return a fully non-object entry to probe the filter/guard paths
  return rng.chance(0.15) ? rng.pick([null, 42, 'binding', [], undefined]) : base;
}

// --------------------------------------------------------------------------------------------
// scenario model
// --------------------------------------------------------------------------------------------
type Scenario = {
  kind: string;
  request: any;
  bindings: any;
  anchored: Map<string, any>;
  publicKeys: Record<string, string>;
  mode: 'present' | 'indeterminate' | 'fail' | 'not-present' | 'any';
  expectedNative?: string;
};

function fetchOf(anchored: Map<string, any>) {
  return (nativeAddress: string): unknown => anchored.get(nativeAddress);
}

function collectKeys(parties: Party[]): Record<string, string> {
  const map: Record<string, string> = {};
  for (const p of parties) map[p.did] = b64url(p.pub);
  return map;
}

// ---- scenario generators -------------------------------------------------------------------

function genValidPresent(rng: Rng): Scenario {
  const jobId = `JOB-${hex(rng.bytes(4))}`;
  const role: BundleBindingRole = rng.pick(['buyer', 'seller']);
  const buyer = makeParty(rng, 'did:demos:buyer');
  const seller = makeParty(rng, 'did:demos:seller');
  const signer = role === 'buyer' ? buyer : seller;
  const { bundle, contentHash } = buildBundle({
    jobId,
    parties: [buyer, seller],
    roles: ['buyer', 'seller'],
    signers: [buyer, seller], // fully signed
    outcome: 'completed',
    faultedParty: 'none',
    anchoredByRole: role,
    nonce: rng.int(1_000_000),
  });
  const native = nativeAddr(rng);
  const binding = buildBinding({ jobId, role, signer, nativeAddress: native, contentHash });
  return {
    kind: 'valid-present',
    request: { jobId, role },
    bindings: [binding],
    anchored: new Map([[native, bundle]]),
    publicKeys: collectKeys([buyer, seller]),
    mode: 'present',
    expectedNative: native,
  };
}

function genPrecedence(rng: Rng): Scenario {
  // A fully-signed completed copy vs a single-signed abort copy that diverges. Full-signature
  // precedence MUST pick the fully-signed one, never let the single-signed divergent copy win.
  const jobId = `JOB-${hex(rng.bytes(4))}`;
  const role: BundleBindingRole = 'seller';
  const buyer = makeParty(rng, 'did:demos:buyer');
  const seller = makeParty(rng, 'did:demos:seller');
  const nonceA = rng.int(500_000);
  const a = buildBundle({
    jobId, parties: [buyer, seller], roles: ['buyer', 'seller'], signers: [buyer, seller],
    outcome: 'completed', faultedParty: 'none', anchoredByRole: 'seller', nonce: nonceA,
  });
  const b = buildBundle({
    jobId, parties: [buyer, seller], roles: ['buyer', 'seller'], signers: [seller], // single-signed
    outcome: 'aborted-by-self', faultedParty: 'seller', anchoredByRole: 'seller', nonce: nonceA + 1 + rng.int(1000),
  });
  const nativeA = nativeAddr(rng);
  const nativeB = nativeAddr(rng);
  const bindingA = buildBinding({ jobId, role, signer: seller, nativeAddress: nativeA, contentHash: a.contentHash });
  const bindingB = buildBinding({ jobId, role, signer: seller, nativeAddress: nativeB, contentHash: b.contentHash });
  return {
    kind: 'full-sig-precedence',
    request: { jobId, role },
    bindings: rng.chance(0.5) ? [bindingA, bindingB] : [bindingB, bindingA],
    anchored: new Map([[nativeA, a.bundle], [nativeB, b.bundle]]),
    publicKeys: collectKeys([buyer, seller]),
    mode: 'present',
    expectedNative: nativeA, // the fully-signed copy must win
  };
}

function genEqualStandingDivergence(rng: Rng): Scenario {
  // Two fully-signed, authorized, byte-DIVERGENT copies at equal standing -> indeterminate (void),
  // never an arbitrary pick.
  const jobId = `JOB-${hex(rng.bytes(4))}`;
  const role: BundleBindingRole = 'seller';
  const buyer = makeParty(rng, 'did:demos:buyer');
  const seller = makeParty(rng, 'did:demos:seller');
  const nonce = rng.int(400_000);
  const a = buildBundle({
    jobId, parties: [buyer, seller], roles: ['buyer', 'seller'], signers: [buyer, seller],
    outcome: 'completed', faultedParty: 'none', anchoredByRole: 'seller', nonce,
  });
  const b = buildBundle({
    jobId, parties: [buyer, seller], roles: ['buyer', 'seller'], signers: [buyer, seller],
    outcome: 'completed', faultedParty: 'none', anchoredByRole: 'seller', nonce: nonce + 1 + rng.int(1000),
  });
  const nativeA = nativeAddr(rng);
  const nativeB = nativeAddr(rng);
  return {
    kind: 'equal-standing-divergence',
    request: { jobId, role },
    bindings: [
      buildBinding({ jobId, role, signer: seller, nativeAddress: nativeA, contentHash: a.contentHash }),
      buildBinding({ jobId, role, signer: seller, nativeAddress: nativeB, contentHash: b.contentHash }),
    ],
    anchored: new Map([[nativeA, a.bundle], [nativeB, b.bundle]]),
    publicKeys: collectKeys([buyer, seller]),
    mode: 'indeterminate',
  };
}

function genBudgetExhaustion(rng: Rng): Scenario {
  // One signer publishes budget+K authenticated candidates for the requested side. Exceeding the
  // per-signer budget MUST be indeterminate, never silent truncation to some winner.
  const jobId = `JOB-${hex(rng.bytes(4))}`;
  const role: BundleBindingRole = 'seller';
  const seller = makeParty(rng, 'did:demos:seller');
  const budget = 1 + rng.int(8); // 1..8
  const count = budget + 1 + rng.int(4); // strictly over budget
  const bindings: BundleBindingV1[] = [];
  for (let i = 0; i < count; i++) {
    bindings.push(buildBinding({
      jobId, role, signer: seller, nativeAddress: nativeAddr(rng), contentHash: hex(rng.bytes(32)),
    }));
  }
  return {
    kind: 'budget-exhaustion',
    request: { jobId, role, budget },
    bindings,
    anchored: new Map(), // never fetched — budget check precedes fetch
    publicKeys: collectKeys([seller]),
    mode: 'indeterminate',
  };
}

function genOutsiderFlood(rng: Rng): Scenario {
  // One genuine winner drowned in a flood of authenticated-but-unauthorized (roster outsider) and
  // invalid-signature (Sybil) bindings under DISTINCT signers. Must still resolve the real winner.
  const jobId = `JOB-${hex(rng.bytes(4))}`;
  const role: BundleBindingRole = 'seller';
  const buyer = makeParty(rng, 'did:demos:buyer');
  const seller = makeParty(rng, 'did:demos:seller');
  const { bundle, contentHash } = buildBundle({
    jobId, parties: [buyer, seller], roles: ['buyer', 'seller'], signers: [buyer, seller],
    outcome: 'completed', faultedParty: 'none', anchoredByRole: 'seller', nonce: rng.int(1_000_000),
  });
  const native = nativeAddr(rng);
  const bindings: any[] = [buildBinding({ jobId, role, signer: seller, nativeAddress: native, contentHash })];
  const allParties = [buyer, seller];
  const floodCount = 1 + rng.int(20);
  for (let i = 0; i < floodCount; i++) {
    const sybil = makeParty(rng, `did:demos:sybil${i}`);
    allParties.push(sybil);
    if (rng.chance(0.5)) {
      // authenticated but its key is not in the roster -> inert (unauthorized) copy pointing at real bundle
      bindings.push(buildBinding({ jobId, role, signer: sybil, nativeAddress: native, contentHash }));
    } else {
      // valid-looking tuple but corrupted signature -> unauthenticated, observedInvalid
      const bad = buildBinding({ jobId, role, signer: sybil, nativeAddress: nativeAddr(rng), contentHash: hex(rng.bytes(32)) });
      (bad as any).signature.value = b64url(rng.bytes(64)); // random sig -> fails BB-4
      bindings.push(bad);
    }
  }
  // shuffle the flood around the real winner
  for (let i = bindings.length - 1; i > 0; i--) {
    const j = rng.int(i + 1);
    [bindings[i], bindings[j]] = [bindings[j], bindings[i]];
  }
  return {
    kind: 'outsider-sybil-flood',
    request: { jobId, role },
    bindings,
    anchored: new Map([[native, bundle]]),
    publicKeys: collectKeys(allParties),
    mode: 'present',
    expectedNative: native,
  };
}

function genBb5Reject(rng: Rng): Scenario {
  // An authenticated binding whose tuple does not match the requested side (bindingVersion != '1')
  // triggers BB-5 reject-on-any: the whole resolution is 'fail'.
  const jobId = `JOB-${hex(rng.bytes(4))}`;
  const role: BundleBindingRole = 'seller';
  const seller = makeParty(rng, 'did:demos:seller');
  const logical = deriveBundleLogicalAddress(jobId, role);
  // authenticated but bindingVersion '2' -> BB-5 mismatch. logicalAddress must match the side so it
  // is "publishedHere"; the version check is what rejects.
  const binding = buildBinding({
    jobId, role, signer: seller, nativeAddress: nativeAddr(rng), contentHash: hex(rng.bytes(32)),
    bindingVersion: '2', logicalAddress: logical,
  });
  return {
    kind: 'bb5-reject-on-any',
    request: { jobId, role },
    bindings: [binding],
    anchored: new Map(),
    publicKeys: collectKeys([seller]),
    mode: 'fail',
  };
}

function genMalformedIngress(rng: Rng): Scenario {
  // Pure malformed ingress: no valid copy is planted, so the ONLY defensible dispositions are
  // fail / indeterminate. This is the round-11 "21 exception escapes" target.
  const jobId = `JOB-${hex(rng.bytes(4))}`;
  const role: BundleBindingRole = rng.pick(ROLES);
  const logical = deriveBundleLogicalAddress(jobId, role);
  const n = rng.int(6);
  const bindings: any[] = [];
  for (let i = 0; i < n; i++) bindings.push(malformedBinding(rng, logical, jobId, role));
  const anchored = new Map<string, any>();
  // seed the fetch map with garbage the resolver might dereference
  for (let i = 0; i < rng.int(4); i++) anchored.set(nativeAddr(rng), garbageScalarOrShape(rng));

  const request: any = rng.chance(0.4)
    ? { jobId, role, budget: garbageScalarOrShape(rng) }
    : {
        jobId: rng.pick([jobId, '', 0, {}, null, ['x']]),
        role: rng.pick([role, 'nope', 42, {}, null]),
        budget: rng.pick([8, '8', null, 8.0, -1, 0, 1.5, NaN, {}, []]),
        partyMap: rng.chance(0.5) ? garbageScalarOrShape(rng) : undefined,
      };
  return {
    kind: 'malformed-ingress',
    request,
    bindings: rng.chance(0.1) ? garbageScalarOrShape(rng) : bindings, // sometimes bindings itself is garbage
    anchored,
    publicKeys: rng.chance(0.5) ? {} : { 'did:demos:ghost': b64url(rng.bytes(rng.pick([32, 16, 33]))) },
    mode: 'not-present',
  };
}

function genCorruptValid(rng: Rng): Scenario {
  // Take a genuinely valid scenario and corrupt ONE aspect. Disposition is legitimately anything,
  // but the universal invariants (no-throw, determinism, permutation-invariance) must still hold.
  const base = rng.pick([genValidPresent, genPrecedence, genEqualStandingDivergence])(rng);
  const bindings = Array.isArray(base.bindings) ? base.bindings.slice() : base.bindings;
  const corruption = rng.int(6);
  if (Array.isArray(bindings) && bindings.length > 0) {
    const idx = rng.int(bindings.length);
    const b = { ...(bindings[idx] as Json) };
    switch (corruption) {
      case 0: b.signature = garbageScalarOrShape(rng); break;
      case 1: b.signer = garbageScalarOrShape(rng); break;
      case 2: b.bundleContentHash = garbageScalarOrShape(rng); break;
      case 3: b.nativeAddress = garbageScalarOrShape(rng); break;
      case 4: b.role = garbageScalarOrShape(rng); break;
      default: b.logicalAddress = garbageScalarOrShape(rng); break;
    }
    bindings[idx] = b;
  }
  return {
    kind: 'corrupt-valid',
    request: rng.chance(0.3) ? { ...base.request, budget: garbageScalarOrShape(rng) } : base.request,
    bindings,
    anchored: base.anchored,
    publicKeys: base.publicKeys,
    mode: 'any',
  };
}

function genPureGarbage(rng: Rng): Scenario {
  // Totally unstructured input. No planted key can validate, so 'present' would be fail-open.
  const request = garbageScalarOrShape(rng);
  const bindings = rng.chance(0.5)
    ? Array.from({ length: rng.int(5) }, () => garbageScalarOrShape(rng))
    : garbageScalarOrShape(rng);
  const anchored = new Map<string, any>();
  for (let i = 0; i < rng.int(3); i++) anchored.set(nativeAddr(rng), garbageScalarOrShape(rng));
  return {
    kind: 'pure-garbage',
    request,
    bindings,
    anchored,
    publicKeys: {},
    mode: 'not-present',
  };
}

const GENERATORS: Array<{ gen: (rng: Rng) => Scenario; weight: number }> = [
  { gen: genValidPresent, weight: 12 },
  { gen: genPrecedence, weight: 12 },
  { gen: genEqualStandingDivergence, weight: 12 },
  { gen: genBudgetExhaustion, weight: 12 },
  { gen: genOutsiderFlood, weight: 12 },
  { gen: genBb5Reject, weight: 8 },
  { gen: genMalformedIngress, weight: 16 }, // round-11 target — weight it up
  { gen: genCorruptValid, weight: 8 },
  { gen: genPureGarbage, weight: 8 },
];
function pickGenerator(rng: Rng): (rng: Rng) => Scenario {
  const total = GENERATORS.reduce((s, g) => s + g.weight, 0);
  let r = rng.int(total);
  for (const g of GENERATORS) {
    if (r < g.weight) return g.gen;
    r -= g.weight;
  }
  return GENERATORS[0]!.gen;
}

// --------------------------------------------------------------------------------------------
// invariant checking
// --------------------------------------------------------------------------------------------
type RunOutcome =
  | { threw: true; error: string }
  | { threw: false; resolution: BundleBindingResolution };

/**
 * publicKeys is a request field in the real API. Inject it for structured requests; leave garbage
 * (non-object) requests untouched so the malformed-request paths are genuinely exercised.
 */
function buildRequest(s: Scenario): any {
  const r = s.request;
  if (r !== null && typeof r === 'object' && !Array.isArray(r)) {
    return 'publicKeys' in r ? r : { ...r, publicKeys: s.publicKeys };
  }
  return r;
}

function runResolver(s: Scenario, bindings: any): RunOutcome {
  try {
    const resolution = resolveBundleBinding(buildRequest(s) as BundleBindingRequest, bindings, fetchOf(s.anchored));
    return { threw: false, resolution };
  } catch (error) {
    return { threw: true, error: error instanceof Error ? `${error.name}: ${error.message}` : String(error) };
  }
}

type Violation = { invariant: string; detail: string };

function checkScenario(s: Scenario): Violation[] {
  const violations: Violation[] = [];
  const first = runResolver(s, s.bindings);

  // INV-1: never throws on any input
  if (first.threw) {
    violations.push({ invariant: 'no-throw', detail: `resolver threw: ${first.error}` });
    return violations; // downstream invariants are meaningless if it threw
  }
  const res = first.resolution;

  // structural sanity of the returned disposition
  if (res.disposition !== 'present' && res.disposition !== 'fail' && res.disposition !== 'indeterminate') {
    violations.push({ invariant: 'valid-disposition', detail: `disposition=${JSON.stringify(res.disposition)}` });
  }

  // INV-2: determinism — same input, same output
  const second = runResolver(s, s.bindings);
  if (second.threw) {
    violations.push({ invariant: 'determinism', detail: `second run threw: ${second.error}` });
  } else if (JSON.stringify(second.resolution) !== JSON.stringify(res)) {
    violations.push({
      invariant: 'determinism',
      detail: `run1=${JSON.stringify(res)} run2=${JSON.stringify(second.resolution)}`,
    });
  }

  // INV-3: permutation invariance — reordering the bindings array must not change the verdict.
  if (Array.isArray(s.bindings) && s.bindings.length > 1) {
    const permRng = makeRng(0x9e3779b1 ^ s.bindings.length);
    const perm = s.bindings.slice();
    for (let i = perm.length - 1; i > 0; i--) {
      const j = permRng.int(i + 1);
      [perm[i], perm[j]] = [perm[j], perm[i]];
    }
    const permuted = runResolver(s, perm);
    if (permuted.threw) {
      violations.push({ invariant: 'permutation-invariance', detail: `permuted run threw: ${permuted.error}` });
    } else {
      if (permuted.resolution.disposition !== res.disposition) {
        violations.push({
          invariant: 'permutation-invariance',
          detail: `disposition flipped ${res.disposition} -> ${permuted.resolution.disposition} on reorder`,
        });
      }
      if (res.disposition === 'present' && permuted.resolution.disposition === 'present' &&
          permuted.resolution.resolvedNativeAddress !== res.resolvedNativeAddress) {
        violations.push({
          invariant: 'permutation-invariance',
          detail: `winner changed ${res.resolvedNativeAddress} -> ${permuted.resolution.resolvedNativeAddress} on reorder`,
        });
      }
    }
  }

  // INV-4: fail-closed monotonicity — an input with no genuinely valid authorized copy is NEVER 'present'.
  if ((s.mode === 'not-present' || s.mode === 'fail' || s.mode === 'indeterminate') && res.disposition === 'present') {
    violations.push({
      invariant: 'fail-closed',
      detail: `expected non-present (${s.mode}) but got present: ${JSON.stringify(res)}`,
    });
  }

  // INV-5: scenario-specific ground-truth (the constructive properties)
  switch (s.mode) {
    case 'present':
      if (res.disposition !== 'present') {
        violations.push({ invariant: `${s.kind}:expect-present`, detail: `got ${res.disposition}: ${res.detail}` });
      } else if (s.expectedNative !== undefined && res.resolvedNativeAddress !== s.expectedNative) {
        violations.push({
          invariant: `${s.kind}:winner`,
          detail: `expected winner ${s.expectedNative} got ${res.resolvedNativeAddress}`,
        });
      }
      break;
    case 'indeterminate':
      if (res.disposition !== 'indeterminate') {
        violations.push({ invariant: `${s.kind}:expect-indeterminate`, detail: `got ${res.disposition}: ${res.detail}` });
      }
      break;
    case 'fail':
      if (res.disposition !== 'fail') {
        violations.push({ invariant: `${s.kind}:expect-fail`, detail: `got ${res.disposition}: ${res.detail}` });
      }
      break;
    // 'not-present' handled by INV-4; 'any' has only the universal invariants
  }
  return violations;
}

// --------------------------------------------------------------------------------------------
// serialisation for minimal-repro reporting
// --------------------------------------------------------------------------------------------
function scenarioToRepro(s: Scenario): Json {
  return {
    kind: s.kind,
    request: s.request,
    bindings: s.bindings,
    anchored: Object.fromEntries(s.anchored),
    publicKeys: s.publicKeys,
    mode: s.mode,
    expectedNative: s.expectedNative,
  };
}

// --------------------------------------------------------------------------------------------
// self-test: prove the signing path actually produces resolver-'present' verdicts, otherwise the
// whole fuzz is vacuous (every "valid" scenario would silently collapse to non-present).
// --------------------------------------------------------------------------------------------
function selfTest(): void {
  const rng = makeRng(1);
  const s = genValidPresent(rng);
  const out = runResolver(s, s.bindings);
  if (out.threw || out.resolution.disposition !== 'present') {
    console.error('FATAL self-test: a hand-built valid scenario did not resolve to present.');
    console.error(out.threw ? out.error : JSON.stringify(out.resolution));
    console.error('Signing/oracle wiring is broken — fuzz results would be vacuous. Aborting.');
    process.exit(2);
  }
}

// --------------------------------------------------------------------------------------------
// CLI + main loop
// --------------------------------------------------------------------------------------------
function parseArgs(argv: string[]): { cases: number; seed: number; caseSeed?: number; verbose: boolean } {
  let cases = 1000;
  let seed = 20260701; // fixed default for reproducibility
  let caseSeed: number | undefined;
  let verbose = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--cases') cases = parseInt(argv[++i]!, 10);
    else if (a === '--seed') seed = parseInt(argv[++i]!, 10) >>> 0;
    else if (a === '--case-seed') caseSeed = parseInt(argv[++i]!, 10) >>> 0;
    else if (a === '--verbose' || a === '-v') verbose = true;
  }
  return { cases, seed, caseSeed, verbose };
}

function runOneCase(caseSeed: number): { scenario: Scenario; violations: Violation[] } {
  const rng = makeRng(caseSeed);
  const scenario = pickGenerator(rng)(rng);
  const violations = checkScenario(scenario);
  return { scenario, violations };
}

function main(): void {
  const { cases, seed, caseSeed, verbose } = parseArgs(process.argv.slice(2));
  selfTest();

  if (caseSeed !== undefined) {
    const { scenario, violations } = runOneCase(caseSeed);
    console.log(`Replaying case-seed ${caseSeed} (kind=${scenario.kind}, mode=${scenario.mode})`);
    console.log(JSON.stringify(scenarioToRepro(scenario), null, 2));
    const live = runResolver(scenario, scenario.bindings);
    console.log('resolution:', live.threw ? `THREW ${live.error}` : JSON.stringify(live.resolution));
    if (violations.length === 0) console.log('\nNo invariant violations for this case.');
    else {
      console.log(`\n${violations.length} violation(s):`);
      for (const v of violations) console.log(`  [${v.invariant}] ${v.detail}`);
      process.exitCode = 1;
    }
    return;
  }

  console.log('DACS-5 §10.4.2 BundleBinding — property-based differential fuzzer');
  console.log(`mode: invariant/metamorphic (second-oracle differential deferred — see README)`);
  console.log(`seed=${seed}  cases=${cases}\n`);

  const kindCounts = new Map<string, number>();
  const invariantCounts = new Map<string, number>();
  type FailRecord = { caseSeed: number; kind: string; violations: Violation[]; repro: Json };
  const firstFailurePerInvariant = new Map<string, FailRecord>();
  let totalViolations = 0;
  let failingCases = 0;

  const master = makeRng(seed);
  for (let i = 0; i < cases; i++) {
    const cs = Math.floor(master.next() * 4294967296) >>> 0;
    const { scenario, violations } = runOneCase(cs);
    kindCounts.set(scenario.kind, (kindCounts.get(scenario.kind) ?? 0) + 1);
    if (violations.length > 0) {
      failingCases++;
      totalViolations += violations.length;
      for (const v of violations) {
        invariantCounts.set(v.invariant, (invariantCounts.get(v.invariant) ?? 0) + 1);
        if (!firstFailurePerInvariant.has(v.invariant)) {
          firstFailurePerInvariant.set(v.invariant, {
            caseSeed: cs, kind: scenario.kind, violations, repro: scenarioToRepro(scenario),
          });
        }
      }
      if (verbose) {
        console.log(`FAIL case-seed=${cs} kind=${scenario.kind}`);
        for (const v of violations) console.log(`    [${v.invariant}] ${v.detail}`);
      }
    }
  }

  console.log('scenario coverage:');
  for (const [kind, count] of [...kindCounts.entries()].sort()) {
    console.log(`  ${kind.padEnd(26)} ${count}`);
  }
  console.log('');

  if (totalViolations === 0) {
    console.log(`RESULT: ${cases}/${cases} cases pass. No invariant violations.`);
    console.log('Invariants exercised: no-throw, determinism, permutation-invariance, fail-closed,');
    console.log('full-signature precedence, equal-standing divergence, budget exhaustion, BB-5 reject-on-any.');
    return;
  }

  console.log(`RESULT: ${failingCases}/${cases} cases had violations (${totalViolations} total).`);
  console.log('violations by invariant:');
  for (const [inv, count] of [...invariantCounts.entries()].sort()) {
    console.log(`  ${inv.padEnd(40)} ${count}`);
  }
  console.log('\nminimal reproductions (first occurrence per invariant):');
  for (const [inv, rec] of firstFailurePerInvariant.entries()) {
    console.log(`\n=== invariant: ${inv} ===`);
    console.log(`replay: tsx conformance/cross-run-corpus/bb-differential-fuzzer.mts --case-seed ${rec.caseSeed}`);
    console.log(`kind: ${rec.kind}`);
    for (const v of rec.violations.filter((x) => x.invariant === inv)) console.log(`detail: ${v.detail}`);
    console.log('input:');
    console.log(JSON.stringify(rec.repro, null, 2));
  }
  process.exitCode = 1;
}

main();
