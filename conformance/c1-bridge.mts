#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { spawn } from "node:child_process";

import { jcsCanonical, jcsHashHex } from "../src/jcs.js";

export const STANDARD_PIN = "662be1d4899a2cadf327fe2d5523e93a80334e5f";

type JsonObject = Record<string, unknown>;
type Decision = "pass" | "fail" | "error" | "indeterminate";

interface Sdk {
  DACS_STANDARD_PIN: string;
  canonicalize(value: unknown): string;
  contentHash(value: JsonObject): string;
  signArtifact(separator: string, doc: JsonObject, seed: Uint8Array): Uint8Array;
  verifyArtifact(separator: string, doc: JsonObject, signature: Uint8Array, key: Uint8Array): boolean;
  publicKeyFromSeed(seed: Uint8Array): unknown;
  publicKeyFromRaw(key: Uint8Array): unknown;
  rawPublicKey(key: unknown): Uint8Array;
  ed25519Verify(message: Uint8Array, signature: Uint8Array, key: unknown): boolean;
  isAgreementArtifact(value: unknown): boolean;
  isSettlementEvidence(value: unknown): boolean;
  verifySettlementEvidence(record: unknown, context?: JsonObject, deps?: JsonObject): Promise<{ decision: Decision; reasons: string[] }>;
  verifyBundleCore(ref: string, deps: JsonObject): Promise<JsonObject>;
  bundleConsistency(copies: JsonObject, deps: JsonObject): Promise<string>;
  deriveReputation(party: string, bundles: JsonObject[], window: JsonObject, deps: JsonObject): JsonObject;
}

interface TraceArtifact {
  artifactId: string;
  kind: string;
  artifact: JsonObject;
  artifactHash: string;
  domainSeparator: string;
  attestationRef?: JsonObject;
  publishedBinding?: { logicalAddress: string; nativeAddress: string };
}

interface BridgeOptions {
  json?: boolean;
  ablate?: boolean;
  standardDir?: string;
  sdkDir?: string;
  standardRef?: string;
  emitManifest?: boolean;
}

export interface BridgeReport extends JsonObject {
  ok: boolean;
  pins: JsonObject;
  golden: JsonObject;
  walkthrough: JsonObject;
  settlementEvidence: JsonObject[];
  bundles: JsonObject;
  ablations: JsonObject[];
  divergences: JsonObject[];
  manifest: JsonObject;
}

function command(command: string, args: string[], cwd?: string, input?: Uint8Array): Promise<Buffer> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, { cwd, stdio: [input ? "pipe" : "ignore", "pipe", "pipe"] });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout!.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr!.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolvePromise(Buffer.concat(stdout));
      else reject(new Error(`${command} ${args.join(" ")} exited ${code}: ${Buffer.concat(stderr).toString("utf8").trim()}`));
    });
    if (input) child.stdin!.end(input);
  });
}

const json = (bytes: Uint8Array): unknown => JSON.parse(Buffer.from(bytes).toString("utf8"));
const object = (value: unknown, label: string): JsonObject => {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  return value as JsonObject;
};
const sha256 = (bytes: Uint8Array): string => createHash("sha256").update(bytes).digest("hex");
const b64url = (value: unknown): Uint8Array => {
  if (typeof value !== "string") throw new TypeError("signature value must be a string");
  return Buffer.from(value, "base64url");
};
function clone<T>(value: T): T { return structuredClone(value); }

function signedScope(kind: string, artifact: JsonObject): JsonObject {
  const scope = clone(artifact);
  delete scope.signature;
  delete scope.signatures;
  if (kind === "AttestationBundle") delete scope.anchoredByRole;
  return scope;
}

function signatures(artifact: JsonObject): Array<{ signer: string; value: string }> {
  const values = artifact.signature ? [artifact.signature] : artifact.signatures;
  assert(Array.isArray(values) && values.length > 0, "signed artifact has no signature(s)");
  return values.map((entry) => {
    const sig = object(entry, "signature");
    const signer = sig.signer ?? sig.party;
    if (typeof signer !== "string" || typeof sig.value !== "string") {
      throw new TypeError("signature signer/value must be strings");
    }
    return { signer, value: sig.value };
  });
}

function mutateScope(kind: string, artifact: JsonObject): JsonObject {
  const changed = clone(artifact);
  const omitted = new Set(["signature", "signatures", ...(kind === "AttestationBundle" ? ["anchoredByRole"] : [])]);
  const field = Object.keys(changed).find((key) => !omitted.has(key));
  assert(field, `${kind} has no mutable signed field`);
  const value = changed[field];
  changed[field] = typeof value === "number" ? value + 1 : typeof value === "string" ? `${value}-ablated` : null;
  return changed;
}

function traceArtifacts(trace: JsonObject): TraceArtifact[] {
  assert(Array.isArray(trace.stages));
  return trace.stages.flatMap((stage) => {
    const row = object(stage, "trace stage");
    assert(Array.isArray(row.artifacts));
    return row.artifacts.map((entry) => object(entry, "trace artifact") as unknown as TraceArtifact);
  });
}

async function git(dir: string, ...args: string[]): Promise<string> {
  return (await command("git", ["-C", dir, ...args])).toString("utf8").trim();
}

async function readPinnedJson(standardDir: string, ref: string, path: string): Promise<JsonObject> {
  return object(json(await command("git", ["-C", standardDir, "show", `${ref}:${path}`])), path);
}

async function runPinnedWalkthrough(standardDir: string, ref: string): Promise<{ trace: JsonObject; stdout: Buffer }> {
  const snapshot = await mkdtemp(join(tmpdir(), "pathos-c1-standard-"));
  const archive = join(snapshot, "standard.tar");
  try {
    await command("git", ["-C", standardDir, "archive", "--format=tar", `--output=${archive}`, ref]);
    await command("tar", ["-xf", archive, "-C", snapshot]);
    const stdout = await command("python3", ["scripts/run_lifecycle_walkthrough.py", "--json"], snapshot);
    return { trace: object(json(stdout), "walkthrough trace"), stdout };
  } finally {
    await rm(snapshot, { recursive: true, force: true });
  }
}

function publicTestKeys(sdk: Sdk): Map<string, Uint8Array> {
  const keys = new Map<string, Uint8Array>();
  for (const role of ["buyer", "seller", "orchestrator"]) {
    const seed = createHash("sha256").update(`DACS issue 261 public test seed:${role}`).digest();
    const publicKey = sdk.rawPublicKey(sdk.publicKeyFromSeed(seed));
    keys.set(`cci:${Buffer.from(publicKey).toString("hex")}`, publicKey);
  }
  return keys;
}

function verifyTraceSignature(sdk: Sdk, item: TraceArtifact, keys: Map<string, Uint8Array>, artifact = item.artifact): boolean {
  const scope = signedScope(item.kind, artifact);
  return signatures(artifact).every((sig) => {
    const key = keys.get(sig.signer);
    return !!key && sdk.verifyArtifact(item.domainSeparator, scope, b64url(sig.value), key);
  });
}

function verifyRaw(sdk: Sdk): (message: Uint8Array, signature: Uint8Array, key: Uint8Array) => boolean {
  return (message, signature, key) => sdk.ed25519Verify(message, signature, sdk.publicKeyFromRaw(key));
}

function evidenceContext(item: TraceArtifact, bundle: JsonObject, agreement: JsonObject): JsonObject {
  const parties = bundle.parties as JsonObject[];
  const orchestrator = parties.find((party) => party.role === "orchestrator")?.primaryClaim;
  const price = object(object(agreement.terms, "agreement terms").price, "agreement price");
  const phase = String(item.artifact.phase);
  const context: JsonObject = {
    orchestrator,
    agreement: { amount: price.amount, currency: price.currency },
    attestationRef: item.attestationRef,
    result: { ok: true },
  };
  if (phase.startsWith("pay-")) {
    context.rail = {
      railId: "evm-erc20:8453:USDC",
      railType: "evm-erc20",
      asset: "USDC",
      network: "eip155:8453",
      handler: "pay-evm-erc20",
    };
  } else {
    context.expectedAnchorLocator = object(item.artifact.deliverableAnchor, "deliverable anchor").locator;
  }
  return context;
}

function signatureOnlyBundleValidator(sdk: Sdk, keys: Map<string, Uint8Array>) {
  return (bundle: JsonObject, role?: string): boolean => {
    if (role && bundle.anchoredByRole !== role) return false;
    const item: TraceArtifact = {
      artifactId: "bundle-validation",
      kind: "AttestationBundle",
      artifact: bundle,
      artifactHash: "",
      domainSeparator: "dacs-bundle:v1:",
    };
    return verifyTraceSignature(sdk, item, keys);
  };
}

function makeManifest(
  commits: { standard: string; sdk: string; implementation: string },
  pins: JsonObject,
  results: { settlement: boolean; bundleCore: boolean },
): JsonObject {
  const capabilities = [
    ["artifact-signatures", "verification-method", "ed25519-domain-separated-artifacts", ["CORE"], true],
    ["canonical-content-hash", "verification-method", "rfc8785-sha256-content-hash", ["CORE"], true],
    ["settlement-evidence", "verification-method", "verify-settlement-evidence", ["DACS-4"], results.settlement],
    ["verify-attestation-bundle", "bundle-operation", "verify-attestation-bundle", ["DACS-5"], results.bundleCore],
    ["bundle-consistency", "bundle-operation", "bundle-consistency", ["DACS-5"], true],
    ["derive-reputation", "reputation-operation", "derive-reputation", ["DACS-5"], true],
  ].map(([ref, kind, id, modules, passed]) => ({
    ref, kind, id, modules, roles: ["verifier"], supportStatus: "implemented", testStatus: passed ? "passed" : "failed", evidenceRefs: [`c1-${ref}`],
  }));
  return {
    manifestVersion: "1",
    generatedAt: new Date().toISOString(),
    implementation: { name: "pathos-dacs-ref", version: "0.1.0", repository: "https://github.com/cX3po/pathos-dacs-ref", commit: commits.implementation },
    profile: {
      id: "DACS-v0.1", repository: "https://github.com/DACS-Agent-commerce/DACS-Standard", commit: commits.standard,
      documents: { CORE: "0.1", "DACS-1": "0.3", "DACS-2": "0.2", "DACS-3": "0.3", "DACS-4": "0.3", "DACS-5": "0.3" },
    },
    roles: ["verifier"],
    conformanceSuite: {
      repository: "https://github.com/DACS-Agent-commerce/DACS-Standard", commit: commits.standard,
      manifestPath: "conformance/MANIFEST.json", manifestSha256: pins.manifestSha256,
    },
    claims: capabilities.filter((capability) => capability.testStatus === "passed").map((capability) => ({
      id: `claim-${capability.ref}`, level: "capability", result: "conformance-tested", roles: ["verifier"],
      modules: capability.modules, capabilityRefs: [capability.ref],
      ruleRefs: capability.ref === "artifact-signatures" ? ["SIG-2"]
        : capability.ref === "canonical-content-hash" ? ["CF-1"]
        : capability.ref === "settlement-evidence" ? ["DACS-4-9.7"]
        : capability.ref === "bundle-consistency" ? ["DACS-5-10.4.3"]
        : capability.ref === "derive-reputation" ? ["DACS-5-10.5.1"]
        : ["DACS-5-10.4.1"],
      evidenceRefs: capability.evidenceRefs,
    })),
    capabilities,
    testRuns: capabilities.map((capability) => ({
      id: capability.evidenceRefs[0], result: capability.testStatus === "passed" ? "pass" : "fail",
      caseIds: [capability.ref],
      command: "npx tsx conformance/c1-bridge.mts --ablate",
    })),
    liveTests: [], deviations: [],
    notes: {
      sdk: { package: "@kynesyslabs/dacs", commit: commits.sdk, standardPin: commits.standard },
      executed: capabilities.map((capability) => capability.ref),
      notExecuted: {
        liveSubstrate: "The Standard walkthrough uses FakeSubstrate and reports liveSdkCalls=false.",
        dispute: "Inputs are constructed in dacs-verify conformance/run.ts and are not shipped as Standard artifacts.",
        disclosure: "Inputs are constructed in dacs-verify conformance/run.ts and are not shipped as Standard artifacts.",
        x402: "The walkthrough uses an EVM ERC-20 settlement and does not execute x402.",
      },
    },
  };
}

export async function runBridge(options: BridgeOptions = {}): Promise<BridgeReport> {
  const standardDir = resolve(options.standardDir ?? process.env.DACS_STANDARD_DIR ?? "../DACS-Standard");
  const sdkDir = resolve(options.sdkDir ?? process.env.DACS_SDK_DIR ?? "../dacs-sdk");
  const standardRef = options.standardRef ?? process.env.DACS_STANDARD_REF ?? STANDARD_PIN;
  const [standardHead, resolvedRef, sdkCommit, implementationCommit] = await Promise.all([
    git(standardDir, "rev-parse", "HEAD"), git(standardDir, "rev-parse", standardRef), git(sdkDir, "rev-parse", "HEAD"), git(process.cwd(), "rev-parse", "HEAD"),
  ]);
  const sdk = await import(pathToFileURL(join(sdkDir, "dist/index.js")).href) as unknown as Sdk;
  if (resolvedRef !== STANDARD_PIN || sdk.DACS_STANDARD_PIN !== STANDARD_PIN) {
    throw new Error(`DACS pin mismatch; Standard HEAD=${standardHead}; configured ref ${standardRef}=${resolvedRef}; SDK DACS_STANDARD_PIN=${sdk.DACS_STANDARD_PIN}; required=${STANDARD_PIN}`);
  }

  const [goldenRoot, pins, walkthrough] = await Promise.all([
    readPinnedJson(standardDir, resolvedRef, "conformance/vectors/golden.json"),
    readPinnedJson(standardDir, resolvedRef, "conformance/walkthrough/PINS.json"),
    runPinnedWalkthrough(standardDir, resolvedRef),
  ]);
  const signing = object(goldenRoot.signing, "golden signing vector");
  const goldenDoc = object(signing.doc, "golden doc");
  const seed = Buffer.from(String(signing.seed), "hex");
  const publicKey = Buffer.from(String(signing.publicKeyHex), "hex");
  const reproduced = Buffer.from(sdk.signArtifact(String(signing.separator), goldenDoc, seed)).toString("base64url");
  assert.equal(reproduced, signing.signature, "SDK did not reproduce the pinned golden signature");
  assert(sdk.verifyArtifact(String(signing.separator), goldenDoc, b64url(signing.signature), publicKey), "SDK rejected golden signature");
  const goldenSdkHash = sdk.contentHash(goldenDoc);
  assert.equal(goldenSdkHash, jcsHashHex(goldenDoc));
  assert.deepEqual(Buffer.from(sdk.canonicalize(goldenDoc)), Buffer.from(jcsCanonical(goldenDoc)));

  const traceHash = sha256(jcsCanonical(walkthrough.trace));
  assert.equal(traceHash, pins.traceSha256, "canonical walkthrough trace bytes do not match PINS.json");
  const artifacts = traceArtifacts(walkthrough.trace);
  const keys = publicTestKeys(sdk);
  const ablations: JsonObject[] = [];
  const artifactKinds = new Set<string>();
  for (const item of artifacts) {
    artifactKinds.add(item.kind);
    const scope = signedScope(item.kind, item.artifact);
    assert(verifyTraceSignature(sdk, item, keys), `${item.artifactId}: SDK signature verification failed`);
    const sdkHash = sdk.contentHash(scope);
    assert.equal(sdkHash, jcsHashHex(scope), `${item.artifactId}: canonicalisers disagree`);
    assert.equal(sdkHash, item.artifactHash, `${item.artifactId}: trace content hash disagrees`);
  }

  const goldenChanged = { ...goldenDoc, listingVersion: Number(goldenDoc.listingVersion) + 1 };
  const goldenMutationRejected = !sdk.verifyArtifact(String(signing.separator), goldenChanged, b64url(signing.signature), publicKey);
  const wrongSeparatorRejected = !sdk.verifyArtifact("dacs-revocation:v1:", goldenDoc, b64url(signing.signature), publicKey);
  assert(goldenMutationRejected && wrongSeparatorRejected);
  const changedSdkHash = sdk.contentHash(goldenChanged);
  assert.equal(changedSdkHash, jcsHashHex(goldenChanged));
  assert.notEqual(changedSdkHash, goldenSdkHash);
  ablations.push({ guard: "golden-signature", field: "listingVersion", passed: goldenMutationRejected });
  ablations.push({ guard: "SIG-2", field: "domainSeparator", passed: wrongSeparatorRejected });
  ablations.push({ guard: "canonical-content-hash", field: "listingVersion", passed: true });

  if (options.ablate) {
    for (const kind of artifactKinds) {
      const item = artifacts.find((candidate) => candidate.kind === kind)!;
      const passed = !verifyTraceSignature(sdk, item, keys, mutateScope(kind, item.artifact));
      assert(passed, `${kind}: signed-field ablation did not invalidate signature`);
      ablations.push({ guard: `walkthrough-signature:${kind}`, field: "signed-scope", passed });
    }
  }

  const agreement = artifacts.find((item) => item.kind === "PayeeBoundAgreementDocument")!;
  const bundleItems = artifacts.filter((item) => item.kind === "AttestationBundle");
  const evidenceItems = artifacts.filter((item) => item.kind === "SettlementEvidence");
  const representativeBundle = bundleItems[0]!.artifact;
  const evidenceResults: JsonObject[] = [];
  const divergences: JsonObject[] = [];
  const phaseIndexProbes = evidenceItems.map((item) => {
    const withoutPhaseIndex = clone(item.artifact);
    delete withoutPhaseIndex.phaseIndex;
    const withField = sdk.isSettlementEvidence(item.artifact);
    const withoutField = sdk.isSettlementEvidence(withoutPhaseIndex);
    assert.equal(withField, false, `${item.artifactId}: SDK unexpectedly accepted SettlementEvidence.phaseIndex`);
    assert.equal(withoutField, true, `${item.artifactId}: removing only SettlementEvidence.phaseIndex did not restore SDK shape validity`);
    return { artifactId: item.artifactId, withField, withoutField };
  });
  divergences.push({
    capability: "settlement-evidence",
    field: "phaseIndex",
    standardReferences: ["scripts/run_lifecycle_walkthrough.py:569", "scripts/run_lifecycle_walkthrough.py:860"],
    sdkReferences: ["src/artifacts/validators.ts:1826-1828"],
    probes: phaseIndexProbes,
  });
  for (const item of evidenceItems) {
    const context = evidenceContext(item, representativeBundle, agreement.artifact);
    const deps = { resolvePublicKey: async (signer: string) => keys.get(signer) ?? null, verify: verifyRaw(sdk) };
    const baseline = await sdk.verifySettlementEvidence(item.artifact, context, deps);
    const result: JsonObject = { artifactId: item.artifactId, decision: baseline.decision, reasons: baseline.reasons };
    if (baseline.decision === "pass") {
      const changed = clone(item.artifact);
      const changedSignature = object(changed.signature, "settlement signature");
      changedSignature.signer = `${String(changedSignature.signer)}-ablated`;
      const ablated = await sdk.verifySettlementEvidence(changed, context, deps);
      assert.notEqual(ablated.decision, baseline.decision, `${item.artifactId}: settlement ablation did not change the decision`);
      result.ablatedDecision = ablated.decision;
      result.ablatedReasons = ablated.reasons;
      ablations.push({ guard: `verifySettlementEvidence:${item.artifactId}`, field: "signed-scope", passed: true });
    }
    evidenceResults.push(result);
  }

  const replacementJobId = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
  const agreementWithCanonicalJobId = { ...agreement.artifact, jobId: replacementJobId };
  const agreementWithStandardJobId = sdk.isAgreementArtifact(agreement.artifact);
  const agreementWithUlid = sdk.isAgreementArtifact(agreementWithCanonicalJobId);
  assert.equal(agreementWithStandardJobId, false, "SDK unexpectedly accepted the walkthrough agreement's non-ULID jobId");
  assert.equal(agreementWithUlid, true, "replacing only the walkthrough agreement jobId with a Crockford ULID did not restore SDK shape validity");
  divergences.push({
    capability: "verify-attestation-bundle",
    field: "jobId",
    standardReferences: ["scripts/run_lifecycle_walkthrough.py:77"],
    sdkReferences: ["src/artifacts/validators.ts:171-172", "src/artifacts/validators.ts:1318"],
    standardValue: agreement.artifact.jobId,
    replacementValue: replacementJobId,
    probes: { withStandardJobId: agreementWithStandardJobId, withCrockfordUlid: agreementWithUlid },
  });

  const byLocator = new Map<string, JsonObject>();
  for (const item of artifacts) {
    if (item.publishedBinding) {
      byLocator.set(item.publishedBinding.nativeAddress, item.artifact);
      byLocator.set(item.publishedBinding.logicalAddress, item.artifact);
    }
  }
  const verifyEvidence = async (evidence: JsonObject, context: JsonObject) => {
    const item = evidenceItems.find((candidate) => candidate.artifact.jobId === evidence.jobId && candidate.artifact.phaseIndex === evidence.phaseIndex)!;
    const result = await sdk.verifySettlementEvidence(evidence, evidenceContext(item, object(context.bundle, "bundle"), agreement.artifact), {
      resolvePublicKey: async (signer: string) => keys.get(signer) ?? null, verify: verifyRaw(sdk),
    });
    const orchestrator = (object(context.bundle, "bundle").parties as JsonObject[]).find((party) => party.role === "orchestrator")?.primaryClaim;
    return { decision: result.decision, authorizedSigner: orchestrator };
  };
  const bundleDeps = (bundle: JsonObject): JsonObject => ({
    readArtifact: async () => bundle,
    resolveAttestationRef: async (ref: JsonObject) => byLocator.get(String(object(ref.anchor, "ref anchor").locator)) ?? null,
    resolveListingRef: async () => artifacts.find((item) => item.kind === "Listing")!.artifact,
    resolvePublicKey: async (signer: string) => keys.get(signer) ?? null,
    verify: verifyRaw(sdk), verifyEvidence,
    verifyCompositeRecord: async (record: JsonObject) => ({ status: "valid", record, freshness: [], dealSpecific: [], freshnessRecipes: [], dealSpecificRecipes: [] }),
  });
  const bundleCore: JsonObject[] = [];
  for (const item of bundleItems) {
    const baseline = await sdk.verifyBundleCore(item.artifactId, bundleDeps(item.artifact));
    const result: JsonObject = { artifactId: item.artifactId, ok: baseline.ok, reason: baseline.reason };
    if (baseline.ok === true) {
      const changed = mutateScope(item.kind, item.artifact);
      const ablated = await sdk.verifyBundleCore(item.artifactId, bundleDeps(changed));
      assert.notDeepEqual(ablated, baseline, `${item.artifactId}: verifyBundleCore ablation was not observable`);
      result.ablatedOk = ablated.ok;
      result.ablatedReason = ablated.reason;
      ablations.push({ guard: `verifyBundleCore:${item.artifactId}`, field: "signed-scope", passed: ablated.ok === false });
    }
    bundleCore.push(result);
  }

  const buyer = bundleItems.find((item) => item.artifact.anchoredByRole === "buyer")!.artifact;
  const seller = bundleItems.find((item) => item.artifact.anchoredByRole === "seller")!.artifact;
  const validateBundle = signatureOnlyBundleValidator(sdk, keys);
  const copies = { buyer: { disposition: "present", bundle: buyer }, seller: { disposition: "present", bundle: seller } };
  const consistency = await sdk.bundleConsistency(copies, { isValid: validateBundle });
  assert.equal(consistency, "unified");
  let consistencyAblation = "no-flip";
  try {
    const changed = mutateScope("AttestationBundle", buyer);
    consistencyAblation = await sdk.bundleConsistency({ ...copies, buyer: { disposition: "present", bundle: changed } }, { isValid: validateBundle });
  } catch {
    consistencyAblation = "rejected";
  }
  assert.notEqual(consistencyAblation, consistency);
  ablations.push({ guard: "bundleConsistency", field: "signed-scope", passed: true });

  const party = String((buyer.parties as JsonObject[]).find((entry) => entry.role === "buyer")!.primaryClaim);
  const finalisedAt = Number(buyer.finalisedAt);
  const window = { windowStart: finalisedAt - 1, windowEnd: finalisedAt + 1, computedAt: finalisedAt + 2 };
  const reputation = sdk.deriveReputation(party, [buyer, seller], window, { isValid: validateBundle });
  assert.equal(reputation.bundleCount, 1);
  const changedBuyer = mutateScope("AttestationBundle", buyer);
  const reputationAblated = sdk.deriveReputation(party, [changedBuyer, seller], window, { isValid: validateBundle });
  assert.notEqual(reputationAblated.bundleCount, reputation.bundleCount);
  ablations.push({ guard: "deriveReputation", field: "signed-scope", passed: true });

  const settlementPassed = evidenceResults.every((row) => row.decision === "pass");
  const bundleCorePassed = bundleCore.every((row) => row.ok === true);
  const manifest = makeManifest(
    { standard: resolvedRef, sdk: sdkCommit, implementation: implementationCommit },
    pins,
    { settlement: settlementPassed, bundleCore: bundleCorePassed },
  );
  if (options.emitManifest !== false) {
    const manifestPath = resolve("conformance/implementation-manifests/pathos-dacs-ref.json");
    await mkdir(dirname(manifestPath), { recursive: true });
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  }

  return {
    ok: settlementPassed && bundleCorePassed,
    pins: { required: STANDARD_PIN, standardHead, configuredRef: standardRef, standardResolved: resolvedRef, sdkStandardPin: sdk.DACS_STANDARD_PIN, sdkCommit, implementationCommit },
    golden: { signatureReproduced: true, signature: reproduced, verified: true, contentHash: goldenSdkHash },
    walkthrough: { stdoutBytes: walkthrough.stdout.length, canonicalTraceSha256: traceHash, artifactCount: artifacts.length, artifactKinds: [...artifactKinds], signaturesVerified: artifacts.reduce((count, item) => count + signatures(item.artifact).length, 0) },
    settlementEvidence: evidenceResults,
    bundles: { verifyBundleCore: bundleCore, consistency, consistencyAblation, reputationBundleCount: reputation.bundleCount, reputationAblatedBundleCount: reputationAblated.bundleCount },
    ablations,
    divergences,
    manifest,
  };
}

function textReport(report: BridgeReport): string {
  const pins = report.pins;
  const walkthrough = report.walkthrough;
  const bundles = report.bundles;
  const capabilitiesVerified = (report.manifest.capabilities as JsonObject[]).filter((row) => row.testStatus === "passed").length;
  return [
    report.ok
      ? `C1 conformance bridge: PASS (${capabilitiesVerified} capabilities verified)`
      : `C1 conformance bridge: PARTIAL (${report.divergences.length} divergences, ${capabilitiesVerified} capabilities verified)`,
    `Standard HEAD: ${pins.standardHead}`,
    `Standard configured ref: ${pins.configuredRef} -> ${pins.standardResolved}`,
    `SDK DACS_STANDARD_PIN: ${pins.sdkStandardPin}`,
    `SDK commit: ${pins.sdkCommit}`,
    `pathos-dacs-ref commit: ${pins.implementationCommit}`,
    `Golden: exact signature reproduced; verified; contentHash=${report.golden.contentHash}`,
    `Walkthrough: canonical trace sha256=${walkthrough.canonicalTraceSha256}; artifacts=${walkthrough.artifactCount}; signatures=${walkthrough.signaturesVerified}`,
    ...report.settlementEvidence.map((row) => `Settlement ${row.artifactId}: ${row.decision} (${(row.reasons as string[]).join("; ")})${row.ablatedDecision === undefined ? "" : ` -> ablated ${row.ablatedDecision}`}`),
    ...((bundles.verifyBundleCore as JsonObject[]).map((row) => `Bundle ${row.artifactId}: verifyBundleCore=${row.ok} (${String(row.reason)})${row.ablatedOk === undefined ? "" : `; ablated=${row.ablatedOk} (${String(row.ablatedReason)})`}`)),
    ...report.divergences.map((row) => `Divergence ${row.field}: Standard ${String((row.standardReferences as string[]).join(", "))}; SDK ${String((row.sdkReferences as string[]).join(", "))}`),
    `bundleConsistency: ${bundles.consistency} -> ablated ${bundles.consistencyAblation}`,
    `deriveReputation bundleCount: ${bundles.reputationBundleCount} -> ablated ${bundles.reputationAblatedBundleCount}`,
    `Ablations: ${report.ablations.filter((row) => row.passed === true).length}/${report.ablations.length} load-bearing guards changed or rejected the input`,
    "Manifest: conformance/implementation-manifests/pathos-dacs-ref.json",
  ].join("\n");
}

export interface CliArgs {
  json: boolean;
  ablate: boolean;
  standardDir?: string;
  sdkDir?: string;
  standardRef?: string;
  out?: string;
}

const VALUE_FLAGS: Record<string, "standardDir" | "sdkDir" | "standardRef" | "out"> = {
  "--standard-dir": "standardDir",
  "--sdk-dir": "sdkDir",
  "--standard-ref": "standardRef",
  "--out": "out",
};

/** Pure argv parser. Flags override the DACS_* environment variables; `--out` also writes the JSON report. */
export function parseCliArgs(argv: readonly string[]): CliArgs {
  const args: CliArgs = { json: false, ablate: false };
  for (const arg of argv) {
    if (arg === "--json") { args.json = true; continue; }
    if (arg === "--ablate") { args.ablate = true; continue; }
    const eq = arg.indexOf("=");
    const flag = eq === -1 ? arg : arg.slice(0, eq);
    const key = VALUE_FLAGS[flag];
    assert(key !== undefined, `unknown argument: ${arg}`);
    const value = eq === -1 ? "" : arg.slice(eq + 1);
    assert(value.length > 0, `${flag} requires a value: ${flag}=<value>`);
    args[key] = value;
  }
  return args;
}

async function main(): Promise<void> {
  const args = parseCliArgs(process.argv.slice(2));
  const report = await runBridge({
    json: args.json,
    ablate: args.ablate,
    standardDir: args.standardDir,
    sdkDir: args.sdkDir,
    standardRef: args.standardRef,
  });
  const jsonText = `${JSON.stringify(report, null, 2)}\n`;
  if (args.out !== undefined) {
    const outPath = resolve(args.out);
    await mkdir(dirname(outPath), { recursive: true });
    await writeFile(outPath, jsonText);
  }
  process.stdout.write(args.json ? jsonText : `${textReport(report)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error: unknown) => {
    process.stderr.write(`C1 conformance bridge: FAIL\n${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
