import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { runBridge, STANDARD_PIN, type BridgeReport } from "../../conformance/c1-bridge.mjs";

const standardDir = process.env.DACS_STANDARD_DIR;
const sdkDir = process.env.DACS_SDK_DIR;
const skip = !standardDir || !sdkDir
  ? "C1 bridge skipped: set both DACS_STANDARD_DIR and DACS_SDK_DIR to the local shipped-source checkouts"
  : false;

let reportPromise: Promise<BridgeReport> | undefined;
const report = (): Promise<BridgeReport> => {
  assert(standardDir && sdkDir);
  reportPromise ??= runBridge({ standardDir, sdkDir, ablate: true });
  return reportPromise;
};

test("C1 bridge pins Standard and SDK to the shipped spine", { skip }, async () => {
  const result = await report();
  assert.equal(result.pins.standardResolved, STANDARD_PIN);
  assert.equal(result.pins.sdkStandardPin, STANDARD_PIN);
});

test("C1 bridge reproduces and verifies the Standard golden signature", { skip }, async () => {
  const result = await report();
  const golden = spawnSync("git", ["-C", standardDir!, "show", `${STANDARD_PIN}:conformance/vectors/golden.json`], { encoding: "utf8" });
  assert.equal(golden.status, 0, golden.stderr);
  const standardSignature = JSON.parse(golden.stdout).signing.signature;
  assert.equal(result.golden.signatureReproduced, true);
  assert.equal(result.golden.verified, true);
  assert.deepEqual(Buffer.from(String(result.golden.signature), "base64url"), Buffer.from(standardSignature, "base64url"));
  assert.match(String(result.golden.contentHash), /^[0-9a-f]{64}$/);
});

test("C1 bridge locks the pinned trace and execution boundary", { skip }, async () => {
  const result = await report();
  assert.equal(result.walkthrough.canonicalTraceSha256, "f6f403984df5dfa98d5b2f51779e551a039ddada4b3b18bf2e67fed0fd31c845");
  const notes = result.manifest.notes as Record<string, unknown>;
  const executed = notes.executed as string[];
  const notExecuted = notes.notExecuted as Record<string, unknown>;
  for (const area of ["dispute", "disclosure"]) {
    assert(area in notExecuted, `${area} must be reported as not executed`);
    assert(!executed.includes(area), `${area} must not be reported as executed`);
  }
});

test("C1 bridge counts ablations only for successful baselines", { skip }, async () => {
  const result = await report();
  const guards = new Set(result.ablations.filter((row) => row.passed === true).map((row) => String(row.guard)));
  for (const expected of [
    "golden-signature",
    "SIG-2",
    "canonical-content-hash",
    "bundleConsistency",
    "deriveReputation",
  ]) assert(guards.has(expected), `missing successful ablation: ${expected}`);
  for (const kind of result.walkthrough.artifactKinds as string[]) {
    assert(guards.has(`walkthrough-signature:${kind}`), `missing signature ablation for ${kind}`);
  }
  assert(![...guards].some((guard) => guard.startsWith("verifySettlementEvidence:")));
  assert(![...guards].some((guard) => guard.startsWith("verifyBundleCore")));
});

test("C1 bridge reports the two executed incompatibility divergences", { skip }, async () => {
  const result = await report();
  assert.equal(result.ok, false);
  assert.deepEqual(result.divergences.map((row) => row.field), ["phaseIndex", "jobId"]);
  const phaseIndex = result.divergences[0]!;
  for (const probe of phaseIndex.probes as Array<Record<string, unknown>>) {
    assert.equal(probe.withField, false);
    assert.equal(probe.withoutField, true);
  }
  const jobId = result.divergences[1]!;
  const probes = jobId.probes as Record<string, unknown>;
  assert.equal(probes.withStandardJobId, false);
  assert.equal(probes.withCrockfordUlid, true);
});

test("emitted implementation manifest validates against the pinned Standard schema", { skip }, async () => {
  await report();
  const schema = spawnSync("git", ["-C", standardDir!, "show", `${STANDARD_PIN}:conformance/implementation-manifest.schema.json`], { encoding: "utf8" });
  assert.equal(schema.status, 0, schema.stderr);
  const manifest = readFileSync("conformance/implementation-manifests/pathos-dacs-ref.json", "utf8");
  const validation = spawnSync("python3", ["-c", [
    "import base64, json, sys, jsonschema",
    "payload=json.loads(base64.b64decode(sys.argv[1]))",
    "validator=jsonschema.Draft202012Validator(payload['schema'], format_checker=jsonschema.FormatChecker())",
    "errors=sorted(validator.iter_errors(payload['manifest']), key=lambda e: list(e.path))",
    "print('\\n'.join(f\"{list(e.path)}: {e.message}\" for e in errors))",
    "raise SystemExit(1 if errors else 0)",
  ].join("; "), Buffer.from(JSON.stringify({ schema: JSON.parse(schema.stdout), manifest: JSON.parse(manifest) })).toString("base64")], { encoding: "utf8" });
  assert.equal(validation.status, 0, validation.stdout || validation.stderr);
});
