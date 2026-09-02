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

// ---- Action / CLI surface (hermetic: no checkouts needed) ----------------------------------

import { parseCliArgs } from "../../conformance/c1-bridge.mjs";

test("C1 bridge CLI parses flags as a pure function and keeps the flag-less default", () => {
  assert.deepEqual(parseCliArgs([]), { json: false, ablate: false });
  assert.deepEqual(parseCliArgs(["--json", "--ablate"]), { json: true, ablate: true });
  assert.deepEqual(
    parseCliArgs(["--standard-dir=/s", "--sdk-dir=/k", "--standard-ref=abc", "--out=out/report.json", "--json"]),
    { json: true, ablate: false, standardDir: "/s", sdkDir: "/k", standardRef: "abc", out: "out/report.json" },
  );
  assert.throws(() => parseCliArgs(["--bogus"]), /unknown argument: --bogus/);
  assert.throws(() => parseCliArgs(["--out"]), /--out requires a value/);
  assert.throws(() => parseCliArgs(["--out="]), /--out requires a value/);
  assert.throws(() => parseCliArgs(["--json=1"]), /unknown argument/);
});

type Step = { name: string; uses: string; run: string; withKeys: Map<string, string>; env: Map<string, string>; raw: string; top: string[] };

/**
 * Minimal, dependency-free reader for the two Actions YAML files in this repo. It splits the
 * document into steps (`- name:` / `- uses:` items) and, per step, collects the `run:` scalar
 * (single-line or block), the `with:` keys, and the `env:` keys, so the assertions below can
 * talk about keys and commands rather than substrings that a comment could satisfy.
 */
function readSteps(text: string): Step[] {
  const lines = text.split("\n");
  const steps: Step[] = [];
  let current: Step | undefined;
  let stepIndent = -1;
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] ?? "";
    const item = /^(\s*)- (name|uses|run):\s*(.*)$/.exec(line);
    if (item && (stepIndent === -1 || item[1]!.length <= stepIndent)) {
      stepIndent = item[1]!.length;
      current = { name: "", uses: "", run: "", withKeys: new Map(), env: new Map(), raw: "", top: [] };
      steps.push(current);
    }
    if (!current) continue;
    current.raw += `${line}\n`;
    const keyIndent = stepIndent + 2;
    const field = new RegExp(`^\\s{${keyIndent}}(?:- )?(name|uses|run|with|env|continue-on-error|if):\\s*(.*)$`).exec(line.replace(/^(\s*)- /, (m, sp: string) => `${sp}  `));
    if (!field) continue;
    const [, key, value] = field;
    if (key === "continue-on-error" || key === "if") current.top.push(`${key}: ${value}`);
    if (key === "name") current.name = value!.trim();
    if (key === "uses") current.uses = value!.trim();
    if (key === "run") {
      if (value!.trim() === "|") {
        let j = i + 1;
        const body: string[] = [];
        while (j < lines.length && (/^\s{8,}/.test(lines[j]!) || lines[j]!.trim() === "")) { body.push(lines[j]!); j += 1; }
        current.run = body.map((b) => b.trimEnd()).join("\n");
      } else current.run = value!.trim();
    }
    if (key === "with" || key === "env") {
      let j = i + 1;
      while (j < lines.length && new RegExp(`^\\s{${keyIndent + 2}}\\S`).test(lines[j]!)) {
        const kv = /^\s+([A-Za-z0-9_.-]+):\s*(.*)$/.exec(lines[j]!);
        if (kv) (key === "with" ? current.withKeys : current.env).set(kv[1]!, kv[2]!.trim());
        j += 1;
      }
    }
  }
  return steps;
}

const actionText = (): string => readFileSync(new URL("../../.github/actions/c1-bridge/action.yml", import.meta.url), "utf8");
const workflowText = (): string => readFileSync(new URL("../../.github/workflows/c1-bridge.yml", import.meta.url), "utf8");
const commandLines = (run: string): string[] => run.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));

test("C1 bridge action: inputs reach shell only through env, the bridge really runs, and the hashed file is what is uploaded", () => {
  const steps = readSteps(actionText());
  assert.ok(steps.length >= 3, `expected setup/install/run/upload steps, saw ${steps.length}`);
  for (const step of steps) {
    assert.doesNotMatch(step.run, /\$\{\{\s*(inputs|secrets)\./, `${step.name || step.uses}: expression interpolated into run:`);
    assert.deepEqual(step.top, [], `${step.name}: continue-on-error is not allowed`);
  }
  const run = steps.find((s) => s.name === "Run the C1 bridge");
  assert.ok(run, "run step present");
  const expectedEnv: Record<string, string> = {
    STANDARD_DIR: "${{ inputs.standard-dir }}", SDK_DIR: "${{ inputs.sdk-dir }}", STANDARD_REF: "${{ inputs.standard-ref }}",
    REPORT_PATH: "${{ inputs.report-path }}", ACTION_PATH: "${{ github.action_path }}",
  };
  for (const [key, value] of Object.entries(expectedEnv)) assert.equal(run.env.get(key), value, `env ${key} carries the input`);
  const cmds = commandLines(run.run);
  assert.ok(cmds.some((l) => l.startsWith("if ! npx tsx conformance/c1-bridge.mts")), "the bridge command is executed and its failure is checked");
  assert.ok(cmds.some((l) => l === 'if [ ! -s "$report" ]; then fail "the bridge finished without writing $report"; fi'), "an empty or missing report is a failure");
  assert.ok(cmds.some((l) => l.startsWith('case "$report" in *[\\*\\?\\[]*) fail ')), "glob metacharacters in the report path are a failure");
  assert.ok(cmds.some((l) => l.startsWith('safe="${RUNNER_TEMP:-')) && cmds.some((l) => l === 'report="$safe"'), "a glob-free copy is what gets hashed");
  assert.ok(cmds.some((l) => l.startsWith('sha="$(sha256sum "$report" | cut -d\' \' -f1)" || fail ')), "the report file is hashed inside fail()");
  assert.ok(cmds.some((l) => l.includes('typeof r.ok !== "boolean" || !Array.isArray(r.divergences)')), "a stub JSON is not a report");
  assert.ok(cmds.some((l) => l === 'echo "report-path=$report" >> "$GITHUB_OUTPUT"'), "the hashed absolute path is the output");
  assert.ok(cmds.some((l) => l === "exit 1"), "failure exits 1");
  assert.ok(cmds.every((l) => !l.includes("::error::") || l.startsWith('echo "::error::$1"')), "every error path goes through fail()");
  assert.doesNotMatch(actionText(), /^[ \t]*continue-on-error\s*:/m);
  assert.doesNotMatch(actionText(), /^[ \t]*if\s*:/m, "no step may be skipped with if:");
  const upload = steps.find((s) => s.uses.startsWith("actions/upload-artifact@"));
  assert.ok(upload, "upload step present");
  assert.equal(upload.withKeys.get("path"), "${{ steps.run.outputs.report-path }}");
  assert.equal(upload.withKeys.get("if-no-files-found"), "error");
  assert.equal(upload.withKeys.get("compression-level"), "0");
});

test("C1 bridge workflow: token gate runs before the private checkout, refs pin on schedule, credentials do not persist", () => {
  const text = workflowText();
  const steps = readSteps(text);
  const names = steps.map((s) => s.name || s.uses);
  const gate = steps.findIndex((s) => s.name === "Require the SDK access token");
  const sdk = steps.findIndex((s) => s.withKeys.get("repository") === "DACS-Agent-commerce/dacs-sdk");
  const standard = steps.findIndex((s) => s.withKeys.get("repository") === "DACS-Agent-commerce/DACS-Standard");
  assert.ok(gate >= 0 && sdk > gate, `token gate must precede the SDK checkout: ${names.join(" > ")}`);
  assert.ok(standard >= 0, "Standard checkout present");
  const gateStep = steps[gate]!;
  assert.equal(gateStep.env.get("DACS_SDK_TOKEN"), "${{ secrets.DACS_SDK_TOKEN }}", "token reaches the gate through env");
  const gateCmds = commandLines(gateStep.run);
  assert.ok(gateCmds.some((l) => l === 'if [ -z "$DACS_SDK_TOKEN" ]; then'), "the token gate is an executed command");
  assert.ok(gateCmds.some((l) => l === "exit 1"), "the token gate exits 1");
  assert.ok(gateCmds.some((l) => l.includes('>> "$GITHUB_STEP_SUMMARY"')), "the token gate writes the reason to the summary");
  for (const step of steps) assert.doesNotMatch(step.run, /\$\{\{\s*(inputs|secrets)\./, `${step.name}: expression in run:`);
  assert.equal(steps[standard]!.withKeys.get("ref"), `\${{ inputs.standard_ref || '${STANDARD_PIN}' }}`);
  assert.equal(steps[standard]!.withKeys.get("fetch-depth"), "0");
  assert.equal(steps[sdk]!.withKeys.get("ref"), "${{ inputs.sdk_ref || 'main' }}");
  assert.equal(steps[sdk]!.withKeys.get("token"), "${{ secrets.DACS_SDK_TOKEN }}");
  assert.equal(steps[sdk]!.withKeys.get("persist-credentials"), "false");
  assert.deepEqual(steps.filter((s) => s.withKeys.has("token")).map((s) => s.withKeys.get("repository")), ["DACS-Agent-commerce/dacs-sdk"]);
  const bridge = steps.find((s) => s.uses === "./.github/actions/c1-bridge");
  assert.ok(bridge, "workflow uses the composite action");
  assert.equal(bridge.withKeys.get("standard-ref"), "${{ inputs.standard_ref || '' }}");
  for (const step of steps) assert.deepEqual(step.top, [], `${step.name}: continue-on-error / if are not allowed`);
  assert.doesNotMatch(text, /^[ \t]*continue-on-error\s*:/m, "no continue-on-error at any level");
  assert.doesNotMatch(text, /^[ \t]*if\s*:/m, "no step or job may be skipped with if:");
  assert.match(text, /^permissions:\n  contents: read$/m);
});
