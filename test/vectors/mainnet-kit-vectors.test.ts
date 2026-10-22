// Offline structural checks for the Mainnet Readiness Kit vector families
// (conformance/vectors/{settlement-rounding,spend-cap-restart,rfq-restart-no-dup}).
// The checks live in conformance/vectors/validate-offline.mjs — a plain-Node,
// zero-dependency validator a recipient can run without npm install — and this
// CI test asserts them. Executing the vectors against the SDK is each family's
// runner.mts (requires DACS_SDK_ROOT).
import { test } from "node:test";
import assert from "node:assert/strict";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
// @ts-expect-error — plain-JS module without type declarations, by design
import { validate, FAMILIES } from "../../conformance/vectors/validate-offline.mjs";

const vectorsRoot = join(dirname(fileURLToPath(import.meta.url)), "../../conformance/vectors");

test("mainnet-kit vector families pass the offline structural validation", () => {
  assert.equal((FAMILIES as string[]).length, 3);
  const failures = validate(vectorsRoot) as string[];
  assert.deepEqual(failures, []);
});
