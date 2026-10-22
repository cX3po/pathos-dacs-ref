// Offline structural checks for the Mainnet Readiness Kit vector families
// (conformance/vectors/{settlement-rounding,spend-cap-restart,rfq-restart-no-dup}).
// These run in CI without a dacs-sdk checkout; executing the vectors against
// the SDK is each family's runner.mts (requires DACS_SDK_ROOT).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "../..");
const families = ["settlement-rounding", "spend-cap-restart", "rfq-restart-no-dup"];

// CORE §B.2 rule CD-1, as a recogniser derived from the quoted clause text:
// minimal-digit decimal, no leading zeros (single 0 before the point allowed),
// no trailing zeros after the point, '.' separator only, no sign, no exponent.
const CD1 = /^(0|[1-9][0-9]*)(\.[0-9]*[1-9])?$/;

interface VectorDoc {
  set: string;
  spec: { standard: string; revision: string; clauses: Record<string, string> };
  vectors: { name: string; cite: string; expect: Record<string, unknown>; offers?: { amount: string; expect: string }[] }[];
}

function load(family: string): VectorDoc {
  return JSON.parse(readFileSync(join(root, "conformance/vectors", family, "vectors.json"), "utf8")) as VectorDoc;
}

for (const family of families) {
  test(`${family}: vectors.json structure, citations, and runner presence`, () => {
    const doc = load(family);
    assert.match(doc.set, /^[a-z-]+-v\d+\.\d+$/);
    assert.equal(doc.spec.standard, "DACS-Agent-commerce/DACS-Standard");
    assert.match(doc.spec.revision, /^[0-9a-f]{40}$/);
    assert.ok(Object.keys(doc.spec.clauses).length >= 1, "at least one quoted clause");
    assert.ok(doc.vectors.length >= 3, "at least three vectors");
    const names = doc.vectors.map((vector) => vector.name);
    assert.equal(new Set(names).size, names.length, "vector names are unique");
    for (const vector of doc.vectors) {
      assert.ok(vector.cite.length >= 20, `${vector.name}: carries a spec citation`);
      const steps = (vector as { steps?: { expect: Record<string, unknown> }[] }).steps;
      const expectations = vector.expect ? [vector.expect] : (steps ?? []).map((step) => step.expect);
      assert.ok(expectations.length >= 1 && expectations.every((expected) => Object.keys(expected).length >= 1),
        `${vector.name}: has an expected outcome`);
    }
    assert.ok(existsSync(join(root, "conformance/vectors", family, "runner.mts")), "runner.mts exists");
  });
}

test("settlement-rounding: expected bands and offer amounts respect CD-1 where required", () => {
  const doc = load("settlement-rounding");
  for (const vector of doc.vectors) {
    const band = vector.expect.band as { lower: string; upper: string } | undefined;
    if (band) {
      assert.match(band.lower, CD1, `${vector.name}: expected lower bound is CD-1 canonical`);
      assert.match(band.upper, CD1, `${vector.name}: expected upper bound is CD-1 canonical`);
    } else {
      assert.equal(vector.expect.refused, true, `${vector.name}: either a band or an explicit refusal`);
    }
    for (const offer of vector.offers ?? []) {
      assert.ok(["within", "outside", "refused-noncanonical"].includes(offer.expect), `${vector.name}/${offer.amount}: known offer expectation`);
      if (offer.expect === "refused-noncanonical") {
        assert.ok(!CD1.test(offer.amount) || offer.amount === "0", `${vector.name}/${offer.amount}: a refused offer must actually violate CD-1 (or be zero)`);
      } else {
        assert.match(offer.amount, CD1, `${vector.name}/${offer.amount}: a compared offer must be CD-1 canonical`);
        assert.notEqual(offer.amount, "0", `${vector.name}/${offer.amount}: zero is never comparable`);
      }
    }
  }
});

test("spend-cap-restart: steps carry statuses from the SDK's declared reason set", () => {
  const doc = load("spend-cap-restart");
  const reasons = new Set(["cumulative-limit", "insufficient-reserve", "per-order-limit", "rolling-limit", "counterparty-limit", "network-fee-limit", "concurrency-limit", "retention-limit"]);
  for (const vector of doc.vectors) {
    const steps = (vector as unknown as { steps: { expect: { status: string; reason?: string } }[] }).steps;
    assert.ok(steps.length >= 1, `${vector.name}: has steps`);
    for (const step of steps) {
      assert.ok(["reserved", "denied"].includes(step.expect.status), `${vector.name}: known status`);
      if (step.expect.status === "denied") {
        assert.ok(step.expect.reason !== undefined && reasons.has(step.expect.reason), `${vector.name}: denial names a declared reason`);
      }
    }
  }
});
