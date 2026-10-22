// Zero-dependency offline validation of the Mainnet Readiness Kit vector
// families. Runs with plain Node (no npm install, no dacs-sdk checkout, no
// network): node conformance/vectors/validate-offline.mjs
// Exit 0: every structural check passed. Exit 1: failures (each printed).
// The CI test (test/vectors/mainnet-kit-vectors.test.ts) asserts on the same
// checks by importing validate() from this file.
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

export const FAMILIES = ["settlement-rounding", "spend-cap-restart", "rfq-restart-no-dup"];

// CORE §B.2 rule CD-1, as a recogniser derived from the quoted clause text:
// minimal-digit decimal, no leading zeros (single 0 before the point allowed),
// no trailing zeros after the point, '.' separator only, no sign, no exponent.
const CD1 = /^(0|[1-9][0-9]*)(\.[0-9]*[1-9])?$/;

const DENIAL_REASONS = new Set(["cumulative-limit", "insufficient-reserve", "per-order-limit", "rolling-limit",
  "counterparty-limit", "network-fee-limit", "concurrency-limit", "retention-limit"]);

/** Validate every family under vectorsRoot; returns a list of failure strings (empty = pass). */
export function validate(vectorsRoot) {
  const failures = [];
  const fail = (message) => failures.push(message);
  for (const family of FAMILIES) {
    let doc;
    try {
      doc = JSON.parse(readFileSync(join(vectorsRoot, family, "vectors.json"), "utf8"));
    } catch (error) {
      fail(`${family}: cannot read vectors.json: ${error.message}`);
      continue;
    }
    if (!/^[a-z-]+-v\d+\.\d+$/.test(doc.set ?? "")) fail(`${family}: set name malformed`);
    if (doc.spec?.standard !== "DACS-Agent-commerce/DACS-Standard") fail(`${family}: spec.standard mismatch`);
    if (!/^[0-9a-f]{40}$/.test(doc.spec?.revision ?? "")) fail(`${family}: spec.revision is not a 40-hex commit`);
    if (!doc.spec?.clauses || Object.keys(doc.spec.clauses).length < 1) fail(`${family}: no quoted clause`);
    const vectors = doc.vectors ?? [];
    if (vectors.length < 3) fail(`${family}: fewer than three vectors`);
    const names = vectors.map((vector) => vector.name);
    if (new Set(names).size !== names.length) fail(`${family}: duplicate vector names`);
    if (!existsSync(join(vectorsRoot, family, "runner.mts"))) fail(`${family}: runner.mts missing`);
    for (const vector of vectors) {
      if (!vector.cite || vector.cite.length < 20) fail(`${family}/${vector.name}: missing spec citation`);
      const expectations = vector.expect ? [vector.expect] : (vector.steps ?? []).map((step) => step.expect);
      if (expectations.length < 1 || !expectations.every((expected) => expected && Object.keys(expected).length >= 1)) {
        fail(`${family}/${vector.name}: no expected outcome`);
      }
    }
    if (family === "settlement-rounding") {
      for (const vector of vectors) {
        const band = vector.expect?.band;
        if (band) {
          if (!CD1.test(band.lower)) fail(`${family}/${vector.name}: expected lower bound not CD-1 canonical`);
          if (!CD1.test(band.upper)) fail(`${family}/${vector.name}: expected upper bound not CD-1 canonical`);
        } else if (vector.expect?.refused !== true) {
          fail(`${family}/${vector.name}: needs a band or an explicit refusal`);
        }
        for (const offer of vector.offers ?? []) {
          if (!["within", "outside", "refused-noncanonical", "refused-zero"].includes(offer.expect)) {
            fail(`${family}/${vector.name}/${offer.amount}: unknown offer expectation`);
          } else if (offer.expect === "refused-noncanonical") {
            if (CD1.test(offer.amount)) fail(`${family}/${vector.name}/${offer.amount}: noncanonical refusal must violate CD-1`);
          } else if (offer.expect === "refused-zero") {
            if (offer.amount !== "0") fail(`${family}/${vector.name}/${offer.amount}: refused-zero is exactly "0"`);
          } else if (!CD1.test(offer.amount) || offer.amount === "0") {
            fail(`${family}/${vector.name}/${offer.amount}: compared offers must be nonzero CD-1 canonical`);
          }
        }
      }
    }
    if (family === "spend-cap-restart") {
      for (const vector of vectors) {
        const steps = vector.steps ?? [];
        if (steps.length < 1) fail(`${family}/${vector.name}: no steps`);
        for (const step of steps) {
          if (!["reserved", "denied"].includes(step.expect?.status)) fail(`${family}/${vector.name}: unknown status`);
          if (step.expect?.status === "denied" && !DENIAL_REASONS.has(step.expect?.reason)) {
            fail(`${family}/${vector.name}: denial must name a declared reason`);
          }
        }
      }
    }
  }
  return failures;
}

if (process.argv[1]?.endsWith("validate-offline.mjs")) {
  const failures = validate(dirname(fileURLToPath(import.meta.url)));
  for (const failure of failures) console.error(`FAIL: ${failure}`);
  console.log(JSON.stringify({ families: FAMILIES.length, failures: failures.length }));
  process.exit(failures.length === 0 ? 0 : 1);
}
