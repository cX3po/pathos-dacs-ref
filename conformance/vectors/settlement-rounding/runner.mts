// Executes settlement-rounding vectors against the real dacs-sdk price-band
// surface (src/negotiate/fixedPrice.ts). Requires a local SDK source checkout:
// DACS_SDK_ROOT=/path/to/dacs-sdk (default ~/dacs-sdk). No network, no wallet,
// no signing — this is pure negotiation-price arithmetic, honestly labeled.
// Exit 0: every vector matched. Exit 1: at least one mismatch. Exit 2: setup error.
import { readFileSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { userInfo } from "node:os";
import { execFileSync } from "node:child_process";

const here = dirname(fileURLToPath(import.meta.url));
const SDK_ROOT = resolve(process.env.DACS_SDK_ROOT ?? join(userInfo().homedir, "dacs-sdk"));

function sdkCommit(root: string): string {
  try {
    return execFileSync("git", ["-C", root, "rev-parse", "HEAD"], { encoding: "utf8", timeout: 10_000 }).trim();
  } catch {
    return "unknown (not a git checkout)";
  }
}

interface Offer { amount: string; expect: "within" | "outside" | "refused-noncanonical" }
interface Vector {
  name: string;
  cite: string;
  pricing: Record<string, unknown>;
  expect: { band?: { lower: string; upper: string }; refused?: boolean };
  offers?: Offer[];
}

async function main(): Promise<number> {
  const doc = JSON.parse(readFileSync(join(here, "vectors.json"), "utf8")) as { set: string; vectors: Vector[] };
  let sdk: Record<string, (...args: never[]) => unknown>;
  try {
    sdk = await import(pathToFileURL(join(SDK_ROOT, "src/negotiate/fixedPrice.ts")).href);
  } catch (error) {
    console.error(`SETUP ERROR: cannot load SDK price-band module from ${SDK_ROOT}: ${(error as Error).message}`);
    console.error("Set DACS_SDK_ROOT to a trusted dacs-sdk source checkout with installed dependencies.");
    return 2;
  }
  const band = sdk.negotiablePriceBand as (pricing: unknown) => { lower: string; upper: string };
  const within = sdk.isNegotiablePriceWithinBand as (amount: string, pricing: unknown) => boolean;

  const failures: string[] = [];
  let checks = 0;
  for (const vector of doc.vectors) {
    if (vector.expect.refused) {
      checks += 1;
      try {
        const got = band(vector.pricing);
        failures.push(`${vector.name}: expected refusal, got band ${JSON.stringify(got)}`);
      } catch {
        // refusal expected
      }
      continue;
    }
    const expected = vector.expect.band!;
    checks += 1;
    try {
      const got = band(vector.pricing);
      if (got.lower !== expected.lower || got.upper !== expected.upper) {
        failures.push(`${vector.name}: band mismatch — spec-derived ${JSON.stringify(expected)}, SDK ${JSON.stringify(got)}`);
        continue; // offer results against a wrong band would only repeat the same failure
      }
    } catch (error) {
      failures.push(`${vector.name}: band refused unexpectedly: ${(error as Error).message}`);
      continue;
    }
    for (const offer of vector.offers ?? []) {
      checks += 1;
      try {
        const result = within(offer.amount, vector.pricing);
        const want = offer.expect === "within" ? true : offer.expect === "outside" ? false : "refusal";
        if (want === "refusal") {
          failures.push(`${vector.name}/${offer.amount}: expected noncanonical refusal, got ${result}`);
        } else if (result !== want) {
          failures.push(`${vector.name}/${offer.amount}: expected ${offer.expect}, got ${result}`);
        }
      } catch (error) {
        if (offer.expect !== "refused-noncanonical") {
          failures.push(`${vector.name}/${offer.amount}: unexpected refusal: ${(error as Error).message}`);
        }
      }
    }
  }

  const report = {
    set: doc.set,
    mode: "real SDK execution, local fixtures (no network, no testnet, no wallet)",
    sdkRoot: SDK_ROOT,
    sdkCommit: sdkCommit(SDK_ROOT),
    vectors: doc.vectors.length,
    checks,
    failures,
  };
  console.log(JSON.stringify(report, null, 2));
  return failures.length === 0 ? 0 : 1;
}

process.exit(await main());
