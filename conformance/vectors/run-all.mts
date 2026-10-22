// Runs the three DACS conformance vector families in sequence:
// settlement-rounding, spend-cap-restart, rfq-restart-no-dup.
// Requires DACS_SDK_ROOT (default ~/dacs-sdk) — a local dacs-sdk source
// checkout with installed dependencies. No network, no testnet, no payment.
// Exit 0 only when every family's runner exits 0.
import { spawnSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const families = ["settlement-rounding", "spend-cap-restart", "rfq-restart-no-dup"];

let failed = false;
for (const family of families) {
  console.log(`\n=== ${family} ===`);
  const result = spawnSync(process.execPath, ["--import", "tsx", join(here, family, "runner.mts")], {
    stdio: "inherit",
    cwd: join(here, "../.."),
    timeout: 600_000,
  });
  if (result.status !== 0) {
    failed = true;
    console.error(`${family}: FAILED (exit ${result.status ?? "signal"})`);
  }
}
process.exit(failed ? 1 : 0);
