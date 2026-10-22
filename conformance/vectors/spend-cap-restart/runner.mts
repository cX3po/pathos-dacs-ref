// Executes spend-cap-restart vectors against the real dacs-sdk wallet spend
// authority (src/rails/walletSpendAuthority{,Fs}.ts). Every step runs in a
// FRESH OS process sharing only the durable state directory and its integrity
// key, so each expectation is a restart-survival claim. Requires a local SDK
// source checkout: DACS_SDK_ROOT (default ~/dacs-sdk). Everything monetary is
// synthetic: fixture balances, no payment rail, nothing signs or spends.
// Exit 0: every vector matched. Exit 1: at least one mismatch. Exit 2: setup error.
import { randomBytes } from "node:crypto";
import { mkdtemp, writeFile, rm, readFile } from "node:fs/promises";
import { readFileSync, existsSync } from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, execFileSync } from "node:child_process";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../..");
const SDK_ROOT = resolve(process.env.DACS_SDK_ROOT ?? join(userInfo().homedir, "dacs-sdk"));

interface Step { reserve: { id: string; amount: string }; expect: { status: string; reason?: string } }
interface Vector {
  name: string;
  cite: string;
  policy: { maximumCumulativeDebit: string; minimumReserve: string; maximumPerOrderDebit: string };
  balance: string;
  steps: Step[];
}

function fullPolicy(vector: Vector) {
  return {
    policyVersion: "1",
    policyId: `conformance-${vector.name}`,
    wallet: "synthetic-wallet",
    chainId: "synthetic:conformance-fixture",
    maximumConcurrentEffects: 8,
    maximumRetainedReservations: 16,
    assets: [{
      asset: "SIM-DEM",
      maximumPerOrderDebit: vector.policy.maximumPerOrderDebit,
      maximumNetworkFeeDebit: "0",
      minimumReserve: vector.policy.minimumReserve,
      rollingWindowMs: 86_400_000,
      maximumRollingEffects: 8,
      maximumRollingDebit: "1000",
      maximumCumulativeDebit: vector.policy.maximumCumulativeDebit,
      maximumCounterpartyDebit: "1000",
    }],
  };
}

function reservation(id: string, amount: string) {
  return {
    reservationVersion: "1",
    reservationId: id,
    jobId: `job-${id}`,
    phaseIndex: 0,
    phase: "conformance-fixture-only",
    agreementHash: "a".repeat(64),
    settlementBindingHash: "b".repeat(64),
    railId: "synthetic-no-rail",
    railDefinitionHash: "c".repeat(64),
    wallet: "synthetic-wallet",
    chainId: "synthetic:conformance-fixture",
    payee: "synthetic-counterparty",
    finality: { model: "fixture-no-chain-finality" },
    debits: [{ asset: "SIM-DEM", purpose: "service", expectedAmount: amount, maximumAmount: amount }],
  };
}

async function worker(): Promise<void> {
  let input = "";
  for await (const chunk of process.stdin) {
    input += chunk;
    if (input.length > 16_384) throw new Error("worker input too large");
  }
  const config = JSON.parse(input) as { root: string; vector: Vector; step: Step };
  const key = await readFile(join(config.root, "integrity.key"));
  if (key.length !== 32) throw new Error("invalid integrity key length");
  const authorityModule = await import(join(SDK_ROOT, "src/rails/walletSpendAuthority.ts"));
  const fsModule = await import(join(SDK_ROOT, "src/rails/walletSpendAuthorityFs.ts"));
  const store = await fsModule.createFsWalletSpendStateStoreV1({ dir: join(config.root, "state"), integrityKey: key });
  key.fill(0);
  const authority = authorityModule.createWalletSpendAuthorityV1(fullPolicy(config.vector), {
    store,
    readBalance: async () => config.vector.balance,
    authenticateRecovery: async () => false, // no recovery authority is installed; always refuse
    owner: `conformance-process-${process.pid}`,
  });
  const claim = await authority.reserve(reservation(config.step.reserve.id, config.step.reserve.amount));
  console.log(JSON.stringify({ pid: process.pid, status: claim.status, ...(claim.status === "denied" ? { reason: claim.reason } : {}) }));
}

function runStep(root: string, vector: Vector, step: Step): Promise<{ pid: number; status: string; reason?: string }> {
  return new Promise((resolveResult, reject) => {
    const child = spawn(process.execPath, ["--import", "tsx", fileURLToPath(import.meta.url), "--worker"], {
      cwd: repoRoot,
      env: { PATH: process.env.PATH ?? "", HOME: userInfo().homedir, DACS_SDK_ROOT: SDK_ROOT },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let output = "";
    let errors = "";
    const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("worker hard deadline exceeded")); }, 30_000);
    child.stdout.on("data", (chunk) => { output += chunk; if (output.length > 65_536) child.kill("SIGKILL"); });
    child.stderr.on("data", (chunk) => { errors = (errors + chunk).slice(0, 4_096); });
    child.on("error", (error) => { clearTimeout(timer); reject(error); });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) return reject(new Error(`worker failed (${code}): ${errors}`));
      try { resolveResult(JSON.parse(output)); } catch { reject(new Error("invalid worker result")); }
    });
    child.stdin.end(JSON.stringify({ root, vector, step }));
  });
}

async function main(): Promise<number> {
  const doc = JSON.parse(readFileSync(join(here, "vectors.json"), "utf8")) as { set: string; vectors: Vector[] };
  if (!existsSync(join(SDK_ROOT, "src/rails/walletSpendAuthority.ts"))) {
    console.error(`SETUP ERROR: no SDK wallet spend-authority module under ${SDK_ROOT}.`);
    console.error("Set DACS_SDK_ROOT to a trusted dacs-sdk source checkout with installed dependencies.");
    return 2;
  }
  let sdkCommit = "unknown (not a git checkout)";
  try {
    sdkCommit = execFileSync("git", ["-C", SDK_ROOT, "rev-parse", "HEAD"], { encoding: "utf8", timeout: 10_000 }).trim();
  } catch { /* reported as unknown */ }

  const failures: string[] = [];
  const processes: { vector: string; pids: number[] }[] = [];
  for (const vector of doc.vectors) {
    const root = await mkdtemp(join(tmpdir(), "dacs-spend-vector-"));
    const pids: number[] = [];
    try {
      await writeFile(join(root, "integrity.key"), randomBytes(32), { mode: 0o600, flag: "wx" });
      for (const [index, step] of vector.steps.entries()) {
        const result = await runStep(root, vector, step);
        pids.push(result.pid);
        if (result.status !== step.expect.status || (step.expect.reason !== undefined && result.reason !== step.expect.reason)) {
          failures.push(`${vector.name}/step${index}: expected ${JSON.stringify(step.expect)}, got ${JSON.stringify({ status: result.status, reason: result.reason })}`);
          break;
        }
      }
      if (new Set(pids).size !== pids.length) {
        failures.push(`${vector.name}: steps shared a process; restart semantics were not exercised`);
      }
    } catch (error) {
      failures.push(`${vector.name}: ${(error as Error).message}`);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
    processes.push({ vector: vector.name, pids });
  }

  const report = {
    set: doc.set,
    mode: "real SDK execution, synthetic fixtures (fixture balances, no payment rail, no network, no testnet); one fresh OS process per step",
    sdkRoot: SDK_ROOT,
    sdkCommit,
    vectors: doc.vectors.length,
    steps: processes.reduce((n, p) => n + p.pids.length, 0),
    failures,
  };
  console.log(JSON.stringify(report, null, 2));
  return failures.length === 0 ? 0 : 1;
}

if (process.argv[2] === "--worker") {
  try {
    await worker();
  } catch (error) {
    console.error((error as Error).message);
    process.exit(1);
  }
} else {
  process.exit(await main());
}
