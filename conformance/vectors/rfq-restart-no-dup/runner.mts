// Executes rfq-restart-no-dup vectors against the real dacs-sdk durable RFQ
// lifecycle (src/negotiate/durableRfqLifecycle{,StoreFs}.ts). Every lifecycle
// action runs in a FRESH OS process over the durable role stores, so each
// expectation is a restart-survival claim. Identity/Vet/Listing authority is
// synthetic fixture data; transport is a local file spool; the clock is fixed.
// Requires a local SDK source checkout: DACS_SDK_ROOT (default ~/dacs-sdk).
// Exit 0: every vector matched. Exit 1: at least one mismatch. Exit 2: setup error.
import { generateKeyPairSync, randomBytes, randomUUID, sign, verify } from "node:crypto";
import { mkdir, mkdtemp, open, link, unlink, rm, writeFile, readFile } from "node:fs/promises";
import { readFileSync, existsSync } from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, execFileSync } from "node:child_process";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../..");
const SDK_ROOT = resolve(process.env.DACS_SDK_ROOT ?? join(userInfo().homedir, "dacs-sdk"));
const ROLES = ["buyer", "seller"] as const;
type Role = (typeof ROLES)[number];

// --- synthetic fixture authority (labeled: nothing here is verified) -------------------
const NOW = 1_780_000_000_000;
const JOB = "01J8ME0SXKQ4T9V2RC5HJ6WX7E";
const CLAIMS: Record<Role, string> = {
  buyer: "did:demos:buyer-conformance-fixture",
  seller: "did:demos:seller-conformance-fixture",
};

function identity(ref: string) {
  return {
    bundleVersion: "1", presentedBy: ref, presentedAt: NOW - 1000,
    claims: [{ ref }], presentation: { kind: "per-claim", signatures: [{ ref, signature: "synthetic-identity-proof" }] },
  };
}

function party(role: Role) {
  return {
    identityBundle: identity(CLAIMS[role]),
    vetRecordRef: { anchor: { kind: "storage-program", locator: `stor:synthetic-${role}-vet` }, contentHash: "a".repeat(64) },
  };
}

function lifecycleInput(contentHash: (value: unknown) => string) {
  const listing = {
    dacsVersion: "1", listingVersion: 3, listingId: "conformance-rfq-restart", requiredCapabilities: ["SR-2", "SR-4"],
    seller: { identity: identity(CLAIMS.seller), displayName: "Conformance fixture seller", publicEndpoint: "https://seller.example/dacs" },
    offering: {
      title: "Conformance RFQ", description: "Restart and replay conformance fixture", category: "data.finance", tags: ["rfq"],
      deliverable: { kind: "attested-payload", payloadFormat: "application/json", verificationMethod: { kind: "self-signed" } },
    },
    buyerRequirement: { requirementVersion: "1", required: [] },
    pipeline: [{ kind: "negotiate-rfq", parameters: { maxTurns: 5, timeoutSec: 10 } }, { kind: "commit-agreement" }, { kind: "deliver-attested-payload" }],
    pricing: { kind: "negotiable", bandCenter: { amount: "10", currency: "USDC" }, minPct: 20, maxPct: 20 },
    terms: { deadlineSecAfterCommit: 600 }, validity: { notBefore: NOW - 10_000, notAfter: NOW + 1_000_000 },
    signature: { algorithm: "ed25519", signer: CLAIMS.seller, value: Buffer.alloc(64, 7).toString("base64url") },
  };
  return {
    jobId: JOB,
    verifiedListing: { disposition: "verified", listing, pin: { listingId: listing.listingId, version: listing.listingVersion, contentHash: contentHash(listing) } },
    buyer: party("buyer"), seller: party("seller"), channelId: "conformance-restart-channel-01",
  };
}

// Sync a temporary inode, then publish without overwrite: a crash before link
// leaves an ignored temporary; a retry reuses the identical durable bytes.
async function durableOnce(path: string, bytes: string, fault?: string): Promise<void> {
  const temp = `${path}.tmp-${randomUUID()}`;
  const fd = await open(temp, "wx", 0o600);
  try { await fd.writeFile(bytes); await fd.sync(); } finally { await fd.close(); }
  try {
    try {
      await link(temp, path);
      if (fault === "crash-after-publish") process.exit(86);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
  } finally { await unlink(temp); }
  if ((await readFile(path)).toString() !== bytes) throw new Error("durable byte conflict");
}

interface WorkerConfig { root: string; role: Role; action: string; amount?: string; packet?: unknown; fault?: string }

async function worker(): Promise<void> {
  let input = "";
  for await (const chunk of process.stdin) {
    input += chunk;
    if (input.length > 262_144) throw new Error("worker input too large");
  }
  const config = JSON.parse(input) as WorkerConfig;
  const dir = join(config.root, config.role);
  const sdk = await import(join(SDK_ROOT, "src/negotiate/durableRfqLifecycle.ts"));
  const { createFsDurableRfqLifecycleStore } = await import(join(SDK_ROOT, "src/negotiate/durableRfqLifecycleStoreFs.ts"));
  const { canonicalize, contentHash } = await import(join(SDK_ROOT, "src/canonical/index.ts"));

  const integrityKey = await readFile(join(dir, "integrity.key"));
  const store = await createFsDurableRfqLifecycleStore({
    dir: join(dir, "store"), role: config.role, integrityKey, lockTimeoutMs: 500, lockStaleMs: 1000, lockPollMs: 5,
  });
  integrityKey.fill(0);
  const privateKey = await readFile(join(dir, "signing.pem"));
  const publicKeys = new Map<string, Buffer>();
  for (const role of ROLES) publicKeys.set(CLAIMS[role], await readFile(join(config.root, `${role}.public.pem`)));

  const packetPath = (packet: { packetId: string }) => {
    if (!/^[0-9a-f]{64}$/.test(packet.packetId)) throw new Error("invalid packet id");
    return join(dir, "mailbox", `${packet.packetId}.json`);
  };
  const transport = {
    async publish(packet: { packetId: string }) {
      try {
        await durableOnce(packetPath(packet), canonicalize(packet), config.fault);
        return { disposition: "acknowledged" };
      } catch { return { disposition: "indeterminate", reason: "local spool write uncertain" }; }
    },
    async reconcile(packet: { packetId: string }) {
      try {
        const prior = await readFile(packetPath(packet));
        return prior.toString() === canonicalize(packet)
          ? { disposition: "acknowledged" }
          : { disposition: "indeterminate", reason: "local spool byte conflict" };
      } catch (error) {
        return (error as NodeJS.ErrnoException).code === "ENOENT"
          ? { disposition: "absent" }
          : { disposition: "indeterminate", reason: "local spool unavailable" };
      }
    },
  };
  const client = sdk.createDurableRfqLifecycleClient({
    role: config.role, store, transport,
    reserveChannelId: async (reservation: unknown) => {
      try { await durableOnce(join(dir, "reservation.json"), canonicalize(reservation)); return "pass"; }
      catch { return "indeterminate"; }
    },
    // Local Ed25519 over the SDK envelopeHash; NOT a Demos signature wire format.
    signChannelMessage: ({ envelopeHash }: { envelopeHash: string }) => sign(null, Buffer.from(envelopeHash), privateKey).toString("base64url"),
    verifyChannelMessage: ({ message, envelopeHash }: { message: { sender: string; signature: string }; envelopeHash: string }) => {
      try {
        const pub = publicKeys.get(message.sender);
        return pub && verify(null, Buffer.from(envelopeHash), pub, Buffer.from(message.signature, "base64url")) ? "pass" : "fail";
      } catch { return "fail"; }
    },
    agreementSigner: { party: CLAIMS[config.role], algorithm: "ed25519", sign: (bytes: Buffer) => sign(null, bytes, privateKey) },
    verifyAgreementContribution: ({ party, signedBytes, value }: { party: string; signedBytes: Buffer; value: string }) => {
      try {
        const pub = publicKeys.get(party);
        return pub && verify(null, signedBytes, pub, Buffer.from(value, "base64url")) ? "valid" : "invalid";
      } catch { return "invalid"; }
    },
    nowMs: () => NOW,
  });

  const proposal = (amount: string) => ({ rfqProposalVersion: "1", price: { amount, currency: "USDC" } });
  let result: { status: string; reason?: string };
  switch (config.action) {
    case "open": result = await client.open(lifecycleInput(contentHash)); break;
    case "offer": result = await client.sendOffer(JOB, proposal(config.amount ?? "9")); break;
    case "counter": result = await client.sendCounter(JOB, proposal(config.amount ?? "9.5")); break;
    case "accept": result = await client.sendAccept(JOB); break;
    case "receive": result = await client.receive(config.packet); break;
    case "resume": result = await client.resumeOutbox(JOB); break;
    case "agreement": result = await client.startAgreement(JOB); break;
    case "status": result = await client.getStatus(JOB); break;
    default: throw new Error("unknown action");
  }
  const loaded = await client.getStatus(JOB);
  const record = loaded.status === "ok" ? loaded.record : undefined;
  console.log(JSON.stringify({
    pid: process.pid, role: config.role, action: config.action, status: result.status,
    ...(result.reason ? { reason: result.reason } : {}),
    ...(record ? {
      revision: record.revision, sessionStatus: record.session.status, transcript: record.transcript,
      packets: record.outbox.map((entry: { packet: unknown }) => entry.packet),
      agreement: record.agreement?.finalized,
    } : {}),
  }));
}

interface WorkerResult {
  pid: number; status: string; reason?: string; revision?: number; sessionStatus?: string;
  transcript?: unknown[]; packets?: { packetId: string }[]; agreement?: { signatures: unknown[]; terms: { price: { amount: string; currency: string } } };
}

function runChild(config: WorkerConfig, expectedExit = 0): Promise<WorkerResult | { pid: number | undefined; exit: number }> {
  return new Promise((resolveResult, reject) => {
    const child = spawn(process.execPath, ["--import", "tsx", fileURLToPath(import.meta.url), "--worker"], {
      cwd: repoRoot,
      env: { PATH: process.env.PATH ?? "", HOME: userInfo().homedir, DACS_SDK_ROOT: SDK_ROOT },
      stdio: ["pipe", "pipe", "pipe"],
    });
    const chunks: Buffer[] = [];
    let errors = "";
    const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("worker hard deadline exceeded")); }, 30_000);
    child.stdout.on("data", (chunk) => chunks.push(chunk));
    child.stderr.on("data", (chunk) => { errors = (errors + chunk).slice(0, 4_096); });
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("close", (code) => {
      clearTimeout(timer);
      if (code !== expectedExit) return reject(new Error(`worker exit=${code}, expected ${expectedExit}: ${errors}`));
      if (expectedExit !== 0) return resolveResult({ pid: child.pid, exit: code ?? -1 });
      try { resolveResult(JSON.parse(Buffer.concat(chunks).toString("utf8"))); } catch { reject(new Error("invalid worker result")); }
    });
    child.stdin.end(JSON.stringify(config));
  });
}

async function main(): Promise<number> {
  const doc = JSON.parse(readFileSync(join(here, "vectors.json"), "utf8")) as { set: string; vectors: { name: string; expect: Record<string, unknown> }[] };
  if (!existsSync(join(SDK_ROOT, "src/negotiate/durableRfqLifecycle.ts"))) {
    console.error(`SETUP ERROR: no SDK durable RFQ lifecycle module under ${SDK_ROOT}.`);
    console.error("Set DACS_SDK_ROOT to a trusted dacs-sdk source checkout with installed dependencies.");
    return 2;
  }
  let sdkCommit = "unknown (not a git checkout)";
  try {
    sdkCommit = execFileSync("git", ["-C", SDK_ROOT, "rev-parse", "HEAD"], { encoding: "utf8", timeout: 10_000 }).trim();
  } catch { /* reported as unknown */ }
  const failures: string[] = [];
  const expectFor = (name: string) => {
    const vector = doc.vectors.find((entry) => entry.name === name);
    if (!vector) throw new Error(`vectors.json is missing vector ${name}`);
    return vector.expect;
  };
  const check = (vector: string, field: string, got: unknown, want: unknown) => {
    if (JSON.stringify(got) !== JSON.stringify(want)) failures.push(`${vector}/${field}: expected ${JSON.stringify(want)}, got ${JSON.stringify(got)}`);
  };

  const root = await mkdtemp(join(tmpdir(), "dacs-rfq-vector-"));
  const pids: (number | undefined)[] = [];
  try {
    for (const role of ROLES) {
      const dir = join(root, role);
      await mkdir(dir, { mode: 0o700 });
      await mkdir(join(dir, "mailbox"), { mode: 0o700 });
      await writeFile(join(dir, "integrity.key"), randomBytes(32), { mode: 0o600, flag: "wx" });
      const keys = generateKeyPairSync("ed25519");
      await writeFile(join(dir, "signing.pem"), keys.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600, flag: "wx" });
      await writeFile(join(root, `${role}.public.pem`), keys.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600, flag: "wx" });
    }
    const call = async (role: Role, action: string, extra: Partial<WorkerConfig> = {}) => {
      const result = (await runChild({ root, role, action, ...extra })) as WorkerResult;
      pids.push(result.pid);
      return result;
    };
    for (const role of ROLES) {
      const opened = await call(role, "open");
      if (opened.status !== "ready") throw new Error(`open(${role}) returned ${opened.status}`);
    }

    // Vector 1 — crash after durable publish, fresh process resumes the exact packet.
    const v1 = expectFor("crash-after-durable-publish-resumes-exact-packet");
    const crashed = await runChild({ root, role: "buyer", action: "offer", fault: "crash-after-publish" }, v1.crashExit as number);
    pids.push(crashed.pid);
    const resumed = await call("buyer", "resume");
    check("crash-after-durable-publish-resumes-exact-packet", "resumeStatus", resumed.status, v1.resumeStatus);
    check("crash-after-durable-publish-resumes-exact-packet", "outboxPackets", resumed.packets?.length, v1.outboxPackets);
    const offer = resumed.packets?.[0];
    if (!offer) throw new Error("no recovered offer packet; cannot continue");
    const delivered = await call("seller", "receive", { packet: offer });
    check("crash-after-durable-publish-resumes-exact-packet", "offerDelivered", delivered.status, v1.offerDelivered);

    // Vector 2 — replaying the exact packet is a duplicate with no state change.
    const v2 = expectFor("same-packet-replay-is-duplicate-no-state-change");
    const before = await call("seller", "status");
    const replay = await call("seller", "receive", { packet: offer });
    check("same-packet-replay-is-duplicate-no-state-change", "replayStatus", replay.status, v2.replayStatus);
    check("same-packet-replay-is-duplicate-no-state-change", "revisionUnchanged", replay.revision === before.revision, v2.revisionUnchanged);
    check("same-packet-replay-is-duplicate-no-state-change", "transcriptLength", replay.transcript?.length, v2.transcriptLength);

    // Vector 3 — full negotiation: exact transcript, identical dual-signed agreement.
    const v3 = expectFor("full-negotiation-exact-transcript-no-duplicates");
    const counter = await call("seller", "counter");
    await call("buyer", "receive", { packet: counter.packets?.at(-1) });
    const accept = await call("buyer", "accept");
    await call("seller", "receive", { packet: accept.packets?.at(-1) });
    const plan = await call("buyer", "agreement");
    const contribution = await call("seller", "receive", { packet: plan.packets?.at(-1) });
    await call("buyer", "receive", { packet: contribution.packets?.at(-1) });
    const buyer = await call("buyer", "status");
    const seller = await call("seller", "status");
    check("full-negotiation-exact-transcript-no-duplicates", "transcriptLength", buyer.transcript?.length, v3.transcriptLength);
    check("full-negotiation-exact-transcript-no-duplicates", "transcriptsIdentical",
      JSON.stringify(buyer.transcript) === JSON.stringify(seller.transcript), v3.transcriptsIdentical);
    check("full-negotiation-exact-transcript-no-duplicates", "agreementSignatures", buyer.agreement?.signatures.length, v3.agreementSignatures);
    check("full-negotiation-exact-transcript-no-duplicates", "agreementsIdentical",
      JSON.stringify(buyer.agreement) === JSON.stringify(seller.agreement), v3.agreementsIdentical);
    check("full-negotiation-exact-transcript-no-duplicates", "acceptedPrice", buyer.agreement?.terms.price, v3.acceptedPrice);
    if (new Set(pids).size !== pids.length) failures.push("lifecycle actions shared a process; restart semantics were not exercised");
  } catch (error) {
    failures.push(`setup/flow: ${(error as Error).message}`);
  } finally {
    await rm(root, { recursive: true, force: true });
  }

  const report = {
    set: doc.set,
    mode: "real SDK execution, synthetic fixture authority (local file-spool transport, fixed clock, no network, no testnet, no payment); one fresh OS process per lifecycle action",
    sdkRoot: SDK_ROOT,
    sdkCommit,
    vectors: doc.vectors.length,
    processes: pids.length,
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
