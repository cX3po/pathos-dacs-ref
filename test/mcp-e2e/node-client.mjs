#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const EXPECTED_PROTOCOL = '2024-11-05';
const EXPECTED_SERVER = { name: '@pathos-labs/dacs-verifier', version: '0.1.0' };
const ROOT = new URL('.', import.meta.url).pathname;
const DEFAULT_FIXTURE = resolve(ROOT, 'fixture-valid.json');
const DEFAULT_INDETERMINATE_FIXTURE = resolve(ROOT, 'fixture-indeterminate.json');
const TIMEOUT_MS = 8_000;

function parseArgs(argv) {
  const out = { server: null, fixture: DEFAULT_FIXTURE, indeterminateFixture: DEFAULT_INDETERMINATE_FIXTURE };
  for (let i = 2; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === '--server' || flag === '--fixture' || flag === '--indeterminate-fixture') {
      const value = argv[++i];
      if (!value) throw new Error(`${flag} requires a value`);
      if (flag === '--server') out.server = value;
      if (flag === '--fixture') out.fixture = value;
      if (flag === '--indeterminate-fixture') out.indeterminateFixture = value;
    } else {
      throw new Error(`unknown option ${flag}`);
    }
  }
  if (!out.server) throw new Error('--server absolute path is required');
  if (!isAbsolute(out.server)) throw new Error('--server must be an absolute path');
  if (!existsSync(out.server)) throw new Error(`server does not exist: ${out.server}`);
  return out;
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256Text(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function loadFixture(path) {
  const bytes = readFileSync(path);
  const value = JSON.parse(bytes.toString('utf8'));
  return { path, value, fileSha256: createHash('sha256').update(bytes).digest('hex'), canonicalSha256: sha256Text(canonical(value)) };
}

function withTimeout(promise, label, timeout = TIMEOUT_MS) {
  let timer;
  const expiry = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${label} timed out after ${timeout}ms`)), timeout); });
  return Promise.race([promise, expiry]).finally(() => clearTimeout(timer));
}

function textOf(result) {
  const content = result?.content;
  if (!Array.isArray(content) || content.length !== 1 || content[0]?.type !== 'text') throw new Error(`unexpected tool result content: ${JSON.stringify(result)}`);
  return content[0].text;
}

function parseVerdict(result, label) {
  if (result?.isError) throw new Error(`${label} unexpectedly returned an MCP error: ${textOf(result)}`);
  return JSON.parse(textOf(result));
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertVerdictShape(result, expectedDecision, expectedExitCode, expectedJobId) {
  assert(result && result.apiVersion === 'pathos-dacs-verifier:1', 'verdict apiVersion mismatch');
  assert(result.bundleKind === 'v1', `verdict bundleKind mismatch: ${result.bundleKind}`);
  assert(result.verdict?.decision === expectedDecision, `expected decision ${expectedDecision}, got ${result.verdict?.decision}`);
  assert(result.exitCode === expectedExitCode, `expected exitCode ${expectedExitCode}, got ${result.exitCode}`);
  assert(result.verdict?.jobId === expectedJobId, `expected jobId ${expectedJobId}, got ${result.verdict?.jobId}`);
}

function signatureStep(verdict) {
  return verdict?.steps?.find((step) => step.step === 'signatures');
}

async function waitForGone(pid) {
  if (!pid) return true;
  const until = Date.now() + 2_000;
  while (Date.now() < until) {
    try { process.kill(pid, 0); } catch (error) { if (error.code === 'ESRCH') return true; }
    await new Promise((resolveWait) => setTimeout(resolveWait, 25));
  }
  return false;
}

async function runSession(server, valid, indeterminate) {
  const stderr = [];
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [server],
    env: { PATH: process.env.PATH ?? '', DACS_VERIFIER_MCP_POLICY: 'offline-enforcing', DACS_VERIFIER_RPC: 'http://127.0.0.1:9' },
    stderr: 'pipe',
    maxBufferSize: 1_048_576,
  });
  transport.stderr?.on('data', (chunk) => stderr.push(chunk.toString()));
  let negotiatedProtocol = null;
  const originalSetProtocolVersion = transport.setProtocolVersion;
  transport.setProtocolVersion = (version) => {
    negotiatedProtocol = version;
    originalSetProtocolVersion?.call(transport, version);
  };
  const client = new Client({ name: 'dacs-verifier-node-e2e', version: '1.0.0' }, { enforceStrictCapabilities: true });
  let closed = false;
  try {
    await withTimeout(client.connect(transport, { timeout: TIMEOUT_MS }), 'initialize');
    const serverInfo = client.getServerVersion();
    assert(JSON.stringify(serverInfo) === JSON.stringify(EXPECTED_SERVER), `server identity mismatch: ${JSON.stringify(serverInfo)}`);
    assert(negotiatedProtocol === EXPECTED_PROTOCOL, `protocol mismatch: ${negotiatedProtocol}`);

    const listed = await withTimeout(client.listTools({}, { timeout: TIMEOUT_MS }), 'tools/list');
    const toolNames = listed.tools.map((tool) => tool.name).sort();
    assert(JSON.stringify(toolNames) === JSON.stringify(['verifier_info', 'verify_bundle']), `tool list mismatch: ${JSON.stringify(toolNames)}`);
    const verifyTool = listed.tools.find((tool) => tool.name === 'verify_bundle');
    assert(verifyTool?.inputSchema?.additionalProperties === false, 'verify_bundle schema is not closed');

    const info = parseVerdict(await withTimeout(client.callTool({ name: 'verifier_info', arguments: {} }, undefined, { timeout: TIMEOUT_MS }), 'verifier_info'), 'verifier_info');
    assert(info.name === EXPECTED_SERVER.name && info.version === EXPECTED_SERVER.version && info.apiVersion === 'pathos-dacs-verifier:1', `verifier_info identity mismatch: ${JSON.stringify(info)}`);
    assert(info.verificationPolicy?.name === 'offline-enforcing', `unexpected verification policy: ${JSON.stringify(info.verificationPolicy)}`);
    assert(info.verificationPolicy.fixtureMode === false && info.verificationPolicy.requireSignatures === true && info.verificationPolicy.offline === true, 'offline-enforcing policy disclosure mismatch');
    assert(info.verificationPolicy.signaturePolicy === 'v1-cryptographic-required', 'signature policy disclosure mismatch');
    assert(info.verificationPolicy.anchoringPolicy === 'two-sided-lookup-skipped', 'anchoring policy disclosure mismatch');

    const validResult = parseVerdict(await withTimeout(client.callTool({ name: 'verify_bundle', arguments: { bundle: valid.value } }, undefined, { timeout: TIMEOUT_MS }), 'valid verify_bundle'), 'valid');
    assertVerdictShape(validResult, 'pass', 0, valid.value.jobId);
    assert(signatureStep(validResult.verdict)?.outcome === 'pass', 'valid signature step did not pass');
    assert(Array.isArray(validResult.verdict.signersVerified) && validResult.verdict.signersVerified.length === 2, 'valid result did not verify two signers');
    assert(validResult.verdict.steps.some((step) => step.step === 'two-sided-anchoring' && step.outcome === 'skipped'), 'offline scope was not disclosed in valid result');

    const tampered = structuredClone(valid.value);
    tampered.jobId = `${tampered.jobId}-tampered`;
    const tamperedResult = parseVerdict(await withTimeout(client.callTool({ name: 'verify_bundle', arguments: { bundle: tampered } }, undefined, { timeout: TIMEOUT_MS }), 'tampered verify_bundle'), 'tampered');
    assertVerdictShape(tamperedResult, 'fail', 1, tampered.jobId);
    assert(signatureStep(tamperedResult.verdict)?.outcome === 'fail', 'tampered signature step did not fail');

    const indeterminateResult = parseVerdict(await withTimeout(client.callTool({ name: 'verify_bundle', arguments: { bundle: indeterminate.value } }, undefined, { timeout: TIMEOUT_MS }), 'indeterminate verify_bundle'), 'indeterminate');
    assertVerdictShape(indeterminateResult, 'indeterminate', 2, indeterminate.value.jobId);
    assert(signatureStep(indeterminateResult.verdict)?.outcome === 'pass', 'indeterminate fixture signatures did not verify');
    assert(indeterminateResult.verdict.steps.some((step) => step.step === 'attestation[0]' && step.outcome === 'indeterminate'), 'missing-evidence step was not indeterminate');

    const downgradeSignature = await withTimeout(client.callTool({ name: 'verify_bundle', arguments: { bundle: valid.value, requireSignatures: false } }, undefined, { timeout: TIMEOUT_MS }), 'requireSignatures downgrade');
    assert(downgradeSignature.isError === true && /conflicts with server policy/.test(textOf(downgradeSignature)), 'requireSignatures=false was not refused');
    const downgradeOffline = await withTimeout(client.callTool({ name: 'verify_bundle', arguments: { bundle: valid.value, offline: false } }, undefined, { timeout: TIMEOUT_MS }), 'offline downgrade');
    assert(downgradeOffline.isError === true && /conflicts with server policy/.test(textOf(downgradeOffline)), 'offline=false was not refused');
    const unknownArgument = await withTimeout(client.callTool({ name: 'verify_bundle', arguments: { bundle: valid.value, unknown: true } }, undefined, { timeout: TIMEOUT_MS }), 'unknown argument');
    assert(unknownArgument.isError === true && /unknown argument/.test(textOf(unknownArgument)), 'unknown argument was not refused');
    const infoUnknown = await withTimeout(client.callTool({ name: 'verifier_info', arguments: { unknown: true } }, undefined, { timeout: TIMEOUT_MS }), 'verifier_info unknown argument');
    assert(infoUnknown.isError === true && /unknown argument/.test(textOf(infoUnknown)), 'verifier_info unknown argument was not refused');

    return {
      serverInfo,
      protocolVersion: negotiatedProtocol,
      tools: toolNames,
      policy: info.verificationPolicy,
      verdicts: {
        valid: validResult,
        tampered: tamperedResult,
        indeterminate: indeterminateResult,
      },
      admission: { requireSignaturesFalse: 'refused', offlineFalse: 'refused', unknownArgument: 'refused', verifierInfoUnknownArgument: 'refused' },
      stderr: stderr.join('').trim(),
    };
  } finally {
    if (!closed) {
      closed = true;
      const pid = transport.pid;
      await withTimeout(client.close(), 'client cleanup').catch(() => {});
      assert(await waitForGone(pid), `server process ${pid ?? 'unknown'} did not exit after cleanup`);
    }
  }
}

async function main() {
  const args = parseArgs(process.argv);
  const valid = loadFixture(resolve(args.fixture));
  const indeterminate = loadFixture(resolve(args.indeterminateFixture));
  const first = await runSession(args.server, valid, indeterminate);
  const repeat = await runSession(args.server, valid, indeterminate);
  assert(canonical(first.verdicts.valid) === canonical(repeat.verdicts.valid), 'fresh-process valid verdict differs');
  const result = {
    client: 'node',
    sdk: '@modelcontextprotocol/sdk@1.30.0',
    server: resolve(args.server),
    fixtureSha256: { validFile: valid.fileSha256, validCanonical: valid.canonicalSha256, indeterminateFile: indeterminate.fileSha256, indeterminateCanonical: indeterminate.canonicalSha256 },
    ...first,
    freshProcessRepeat: { validVerdictMatches: true },
    runtimeAssertions: {
      networkNamespace: 'runner-enforced-bwrap-unshare-net',
      verifierPolicy: 'offline-enforcing',
      rpcSink: 'http://127.0.0.1:9',
      walletPaymentModelCalls: 'not instrumented; probe exposes no wallet, payment, or model interface',
    },
  };
  delete result.stderr;
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

main().catch((error) => {
  process.stderr.write(`node-client failed: ${error.stack ?? error}\n`);
  process.exitCode = 1;
});
