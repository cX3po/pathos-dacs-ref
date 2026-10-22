import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { userInfo } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';

const HERE = dirname(fileURLToPath(import.meta.url));
export const SDK_ROOT = resolve(process.env.DACS_SDK_ROOT || join(userInfo().homedir, 'dacs-sdk'));
const load = path => import(pathToFileURL(join(SDK_ROOT, 'src', path)));
const { buildTwoSidedBundle } = await load('agent/twoSidedBundle.ts');
const { verifyBundleCopy } = await load('agent/bundleCopyValidity.ts');
const { deriveReputationWithValidation } = await load('agent/reputationDerivation.ts');
const { privateKeyFromSeed, publicKeyFromSeed, rawPublicKey, ed25519Verify, publicKeyFromRaw } = await load('crypto/index.ts');
export const TIME = 1792627200000;
const h = c => c.repeat(64);
function party(name, bundleHash) {
  // Public, deterministic fixture material only. No wallet or real signing identity.
  const seed = createHash('sha256').update(`FAULT-THEATER-SYNTHETIC-NEVER-FUND:${name}`).digest();
  const raw = rawPublicKey(publicKeyFromSeed(seed));
  return { primaryClaim: `demos:0x${Buffer.from(raw).toString('hex')}`, bundleHash, signer: privateKeyFromSeed(seed) };
}
const buyer = party('buyer', h('d')), seller = party('seller', h('e'));
export const CLAIMS = Object.freeze({ buyer: buyer.primaryClaim, seller: seller.primaryClaim });
const keys = new Map([buyer, seller].map(p => [p.primaryClaim, Uint8Array.from(Buffer.from(p.primaryClaim.slice(8), 'hex'))]));
export const deps = {
  resolvePublicKey: async claim => keys.get(claim) || null,
  verify: (bytes, sig, pub) => ed25519Verify(bytes, sig, publicKeyFromRaw(pub)),
};
export function facts(jobId, outcome = 'completed', swapped = false) {
  return { jobId, outcome, ...(outcome === 'completed' ? {} : { faultedParty: 'buyer' }),
    listingRef: { listingId: 'synthetic-fault-theater', version: 1, contentHash: h('a') },
    agreementRef: { anchor: { kind: 'storage-program', locator: 'synthetic-agreement-not-anchored' }, contentHash: h('b') },
    phaseSummary: [{ index: 0, kind: 'pay-dem', outcome: 'ok', txRefs: [{ kind: 'demos', txHash: h('f'), blockNumber: 5 }] }],
    vetRecords: [], settlementEvidence: [{ anchor: { kind: 'storage-program', locator: 'synthetic-evidence-not-anchored' }, contentHash: h('c') }],
    recipeRegistryVersion: 1, railRegistryVersion: 1, finalisedAt: TIME,
    buyer: swapped ? seller : buyer, seller: swapped ? buyer : seller };
}
export async function fixtures() {
  return {
    completed: await buildTwoSidedBundle(facts('synthetic-completed')),
    selfAbort: await buildTwoSidedBundle(facts('synthetic-self-abort', 'aborted-by-self')),
    relabelled: await buildTwoSidedBundle(facts('synthetic-relabelled', 'aborted-by-self', true)),
  };
}
export const validity = (bundle, role, cryptoDeps = deps) => verifyBundleCopy(bundle, role, cryptoDeps);
export async function score(bundles, roleAuthority, copyAbsence = () => 'indeterminate') {
  const roleDeps = typeof roleAuthority === 'function'
    ? { resolvePartyRole: roleAuthority }
    : roleAuthority?.trustBundlePartyRoles === true
      ? { trustBundlePartyRoles: true }
      : { resolvePartyRole: () => undefined };
  return deriveReputationWithValidation(CLAIMS.buyer, bundles,
    { windowStart: TIME - 1, windowEnd: TIME + 1, computedAt: TIME + 1 }, {
      validate: async bundle => (await validity(bundle, bundle.anchoredByRole)).valid,
      ...roleDeps, copyAbsence,
    });
}
export function mutations(bundle) {
  const result = spawnSync(process.env.PYTHON || 'python3', [join(HERE, 'mutations.py')], {
    input: JSON.stringify(bundle), encoding: 'utf8', timeout: 10000, maxBuffer: 1024 * 1024,
    cwd: HERE,
  });
  if (result.error || result.status !== 0) throw Error('Mutation corpus failed or timed out');
  const output = JSON.parse(result.stdout);
  assert.equal(output.names.length, 5);
  assert.deepEqual(Object.keys(output.mutations), output.names);
  return output.mutations;
}
const externalRole = ({ jobId, partyPrimaryClaim }) =>
  ['synthetic-self-abort', 'synthetic-relabelled'].includes(jobId) && partyPrimaryClaim === CLAIMS.buyer ? 'buyer' : undefined;
export const rejectionReasons = Object.freeze({
  'finality-removed': /^not an attestation bundle$/,
  'chain-identity-replaced': /^not an attestation bundle$/,
  'content-changed': /^faultedParty is not permitted for outcome and anchoredByRole$/,
  'vet-pass-forged': /^signature by demos:0x[0-9a-f]{64} failed verification$/,
  'role-signature-broken': /^signature by demos:0x[0-9a-f]{64} failed verification$/,
});
export async function gallery() {
  const signed = await fixtures();
  const rows = [];
  for (const [name, pair] of Object.entries(signed)) {
    for (const role of ['buyer', 'seller']) {
      const result = await validity(pair[`${role}Copy`], role);
      assert.equal(result.valid, true, `${name}/${role}: ${result.reason}`);
      rows.push({ name: `${name}/${role}`, expected: 'valid', result });
    }
  }
  for (const [name, bundle] of Object.entries(mutations(signed.completed.buyerCopy))) {
    const result = await validity(bundle, 'buyer');
    assert.equal(result.valid, false, name);
    assert.match(result.reason, rejectionReasons[name], name);
    rows.push({ name, expected: 'invalid', result });
  }
  const original = await score([signed.selfAbort.buyerCopy, signed.selfAbort.sellerCopy], externalRole);
  const authenticated = await score([signed.relabelled.buyerCopy, signed.relabelled.sellerCopy], externalRole);
  // Deliberately unsafe: SDK's compatibility path trusts bundle-local role labels.
  const untrusted = await score([signed.relabelled.buyerCopy, signed.relabelled.sellerCopy], { trustBundlePartyRoles: true });
  const unknown = await score([signed.relabelled.buyerCopy, signed.relabelled.sellerCopy], () => undefined);
  assert.equal(original.metrics.counterpartyFaultRate, 0);
  assert.equal(authenticated.metrics.counterpartyFaultRate, 0);
  assert.equal(untrusted.metrics.counterpartyFaultRate, 1);
  assert.equal(unknown.bundleCount, 0);
  assert.equal(unknown.metrics.counterpartyFaultRate, null);
  const git = spawnSync('git', ['-C', SDK_ROOT, 'rev-parse', 'HEAD'], { encoding: 'utf8', timeout: 5000 });
  if (git.error || git.status !== 0) throw Error('Cannot identify SDK source');
  return { mode: 'offline-synthetic', trust: 'Synthetic pinned keys and independent per-job role map; synthetic authoritative absence when invoked. Copy signatures only: no identity, agreement, evidence resolution, chain, lifecycle or finality verification.',
    sdkCommit: git.stdout.trim(), claims: CLAIMS, signed, rows,
    comparison: { original, authenticated, untrusted, unknown } };
}
export function html(report) {
  const escape = value => String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  return `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>Fault Theater — synthetic local gallery</title><style>body{font:18px system-ui;max-width:960px;margin:2rem auto;padding:1rem;background:#101720;color:#e6edf3}td,th{text-align:left;padding:.6rem;border-bottom:1px solid #506070}pre{white-space:pre-wrap;overflow-wrap:anywhere}summary{cursor:pointer}</style><h1>Fault Theater</h1><p>Offline synthetic fixtures. No live-chain claim.</p><p>${escape(report.trust)}</p><p>Signed role labels are producer assertions. The independent role map keeps a self-abort from becoming counterparty fault.</p><table><tr><th>Scenario</th><th>Counterparty fault rate</th><th>Jobs admitted</th></tr>${Object.entries(report.comparison).map(([name, r]) => `<tr><td>${escape(name)}</td><td>${escape(r.metrics.counterpartyFaultRate)}</td><td>${r.bundleCount}</td></tr>`).join('')}</table><h2>Copy validation and tampering</h2><table>${report.rows.map(r => `<tr><td>${escape(r.name)}</td><td>${r.result.valid ? 'valid' : 'invalid'}</td><td>${escape(r.result.reason || 'Ed25519 signatures verified')}</td></tr>`).join('')}</table><details><summary>Signed fixtures and full local report</summary><pre>${escape(JSON.stringify(report, null, 2))}</pre></details>`;
}
async function main() {
  const args = process.argv.slice(2);
  if (args.length > 1 || (args[0] && args[0] !== '--generate')) throw Error('Usage: bun main.mjs [--generate]');
  const report = await gallery();
  if (args[0] === '--generate') {
    // Exclusive writes avoid destroying an earlier result; reruns normally print JSON.
    await writeFile(join(HERE, 'fixtures.json'), JSON.stringify(report.signed, null, 2) + '\n', { flag: 'wx' });
    await writeFile(join(HERE, 'gallery.html'), html(report), { flag: 'wx' });
  }
  console.log(JSON.stringify(report, null, 2));
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
