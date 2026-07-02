/**
 * MULTI-IMPL DACS CONVERGENCE HARNESS — the referee layer.
 *
 * Runs a shared corpus of AttestationBundles through every registered implementation ADAPTER and reports
 * where the impls AGREE. Offered to the ecosystem non-territorially: independent DACS impls converge HERE
 * rather than each building a private, parallel runner. Peers are validated AGAINST, not graded.
 *
 *   PRIMARY   = canonical bundle-hash agreement. KEY-FREE, impl-agnostic — every adapter independently
 *               computes the §10.4.1 / R5-1 canonical bundle signed-scope hash. Same hash ⇒ same
 *               canonicalization ⇒ the cleanest convergence proof (no keys, no signatures, no identity).
 *
 *   SECONDARY = decision agreement, for portable-resolvable bundles only. Cross-impl decision divergence
 *               is usually a claim/key-resolution CONVENTION (self-describing `cci:<hex>` vs resolvable
 *               `did:demos:*`), not a spec gap — so it is contextualized, not graded.
 *
 * Standalone & portable: corpus paths resolve via import.meta.url (no machine-specific paths). Add an
 * impl by implementing ConvergenceAdapter (see ./adapter.ts) and registering it in ADAPTERS below.
 *
 * Run: npx tsx conformance/security-vectors/convergence-harness/harness.mts
 */
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import type { Bundle, ConvergenceAdapter } from './adapter.js';
import { pathosAdapter } from './adapters/pathos.js';
import { dacsVerifyAdapter } from './adapters/dacs-verify.js';
// To add an external impl (e.g. dacs-verify), implement ConvergenceAdapter in ./adapters/<name>.ts and
// register it here. The template is a non-functional stub, so it stays commented out by default:
// import { externalTemplateAdapter } from './adapters/external-template.js';

// ── Registered adapters ────────────────────────────────────────────────────────────────────────────
const ADAPTERS: ConvergenceAdapter[] = [
  pathosAdapter,
  dacsVerifyAdapter,
  // externalTemplateAdapter,   // ← uncomment once wired to a real impl
];

const HERE = dirname(fileURLToPath(import.meta.url));
const CORPUS_DIR = join(HERE, 'corpus');

/**
 * A bundle is "portable-resolvable" iff EVERY signer/party claim carries a trailing 64-hex ed25519 key
 * (e.g. `cci:<hex>`) that ANY impl can resolve without an impl-native identity resolver. Opaque
 * `did:demos:*` fixtures are NOT portable here — decision comparison is not attempted for them (their
 * native resolver belongs to the owning impl); only hash convergence is compared.
 */
function portableResolvable(b: Bundle): boolean {
  try {
    const sigs = (b.signatures as { party?: string }[] | undefined) ?? [];
    const parties = (b.parties as { primaryClaim?: string }[] | undefined) ?? [];
    const claims: string[] = [
      ...sigs.map((s) => s.party),
      ...parties.map((p) => p.primaryClaim),
    ].filter((c): c is string => Boolean(c));
    return claims.length > 0 && claims.every((c) => /(?:^|:)(?:0x)?[0-9a-fA-F]{64}$/.test(c));
  } catch {
    return false;
  }
}

// ── Load corpus ─────────────────────────────────────────────────────────────────────────────────────
const corpus = readdirSync(CORPUS_DIR)
  .filter((f) => f.endsWith('.json'))
  .sort()
  .map((file) => {
    const bundle = JSON.parse(readFileSync(join(CORPUS_DIR, file), 'utf8')) as Bundle;
    return { name: file.replace(/\.json$/, ''), bundle, portable: portableResolvable(bundle) };
  });

// Normalize each impl's native decision enum to verified-or-not for cross-comparison.
const isVerified = (d: string) => d === 'accept' || d === 'pass';

// ── Run every adapter over every bundle ───────────────────────────────────────────────────────────
const rows = corpus.map((c) => {
  const results = ADAPTERS.map((a) => ({ name: a.name, ...a.verify(c.bundle) }));
  // PRIMARY: all non-empty hashes equal ⇒ canonical-hash agreement.
  const hashes = results.map((r) => r.hash);
  const haveHashes = hashes.filter(Boolean);
  const hashAgree = haveHashes.length === results.length && new Set(haveHashes).size === 1;
  // SECONDARY: only for portable-resolvable bundles, compare verified-or-not across impls.
  let decisionAgree: boolean | null = null;
  if (c.portable) {
    const verdicts = results.map((r) => isVerified(r.decision));
    decisionAgree = new Set(verdicts).size === 1;
  }
  return { ...c, results, hashAgree, decisionAgree };
});

const total = rows.length;
const single = ADAPTERS.length === 1;
const hashAgreeCount = rows.filter((r) => r.hashAgree).length;
const portableRows = rows.filter((r) => r.portable);
const decisionAgreeCount = portableRows.filter((r) => r.decisionAgree).length;

const short = (h: string) => (h ? h.slice(0, 12) + '…' : '—');
const date = new Date().toISOString().slice(0, 10);
const adapterNames = ADAPTERS.map((a) => a.name).join(' · ');

// ── Build report ────────────────────────────────────────────────────────────────────────────────────
const md = [
  '# DACS multi-impl convergence report',
  '',
  `_Generated by the convergence harness. Registered impls: ${adapterNames}. Date: ${date}._`,
  '',
  'Where independent DACS implementations agree on a shared bundle corpus. Offered to the ecosystem —',
  'peers are validated against, not graded. The PRIMARY metric is canonical bundle-hash convergence',
  '(the canonicalization layer: key-free, impl-agnostic). Decision agreement is secondary and is only',
  'compared for portable-resolvable bundles (see fairness note).',
  ...(single
    ? [
        '',
        '> **Note:** only one adapter is registered, so this run is a SELF-REPORT — every "AGREE" cell is',
        '> trivially true (one impl always agrees with itself). It becomes a real convergence matrix once a',
        '> second adapter is registered. The pathos hash + decision columns below are nonetheless the real,',
        '> reproducible values another impl can target.',
      ]
    : []),
  '',
  `## Canonical bundle-hash convergence (PRIMARY — canonicalization layer): ${hashAgreeCount}/${total}`,
  '',
  '_Every impl computes the same §10.4.1 / R5-1 canonical bundle hash. Needs no keys → cleanest convergence proof._',
  '',
  `| bundle | portable? | ${ADAPTERS.map((a) => a.name + ' hash').join(' | ')} | AGREE |`,
  `|---|---|${ADAPTERS.map(() => '---').join('|')}|---|`,
  ...rows.map(
    (r) =>
      `| ${r.name} | ${r.portable ? 'yes' : 'no (did:* native resolver)'} | ` +
      `${r.results.map((x) => short(x.hash)).join(' | ')} | ${r.hashAgree ? '✅' : '❌'} |`,
  ),
  '',
  `## Decision agreement (SECONDARY — portable-resolvable bundles only): ${decisionAgreeCount}/${portableRows.length}`,
  '',
  '**Fairness note:** decisions are compared ONLY for bundles whose claims carry a self-describing key any',
  'impl can resolve. Opaque `did:demos:*` fixtures are natively resolvable by the impl that owns them, not by',
  'the portable harness — so their decision is **not evaluated here**. An `n.e.` cell is a HARNESS RESOLVER',
  'LIMITATION, NOT an impl failure on its own fixtures. Hash convergence still holds for those rows.',
  '',
  `| bundle | ${ADAPTERS.map((a) => a.name + ' decision').join(' | ')} | compared? | note |`,
  `|---|${ADAPTERS.map(() => '---').join('|')}|---|---|`,
  ...rows.map((r) => {
    if (!r.portable) {
      return (
        `| ${r.name} | ${r.results.map(() => 'n.e.').join(' | ')} | no | ` +
        'native did:* resolver required — not evaluated by portable harness; hash convergence still holds |'
      );
    }
    const note = single ? 'self-report (one impl)' : r.decisionAgree ? 'agree' : 'DIVERGENCE — investigate';
    return `| ${r.name} | ${r.results.map((x) => x.decision).join(' | ')} | yes | ${note} |`;
  }),
  '',
  '## Interop conventions to align (alignment items, not bugs)',
  '1. **Claim / key resolution.** Self-describing `cci:<hex>` vs resolvable `did:demos:*`. A bundle',
  '   cross-verifies on DECISION only if both impls can resolve the signer key. Hash agreement holds',
  '   regardless (canonical form needs no keys). Alignment target: agree a portable test-fixture claim',
  '   convention so decisions cross-verify, not just hashes.',
  '2. **Signature encoding.** base64 vs base64url for the bundle signature `value` field. Lenient decoders',
  '   bridge it; a strict one would not. Alignment target: pin one encoding.',
  '',
  '## Honest scope',
  ...(single
    ? ['- Canonical hash values are real, reproducible pathos outputs for this corpus; register a second adapter',
       '  to MEASURE cross-impl hash agreement (with one adapter this is a self-report, not a convergence claim).']
    : [`- Canonical hash agreement (${hashAgreeCount}/${total}) is the strong, key-free convergence result:`,
       '  independent impls compute the SAME §10.4.1 / R5-1 canonical bundle hash. This is the load-bearing claim.']),
  '- Decision cross-verification depends on the claim-resolution convention above; where keys resolve,',
  '  decisions agree.',
  '- Covers the §10.4 bundle surface only. Dispute/disclosure and the vet-recipe surface are follow-on',
  '  convergence targets.',
].join('\n');

const reportMd = join(HERE, 'report.md');
const reportJson = join(HERE, 'report.json');
writeFileSync(reportMd, md + '\n');
writeFileSync(
  reportJson,
  JSON.stringify(
    {
      metric: 'canonicalization-convergence',
      date,
      impls: ADAPTERS.map((a) => a.name),
      singleAdapterSelfReport: single,
      hashAgreeCount,
      total,
      decisionAgreeCount,
      portableCount: portableRows.length,
      rows: rows.map((r) => ({
        name: r.name,
        portable: r.portable,
        hashAgree: r.hashAgree,
        decisionAgree: r.decisionAgree,
        results: r.results,
      })),
    },
    null,
    2,
  ) + '\n',
);

// ── Console summary ─────────────────────────────────────────────────────────────────────────────────
console.log('\n=== DACS multi-impl convergence ===');
console.log(`registered impls: ${adapterNames}${single ? '  (single adapter → SELF-REPORT)' : ''}`);
for (const r of rows) {
  const decs = r.portable
    ? r.results.map((x) => `${x.name}=${x.decision}`).join(' ')
    : '(decision not evaluated — native did:* resolver)';
  console.log(`  ${r.hashAgree ? '✅' : '❌'} hash  ${r.name.padEnd(34)} ${decs}`);
  for (const x of r.results) {
    if (x.error) console.log(`        ⚠ ${x.name}: ${x.error}`);
  }
}
console.log(`\nCanonical-hash convergence: ${hashAgreeCount}/${total}`);
console.log(`Decision agreement (portable-resolvable only): ${decisionAgreeCount}/${portableRows.length}`);
console.log(`report → ${reportMd}`);

if (hashAgreeCount !== total) {
  console.log('\n⚠️ canonical-hash divergence — investigate before relying on it.');
  process.exit(1);
}
console.log(
  single
    ? '\n✅ pathos adapter produced a real hash + decision for every corpus bundle (self-report).'
    : '\n✅ canonical form converges across all registered impls in the corpus.',
);
