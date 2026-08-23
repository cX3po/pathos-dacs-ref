/**
 * Conformance vectors for DACS §7.3.2 VP holder-binding — GAP vector #11 (VP-replay).
 * Covers: valid holder-binding, holder-proof absent, cross-session nonce replay, non-holder presenter,
 * tampered credential (issuer sig), malformed (error), issuer-unresolvable (indeterminate). Run: npx tsx run.mts
 */
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { verifyHolderBinding, pubRawFromSeed, edSign, holderSignedBytes, issuerSignedBytes, type Presentation } from './validate.js';

const DIR = fileURLToPath(new URL('.', import.meta.url)).replace(/\/$/, ''); // portable: this script's dir
if (!existsSync(`${DIR}/vectors`)) mkdirSync(`${DIR}/vectors`, { recursive: true });
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const seed = (n: number) => Buffer.alloc(32, n).toString('hex');

const SUBJECT = seed(0x51), ISSUER = seed(0x52), ATTACKER = seed(0x53);
const subjectPub = pubRawFromSeed(SUBJECT), issuerPub = pubRawFromSeed(ISSUER);
const NONCE = 'session-nonce-ABC';                 // this session
const OLD_NONCE = 'session-nonce-OLD';             // a different/earlier session

// genuine credential (issuer-signed)
const credBody = { subject: subjectPub, issuer: issuerPub, claims: { kind: 'kyb', status: 'verified' } };
const issuerSig = edSign(issuerSignedBytes(credBody), ISSUER);
const credential = { ...credBody, issuerSig };

// a valid presentation: holder (subject) signs a challenge carrying THIS session's nonce
const validChallenge = { sessionNonce: NONCE, audience: 'verifier-1' };
const base: Presentation = { credential, holderProof: { challenge: validChallenge, signature: edSign(holderSignedBytes(validChallenge), SUBJECT) } };

// issuer resolver: knows the genuine issuer, not an unknown one
const resolve = (issuer: string) => (issuer === issuerPub ? issuerPub : null);

// `sn` maps each vector to the CORE §B.8 session-nonce rule (SN-1..SN-4, PR #143) it exercises, or to the
// §7.3.2/§7.5.1 surface when it isn't an SN rule — so a second impl can DIFF SN-rule agreement (RB's ask,
// 2026-06-22: "point these at the SN rules → cross-impl validation that two impls agree on SN-1..4").
type C = { name: string; expected: 'pass' | 'fail' | 'indeterminate' | 'error'; p: Presentation; nonce: string; resolve: (i: string) => string | null; sn: string };
const m = (f: (p: Presentation) => void) => { const p = clone(base); f(p); return p; };

const cases: C[] = [
  // A matching challenge nonce is accepted. The harness supplies the expected nonce, so this proves
  // the comparison branch but not SN-1 verifier-generation provenance or SN-4 single-use state.
  { name: 'valid-holder-binding', expected: 'pass', p: base, nonce: NONCE, resolve, sn: '§7.3.2-step6' },
  // the headline: a genuine, issuer-valid credential with NO holder proof must NOT pass (issuer-genuine ≠ holder-presents)
  { name: 'issuer-genuine-but-no-holder-proof', expected: 'fail', p: m((p) => { delete p.holderProof; }), nonce: NONCE, resolve, sn: '§7.3.2-step6' },
  // SN-3 issuance binding: the REAL holder's proof from an OLD session is not the nonce issued for this jobId.
  { name: 'cross-session-nonce-replay', expected: 'fail',
    p: { credential, holderProof: { challenge: { sessionNonce: OLD_NONCE, audience: 'verifier-1' }, signature: edSign(holderSignedBytes({ sessionNonce: OLD_NONCE, audience: 'verifier-1' }), SUBJECT) } },
    nonce: NONCE, resolve, sn: 'SN-3' },
  // replay by a non-holder: attacker signs THIS session's challenge, but is not the credential subject
  { name: 'non-holder-presenter', expected: 'fail',
    p: { credential, holderProof: { challenge: validChallenge, signature: edSign(holderSignedBytes(validChallenge), ATTACKER) } },
    nonce: NONCE, resolve, sn: '§7.3.2-step6' },
  // tampered credential: claims mutated after issuer signed → issuer sig fails
  { name: 'tampered-credential', expected: 'fail', p: m((p) => { p.credential.claims = { kind: 'kyb', status: 'FORGED' }; }), nonce: NONCE, resolve, sn: '§7.3.2-step1' },
  // malformed presentation → error (verifier-side, retryable; never fail)
  { name: 'malformed-presentation', expected: 'error', p: ({ credential: { subject: subjectPub } } as unknown as Presentation), nonce: NONCE, resolve, sn: '§7.5.1-error' },
  // issuer key unresolvable → indeterminate (genuineness undecidable), holder-binding otherwise valid
  { name: 'issuer-unresolvable-indeterminate', expected: 'indeterminate', p: base, nonce: NONCE, resolve: () => null, sn: '§7.5.1-indeterminate' },
  // ── edge cases the security review demanded ──
  // No expected session nonce is available → indeterminate, MUST NOT silently pass. This is a
  // harness-availability boundary, not proof that the verifier generated the nonce under SN-1.
  { name: 'empty-expected-nonce-indeterminate', expected: 'indeterminate', p: base, nonce: '', resolve, sn: '§7.5.1-indeterminate' },
  // SN-3: challenge omits the nonce issued for this jobId (holder validly signed it) → fail.
  { name: 'challenge-omits-session-nonce', expected: 'fail',
    p: { credential, holderProof: { challenge: { audience: 'verifier-1' }, signature: edSign(holderSignedBytes({ audience: 'verifier-1' }), SUBJECT) } },
    nonce: NONCE, resolve, sn: 'SN-3' },
  // SN-3: empty challenge nonce cannot match the nonce issued for this jobId.
  { name: 'empty-challenge-nonce', expected: 'fail',
    p: { credential, holderProof: { challenge: { sessionNonce: '', audience: 'verifier-1' }, signature: edSign(holderSignedBytes({ sessionNonce: '', audience: 'verifier-1' }), SUBJECT) } },
    nonce: NONCE, resolve, sn: 'SN-3' },
  // malformed holderProof signature (not 64-byte hex) → error (verifier-side parse, not fail)
  { name: 'malformed-holderproof-sig', expected: 'error', p: m((p) => { p.holderProof!.signature = 'zz'; }), nonce: NONCE, resolve, sn: '§7.5.1-error' },
  // malformed subject key hex → error
  { name: 'malformed-subject-key', expected: 'error', p: m((p) => { p.credential.subject = 'zz'; }), nonce: NONCE, resolve, sn: '§7.5.1-error' },
  // self-issued (issuer === subject), resolvable + holder-signed → pass (issuer allow-list is scoped out;
  //   documented intentional — a self-issued VC still requires a valid holder proof to be presented)
  { name: 'self-issued-with-holder-proof', expected: 'pass',
    p: (() => { const cb = { subject: subjectPub, issuer: subjectPub, claims: { kind: 'self', status: 'asserted' } }; const cred = { ...cb, issuerSig: edSign(issuerSignedBytes(cb), SUBJECT) }; return { credential: cred, holderProof: { challenge: validChallenge, signature: edSign(holderSignedBytes(validChallenge), SUBJECT) } }; })(),
    nonce: NONCE, resolve: (i: string) => (i === subjectPub ? subjectPub : null), sn: '§7.3.2-step6' },
];

const vectors = cases.map((c) => ({ name: c.name, expected: c.expected, sn: c.sn, sessionNonce: c.nonce, presentation: c.p }));
const setHash = sha(JSON.stringify(vectors));
// SN-1..4 (CORE §B.8) coverage map so a second impl can diff agreement per rule, and so the gaps are honest.
const snTags = [...new Set(vectors.flatMap((v) => v.sn.split(',').map((s) => s.trim())))].filter((s) => s.startsWith('SN-')).sort();
const snCoverage = {
  exercised: snTags,                            // SN rules this set actually drives a verdict for
  notEnforcedHere: {
    'SN-1': 'Verifier generation and nonce provenance are not exercised: this stateless harness receives an expected nonce as input and has no generator or authenticated issuance record.',
    'SN-2': 'SN-2 entropy/native-format checks are issuer obligations. CORE explicitly does not require a verifier to re-check entropy or hex length on the presented value, and such a unilateral re-check is not a conformance divergence. These vectors therefore keep non-hex placeholders.',
    'SN-4': 'single-use consumption, bounded lifetime, and retain-until-terminal require verifier-side state and are not exercised by this stateless expected-nonce validator; see the dedicated sn4-single-use set.',
  },
  sn3Scope: 'The three mismatch/omission cases exercise only the SN-3 comparison branch while assuming the explicit expected nonce is authenticated current-job issuance state. This harness has no jobId or issue-before-presentation proof.',
  note: 'Each vector carries an `sn` tag for the rule it exercises, or the §7.3.2/§7.5.1 surface when not an SN rule. This stateless set exercises only the SN-3 comparison branch. SN-1 provenance and SN-4 state require separate stateful harnesses; SN-2 is issuer-side.',
  hashDivergence: 'Semantic verdict inputs remain identical to DACS-Standard vp-replay-v0.1 (hash 1cebf46c4b1007d29989996eef23b1ac26de534ea052e43727e8e3aa89eb9c74), but this implementation adds and retags `sn` metadata. The resulting local set hash therefore differs and the two JSON corpora are not byte-identical.',
  spec: 'CORE §B.8 SN-1..SN-4 (PR #143, closes D9/#133)',
};
writeFileSync(`${DIR}/vectors/vp-replay-v0.1.json`, JSON.stringify({ set: 'vp-replay-v0.1', spec: 'DACS §7.3.2 + CORE §B.8 (SN-1..4)', hash: setHash, count: vectors.length, snCoverage, vectors, keys: { subjectPub, issuerPub, note: 'seeds 0x51/0x52/0x53; raw ed25519' } }, null, 2));
console.log(`SN coverage: exercised ${snTags.join(',')} | SN-1 provenance out-of-scope | SN-2 issuer-side | SN-4 stateful/out-of-scope`);

let pass = 0;
console.log('\n=== DACS §7.3.2 VP holder-binding conformance vectors v0.1 (GAP #11 VP-replay) ===');
for (const c of cases) {
  const v = verifyHolderBinding(c.p, c.nonce, c.resolve);
  const ok = v.decision === c.expected;
  pass += ok ? 1 : 0;
  const fails = v.checks.filter((k) => k.ok === false).map((k) => k.id).join(',');
  const nulls = v.checks.filter((k) => k.ok === null).map((k) => k.id).join(',');
  console.log(`  [${ok ? '✓' : '✗'}] ${c.name.padEnd(36)} exp=${c.expected.padEnd(13)} got=${v.decision.padEnd(13)}${fails ? ' FAIL:' + fails : ''}${nulls ? ' INDET:' + nulls : ''}`);
}
console.log(`\nset hash: ${setHash.slice(0, 24)}…`);
console.log(`${pass}/${cases.length} vectors pass → vectors/vp-replay-v0.1.json`);
if (pass !== cases.length) process.exit(1);
