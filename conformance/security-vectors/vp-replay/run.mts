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

type C = { name: string; expected: 'pass' | 'fail' | 'indeterminate' | 'error'; p: Presentation; nonce: string; resolve: (i: string) => string | null };
const m = (f: (p: Presentation) => void) => { const p = clone(base); f(p); return p; };

const cases: C[] = [
  { name: 'valid-holder-binding', expected: 'pass', p: base, nonce: NONCE, resolve },
  // the headline: a genuine, issuer-valid credential with NO holder proof must NOT pass (issuer-genuine ≠ holder-presents)
  { name: 'issuer-genuine-but-no-holder-proof', expected: 'fail', p: m((p) => { delete p.holderProof; }), nonce: NONCE, resolve },
  // cross-session replay: the REAL holder's proof from an OLD session re-presented now
  { name: 'cross-session-nonce-replay', expected: 'fail',
    p: { credential, holderProof: { challenge: { sessionNonce: OLD_NONCE, audience: 'verifier-1' }, signature: edSign(holderSignedBytes({ sessionNonce: OLD_NONCE, audience: 'verifier-1' }), SUBJECT) } },
    nonce: NONCE, resolve },
  // replay by a non-holder: attacker signs THIS session's challenge, but is not the credential subject
  { name: 'non-holder-presenter', expected: 'fail',
    p: { credential, holderProof: { challenge: validChallenge, signature: edSign(holderSignedBytes(validChallenge), ATTACKER) } },
    nonce: NONCE, resolve },
  // tampered credential: claims mutated after issuer signed → issuer sig fails
  { name: 'tampered-credential', expected: 'fail', p: m((p) => { p.credential.claims = { kind: 'kyb', status: 'FORGED' }; }), nonce: NONCE, resolve },
  // malformed presentation → error (verifier-side, retryable; never fail)
  { name: 'malformed-presentation', expected: 'error', p: ({ credential: { subject: subjectPub } } as unknown as Presentation), nonce: NONCE, resolve },
  // issuer key unresolvable → indeterminate (genuineness undecidable), holder-binding otherwise valid
  { name: 'issuer-unresolvable-indeterminate', expected: 'indeterminate', p: base, nonce: NONCE, resolve: () => null },
  // ── edge cases the security review demanded ──
  // verifier handed NO session nonce to bind against → indeterminate, MUST NOT silently pass
  { name: 'empty-expected-nonce-indeterminate', expected: 'indeterminate', p: base, nonce: '', resolve },
  // challenge omits sessionNonce entirely (holder validly signed it) → fail (the SIWD-note bypass, closed)
  { name: 'challenge-omits-session-nonce', expected: 'fail',
    p: { credential, holderProof: { challenge: { audience: 'verifier-1' }, signature: edSign(holderSignedBytes({ audience: 'verifier-1' }), SUBJECT) } },
    nonce: NONCE, resolve },
  // empty-string challenge nonce → fail (a vacuous nonce must not clear the guard)
  { name: 'empty-challenge-nonce', expected: 'fail',
    p: { credential, holderProof: { challenge: { sessionNonce: '', audience: 'verifier-1' }, signature: edSign(holderSignedBytes({ sessionNonce: '', audience: 'verifier-1' }), SUBJECT) } },
    nonce: NONCE, resolve },
  // malformed holderProof signature (not 64-byte hex) → error (verifier-side parse, not fail)
  { name: 'malformed-holderproof-sig', expected: 'error', p: m((p) => { p.holderProof!.signature = 'zz'; }), nonce: NONCE, resolve },
  // malformed subject key hex → error
  { name: 'malformed-subject-key', expected: 'error', p: m((p) => { p.credential.subject = 'zz'; }), nonce: NONCE, resolve },
  // self-issued (issuer === subject), resolvable + holder-signed → pass (issuer allow-list is scoped out;
  //   documented intentional — a self-issued VC still requires a valid holder proof to be presented)
  { name: 'self-issued-with-holder-proof', expected: 'pass',
    p: (() => { const cb = { subject: subjectPub, issuer: subjectPub, claims: { kind: 'self', status: 'asserted' } }; const cred = { ...cb, issuerSig: edSign(issuerSignedBytes(cb), SUBJECT) }; return { credential: cred, holderProof: { challenge: validChallenge, signature: edSign(holderSignedBytes(validChallenge), SUBJECT) } }; })(),
    nonce: NONCE, resolve: (i: string) => (i === subjectPub ? subjectPub : null) },
];

const vectors = cases.map((c) => ({ name: c.name, expected: c.expected, sessionNonce: c.nonce, presentation: c.p }));
const setHash = sha(JSON.stringify(vectors));
writeFileSync(`${DIR}/vectors/vp-replay-v0.1.json`, JSON.stringify({ set: 'vp-replay-v0.1', spec: 'DACS §7.3.2', hash: setHash, count: vectors.length, vectors, keys: { subjectPub, issuerPub, note: 'seeds 0x51/0x52/0x53; raw ed25519' } }, null, 2));

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
