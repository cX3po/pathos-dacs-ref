/**
 * DACS Shared Conformance Suite — adapter contract (v0).
 *
 * An IMPLEMENTATION participates by exporting an object of this shape. Every function is
 * PURE: deterministic, no network, no keys held. Omit a function to ABSTAIN from its family
 * (the suite records abstain, never "disagree"). See ADAPTER.md for the normative-ish spec
 * of each function and the result semantics.
 *
 * @typedef {Object} DacsAdapter
 * @property {string}  name                                  // e.g. "pathos-dacs-ref"
 * @property {(value:object)=>{hex:string}}         [canonicalize]         // F1 — RFC 8785 JCS bytes (hex)
 * @property {(artifact:object)=>{hex:string}}      [signedScopeHash]      // F2 — sha256 over signed scope
 * @property {(value:string)=>("ACCEPT"|"REJECT")}  [signatureValueVerdict]// F3 — CORE SIG-6
 * @property {(bundle:object)=>{decision:("accept"|"reject"|"indeterminate")}} [verifyBundle] // F4 — DACS-5 §10.4
 * @property {(msg:Uint8Array,sep:string,priv:Uint8Array,intermediateHash?:Uint8Array)=>{hex:string}} [domainSepSign]   // F5 (optional)
 * @property {(msg:Uint8Array,sep:string,sig:Uint8Array,pub:Uint8Array,intermediateHash?:Uint8Array)=>boolean}          [domainSepVerify] // F5 (optional)
 */

/**
 * The WIRED reference adapter ("pathos-dacs-ref") lives in `./reference-adapter.mjs`, not
 * here — this file stays the reviewable CONTRACT (the shape + the comparison engine), the
 * reference adapter is one IMPLEMENTATION of that contract, same as any other adapter that
 * registers with `crossRun()`.
 */
export { referenceAdapter } from './reference-adapter.mjs';

/**
 * A normalised seed-corpus vector, as produced by `./seed-corpus.mjs::loadSeedCorpus()`.
 * `invoke` never throws: it calls `adapter[fnName]` and normalises the result (or a thrown
 * error) to a comparable string. That keeps `crossRun` itself family-agnostic — it never
 * needs to know what a vector's raw shape looks like, only whether the adapter's normalised
 * outcome equals `expected`.
 *
 * @typedef {Object} SeedVector
 * @property {string} id
 * @property {string} family        // e.g. "canonical-accept", "sig-value-encoding"
 * @property {string} fnName        // the DacsAdapter method this vector exercises
 * @property {string} description
 * @property {string} expected      // the vector's declared-correct normalised outcome
 * @property {(adapter:DacsAdapter)=>string} invoke
 */

/**
 * Run every vector through every registered adapter and apply the ADAPTER.md result
 * semantics:
 *
 *   | adapters vs expected      | adapters vs each other | outcome       |
 *   |----------------------------|-------------------------|---------------|
 *   | all match expected         | agree                   | PASS          |
 *   | all differ from expected   | agree with each other   | SPEC-QUESTION |
 *   | —                           | disagree                | SPEC-QUESTION |
 *   | adapter has no function    | —                        | ABSTAIN (per-adapter, never a disagreement) |
 *
 * NEVER emits "implementation X is non-conformant" — only PASS / SPEC-QUESTION / ABSTAIN,
 * with the full per-adapter outcome attached so a SPEC-QUESTION row is ready to file
 * upstream as evidence, not a verdict.
 *
 * @param {DacsAdapter[]} adapters
 * @param {SeedVector[]} vectors
 * @returns {{matrix: object[], specQuestions: object[]}}
 */
export function crossRun(adapters, vectors) {
  const matrix = [];
  const specQuestions = [];

  for (const v of vectors) {
    const perAdapter = {};
    const participating = [];

    for (const a of adapters) {
      if (typeof a[v.fnName] !== 'function') {
        perAdapter[a.name] = { status: 'ABSTAIN', outcome: null };
        continue;
      }
      const outcome = v.invoke(a);
      perAdapter[a.name] = { status: null, outcome };
      participating.push(a.name);
    }

    let verdict;
    if (participating.length === 0) {
      verdict = 'ABSTAIN';
    } else {
      const outcomes = new Set(participating.map((n) => perAdapter[n].outcome));
      const allMatchExpected = outcomes.size === 1 && outcomes.has(v.expected);
      verdict = allMatchExpected ? 'PASS' : 'SPEC-QUESTION';
      for (const n of participating) {
        perAdapter[n].status = perAdapter[n].outcome === v.expected ? 'matches-expected' : 'diverges';
      }
    }

    const row = {
      id: v.id, family: v.family, fnName: v.fnName, description: v.description,
      expected: v.expected, verdict, perAdapter,
    };
    matrix.push(row);
    if (verdict === 'SPEC-QUESTION') specQuestions.push(row);
  }

  return { matrix, specQuestions };
}
