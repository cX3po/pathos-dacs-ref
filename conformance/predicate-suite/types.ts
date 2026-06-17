/**
 * dacs_conformance — predicate-suite shared contracts.
 *
 * A DEFENSIVE conformance harness: it proves the DACS verifier correctly ACCEPTS valid
 * inputs and REJECTS inputs that violate exactly one verification predicate. Pure,
 * deterministic, NO LLM / NO API / NO network at run time — every fixture is built from
 * fixed seeds, salts and timestamps so the corpus is reproducible byte-for-byte.
 *
 * Naming is deliberately neutral: "conformance", "negative-case", "expected-reject".
 */

/** A verifier verdict, normalised to the two terminal states this harness asserts on. */
export type Decision = 'ACCEPT' | 'REJECT';

/** One enumerated conformance case. */
export interface ConformanceCase {
  /** Stable unique name: `<family>/<predicate>`. */
  name: string;
  /** Which verifier family this case exercises. */
  family: string;
  /**
   * The predicate this case targets. For the positive case this is `valid`; for a
   * negative case it is the single predicate the input is built to violate.
   */
  predicate: string;
  /** The verdict the verifier MUST return for this input. */
  expected: Decision;
  /** Human-readable note on why this verdict is expected (the predicate, for negatives). */
  reason: string;
  /** Family-specific, JSON-serialisable input the family's `run()` consumes. */
  input: unknown;
}

/** A verifier surface the harness can enumerate cases for and run inputs through. */
export interface Family {
  /** Family / set name (also the golden-file basename). */
  name: string;
  /** Deterministic enumeration: one valid case + N exactly-one-violation negative cases. */
  buildCases(): ConformanceCase[];
  /** Run one case input through the REAL verifier predicate; never throws. */
  run(input: unknown): { decision: Decision; detail: string };
}
