/**
 * DACS Shared Conformance Suite comparison engine (adapter protocol v1).
 *
 * The WG boundary is the subprocess protocol in ADAPTER-PROTOCOL.md. The objects consumed
 * here are runner-side clients for those subprocesses. In-process objects remain useful in
 * unit tests, but are not the cross-implementation contract.
 */

function adapterName(adapter) {
  return adapter.metadata?.name ?? adapter.name ?? 'unnamed-adapter';
}

function independentImplementationCount(adapters, names) {
  const repositories = new Set();
  for (const adapter of adapters) {
    if (!names.includes(adapterName(adapter))) continue;
    const repository = adapter.metadata?.repository;
    if (repository && adapter.metadata?.revision && adapter.metadata?.kind !== 'demo') {
      repositories.add(repository);
    }
  }
  return repositories.size;
}

/**
 * Execute every vector and classify evidence without performing specification triage.
 * `triagedSpecQuestions` is an explicit set of vector ids whose mismatch/divergence has
 * already been reviewed and assigned SPEC-QUESTION. No mismatch is promoted automatically.
 */
export async function crossRun(adapters, vectors, { triagedSpecQuestions = new Set() } = {}) {
  const matrix = [];
  const specQuestions = [];

  for (const vector of vectors) {
    const perAdapter = {};
    const participating = [];

    for (const adapter of adapters) {
      const name = adapterName(adapter);
      if (typeof adapter[vector.fnName] !== 'function') {
        perAdapter[name] = { status: 'ABSTAIN', outcome: null };
        continue;
      }
      const outcome = await vector.invoke(adapter);
      perAdapter[name] = {
        status: outcome === vector.expected ? 'matches-expected' : 'vector-mismatch',
        outcome,
      };
      participating.push(name);
    }

    const outcomes = new Set(participating.map((name) => perAdapter[name].outcome));
    const vectorMismatch = participating.some((name) => perAdapter[name].outcome !== vector.expected);
    const implementationDivergence = outcomes.size > 1;
    const independentImplementations = independentImplementationCount(adapters, participating);

    let status;
    if (participating.length === 0) status = 'ABSTAIN';
    else if (implementationDivergence) status = 'IMPLEMENTATION-DIVERGENCE';
    else if (vectorMismatch) status = 'VECTOR-MISMATCH';
    else if (independentImplementations >= 2) status = 'INTEROP-AGREE';
    else status = 'SELF-CHECK';

    const resultCategories = [];
    if (vectorMismatch) resultCategories.push('vector-mismatch');
    if (implementationDivergence) resultCategories.push('implementation-divergence');
    const triagedSpecQuestion = triagedSpecQuestions.has(vector.id)
      && (vectorMismatch || implementationDivergence);
    if (triagedSpecQuestion) resultCategories.push('spec-question');

    const row = {
      id: vector.id,
      family: vector.family,
      fnName: vector.fnName,
      description: vector.description,
      expected: vector.expected,
      status,
      resultCategories,
      triage: triagedSpecQuestion ? 'SPEC-QUESTION' : 'UNTRIAGED',
      participatingAdapters: participating.length,
      independentImplementations,
      perAdapter,
    };
    matrix.push(row);
    if (triagedSpecQuestion) specQuestions.push(row);
  }

  return { matrix, specQuestions };
}
