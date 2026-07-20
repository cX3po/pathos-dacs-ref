/**
 * DACS Shared Conformance Suite comparison engine (adapter protocol v1).
 *
 * The WG boundary is the subprocess protocol in ADAPTER-PROTOCOL.md. The objects consumed
 * here are runner-side clients for those subprocesses. In-process objects remain useful in
 * unit tests, but are not the cross-implementation contract.
 *
 * DACS-Standard#270 steward corrections (2026-07-20):
 *  - Blocker 1: every adapter run is given a unique runner-side identity (`runId`) that is
 *    independent of the self-reported `metadata.name`. `perAdapter` is keyed by that runId,
 *    so two adapters that self-report the SAME name can never clobber each other's result and
 *    produce a false INTEROP-AGREE. INTEROP-AGREE requires results from genuinely distinct
 *    runner-tracked adapters.
 *  - Blocker 2: independence is inferred from a *canonicalized* codebase identity, not from
 *    the raw self-reported repository string. `https://x/impl` and `https://x/impl.git` count
 *    as ONE codebase; two wrappers over one impl are NOT independent. An explicit
 *    `metadata.provenanceCodebase` (recorded steward assertion) overrides structural inference
 *    when independence cannot be established from the URL alone.
 */

function adapterName(adapter) {
  return adapter.metadata?.name ?? adapter.name ?? 'unnamed-adapter';
}

/**
 * Canonicalize a self-reported repository string to a stable codebase identity so that
 * cosmetic differences do not read as independent implementations. Normalization:
 *   - strip a leading VCS transport prefix (`git+`)
 *   - lower-case scheme + host (paths stay case-sensitive; many forges are path-sensitive)
 *   - drop credentials, default ports, query, and fragment
 *   - normalize `scp`-style `git@host:owner/repo` to `host/owner/repo`
 *   - strip a trailing `.git` and any trailing slashes
 * Returns null when no usable repository string is present.
 */
export function canonicalizeRepository(repository) {
  if (typeof repository !== 'string') return null;
  let value = repository.trim();
  if (value.length === 0) return null;

  // git+https://... / git+ssh://... — the git+ transport prefix is not identity.
  value = value.replace(/^git\+/i, '');

  // scp-like syntax: git@github.com:owner/repo(.git) — rewrite to a URL-ish form we can parse.
  const scpMatch = /^([^/@]+@)?([^/:]+):(?!\/)(.+)$/.exec(value);
  if (scpMatch && !/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
    value = `ssh://${scpMatch[2]}/${scpMatch[3]}`;
  }

  let host = '';
  let pathname = '';
  try {
    const url = new URL(value);
    host = url.host.toLowerCase(); // host includes non-default port if present
    // Drop a default port so :443/:22 do not fork identity.
    host = host.replace(/:(?:22|80|443)$/, '');
    pathname = url.pathname;
  } catch {
    // Not a URL (bare path, opaque id). Fall back to the raw string minus casing of any
    // leading scheme; treat the whole thing as an opaque codebase id.
    const bare = value.replace(/\/+$/, '').replace(/\.git$/i, '');
    return bare.toLowerCase();
  }

  pathname = pathname
    .replace(/\.git$/i, '')
    .replace(/\/+$/, ''); // trailing slashes
  if (pathname === '') pathname = '/';

  // Path case is preserved (GitHub is case-insensitive on owner/repo, but many hosts are
  // not; preserving path case is the conservative choice — it can only ever UNDER-merge,
  // never falsely merge two genuinely different codebases into one). Host is lower-cased.
  return `${host}${pathname}`;
}

/**
 * The stable codebase identity used for independence counting. An explicit
 * `metadata.provenanceCodebase` is honored first (recorded steward assertion), otherwise the
 * canonicalized repository string is used. Demo adapters and adapters with no provenance
 * contribute no codebase identity (they cannot establish independence).
 */
export function codebaseIdentity(adapter) {
  if (adapter?.metadata?.kind === 'demo') return null;
  const asserted = adapter?.metadata?.provenanceCodebase;
  if (typeof asserted === 'string' && asserted.trim().length > 0) {
    return `asserted:${asserted.trim().toLowerCase()}`;
  }
  const repository = adapter?.metadata?.repository;
  const revision = adapter?.metadata?.revision;
  // A pinned immutable revision is required for real provenance (see ADAPTER-PROTOCOL.md).
  if (!repository || !revision) return null;
  const canonical = canonicalizeRepository(repository);
  return canonical ? `repo:${canonical}` : null;
}

/**
 * Count genuinely-independent codebases among the participating runs. Participation is tracked
 * by runner-assigned runId (Blocker 1), and independence is by canonicalized codebase identity
 * (Blocker 2) — never by self-reported name or raw repository string.
 */
function independentImplementationCount(runs, participatingRunIds) {
  const codebases = new Set();
  for (const runEntry of runs) {
    if (!participatingRunIds.has(runEntry.runId)) continue;
    const identity = codebaseIdentity(runEntry.adapter);
    if (identity) codebases.add(identity);
  }
  return codebases.size;
}

/**
 * Execute every vector and classify evidence without performing specification triage.
 * `triagedSpecQuestions` is an explicit set of vector ids whose mismatch/divergence has
 * already been reviewed and assigned SPEC-QUESTION. No mismatch is promoted automatically.
 */
export async function crossRun(adapters, vectors, { triagedSpecQuestions = new Set() } = {}) {
  const matrix = [];
  const specQuestions = [];

  // Blocker 1: assign every adapter run a unique, runner-controlled identity. This is the
  // ONLY key used to track results; the self-reported metadata.name is retained purely as a
  // display label. Two adapters reporting the same name get different runIds and can never
  // overwrite one another.
  const runs = adapters.map((adapter, index) => ({
    runId: `run-${index}`,
    reportedName: adapterName(adapter),
    adapter,
  }));

  // Detect self-reported identity collisions so a report can surface them explicitly instead
  // of silently trusting a name that two different adapters both claim.
  const nameCounts = new Map();
  for (const runEntry of runs) {
    nameCounts.set(runEntry.reportedName, (nameCounts.get(runEntry.reportedName) ?? 0) + 1);
  }
  const duplicateReportedNames = [...nameCounts.entries()]
    .filter(([, count]) => count > 1)
    .map(([name]) => name);

  for (const vector of vectors) {
    const perAdapter = {};
    const participatingRunIds = new Set();

    for (const runEntry of runs) {
      const { runId, reportedName, adapter } = runEntry;
      if (typeof adapter[vector.fnName] !== 'function') {
        perAdapter[runId] = { runId, name: reportedName, status: 'ABSTAIN', outcome: null };
        continue;
      }
      const outcome = await vector.invoke(adapter);
      perAdapter[runId] = {
        runId,
        name: reportedName,
        status: outcome === vector.expected ? 'matches-expected' : 'vector-mismatch',
        outcome,
      };
      participatingRunIds.add(runId);
    }

    const participatingEntries = [...participatingRunIds].map((runId) => perAdapter[runId]);
    const outcomes = new Set(participatingEntries.map((entry) => entry.outcome));
    const vectorMismatch = participatingEntries.some((entry) => entry.outcome !== vector.expected);
    const implementationDivergence = outcomes.size > 1;
    const independentImplementations = independentImplementationCount(runs, participatingRunIds);

    let status;
    if (participatingRunIds.size === 0) status = 'ABSTAIN';
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
      participatingAdapters: participatingRunIds.size,
      independentImplementations,
      duplicateReportedNames,
      perAdapter,
    };
    matrix.push(row);
    if (triagedSpecQuestion) specQuestions.push(row);
  }

  return { matrix, specQuestions, runs: runs.map(({ runId, reportedName }) => ({ runId, reportedName })), duplicateReportedNames };
}
