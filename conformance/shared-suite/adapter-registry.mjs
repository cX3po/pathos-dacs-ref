/**
 * DACS shared-suite adapter registry (DACS-Standard#270, Blocker 3).
 *
 * Turns declarative adapter specs (from CLI flags or a config file) into launched, handshaked
 * runner-side clients over the `dacs-adapter/1` JSONL subprocess protocol. Every spec is
 * launched independently; a spec that fails to launch/handshake (crash, timeout, output flood,
 * bad metadata) is recorded as an UNAVAILABLE adapter — fail-closed — instead of aborting the
 * whole cross-run. UNAVAILABLE adapters expose no operations, so they ABSTAIN on every vector
 * and can never contribute a silent pass or a false INTEROP-AGREE.
 *
 * OUT OF SCOPE (Blocker 4, still open): this registry provides the multi-adapter INVOCATION
 * path and preserves declared provenance, but it does NOT ship a second genuine independent
 * implementation adapter, nor a signed/pinned adapter manifest. Two independent real adapters
 * plus a manifest pin remain required before any INTEROP-AGREE is real cross-implementation
 * evidence. Registering N copies of the reference adapter is still a SELF-CHECK by design
 * (see adapter-contract.mjs codebaseIdentity()).
 */
import {
  DEFAULT_ADAPTER_MAX_OUTPUT_BYTES,
  DEFAULT_ADAPTER_TIMEOUT_MS,
  startAdapterProcess,
} from './adapter-process-client.mjs';

/**
 * Minimal POSIX-ish shell-word tokenizer for `--adapter "<command>"`. Handles single/double
 * quotes and backslash escapes; deliberately does NOT interpret globs, env vars, pipes, or
 * redirection — an adapter command is argv, not a shell script.
 */
export function tokenizeCommand(input) {
  if (Array.isArray(input)) return input.slice();
  if (typeof input !== 'string') throw new Error('adapter command must be a string or string[]');
  const tokens = [];
  let current = '';
  let quote = null;
  let hasToken = false;
  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    if (quote) {
      if (ch === '\\' && quote === '"' && i + 1 < input.length) { current += input[++i]; continue; }
      if (ch === quote) { quote = null; continue; }
      current += ch;
      continue;
    }
    if (ch === '"' || ch === "'") { quote = ch; hasToken = true; continue; }
    if (ch === '\\' && i + 1 < input.length) { current += input[++i]; hasToken = true; continue; }
    if (/\s/.test(ch)) {
      if (hasToken) { tokens.push(current); current = ''; hasToken = false; }
      continue;
    }
    current += ch;
    hasToken = true;
  }
  if (quote) throw new Error(`unbalanced ${quote} quote in adapter command: ${input}`);
  if (hasToken) tokens.push(current);
  if (tokens.length === 0) throw new Error('adapter command is empty');
  return tokens;
}

/**
 * Normalize one adapter spec into `{ command: string[], provenanceCodebase?, timeoutMs?,
 * maxOutputBytes?, cwd? }`.
 */
export function normalizeAdapterSpec(spec) {
  const raw = typeof spec === 'string' || Array.isArray(spec) ? { command: spec } : { ...spec };
  const command = tokenizeCommand(raw.command);
  const normalized = { command };
  if (raw.provenanceCodebase != null) normalized.provenanceCodebase = String(raw.provenanceCodebase);
  if (raw.cwd != null) normalized.cwd = String(raw.cwd);
  if (raw.timeoutMs != null) {
    const t = Number(raw.timeoutMs);
    if (!Number.isFinite(t) || t <= 0) throw new Error(`invalid timeoutMs: ${raw.timeoutMs}`);
    normalized.timeoutMs = t;
  }
  if (raw.maxOutputBytes != null) {
    const b = Number(raw.maxOutputBytes);
    if (!Number.isFinite(b) || b <= 0) throw new Error(`invalid maxOutputBytes: ${raw.maxOutputBytes}`);
    normalized.maxOutputBytes = b;
  }
  return normalized;
}

/**
 * An UNAVAILABLE adapter stand-in. It carries the declared provenance for the report but
 * advertises NO operations, so crossRun() records ABSTAIN for every vector (fail-closed).
 */
function unavailableAdapter(spec, error) {
  return {
    name: `unavailable:${spec.command.join(' ')}`,
    metadata: {
      name: `unavailable:${spec.command[0] ?? 'adapter'}`,
      version: '0',
      repository: spec.provenanceCodebase ?? spec.command.join(' '),
      // No usable revision → codebaseIdentity() returns null → cannot count toward independence.
      revision: '',
      provenanceCodebase: spec.provenanceCodebase,
      supportedFamilies: [],
      operations: [],
      kind: 'unavailable',
      unavailableReason: error instanceof Error ? `${error.name}: ${error.message}` : String(error),
    },
    close: async () => {},
  };
}

/**
 * Launch every spec over the subprocess protocol. Returns `{ adapters, launched, unavailable }`
 * where `adapters` is the full list (available + unavailable stand-ins) ready for crossRun().
 * Never throws for a per-adapter launch failure — those become unavailable stand-ins.
 */
export async function launchAdapters(specs, {
  defaultCwd,
  defaultTimeoutMs = DEFAULT_ADAPTER_TIMEOUT_MS,
  defaultMaxOutputBytes = DEFAULT_ADAPTER_MAX_OUTPUT_BYTES,
} = {}) {
  const adapters = [];
  const launched = [];
  const unavailable = [];
  for (const rawSpec of specs) {
    const spec = normalizeAdapterSpec(rawSpec);
    const [command, ...args] = spec.command;
    try {
      const adapter = await startAdapterProcess(command, args, {
        cwd: spec.cwd ?? defaultCwd,
        timeoutMs: spec.timeoutMs ?? defaultTimeoutMs,
        maxOutputBytes: spec.maxOutputBytes ?? defaultMaxOutputBytes,
      });
      // Attach an explicit recorded provenance assertion when supplied (Blocker 2 escape hatch).
      if (spec.provenanceCodebase) {
        adapter.metadata = { ...adapter.metadata, provenanceCodebase: spec.provenanceCodebase };
      }
      adapters.push(adapter);
      launched.push({ spec, metadata: adapter.metadata });
    } catch (error) {
      const stub = unavailableAdapter(spec, error);
      adapters.push(stub);
      unavailable.push({ spec, reason: stub.metadata.unavailableReason });
    }
  }
  return { adapters, launched, unavailable };
}

/**
 * Parse adapter specs from CLI argv fragments. Recognized:
 *   --adapter "<command>"                 (repeatable) launch this command as an adapter
 *   --adapter-provenance "<codebase-id>"  attach a recorded steward provenance assertion to the
 *                                          MOST RECENT --adapter (Blocker 2 explicit-assertion path)
 *   --adapter-timeout-ms <n>              per-adapter wall-clock timeout for the MOST RECENT --adapter
 *   --adapter-max-output-bytes <n>        per-adapter output cap for the MOST RECENT --adapter
 *   --config <file.json>                  JSON { "adapters": [ specObject, ... ] }
 * Returns { specs, rest } where `rest` are argv tokens this parser did not consume.
 */
export function parseAdapterArgs(args, { readFileSync } = {}) {
  const specs = [];
  const rest = [];
  const attachToLast = (mutator, flag) => {
    if (specs.length === 0) throw new Error(`${flag} must follow an --adapter`);
    mutator(specs[specs.length - 1]);
  };
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--adapter') {
      if (!args[i + 1]) throw new Error('--adapter requires a command string');
      specs.push({ command: args[++i] });
    } else if (arg === '--adapter-provenance') {
      if (!args[i + 1]) throw new Error('--adapter-provenance requires a value');
      const value = args[++i];
      attachToLast((s) => { s.provenanceCodebase = value; }, '--adapter-provenance');
    } else if (arg === '--adapter-timeout-ms') {
      if (!args[i + 1]) throw new Error('--adapter-timeout-ms requires a value');
      const value = args[++i];
      attachToLast((s) => { s.timeoutMs = value; }, '--adapter-timeout-ms');
    } else if (arg === '--adapter-max-output-bytes') {
      if (!args[i + 1]) throw new Error('--adapter-max-output-bytes requires a value');
      const value = args[++i];
      attachToLast((s) => { s.maxOutputBytes = value; }, '--adapter-max-output-bytes');
    } else if (arg === '--config') {
      if (!args[i + 1]) throw new Error('--config requires a file path');
      const file = args[++i];
      if (typeof readFileSync !== 'function') throw new Error('--config requires a file reader');
      let parsed;
      try { parsed = JSON.parse(readFileSync(file, 'utf8')); }
      catch (error) { throw new Error(`--config ${file}: ${error instanceof Error ? error.message : String(error)}`); }
      if (!parsed || !Array.isArray(parsed.adapters)) {
        throw new Error(`--config ${file}: expected { "adapters": [ ... ] }`);
      }
      for (const spec of parsed.adapters) specs.push(spec);
    } else {
      rest.push(arg);
    }
  }
  return { specs, rest };
}
