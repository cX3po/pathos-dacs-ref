#!/usr/bin/env node
/**
 * TEST FIXTURE ONLY — a deliberately flooding adapter. It writes an unbounded stream to stdout
 * without ever emitting a valid single-line response, so the runner's bounded-output guard
 * (Blocker 3) must SIGKILL it and record it as UNAVAILABLE rather than filling the disk / OOMing.
 * Not a real DACS implementation; never registered by the default cross-run.
 */
const chunk = 'x'.repeat(64 * 1024) + '\n';
function flood() {
  // Write as fast as the pipe/file will take it; ignore backpressure — the point is to exceed
  // the output budget quickly.
  while (process.stdout.write(chunk)) { /* keep going */ }
  setImmediate(flood);
}
flood();
