#!/usr/bin/env node
/**
 * TEST FIXTURE ONLY — a deliberately hung adapter. It performs the metadata handshake read but
 * never replies and never exits, so the runner's per-adapter timeout (Blocker 3) must SIGKILL it
 * and record it as an UNAVAILABLE / timed-out adapter rather than hanging the whole cross-run.
 * Not a real DACS implementation; never registered by the default cross-run.
 */
// Keep the event loop alive forever without emitting a response.
setInterval(() => {}, 1 << 30);
