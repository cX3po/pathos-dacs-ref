/**
 * DACS commerce showcase — entry point.
 *
 *   npx tsx src/showcase/demo.ts
 *
 * Runs one Vendor↔Shopper DACS-1→5 commerce session end-to-end on the reference
 * impl, renders each stage to the configured surface (console by default;
 * Telegram if SHOWCASE_VENDOR_BOT_TOKEN + SHOWCASE_TG_GROUP_ID are set), and
 * prints the two-sided verifyBundle verdict. Exits non-zero unless BOTH bundles
 * verify PASS.
 */
import { loadConfig } from './config.js';
import { runShowcaseSession } from './flow.js';
import { Relay } from './display.js';

async function main() {
  const cfg = loadConfig();
  const relay = new Relay(cfg);

  await relay.header(`DACS commerce showcase — surface=${cfg.surface}, settle=${cfg.settleMode}`);
  const session = await runShowcaseSession();

  for (const e of session.events) await relay.post(e);

  await relay.header(`Session ${session.jobId} complete`);
  const { buyer, seller } = session.verdicts;
  console.log(`\n  jobId:        ${session.jobId}`);
  console.log(`  Vendor:       cci:${session.vendorId.slice(0, 16)}…`);
  console.log(`  Shopper:      cci:${session.shopperId.slice(0, 16)}…`);
  console.log(`  anchors:      buyer=${session.anchors.buyer.slice(0, 20)}… seller=${session.anchors.seller.slice(0, 20)}…`);
  console.log(`  buyer bundle:  ${buyer.decision.toUpperCase()} (${buyer.signersVerified.length} signer)`);
  console.log(`  seller bundle: ${seller.decision.toUpperCase()} (${seller.signersVerified.length} signer)`);

  const ok = buyer.decision === 'pass' && seller.decision === 'pass';
  console.log(`\n  ${ok ? '✅ BOTH bundles PASS — end-to-end DACS-1→5 verified' : '❌ a bundle did not pass'}`);
  process.exit(ok ? 0 : 1);
}

main().catch((e) => { console.error('showcase error:', e); process.exit(2); });
