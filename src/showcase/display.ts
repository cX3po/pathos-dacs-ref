/**
 * Display/relay for the showcase. Renders each StageEvent as a chat card and
 * posts it — to Telegram (real, via the Bot API over fetch — no extra deps) when
 * tokens+group are configured, else to the console. Vendor turns post from the
 * Vendor bot, Shopper turns from the Shopper bot, stage headers from the
 * Narrator bot, mirroring the "two agents chatting" surface RB described.
 *
 * NOTE (honest): Telegram bots cannot read each other's messages in a group, so
 * this is backend-coordinated DACS traffic DISPLAYED per-agent — not bots
 * literally reading each other. That's the only buildable shape.
 */
import type { ShowcaseConfig } from './config.js';
import type { StageEvent } from './flow.js';

const STAGE_BADGE: Record<string, string> = {
  'DACS-1 Identify': '🟦 1·IDENTIFY',
  'DACS-2 Vet': '🟩 2·VET',
  'DACS-3 Negotiate': '🟨 3·NEGOTIATE',
  'DACS-4 Settle': '🟧 4·SETTLE',
  'DACS-5 Verify': '🟪 5·VERIFY',
};

export function formatCard(e: StageEvent): string {
  const who = e.actor === 'Vendor' ? '🛒 Vendor' : '🧑‍💻 Shopper';
  const hash = e.artifactHash ? `\n    └ artifact ${e.artifactHash.slice(0, 16)}…` : '';
  return `${STAGE_BADGE[e.stage] ?? e.stage}  ${who}: ${e.line}${hash}`;
}

async function tgSend(token: string, chatId: string, text: string): Promise<void> {
  const res = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, text, disable_web_page_preview: true }),
  });
  if (!res.ok) throw new Error(`tg send ${res.status}: ${(await res.text()).slice(0, 120)}`);
}

export class Relay {
  constructor(private cfg: ShowcaseConfig) {}

  async post(e: StageEvent): Promise<void> {
    const card = formatCard(e);
    if (this.cfg.surface === 'console') { console.log(card); return; }
    const token = e.actor === 'Vendor' ? this.cfg.vendorBotToken : this.cfg.shopperBotToken;
    const useToken = token ?? this.cfg.narratorBotToken ?? this.cfg.vendorBotToken!;
    try {
      await tgSend(useToken, this.cfg.tgGroupId!, card);
    } catch (err) {
      console.error(`[relay] telegram send failed, falling back to console: ${(err as Error).message}`);
      console.log(card);
    }
  }

  async header(text: string): Promise<void> {
    if (this.cfg.surface === 'console') { console.log(`\n— ${text} —`); return; }
    const t = this.cfg.narratorBotToken ?? this.cfg.vendorBotToken;
    if (t) { try { await tgSend(t, this.cfg.tgGroupId!, `— ${text} —`); return; } catch { /* fall through */ } }
    console.log(`\n— ${text} —`);
  }
}
