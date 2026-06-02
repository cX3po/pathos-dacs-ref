/**
 * Showcase config — env-driven so the backend is bot/surface-agnostic.
 * With no env set, the demo runs in CONSOLE mode (no Telegram needed).
 */
export interface ShowcaseConfig {
  vendorBotToken?: string;
  shopperBotToken?: string;
  narratorBotToken?: string;
  tgGroupId?: string;
  settleMode: 'mock' | 'testnet';
  surface: 'console' | 'telegram';
}

export function loadConfig(env: Record<string, string | undefined> = process.env): ShowcaseConfig {
  const vendorBotToken = env.SHOWCASE_VENDOR_BOT_TOKEN;
  const tgGroupId = env.SHOWCASE_TG_GROUP_ID;
  return {
    vendorBotToken,
    shopperBotToken: env.SHOWCASE_SHOPPER_BOT_TOKEN,
    narratorBotToken: env.SHOWCASE_NARRATOR_BOT_TOKEN,
    tgGroupId,
    settleMode: env.SHOWCASE_SETTLE === 'testnet' ? 'testnet' : 'mock',
    // telegram surface only when at least a token + group are configured
    surface: vendorBotToken && tgGroupId ? 'telegram' : 'console',
  };
}
