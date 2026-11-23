export interface CloudEnv {
  DB: D1Database;
  LUCIFER_ENV?: string;
  DEFAULT_TIMEZONE?: string;
  BUDGET_MODE?: 'FREE_ONLY' | 'ALL';
  TELEGRAM_BOT_TOKEN?: string;
  TELEGRAM_OWNER_ID?: string;
  TELEGRAM_WEBHOOK_SECRET?: string;
  GEMINI_API_KEYS?: string;
  GROQ_API_KEYS?: string;
  OPENROUTER_API_KEYS?: string;
  CLOUDFLARE_ACCOUNT_ID?: string;
  CLOUDFLARE_API_TOKEN?: string;
  GITHUB_TOKEN?: string;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  OLLAMA_URL?: string;
  DEVICE_PAIRING_SECRET?: string;
  AI?: any; // Cloudflare Workers AI binding if present
}
