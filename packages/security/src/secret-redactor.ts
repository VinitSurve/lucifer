/**
 * Redacts secrets, tokens, and keys from logs, outputs, and user-facing messages.
 */
export class SecretRedactor {
  private static SECRET_PATTERNS = [
    // Telegram Bot Token (e.g., 123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ)
    /\b\d{9,10}:[A-Za-z0-9_-]{35}\b/g,
    // Generic API Keys (sk-..., gsk_..., AIza...)
    /\b(sk-[a-zA-Z0-9_-]{20,})\b/g,
    /\b(gsk_[a-zA-Z0-9]{30,})\b/g,
    /\b(AIza[0-9A-Za-z-_]{35})\b/g,
    // GitHub Tokens (ghp_..., gho_..., ghu_...)
    /\b(gh[pousr]_[A-Za-z0-9_]{36,})\b/g,
    // Bearer authorization headers
    /Bearer\s+([A-Za-z0-9\-._~+/]+=*)/gi,
    // Cloudflare API tokens (40 hex or base64 chars)
    /\b([a-zA-Z0-9_-]{40})\b/g,
  ];

  public static redact(text: string): string {
    if (!text || typeof text !== 'string') return text;

    let sanitized = text;

    // Telegram Bot Token (e.g., 123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ)
    sanitized = sanitized.replace(/\b\d{8,11}:[A-Za-z0-9_-]{30,50}\b/g, '[REDACTED_TELEGRAM_TOKEN]');

    // Gemini API Key (starts with AIza...)
    sanitized = sanitized.replace(/\bAIza[0-9A-Za-z-_]{30,45}\b/g, '[REDACTED_GEMINI_KEY]');

    // Groq API Key (starts with gsk_...)
    sanitized = sanitized.replace(/\bgsk_[a-zA-Z0-9]{20,}\b/g, '[REDACTED_GROQ_KEY]');

    // OpenRouter / OpenAI Key (starts with sk-...)
    sanitized = sanitized.replace(/\bsk-[a-zA-Z0-9_-]{20,}\b/g, '[REDACTED_AI_KEY]');

    // GitHub Tokens (starts with ghp_, gho_, etc.)
    sanitized = sanitized.replace(/\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g, '[REDACTED_GITHUB_TOKEN]');

    // Bearer tokens
    sanitized = sanitized.replace(/Bearer\s+([A-Za-z0-9\-._~+/]{8,})/gi, 'Bearer [REDACTED_AUTH_TOKEN]');

    return sanitized;
  }
}
