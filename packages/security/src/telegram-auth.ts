export interface TelegramAuthConfig {
  ownerId: number | string;
  allowedUserIds?: Array<number | string>;
  webhookSecret?: string;
}

export class TelegramAuthGuard {
  private allowedIds: Set<string>;
  private webhookSecret?: string;

  constructor(config: TelegramAuthConfig) {
    this.allowedIds = new Set<string>();
    if (config.ownerId) {
      this.allowedIds.add(String(config.ownerId).trim());
    }
    if (config.allowedUserIds) {
      for (const id of config.allowedUserIds) {
        if (id) this.allowedIds.add(String(id).trim());
      }
    }
    this.webhookSecret = config.webhookSecret?.trim();
  }

  /**
   * Validates the X-Telegram-Bot-Api-Secret-Token header
   */
  public validateWebhookSecret(incomingHeaderToken: string | null | undefined): boolean {
    if (!this.webhookSecret) {
      // If no secret configured, warn/deny in production
      return false;
    }
    if (!incomingHeaderToken) {
      return false;
    }
    // Constant-time comparison to prevent timing attacks
    return this.constantTimeCompare(incomingHeaderToken.trim(), this.webhookSecret);
  }

  /**
   * Verifies if a Telegram user ID is authorized to interact with Lucifer
   */
  public isUserAuthorized(userId: number | string | undefined): boolean {
    if (userId === undefined || userId === null) {
      return false;
    }
    return this.allowedIds.has(String(userId).trim());
  }

  private constantTimeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false;
    }
    let mismatch = 0;
    for (let i = 0; i < a.length; i++) {
      mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return mismatch === 0;
  }
}
