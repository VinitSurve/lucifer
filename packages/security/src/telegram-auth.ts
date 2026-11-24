export interface TelegramAuthConfig {
  ownerId?: number | string;
  allowedUserIds?: Array<number | string>;
  webhookSecret?: string;
}

export class TelegramAuthGuard {
  private allowedIds: Set<string>;
  private webhookSecret?: string;

  /**
   * Validates that an identifier is a strictly positive numeric Telegram user ID.
   * Usernames (e.g. @username or plain handles), negative numbers, decimals,
   * symbols, and empty/non-numeric values are strictly rejected.
   */
  public static isValidNumericTelegramId(id: unknown): boolean {
    if (id === undefined || id === null) {
      return false;
    }
    if (typeof id === 'number') {
      return Number.isSafeInteger(id) && id > 0;
    }
    if (typeof id === 'string') {
      return /^[1-9]\d*$/.test(id.trim());
    }
    return false;
  }

  constructor(config: TelegramAuthConfig) {
    this.allowedIds = new Set<string>();

    if (config.ownerId !== undefined && config.ownerId !== null && String(config.ownerId).trim() !== '') {
      const raw = config.ownerId;
      if (!TelegramAuthGuard.isValidNumericTelegramId(raw)) {
        throw new Error(
          `Invalid Telegram ownerId: "${String(raw)}". Telegram owner ID must be an immutable numeric ID (e.g. obtained from @userinfobot). Usernames cannot be used for authorization.`
        );
      }
      this.allowedIds.add(String(raw).trim());
    }

    if (config.allowedUserIds) {
      for (const id of config.allowedUserIds) {
        if (id !== undefined && id !== null && String(id).trim() !== '') {
          if (!TelegramAuthGuard.isValidNumericTelegramId(id)) {
            throw new Error(
              `Invalid Telegram allowedUserId: "${String(id)}". Telegram user ID must be an immutable numeric ID. Usernames cannot be used for authorization.`
            );
          }
          this.allowedIds.add(String(id).trim());
        }
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
   * Verifies if a Telegram user ID is authorized to interact with Lucifer.
   * Incoming user ID must be a valid numeric Telegram ID and present in the allowlist.
   * Usernames or non-numeric representations are immediately rejected.
   */
  public isUserAuthorized(userId: unknown): boolean {
    if (!TelegramAuthGuard.isValidNumericTelegramId(userId)) {
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

