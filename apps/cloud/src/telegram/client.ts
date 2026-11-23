export interface SendMessageOptions {
  parse_mode?: 'Markdown' | 'HTML';
  reply_markup?: {
    inline_keyboard?: Array<Array<{ text: string; callback_data?: string; url?: string }>>;
  };
}

export class TelegramBotClient {
  private botToken: string;
  private baseUrl: string;

  constructor(botToken: string) {
    this.botToken = botToken.trim();
    this.baseUrl = `https://api.telegram.org/bot${this.botToken}`;
  }

  public async sendMessage(
    chatId: number | string,
    text: string,
    options?: SendMessageOptions
  ): Promise<any> {
    const MAX_LEN = 4000;
    // Paginate if message exceeds Telegram limit
    if (text.length > MAX_LEN) {
      const chunks = [];
      for (let i = 0; i < text.length; i += MAX_LEN) {
        chunks.push(text.slice(i, i + MAX_LEN));
      }

      let lastResult;
      for (let idx = 0; idx < chunks.length; idx++) {
        const chunkHeader = chunks.length > 1 ? `[Part ${idx + 1}/${chunks.length}]\n` : '';
        lastResult = await this.postRequest('/sendMessage', {
          chat_id: chatId,
          text: chunkHeader + chunks[idx],
          parse_mode: options?.parse_mode,
          reply_markup: idx === chunks.length - 1 ? options?.reply_markup : undefined
        });
      }
      return lastResult;
    }

    return this.postRequest('/sendMessage', {
      chat_id: chatId,
      text,
      parse_mode: options?.parse_mode,
      reply_markup: options?.reply_markup
    });
  }

  public async editMessageText(
    chatId: number | string,
    messageId: number,
    text: string,
    options?: SendMessageOptions
  ): Promise<any> {
    return this.postRequest('/editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text,
      parse_mode: options?.parse_mode,
      reply_markup: options?.reply_markup
    });
  }

  public async answerCallbackQuery(
    callbackQueryId: string,
    text?: string,
    showAlert = false
  ): Promise<any> {
    return this.postRequest('/answerCallbackQuery', {
      callback_query_id: callbackQueryId,
      text,
      show_alert: showAlert
    });
  }

  public async sendChatAction(chatId: number | string, action = 'typing'): Promise<any> {
    return this.postRequest('/sendChatAction', {
      chat_id: chatId,
      action
    });
  }

  private async postRequest(endpoint: string, payload: Record<string, unknown>): Promise<any> {
    const resp = await fetch(`${this.baseUrl}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(10000)
    });

    if (!resp.ok) {
      const err = await resp.text();
      throw new Error(`Telegram API Error (${resp.status}): ${err}`);
    }

    return resp.json();
  }
}
