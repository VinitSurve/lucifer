import { PromptInjectionDefense } from '@lucifer/security';

export interface GmailMessageSummary {
  id: string;
  threadId: string;
  from: string;
  subject: string;
  date: string;
  snippet: string;
}

export class GmailService {
  /**
   * Searches Gmail inbox
   */
  public static async searchEmails(
    query = 'is:unread',
    maxResults = 5,
    accessToken?: string
  ): Promise<{ authenticated: boolean; messages: GmailMessageSummary[]; messageText?: string }> {
    if (!accessToken) {
      return {
        authenticated: false,
        messages: [],
        messageText: 'Gmail integration is not yet connected with Google OAuth. Use /email connect to link your account.'
      };
    }

    try {
      const listUrl = `https://gmail.googleapis.com/gmail/v1/users/me/messages?q=${encodeURIComponent(query)}&maxResults=${maxResults}`;
      const listResp = await fetch(listUrl, {
        headers: { Authorization: `Bearer ${accessToken}` },
        signal: AbortSignal.timeout(8000)
      });

      if (!listResp.ok) {
        return {
          authenticated: false,
          messages: [],
          messageText: `Gmail API error (${listResp.status}). Token may be expired or revoked.`
        };
      }

      const listData = (await listResp.json()) as any;
      const messageIds: Array<{ id: string; threadId: string }> = listData.messages || [];

      const summaries: GmailMessageSummary[] = [];
      for (const m of messageIds.slice(0, maxResults)) {
        const msgResp = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${m.id}?format=metadata`, {
          headers: { Authorization: `Bearer ${accessToken}` }
        });
        if (msgResp.ok) {
          const msgData = (await msgResp.json()) as any;
          const headers = msgData.payload?.headers || [];
          const from = headers.find((h: any) => h.name.toLowerCase() === 'from')?.value || 'Unknown';
          const subject = headers.find((h: any) => h.name.toLowerCase() === 'subject')?.value || '(No Subject)';
          const date = headers.find((h: any) => h.name.toLowerCase() === 'date')?.value || '';

          // Wrap external snippet with prompt injection protection
          const safeSnippet = PromptInjectionDefense.wrapUntrustedContent('email_snippet', msgData.snippet || '', {
            from,
            subject,
            date
          });

          summaries.push({
            id: m.id,
            threadId: m.threadId,
            from,
            subject,
            date,
            snippet: safeSnippet
          });
        }
      }

      return {
        authenticated: true,
        messages: summaries
      };
    } catch (err: any) {
      return {
        authenticated: false,
        messages: [],
        messageText: `Gmail service error: ${err.message}`
      };
    }
  }

  /**
   * Creates a draft in Gmail
   */
  public static async createDraft(
    to: string,
    subject: string,
    bodyText: string,
    accessToken?: string
  ): Promise<{ success: boolean; draftId?: string; message: string }> {
    if (!accessToken) {
      return {
        success: false,
        message: 'Google OAuth credentials missing. Connect via /email connect.'
      };
    }

    const emailLines = [
      `To: ${to}`,
      `Subject: ${subject}`,
      'Content-Type: text/plain; charset=utf-8',
      '',
      bodyText
    ];
    const rawEmail = btoa(unescape(encodeURIComponent(emailLines.join('\r\n'))));

    const resp = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/drafts', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        message: { raw: rawEmail }
      })
    });

    if (!resp.ok) {
      return { success: false, message: `Failed to create draft: status ${resp.status}` };
    }

    const data = (await resp.json()) as any;
    return { success: true, draftId: data.id, message: `Draft created successfully (ID: ${data.id})` };
  }
}
