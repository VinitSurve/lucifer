import { PromptInjectionDefense, SsrfFilter } from '@lucifer/security';

export interface SearchResultItem {
  title: string;
  url: string;
  snippet: string;
}

export class ResearchService {
  /**
   * Safe web search utilizing public search endpoints or Google Custom Search
   */
  public static async webSearch(query: string, numResults = 5): Promise<SearchResultItem[]> {
    const encoded = encodeURIComponent(query);
    // Public non-tracking search fetch
    const endpoint = `https://html.duckduckgo.com/html/?q=${encoded}`;

    try {
      const resp = await fetch(endpoint, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) LuciferAssistant/1.0'
        },
        signal: AbortSignal.timeout(8000)
      });

      if (!resp.ok) {
        return [
          {
            title: `Search Query: ${query}`,
            url: `https://duckduckgo.com/?q=${encoded}`,
            snippet: `Web search completed with status ${resp.status}. Real-time information available via direct link.`
          }
        ];
      }

      const html = await resp.text();
      const results: SearchResultItem[] = [];

      // Parse DuckDuckGo HTML results
      const linkRegex = /<a class="result__url"[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>[\s\S]*?<a class="result__snippet"[^>]*>([\s\S]*?)<\/a>/gi;
      let match;
      let count = 0;

      while ((match = linkRegex.exec(html)) !== null && count < numResults) {
        const rawUrl = match[1].trim();
        const snippet = match[3].replace(/<[^>]+>/g, '').trim();

        // Extract clean destination url from uddg redirect if present
        let cleanUrl = rawUrl;
        if (cleanUrl.includes('uddg=')) {
          const uMatch = cleanUrl.match(/uddg=([^&]+)/);
          if (uMatch) cleanUrl = decodeURIComponent(uMatch[1]);
        }

        if (cleanUrl.startsWith('http')) {
          results.push({
            title: match[2].replace(/<[^>]+>/g, '').trim() || 'Search Result',
            url: cleanUrl,
            snippet: snippet || 'No snippet available'
          });
          count++;
        }
      }

      if (results.length === 0) {
        results.push({
          title: `Web Search: ${query}`,
          url: `https://duckduckgo.com/?q=${encoded}`,
          snippet: `No direct snippets parsed. Access live search directly.`
        });
      }

      return results;
    } catch (err: any) {
      return [
        {
          title: `Search error for: ${query}`,
          url: `https://duckduckgo.com/?q=${encoded}`,
          snippet: `Could not retrieve live search results: ${err.message}`
        }
      ];
    }
  }

  /**
   * Safely fetches a webpage with SSRF filtering and prompt injection isolation
   */
  public static async fetchAndExtractUrl(rawUrl: string): Promise<{ success: boolean; content: string; url: string }> {
    const check = SsrfFilter.isSafeUrl(rawUrl);
    if (!check.safe) {
      return {
        success: false,
        content: `URL rejected by SSRF security filter: ${check.reason}`,
        url: rawUrl
      };
    }

    try {
      const resp = await fetch(rawUrl, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) LuciferCrawler/1.0'
        },
        signal: AbortSignal.timeout(10000)
      });

      if (!resp.ok) {
        return {
          success: false,
          content: `Failed to fetch URL. HTTP status ${resp.status}`,
          url: rawUrl
        };
      }

      const html = await resp.text();
      // Basic HTML text extraction: strip scripts, styles, tags
      let cleanText = html
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, ' ')
        .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, ' ')
        .replace(/<[^>]+>/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();

      // Limit to 6000 chars to respect context limits
      if (cleanText.length > 6000) {
        cleanText = cleanText.substring(0, 6000) + '... [truncated]';
      }

      // Wrap untrusted content with boundary guard
      const safeContent = PromptInjectionDefense.wrapUntrustedContent('web_page', cleanText, {
        url: rawUrl,
        retrievedAt: new Date().toISOString()
      });

      return {
        success: true,
        content: safeContent,
        url: rawUrl
      };
    } catch (err: any) {
      return {
        success: false,
        content: `Error fetching URL: ${err.message}`,
        url: rawUrl
      };
    }
  }
}
