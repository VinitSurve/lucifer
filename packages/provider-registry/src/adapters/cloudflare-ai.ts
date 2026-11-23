import {
  ChatMessage,
  GenerateOptions,
  GenerateResult,
  ModelDescriptor,
  ProviderHealth,
  ProviderId
} from '@lucifer/shared-types';
import { AIProvider } from '../types';

export class CloudflareAIProvider implements AIProvider {
  public id: ProviderId = 'cloudflare_ai';
  public name = 'Cloudflare Workers AI';
  private accountId?: string;
  private apiToken?: string;
  private aiBinding?: any; // Cloudflare Worker env.AI binding

  constructor(accountId?: string, apiToken?: string, aiBinding?: any) {
    this.accountId = accountId?.trim();
    this.apiToken = apiToken?.trim();
    this.aiBinding = aiBinding;
  }

  public isConfigured(): boolean {
    return Boolean(this.aiBinding || (this.accountId && this.apiToken));
  }

  public getModels(): ModelDescriptor[] {
    return [
      {
        id: '@cf/meta/llama-3.1-8b-instruct',
        providerId: 'cloudflare_ai',
        displayName: 'Cloudflare Llama 3.1 8B',
        contextWindow: 8192,
        maxOutputTokens: 2048,
        supportsTools: false,
        supportsVision: false,
        supportsJson: true,
        isFreeTier: true,
        costPer1kInputTokens: 0,
        costPer1kOutputTokens: 0,
        averageLatencyMs: 450,
        qualityScore: 7.5
      }
    ];
  }

  public async generate(messages: ChatMessage[], options?: GenerateOptions): Promise<GenerateResult> {
    const model = '@cf/meta/llama-3.1-8b-instruct';
    const startTime = Date.now();

    // Direct Workers binding execution
    if (this.aiBinding) {
      const response = await this.aiBinding.run(model, {
        messages: messages.map((m) => ({ role: m.role, content: m.content })),
        max_tokens: options?.maxTokens ?? 1024
      });
      const latencyMs = Date.now() - startTime;
      return {
        content: response.response || '',
        modelUsed: model,
        providerUsed: 'cloudflare_ai',
        latencyMs
      };
    }

    // REST API fallback
    if (!this.accountId || !this.apiToken) {
      throw new Error('Cloudflare AI requires account ID and API token or env.AI binding');
    }

    const endpoint = `https://api.cloudflare.com/client/v4/accounts/${this.accountId}/ai/run/${model}`;
    const resp = await fetch(endpoint, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.apiToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        messages: messages.map((m) => ({ role: m.role, content: m.content })),
        max_tokens: options?.maxTokens ?? 1024
      }),
      signal: options?.timeoutMs ? AbortSignal.timeout(options.timeoutMs) : undefined
    });

    if (!resp.ok) {
      const errText = await resp.text();
      throw new Error(`Cloudflare Workers AI error (${resp.status}): ${errText}`);
    }

    const data = (await resp.json()) as any;
    const latencyMs = Date.now() - startTime;

    return {
      content: data.result?.response || '',
      modelUsed: model,
      providerUsed: 'cloudflare_ai',
      latencyMs
    };
  }

  public async healthCheck(): Promise<ProviderHealth> {
    if (!this.isConfigured()) {
      return { providerId: 'cloudflare_ai', status: 'DISABLED', consecutiveFailures: 0 };
    }
    return { providerId: 'cloudflare_ai', status: 'HEALTHY', consecutiveFailures: 0 };
  }
}
