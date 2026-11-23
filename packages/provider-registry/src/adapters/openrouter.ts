import {
  ChatMessage,
  GenerateOptions,
  GenerateResult,
  ModelDescriptor,
  ProviderHealth,
  ProviderId
} from '@lucifer/shared-types';
import { AIProvider } from '../types';

export class OpenRouterProvider implements AIProvider {
  public id: ProviderId = 'openrouter';
  public name = 'OpenRouter API';
  private apiKeys: string[];
  private budgetMode: 'FREE_ONLY' | 'ALL';

  constructor(apiKeys: string[] = [], budgetMode: 'FREE_ONLY' | 'ALL' = 'FREE_ONLY') {
    this.apiKeys = apiKeys.filter((k) => k.trim().length > 0);
    this.budgetMode = budgetMode;
  }

  public isConfigured(): boolean {
    return this.apiKeys.length > 0;
  }

  public getModels(): ModelDescriptor[] {
    // Only verified zero-cost models in FREE_ONLY mode
    return [
      {
        id: 'meta-llama/llama-3.3-70b-instruct:free',
        providerId: 'openrouter',
        displayName: 'Llama 3.3 70B (OpenRouter Free)',
        contextWindow: 131072,
        maxOutputTokens: 4096,
        supportsTools: true,
        supportsVision: false,
        supportsJson: true,
        isFreeTier: true,
        costPer1kInputTokens: 0,
        costPer1kOutputTokens: 0,
        averageLatencyMs: 850,
        qualityScore: 8.5
      },
      {
        id: 'google/gemini-2.0-flash-exp:free',
        providerId: 'openrouter',
        displayName: 'Gemini 2.0 Flash Exp (OpenRouter Free)',
        contextWindow: 1048576,
        maxOutputTokens: 8192,
        supportsTools: true,
        supportsVision: true,
        supportsJson: true,
        isFreeTier: true,
        costPer1kInputTokens: 0,
        costPer1kOutputTokens: 0,
        averageLatencyMs: 900,
        qualityScore: 8.8
      }
    ];
  }

  public async generate(messages: ChatMessage[], options?: GenerateOptions): Promise<GenerateResult> {
    if (!this.isConfigured()) throw new Error('OpenRouter API key not configured');
    const key = this.apiKeys[0];
    const model = 'meta-llama/llama-3.3-70b-instruct:free';
    const startTime = Date.now();

    const formattedMessages = messages.map((m) => ({
      role: m.role,
      content: m.content
    }));

    const payload: Record<string, unknown> = {
      model,
      messages: formattedMessages,
      temperature: options?.temperature ?? 0.2
    };

    const resp = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${key}`,
        'HTTP-Referer': 'https://github.com/vinit/lucifer',
        'X-Title': 'Lucifer Assistant'
      },
      body: JSON.stringify(payload),
      signal: options?.timeoutMs ? AbortSignal.timeout(options.timeoutMs) : undefined
    });

    if (!resp.ok) {
      const errText = await resp.text();
      throw new Error(`OpenRouter API error (${resp.status}): ${errText}`);
    }

    const data = (await resp.json()) as any;
    const choice = data.choices?.[0];
    const latencyMs = Date.now() - startTime;

    return {
      content: choice?.message?.content || '',
      modelUsed: model,
      providerUsed: 'openrouter',
      usage: data.usage
        ? {
            promptTokens: data.usage.prompt_tokens || 0,
            completionTokens: data.usage.completion_tokens || 0,
            totalTokens: data.usage.total_tokens || 0
          }
        : undefined,
      latencyMs
    };
  }

  public async healthCheck(): Promise<ProviderHealth> {
    if (!this.isConfigured()) {
      return { providerId: 'openrouter', status: 'DISABLED', consecutiveFailures: 0 };
    }
    return { providerId: 'openrouter', status: 'HEALTHY', consecutiveFailures: 0 };
  }
}
