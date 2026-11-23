import {
  ChatMessage,
  GenerateOptions,
  GenerateResult,
  ModelDescriptor,
  ProviderHealth,
  ProviderId
} from '@lucifer/shared-types';
import { AIProvider } from '../types';

export class GroqProvider implements AIProvider {
  public id: ProviderId = 'groq';
  public name = 'Groq Cloud API';
  private apiKeys: string[];
  private currentKeyIndex = 0;

  constructor(apiKeys: string[] = []) {
    this.apiKeys = apiKeys.filter((k) => k.trim().length > 0);
  }

  public isConfigured(): boolean {
    return this.apiKeys.length > 0;
  }

  private getActiveKey(): string {
    if (this.apiKeys.length === 0) throw new Error('Groq API key not configured');
    const key = this.apiKeys[this.currentKeyIndex % this.apiKeys.length];
    this.currentKeyIndex++;
    return key;
  }

  public getModels(): ModelDescriptor[] {
    return [
      {
        id: 'llama-3.3-70b-versatile',
        providerId: 'groq',
        displayName: 'Llama 3.3 70B (Versatile)',
        contextWindow: 128000,
        maxOutputTokens: 8192,
        supportsTools: true,
        supportsVision: false,
        supportsJson: true,
        isFreeTier: true,
        costPer1kInputTokens: 0,
        costPer1kOutputTokens: 0,
        averageLatencyMs: 380,
        qualityScore: 9
      },
      {
        id: 'llama-3.1-8b-instant',
        providerId: 'groq',
        displayName: 'Llama 3.1 8B (Instant)',
        contextWindow: 128000,
        maxOutputTokens: 8192,
        supportsTools: true,
        supportsVision: false,
        supportsJson: true,
        isFreeTier: true,
        costPer1kInputTokens: 0,
        costPer1kOutputTokens: 0,
        averageLatencyMs: 180,
        qualityScore: 7
      }
    ];
  }

  public async generate(messages: ChatMessage[], options?: GenerateOptions): Promise<GenerateResult> {
    const key = this.getActiveKey();
    const model = options?.taskClass === 'FAST' ? 'llama-3.1-8b-instant' : 'llama-3.3-70b-versatile';
    const startTime = Date.now();

    const formattedMessages = messages.map((m) => ({
      role: m.role,
      content: m.content
    }));

    const payload: Record<string, unknown> = {
      model,
      messages: formattedMessages,
      temperature: options?.temperature ?? 0.2,
      max_tokens: options?.maxTokens ?? 2048
    };

    if (options?.tools && options.tools.length > 0) {
      payload.tools = options.tools.map((t) => ({
        type: 'function',
        function: {
          name: t.name,
          description: t.description,
          parameters: t.parameters
        }
      }));
    }

    const resp = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${key}`
      },
      body: JSON.stringify(payload),
      signal: options?.timeoutMs ? AbortSignal.timeout(options.timeoutMs) : undefined
    });

    if (!resp.ok) {
      const errText = await resp.text();
      throw new Error(`Groq API error (${resp.status}): ${errText}`);
    }

    const data = (await resp.json()) as any;
    const choice = data.choices?.[0];
    const latencyMs = Date.now() - startTime;

    const toolCalls: Array<{ id: string; name: string; arguments: Record<string, unknown> }> = [];
    if (choice?.message?.tool_calls) {
      for (const tc of choice.message.tool_calls) {
        let args = {};
        try {
          args = JSON.parse(tc.function.arguments || '{}');
        } catch {
          // Keep empty if invalid JSON
        }
        toolCalls.push({
          id: tc.id,
          name: tc.function.name,
          arguments: args
        });
      }
    }

    return {
      content: choice?.message?.content || '',
      modelUsed: model,
      providerUsed: 'groq',
      toolCalls: toolCalls.length > 0 ? toolCalls : undefined,
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
      return { providerId: 'groq', status: 'DISABLED', consecutiveFailures: 0 };
    }
    return { providerId: 'groq', status: 'HEALTHY', consecutiveFailures: 0 };
  }
}
