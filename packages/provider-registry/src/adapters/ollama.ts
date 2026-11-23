import {
  ChatMessage,
  GenerateOptions,
  GenerateResult,
  ModelDescriptor,
  ProviderHealth,
  ProviderId
} from '@lucifer/shared-types';
import { AIProvider } from '../types';

export class OllamaProvider implements AIProvider {
  public id: ProviderId = 'ollama';
  public name = 'Local Ollama Instance';
  private baseUrl: string;
  private defaultModel: string;

  constructor(baseUrl = 'http://127.0.0.1:11434', defaultModel = 'gemma2:2b') {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.defaultModel = defaultModel;
  }

  public isConfigured(): boolean {
    return Boolean(this.baseUrl);
  }

  public getModels(): ModelDescriptor[] {
    return [
      {
        id: this.defaultModel,
        providerId: 'ollama',
        displayName: `Ollama (${this.defaultModel})`,
        contextWindow: 32768,
        maxOutputTokens: 4096,
        supportsTools: true,
        supportsVision: false,
        supportsJson: true,
        isFreeTier: true,
        costPer1kInputTokens: 0,
        costPer1kOutputTokens: 0,
        averageLatencyMs: 950,
        qualityScore: 7.8
      }
    ];
  }

  public async generate(messages: ChatMessage[], options?: GenerateOptions): Promise<GenerateResult> {
    const startTime = Date.now();
    const formattedMessages = messages.map((m) => ({
      role: m.role,
      content: m.content
    }));

    const payload: Record<string, unknown> = {
      model: this.defaultModel,
      messages: formattedMessages,
      stream: false,
      options: {
        temperature: options?.temperature ?? 0.2
      }
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

    const resp = await fetch(`${this.baseUrl}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: options?.timeoutMs ? AbortSignal.timeout(options.timeoutMs) : undefined
    });

    if (!resp.ok) {
      const errText = await resp.text();
      throw new Error(`Ollama error (${resp.status}): ${errText}`);
    }

    const data = (await resp.json()) as any;
    const latencyMs = Date.now() - startTime;

    const toolCalls: Array<{ id: string; name: string; arguments: Record<string, unknown> }> = [];
    if (data.message?.tool_calls) {
      for (const tc of data.message.tool_calls) {
        toolCalls.push({
          id: `ollama_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
          name: tc.function.name,
          arguments: tc.function.arguments || {}
        });
      }
    }

    return {
      content: data.message?.content || '',
      modelUsed: this.defaultModel,
      providerUsed: 'ollama',
      toolCalls: toolCalls.length > 0 ? toolCalls : undefined,
      usage: data.prompt_eval_count
        ? {
            promptTokens: data.prompt_eval_count,
            completionTokens: data.eval_count || 0,
            totalTokens: data.prompt_eval_count + (data.eval_count || 0)
          }
        : undefined,
      latencyMs
    };
  }

  public async healthCheck(): Promise<ProviderHealth> {
    try {
      const resp = await fetch(`${this.baseUrl}/api/tags`, {
        signal: AbortSignal.timeout(2000)
      });
      if (resp.ok) {
        return { providerId: 'ollama', status: 'HEALTHY', consecutiveFailures: 0 };
      }
      return {
        providerId: 'ollama',
        status: 'UNAVAILABLE',
        consecutiveFailures: 1,
        lastErrorMessage: `Status: ${resp.status}`
      };
    } catch (err: any) {
      return {
        providerId: 'ollama',
        status: 'UNAVAILABLE',
        consecutiveFailures: 1,
        lastErrorMessage: err.message
      };
    }
  }
}
