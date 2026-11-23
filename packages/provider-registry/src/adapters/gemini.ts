import {
  ChatMessage,
  GenerateOptions,
  GenerateResult,
  ModelDescriptor,
  ProviderHealth,
  ProviderId
} from '@lucifer/shared-types';
import { AIProvider } from '../types';

export class GeminiProvider implements AIProvider {
  public id: ProviderId = 'gemini';
  public name = 'Google Gemini API';
  private apiKeys: string[];
  private currentKeyIndex = 0;

  constructor(apiKeys: string[] = []) {
    this.apiKeys = apiKeys.filter((k) => k.trim().length > 0);
  }

  public isConfigured(): boolean {
    return this.apiKeys.length > 0;
  }

  private getActiveKey(): string {
    if (this.apiKeys.length === 0) throw new Error('Gemini API key not configured');
    const key = this.apiKeys[this.currentKeyIndex % this.apiKeys.length];
    this.currentKeyIndex++;
    return key;
  }

  public getModels(): ModelDescriptor[] {
    return [
      {
        id: 'gemini-2.0-flash',
        providerId: 'gemini',
        displayName: 'Gemini 2.0 Flash',
        contextWindow: 1048576,
        maxOutputTokens: 8192,
        supportsTools: true,
        supportsVision: true,
        supportsJson: true,
        isFreeTier: true,
        costPer1kInputTokens: 0,
        costPer1kOutputTokens: 0,
        averageLatencyMs: 650,
        qualityScore: 9
      },
      {
        id: 'gemini-1.5-flash',
        providerId: 'gemini',
        displayName: 'Gemini 1.5 Flash',
        contextWindow: 1048576,
        maxOutputTokens: 8192,
        supportsTools: true,
        supportsVision: true,
        supportsJson: true,
        isFreeTier: true,
        costPer1kInputTokens: 0,
        costPer1kOutputTokens: 0,
        averageLatencyMs: 700,
        qualityScore: 8
      }
    ];
  }

  public async generate(messages: ChatMessage[], options?: GenerateOptions): Promise<GenerateResult> {
    const key = this.getActiveKey();
    const model = 'gemini-2.0-flash';
    const startTime = Date.now();

    // Map system instruction
    const systemMsg = messages.find((m) => m.role === 'system');
    const nonSystemMsgs = messages.filter((m) => m.role !== 'system');

    // Build Gemini contents format
    const contents = nonSystemMsgs.map((msg) => {
      let role = msg.role === 'assistant' ? 'model' : 'user';
      if (msg.role === 'tool') role = 'function';
      return {
        role,
        parts: [{ text: msg.content }]
      };
    });

    const payload: Record<string, unknown> = {
      contents,
      generationConfig: {
        temperature: options?.temperature ?? 0.3,
        maxOutputTokens: options?.maxTokens ?? 2048
      }
    };

    if (systemMsg) {
      payload.systemInstruction = {
        parts: [{ text: systemMsg.content }]
      };
    }

    // Tools mapping
    if (options?.tools && options.tools.length > 0) {
      payload.tools = [
        {
          functionDeclarations: options.tools.map((t) => ({
            name: t.name,
            description: t.description,
            parameters: t.parameters
          }))
        }
      ];
    }

    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`;
    const resp = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: options?.timeoutMs ? AbortSignal.timeout(options.timeoutMs) : undefined
    });

    if (!resp.ok) {
      const errText = await resp.text();
      throw new Error(`Gemini API error (${resp.status}): ${errText}`);
    }

    const data = (await resp.json()) as any;
    const candidate = data.candidates?.[0];
    const latencyMs = Date.now() - startTime;

    let contentText = '';
    const toolCalls: Array<{ id: string; name: string; arguments: Record<string, unknown> }> = [];

    if (candidate?.content?.parts) {
      for (const part of candidate.content.parts) {
        if (part.text) {
          contentText += part.text;
        }
        if (part.functionCall) {
          toolCalls.push({
            id: `call_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
            name: part.functionCall.name,
            arguments: part.functionCall.args || {}
          });
        }
      }
    }

    return {
      content: contentText,
      modelUsed: model,
      providerUsed: 'gemini',
      toolCalls: toolCalls.length > 0 ? toolCalls : undefined,
      usage: data.usageMetadata
        ? {
            promptTokens: data.usageMetadata.promptTokenCount || 0,
            completionTokens: data.usageMetadata.candidatesTokenCount || 0,
            totalTokens: data.usageMetadata.totalTokenCount || 0
          }
        : undefined,
      latencyMs
    };
  }

  public async healthCheck(): Promise<ProviderHealth> {
    if (!this.isConfigured()) {
      return { providerId: 'gemini', status: 'DISABLED', consecutiveFailures: 0 };
    }
    return { providerId: 'gemini', status: 'HEALTHY', consecutiveFailures: 0 };
  }
}
