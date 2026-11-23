import { describe, it, expect, vi } from 'vitest';
import {
  ModelRouter,
  ProviderHealthTracker,
  AIProvider,
  ChatMessage,
  ModelDescriptor,
  ProviderHealth
} from '../src';

class MockProvider implements AIProvider {
  public id: any;
  public name: string;
  private configured: boolean;
  public shouldFail: boolean = false;

  constructor(id: string, name: string, configured = true) {
    this.id = id;
    this.name = name;
    this.configured = configured;
  }

  isConfigured(): boolean {
    return this.configured;
  }

  getModels(): ModelDescriptor[] {
    return [
      {
        id: `${this.id}-model-1`,
        providerId: this.id,
        displayName: `${this.name} Default`,
        contextWindow: 32000,
        maxOutputTokens: 2048,
        supportsTools: true,
        supportsVision: false,
        supportsJson: true,
        isFreeTier: true,
        costPer1kInputTokens: 0,
        costPer1kOutputTokens: 0,
        averageLatencyMs: 300,
        qualityScore: 8
      }
    ];
  }

  async generate(messages: ChatMessage[]): Promise<any> {
    if (this.shouldFail) {
      throw new Error(`${this.name} 429 Too Many Requests`);
    }
    return {
      content: `Response from ${this.name}`,
      modelUsed: `${this.id}-model-1`,
      providerUsed: this.id,
      latencyMs: 150
    };
  }

  async healthCheck(): Promise<ProviderHealth> {
    return { providerId: this.id, status: 'HEALTHY', consecutiveFailures: 0 };
  }
}

describe('ModelRouter', () => {
  it('classifies task types accurately', () => {
    const health = new ProviderHealthTracker();
    const router = new ModelRouter([], health);

    expect(router.classifyTask('hi').taskClass).toBe('FAST');
    expect(router.classifyTask('search for typescript tutorials').taskClass).toBe('RESEARCH');
    expect(router.classifyTask('write a python script to parse json').taskClass).toBe('CODING');
    expect(router.classifyTask('run locally on mac').taskClass).toBe('PRIVATE');
    expect(router.classifyTask('run locally on mac').privacy).toBe('LOCAL_ONLY');
  });

  it('routes PRIVATE tasks exclusively to Ollama', () => {
    const health = new ProviderHealthTracker();
    const router = new ModelRouter([], health);

    const plan = router.createRoutePlan('PRIVATE', 'LOCAL_ONLY');
    expect(plan.selectedProvider).toBe('ollama');
    expect(plan.fallbackChain.length).toBe(0);
  });

  it('routes and executes fallback when primary provider fails', async () => {
    const groq = new MockProvider('groq', 'Groq');
    const gemini = new MockProvider('gemini', 'Gemini');
    groq.shouldFail = true; // Simulate primary failure

    const health = new ProviderHealthTracker();
    const router = new ModelRouter([groq, gemini], health);

    const messages: ChatMessage[] = [{ role: 'user', content: 'hello' }];
    const res = await router.executeWithFallback(messages);

    expect(res.providerUsed).toBe('gemini');
    expect(res.fallbackUsed).toBe(true);
    expect(health.getHealth('groq').status).toBe('RATE_LIMITED');
  });
});
