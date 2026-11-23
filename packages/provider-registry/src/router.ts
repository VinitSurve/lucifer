import {
  ChatMessage,
  GenerateOptions,
  GenerateResult,
  PrivacyClassification,
  ProviderId,
  TaskClass
} from '@lucifer/shared-types';
import { AIProvider } from './types';
import { ProviderHealthTracker } from './health-tracker';

export interface RouterConfig {
  budgetMode: 'FREE_ONLY' | 'ALL';
  defaultPrivacyLevel?: PrivacyClassification;
}

export interface RoutePlan {
  taskClass: TaskClass;
  privacy: PrivacyClassification;
  selectedProvider: ProviderId;
  fallbackChain: ProviderId[];
  candidateScores: Record<string, number>;
}

export class ModelRouter {
  private providers: Map<ProviderId, AIProvider> = new Map();
  private healthTracker: ProviderHealthTracker;
  private config: RouterConfig;

  constructor(
    providers: AIProvider[],
    healthTracker: ProviderHealthTracker,
    config: RouterConfig = { budgetMode: 'FREE_ONLY' }
  ) {
    for (const p of providers) {
      this.providers.set(p.id, p);
    }
    this.healthTracker = healthTracker;
    this.config = config;
  }

  /**
   * Deterministic fast classifier for incoming messages
   */
  public classifyTask(text: string, options?: GenerateOptions): { taskClass: TaskClass; privacy: PrivacyClassification } {
    const lower = text.toLowerCase();

    // Check private / local-only triggers
    if (
      lower.includes('local model') ||
      lower.includes('run locally') ||
      lower.includes('private task') ||
      lower.includes('my password') ||
      lower.includes('ssh key')
    ) {
      return { taskClass: 'PRIVATE', privacy: 'LOCAL_ONLY' };
    }

    // Check research
    if (
      lower.includes('search') ||
      lower.includes('research') ||
      lower.includes('latest news') ||
      lower.includes('what happened') ||
      lower.startsWith('find ')
    ) {
      return { taskClass: 'RESEARCH', privacy: 'NORMAL' };
    }

    // Check coding
    if (
      lower.includes('code') ||
      lower.includes('function') ||
      lower.includes('bug') ||
      lower.includes('script') ||
      lower.includes('test') ||
      lower.includes('refactor') ||
      lower.includes('typescript') ||
      lower.includes('python')
    ) {
      return { taskClass: 'CODING', privacy: 'NORMAL' };
    }

    // Check fast greetings & short prompts
    if (
      lower.startsWith('hi') ||
      lower.startsWith('hello') ||
      lower.startsWith('hey') ||
      lower === '/start' ||
      text.length < 25
    ) {
      return { taskClass: 'FAST', privacy: 'NORMAL' };
    }

    if (options?.tools && options.tools.length > 0) {
      return { taskClass: 'TOOL_EXECUTION', privacy: 'NORMAL' };
    }

    return { taskClass: 'STANDARD', privacy: 'NORMAL' };
  }

  /**
   * Evaluates candidates and creates a prioritized route plan
   */
  public createRoutePlan(
    taskClass: TaskClass,
    privacy: PrivacyClassification,
    requiresTools = false
  ): RoutePlan {
    // If strictly local / private, route only to Ollama
    if (privacy === 'LOCAL_ONLY' || taskClass === 'PRIVATE') {
      return {
        taskClass,
        privacy,
        selectedProvider: 'ollama',
        fallbackChain: [],
        candidateScores: { ollama: 100 }
      };
    }

    const scores: Record<string, number> = {};

    for (const [id, provider] of this.providers.entries()) {
      if (!provider.isConfigured()) continue;

      let score = 50;

      // Check health
      const isAvail = this.healthTracker.isAvailable(id);
      if (!isAvail) {
        score -= 40;
      }

      // Check models capability
      const models = provider.getModels();
      const freeModel = models.find((m) => m.isFreeTier);

      if (this.config.budgetMode === 'FREE_ONLY' && !freeModel) {
        continue; // Exclude non-free
      }

      const toolModel = models.find((m) => m.supportsTools);
      if (requiresTools && !toolModel) {
        score -= 30;
      }

      // Task class optimizations
      if (taskClass === 'FAST') {
        if (id === 'groq') score += 35; // Groq is fastest
        if (id === 'gemini') score += 20;
      } else if (taskClass === 'CODING' || taskClass === 'REASONING') {
        if (id === 'gemini') score += 30; // 2.0 Flash is strongest
        if (id === 'groq') score += 25; // 70B is strong
      } else if (taskClass === 'RESEARCH') {
        if (id === 'gemini') score += 35; // Gemini has search grounding
        if (id === 'groq') score += 15;
      } else {
        // Standard
        if (id === 'gemini') score += 25;
        if (id === 'groq') score += 25;
        if (id === 'openrouter') score += 15;
        if (id === 'cloudflare_ai') score += 15;
      }

      scores[id] = score;
    }

    const sortedProviders = Object.entries(scores)
      .sort(([, a], [, b]) => b - a)
      .map(([id]) => id as ProviderId);

    const selectedProvider = sortedProviders[0] || 'ollama';
    const fallbackChain = sortedProviders.slice(1);

    return {
      taskClass,
      privacy,
      selectedProvider,
      fallbackChain,
      candidateScores: scores
    };
  }

  /**
   * Executes prompt with intelligent fallback
   */
  public async executeWithFallback(
    messages: ChatMessage[],
    options?: GenerateOptions,
    explicitPrivacy?: PrivacyClassification
  ): Promise<GenerateResult & { fallbackUsed?: boolean }> {
    const lastUserMsg = messages.filter((m) => m.role === 'user').pop()?.content || '';
    const { taskClass, privacy } = this.classifyTask(lastUserMsg, options);
    const effectivePrivacy = explicitPrivacy || privacy;
    const requiresTools = Boolean(options?.tools && options.tools.length > 0);

    const plan = this.createRoutePlan(taskClass, effectivePrivacy, requiresTools);
    const candidateChain = [plan.selectedProvider, ...plan.fallbackChain];

    let lastError: Error | null = null;
    let attemptedCount = 0;

    for (const providerId of candidateChain) {
      const provider = this.providers.get(providerId);
      if (!provider) continue;

      attemptedCount++;
      const startTime = Date.now();

      try {
        const result = await provider.generate(messages, {
          ...options,
          taskClass
        });

        this.healthTracker.recordSuccess(providerId, Date.now() - startTime);
        return {
          ...result,
          fallbackUsed: attemptedCount > 1
        };
      } catch (err: any) {
        lastError = err;
        const isRateLimit = String(err.message).includes('429') || String(err.message).toLowerCase().includes('rate');
        const isAuth = String(err.message).includes('401') || String(err.message).includes('403');
        this.healthTracker.recordFailure(providerId, err, isRateLimit, isAuth);
        // Continue loop to try next fallback
      }
    }

    throw new Error(
      `All AI providers failed. Candidates attempted: [${candidateChain.join(', ')}]. Last error: ${lastError?.message}`
    );
  }
}
