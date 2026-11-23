export type TaskClass =
  | 'FAST'
  | 'CLASSIFICATION'
  | 'EXTRACTION'
  | 'SUMMARIZATION'
  | 'STANDARD'
  | 'RESEARCH'
  | 'REASONING'
  | 'CODING'
  | 'VISION'
  | 'LONG_CONTEXT'
  | 'PRIVATE'
  | 'TOOL_EXECUTION';

export type ProviderId = 'gemini' | 'groq' | 'openrouter' | 'cloudflare_ai' | 'ollama';

export type ProviderHealthStatus =
  | 'HEALTHY'
  | 'DEGRADED'
  | 'RATE_LIMITED'
  | 'AUTH_ERROR'
  | 'UNAVAILABLE'
  | 'DISABLED'
  | 'UNKNOWN';

export interface ProviderHealth {
  providerId: ProviderId;
  status: ProviderHealthStatus;
  lastSuccessAt?: number;
  lastFailureAt?: number;
  consecutiveFailures: number;
  cooldownUntil?: number;
  lastErrorMessage?: string;
  latencyMs?: number;
}

export interface ModelDescriptor {
  id: string;
  providerId: ProviderId;
  displayName: string;
  contextWindow: number;
  maxOutputTokens: number;
  supportsTools: boolean;
  supportsVision: boolean;
  supportsJson: boolean;
  isFreeTier: boolean;
  costPer1kInputTokens: number; // 0 for free
  costPer1kOutputTokens: number; // 0 for free
  averageLatencyMs: number;
  qualityScore: number; // 1 to 10
}

export interface ChatMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string;
  toolCallId?: string;
  toolCalls?: Array<{
    id: string;
    type: 'function';
    function: {
      name: string;
      arguments: string;
    };
  }>;
}

export interface GenerateOptions {
  taskClass?: TaskClass;
  temperature?: number;
  maxTokens?: number;
  tools?: Array<{
    name: string;
    description: string;
    parameters: Record<string, unknown>;
  }>;
  jsonOutput?: boolean;
  timeoutMs?: number;
}

export interface GenerateResult {
  content: string;
  modelUsed: string;
  providerUsed: ProviderId;
  toolCalls?: Array<{
    id: string;
    name: string;
    arguments: Record<string, unknown>;
  }>;
  usage?: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
  };
  latencyMs: number;
}
