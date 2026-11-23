import {
  ChatMessage,
  GenerateOptions,
  GenerateResult,
  ModelDescriptor,
  ProviderHealth,
  ProviderId
} from '@lucifer/shared-types';

export interface AIProvider {
  id: ProviderId;
  name: string;
  isConfigured(): boolean;
  getModels(): ModelDescriptor[];
  generate(messages: ChatMessage[], options?: GenerateOptions): Promise<GenerateResult>;
  healthCheck(): Promise<ProviderHealth>;
}
