import { ProviderHealth, ProviderHealthStatus, ProviderId } from '@lucifer/shared-types';

export class ProviderHealthTracker {
  private healthMap: Map<ProviderId, ProviderHealth> = new Map();

  constructor() {
    const defaultProviders: ProviderId[] = ['gemini', 'groq', 'openrouter', 'cloudflare_ai', 'ollama'];
    for (const p of defaultProviders) {
      this.healthMap.set(p, {
        providerId: p,
        status: 'UNKNOWN',
        consecutiveFailures: 0
      });
    }
  }

  public getHealth(providerId: ProviderId): ProviderHealth {
    return (
      this.healthMap.get(providerId) || {
        providerId,
        status: 'UNKNOWN',
        consecutiveFailures: 0
      }
    );
  }

  public getAllHealth(): ProviderHealth[] {
    return Array.from(this.healthMap.values());
  }

  public recordSuccess(providerId: ProviderId, latencyMs: number): void {
    const current = this.getHealth(providerId);
    this.healthMap.set(providerId, {
      ...current,
      status: 'HEALTHY',
      consecutiveFailures: 0,
      lastSuccessAt: Date.now(),
      cooldownUntil: undefined,
      latencyMs
    });
  }

  public recordFailure(
    providerId: ProviderId,
    error: Error | string,
    isRateLimit = false,
    isAuthError = false
  ): void {
    const current = this.getHealth(providerId);
    const failures = current.consecutiveFailures + 1;
    let status: ProviderHealthStatus = 'DEGRADED';
    let cooldownMs = 15000 * Math.min(failures, 4); // Exponential backoff max 60s

    if (isRateLimit) {
      status = 'RATE_LIMITED';
      cooldownMs = 60000; // 1 minute cooldown
    } else if (isAuthError) {
      status = 'AUTH_ERROR';
      cooldownMs = 300000; // 5 minutes cooldown
    } else if (failures >= 3) {
      status = 'UNAVAILABLE';
    }

    const errorMessage = typeof error === 'string' ? error : error.message;

    this.healthMap.set(providerId, {
      ...current,
      status,
      consecutiveFailures: failures,
      lastFailureAt: Date.now(),
      cooldownUntil: Date.now() + cooldownMs,
      lastErrorMessage: errorMessage
    });
  }

  public isAvailable(providerId: ProviderId): boolean {
    const current = this.getHealth(providerId);
    if (current.status === 'DISABLED' || current.status === 'AUTH_ERROR') {
      return false;
    }
    if (current.cooldownUntil && Date.now() < current.cooldownUntil) {
      return false;
    }
    return true;
  }
}
