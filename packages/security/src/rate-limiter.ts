/**
 * Memory-based sliding window rate limiter with bounded memory allocation.
 * Protects Worker isolates against unbounded Map growth (DoS) via maxKeys and LRU eviction.
 */
export class SlidingWindowRateLimiter {
  private requests: Map<string, number[]> = new Map();
  private maxRequests: number;
  private windowMs: number;
  private maxKeys: number;

  constructor(maxRequests = 30, windowMs = 60000, maxKeys = 1000) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
    this.maxKeys = maxKeys;
  }

  public isAllowed(key: string): { allowed: boolean; remaining: number; retryAfterMs: number } {
    const now = Date.now();
    const timestamps = this.requests.get(key) || [];

    // Filter out timestamps outside the active window
    const validTimestamps = timestamps.filter((t) => now - t < this.windowMs);

    if (validTimestamps.length >= this.maxRequests) {
      const oldest = validTimestamps[0];
      const retryAfterMs = Math.max(0, this.windowMs - (now - oldest));
      return { allowed: false, remaining: 0, retryAfterMs };
    }

    // Bounded memory enforcement: if inserting a new key and Map is full, evict oldest key
    if (!this.requests.has(key) && this.requests.size >= this.maxKeys) {
      // Find and delete the first/oldest key
      const oldestKey = this.requests.keys().next().value;
      if (oldestKey) {
        this.requests.delete(oldestKey);
      }
    }

    validTimestamps.push(now);
    this.requests.set(key, validTimestamps);

    return {
      allowed: true,
      remaining: this.maxRequests - validTimestamps.length,
      retryAfterMs: 0
    };
  }

  public reset(key: string): void {
    this.requests.delete(key);
  }

  public clear(): void {
    this.requests.clear();
  }
}
