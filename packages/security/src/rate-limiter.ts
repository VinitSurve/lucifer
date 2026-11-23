/**
 * Memory-based sliding window rate limiter
 */
export class SlidingWindowRateLimiter {
  private requests: Map<string, number[]> = new Map();
  private maxRequests: number;
  private windowMs: number;

  constructor(maxRequests = 30, windowMs = 60000) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
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
}
