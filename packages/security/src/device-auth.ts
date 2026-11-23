/**
 * Secure device authentication utilities
 * Provides constant-time token comparison, SHA-256 token hashing,
 * and header token extraction.
 */
export class DeviceAuthGuard {
  /**
   * Hashes a device secret using SHA-256 (Web Crypto compatible)
   */
  public static async hashToken(token: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(token.trim());
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Verifies a presented raw token against a stored SHA-256 hash
   * in constant time to prevent timing side-channel attacks.
   */
  public static async verifyToken(presentedToken: string | undefined | null, storedHash: string): Promise<boolean> {
    if (!presentedToken || !storedHash) return false;
    const computedHash = await this.hashToken(presentedToken);
    return this.constantTimeCompare(computedHash, storedHash);
  }

  /**
   * Extracts a Bearer or device token from Authorization or X-Device-Token header
   */
  public static extractToken(authHeader: string | null | undefined, customHeader?: string | null): string | null {
    if (customHeader && customHeader.trim().length > 0) {
      return customHeader.trim();
    }
    if (!authHeader) return null;
    const match = authHeader.match(/^Bearer\s+(.+)$/i);
    return match ? match[1].trim() : null;
  }

  /**
   * Constant-time string comparison
   */
  public static constantTimeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false;
    }
    let mismatch = 0;
    for (let i = 0; i < a.length; i++) {
      mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return mismatch === 0;
  }
}
