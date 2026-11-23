/**
 * Protects against Server-Side Request Forgery (SSRF)
 * Rejects private, loopback, link-local, and cloud metadata addresses.
 */
export class SsrfFilter {
  private static PRIVATE_IP_RANGES = [
    /^127\./,                         // Loopback IPv4
    /^10\./,                          // RFC 1918 Class A
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // RFC 1918 Class B
    /^192\.168\./,                    // RFC 1918 Class C
    /^169\.254\./,                    // IPv4 Link-local / AWS / GCP / Azure metadata
    /^0\./,                           // Zero addresses
    /^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\./, // CGNAT
  ];

  /**
   * Validates if a target URL is safe to fetch outbound
   */
  public static isSafeUrl(rawUrl: string): { safe: boolean; reason?: string } {
    try {
      const parsed = new URL(rawUrl);

      // Enforce protocol
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return { safe: false, reason: `Disallowed protocol: ${parsed.protocol}` };
      }

      const hostname = parsed.hostname.toLowerCase();

      // Block localhost, local, internal domain names
      if (
        hostname === 'localhost' ||
        hostname.endsWith('.localhost') ||
        hostname.endsWith('.local') ||
        hostname.endsWith('.internal') ||
        hostname === 'metadata.google.internal' ||
        hostname === 'instance-data'
      ) {
        return { safe: false, reason: `Blocked hostname: ${hostname}` };
      }

      // Check IPv6 loopback / unspecified
      if (hostname === '::1' || hostname === '::' || hostname.startsWith('fe80:') || hostname.startsWith('fc00:')) {
        return { safe: false, reason: 'Private or loopback IPv6 address' };
      }

      // Check IPv4 private ranges
      for (const pattern of this.PRIVATE_IP_RANGES) {
        if (pattern.test(hostname)) {
          return { safe: false, reason: `Target IP belongs to private/metadata range: ${hostname}` };
        }
      }

      return { safe: true };
    } catch {
      return { safe: false, reason: 'Malformed URL' };
    }
  }
}
