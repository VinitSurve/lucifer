import { ToolRiskTier } from '@lucifer/shared-types';

export interface PermissionCheckResult {
  allowed: boolean;
  requiresApproval: boolean;
  tier: ToolRiskTier;
  reason?: string;
}

export class ToolPermissionGuard {
  /**
   * Evaluates if a tool can run automatically or requires human confirmation.
   * Defaults to secure behavior (userAutoApproveTier1 = false).
   */
  public static evaluate(riskTier: ToolRiskTier, userAutoApproveTier1 = false): PermissionCheckResult {
    switch (riskTier) {
      case 'TIER_0_READ_ONLY':
        return {
          allowed: true,
          requiresApproval: false,
          tier: riskTier
        };

      case 'TIER_1_LOW_RISK':
        return {
          allowed: true,
          requiresApproval: !userAutoApproveTier1,
          tier: riskTier
        };

      case 'TIER_2_SENSITIVE':
        return {
          allowed: false,
          requiresApproval: true,
          tier: riskTier,
          reason: 'Sensitive action modifying user data or resources requires confirmation'
        };

      case 'TIER_3_DANGEROUS':
        return {
          allowed: false,
          requiresApproval: true,
          tier: riskTier,
          reason: 'Dangerous local execution requires explicit owner authorization'
        };

      default:
        return {
          allowed: false,
          requiresApproval: true,
          tier: 'TIER_3_DANGEROUS',
          reason: 'Unknown risk tier defaults to strict approval'
        };
    }
  }
}
