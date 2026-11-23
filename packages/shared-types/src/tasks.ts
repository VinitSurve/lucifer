export type TaskStatus =
  | 'PENDING'
  | 'QUEUED'
  | 'RUNNING'
  | 'WAITING_APPROVAL'
  | 'WAITING_FOR_LOCAL_AGENT'
  | 'RETRYING'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED';

export type TaskPriority = 'LOW' | 'NORMAL' | 'HIGH' | 'CRITICAL';

export interface TaskRecord {
  id: string;
  ownerId: string;
  description: string;
  type: string;
  priority: TaskPriority;
  status: TaskStatus;
  createdAt: number;
  updatedAt: number;
  scheduledTime?: number;
  executionTarget: 'CLOUD' | 'LOCAL_MAC';
  requiredTools: string[];
  approvalId?: string;
  progress: number; // 0 to 100
  retries: number;
  maxRetries: number;
  result?: string;
  error?: string;
  correlationId: string;
  payload?: Record<string, unknown>;
}

export type ApprovalState = 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED';

export interface ApprovalRecord {
  id: string;
  taskId: string;
  userId: string;
  actionName: string;
  actionDetails: Record<string, unknown>;
  state: ApprovalState;
  createdAt: number;
  expiresAt: number;
  decidedAt?: number;
  decisionReason?: string;
}

export type ToolRiskTier =
  | 'TIER_0_READ_ONLY'   // Auto-approved, safe read operations
  | 'TIER_1_LOW_RISK'    // Low-risk writes or triggers, allowed by policy
  | 'TIER_2_SENSITIVE'   // Modifies email, calendar, public repos -> Requires confirmation
  | 'TIER_3_DANGEROUS';  // Shell commands, deletions, system changes -> Strict explicit approval

export interface ToolParameterSchema {
  type: string;
  description?: string;
  properties?: Record<string, {
    type: string;
    description: string;
    enum?: string[];
  }>;
  required?: string[];
  [key: string]: unknown;
}

export interface ToolDefinition {
  name: string;
  description: string;
  riskTier: ToolRiskTier;
  executionTarget: 'CLOUD' | 'LOCAL_MAC' | 'ANY';
  parameters: ToolParameterSchema;
  timeoutMs: number;
}

export interface ToolCall {
  id: string;
  name: string;
  arguments: Record<string, unknown>;
}

export interface ToolResult {
  toolCallId: string;
  name: string;
  success: boolean;
  output?: unknown;
  error?: string;
  sourceUrl?: string;
}
