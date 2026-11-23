import { ApprovalRecord, TaskRecord } from '@lucifer/shared-types';
import { DeviceAuthGuard } from '@lucifer/security';

export class LuciferDbRepository {
  private db: D1Database;

  constructor(db: D1Database) {
    this.db = db;
  }

  public async getOrCreateUser(telegramId: string, username?: string): Promise<{ id: string; telegramId: string }> {
    const existing = await this.db
      .prepare('SELECT id, telegram_id as telegramId FROM users WHERE telegram_id = ?')
      .bind(telegramId)
      .first<{ id: string; telegramId: string }>();

    if (existing) {
      return existing;
    }

    const id = `usr_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    const now = Date.now();
    await this.db
      .prepare('INSERT INTO users (id, telegram_id, username, created_at) VALUES (?, ?, ?, ?)')
      .bind(id, telegramId, username || null, now)
      .run();

    await this.db
      .prepare('INSERT INTO user_settings (user_id, timezone, budget_mode, auto_approve_tier1, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(id, 'Asia/Kolkata', 'FREE_ONLY', 1, now, now)
      .run();

    return { id, telegramId };
  }

  public async getOrCreateActiveConversation(userId: string): Promise<string> {
    const conv = await this.db
      .prepare('SELECT id FROM conversations WHERE user_id = ? ORDER BY updated_at DESC LIMIT 1')
      .bind(userId)
      .first<{ id: string }>();

    if (conv) return conv.id;

    const id = `conv_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    const now = Date.now();
    await this.db
      .prepare('INSERT INTO conversations (id, user_id, title, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
      .bind(id, userId, 'Default Conversation', now, now)
      .run();

    return id;
  }

  public async saveMessage(
    conversationId: string,
    role: string,
    content: string,
    toolCalls?: string,
    toolCallId?: string
  ): Promise<void> {
    const id = `msg_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    const now = Date.now();
    await this.db
      .prepare('INSERT INTO messages (id, conversation_id, role, content, tool_calls, tool_call_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .bind(id, conversationId, role, content, toolCalls || null, toolCallId || null, now)
      .run();

    await this.db
      .prepare('UPDATE conversations SET updated_at = ? WHERE id = ?')
      .bind(now, conversationId)
      .run();
  }

  public async getRecentMessages(conversationId: string, limit = 10): Promise<Array<{ role: string; content: string }>> {
    const rows = await this.db
      .prepare('SELECT role, content FROM messages WHERE conversation_id = ? ORDER BY created_at ASC LIMIT ?')
      .bind(conversationId, limit)
      .all<{ role: string; content: string }>();

    return rows.results || [];
  }

  // Tasks
  public async createTask(task: TaskRecord): Promise<void> {
    await this.db
      .prepare(`INSERT INTO tasks (
        id, owner_id, description, type, priority, status, execution_target,
        required_tools, approval_id, progress, retries, max_retries, result, error,
        correlation_id, payload, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(
        task.id,
        task.ownerId,
        task.description,
        task.type,
        task.priority,
        task.status,
        task.executionTarget,
        JSON.stringify(task.requiredTools || []),
        task.approvalId || null,
        task.progress,
        task.retries,
        task.maxRetries,
        task.result || null,
        task.error || null,
        task.correlationId,
        task.payload ? JSON.stringify(task.payload) : null,
        task.createdAt,
        task.updatedAt
      )
      .run();
  }

  public async getTask(taskId: string): Promise<TaskRecord | null> {
    const row = await this.db
      .prepare('SELECT * FROM tasks WHERE id = ?')
      .bind(taskId)
      .first<any>();

    if (!row) return null;
    return {
      id: row.id,
      ownerId: row.owner_id,
      description: row.description,
      type: row.type,
      priority: row.priority,
      status: row.status,
      executionTarget: row.execution_target,
      requiredTools: JSON.parse(row.required_tools || '[]'),
      approvalId: row.approval_id,
      progress: row.progress,
      retries: row.retries,
      maxRetries: row.max_retries,
      result: row.result,
      error: row.error,
      correlationId: row.correlation_id,
      payload: row.payload ? JSON.parse(row.payload) : undefined,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  public async updateTaskStatus(
    taskId: string,
    status: string,
    result?: string,
    error?: string,
    progress?: number
  ): Promise<void> {
    const now = Date.now();
    await this.db
      .prepare('UPDATE tasks SET status = ?, result = COALESCE(?, result), error = COALESCE(?, error), progress = COALESCE(?, progress), updated_at = ? WHERE id = ?')
      .bind(status, result || null, error || null, progress ?? null, now, taskId)
      .run();
  }

  public async listTasks(ownerId: string, limit = 5, status?: string): Promise<TaskRecord[]> {
    let query = 'SELECT * FROM tasks WHERE owner_id = ?';
    const params: any[] = [ownerId];
    if (status) {
      query += ' AND status = ?';
      params.push(status);
    }
    query += ' ORDER BY created_at DESC LIMIT ?';
    params.push(limit);

    const rows = await this.db.prepare(query).bind(...params).all<any>();
    return (rows.results || []).map((row: any) => ({
      id: row.id,
      ownerId: row.owner_id,
      description: row.description,
      type: row.type,
      priority: row.priority,
      status: row.status,
      executionTarget: row.execution_target,
      requiredTools: JSON.parse(row.required_tools || '[]'),
      progress: row.progress,
      retries: row.retries,
      maxRetries: row.max_retries,
      result: row.result,
      error: row.error,
      correlationId: row.correlation_id,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    }));
  }

  // Approvals
  public async createApproval(approval: ApprovalRecord): Promise<void> {
    await this.db
      .prepare('INSERT INTO approvals (id, task_id, user_id, action_name, action_details, state, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(
        approval.id,
        approval.taskId,
        approval.userId,
        approval.actionName,
        JSON.stringify(approval.actionDetails),
        approval.state,
        approval.createdAt,
        approval.expiresAt
      )
      .run();
  }

  public async getApproval(approvalId: string): Promise<ApprovalRecord | null> {
    const row = await this.db
      .prepare('SELECT * FROM approvals WHERE id = ?')
      .bind(approvalId)
      .first<any>();

    if (!row) return null;
    return {
      id: row.id,
      taskId: row.task_id,
      userId: row.user_id,
      actionName: row.action_name,
      actionDetails: JSON.parse(row.action_details || '{}'),
      state: row.state,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
      decidedAt: row.decided_at,
      decisionReason: row.decision_reason
    };
  }

  public async updateApprovalState(
    approvalId: string,
    state: string,
    reason?: string
  ): Promise<void> {
    const now = Date.now();
    await this.db
      .prepare('UPDATE approvals SET state = ?, decided_at = ?, decision_reason = ? WHERE id = ?')
      .bind(state, now, reason || null, approvalId)
      .run();
  }

  // Memories
  public async saveMemory(userId: string, key: string, value: string, category = 'general'): Promise<void> {
    const now = Date.now();
    const id = `mem_${now}_${Math.random().toString(36).slice(2, 6)}`;
    await this.db
      .prepare('INSERT INTO memories (id, user_id, key, value, category, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET value = ?, updated_at = ?')
      .bind(id, userId, key, value, category, now, now, value, now)
      .run();
  }

  public async getMemories(userId: string): Promise<Array<{ key: string; value: string; category: string }>> {
    const rows = await this.db
      .prepare('SELECT key, value, category FROM memories WHERE user_id = ? ORDER BY updated_at DESC LIMIT 20')
      .bind(userId)
      .all<{ key: string; value: string; category: string }>();

    return rows.results || [];
  }

  public async deleteMemory(userId: string, key: string): Promise<number> {
    const res = await this.db
      .prepare('DELETE FROM memories WHERE user_id = ? AND key = ?')
      .bind(userId, key)
      .run();
    return res.meta?.changes || 0;
  }

  // Device & Outbound Polling
  public async upsertDevice(
    deviceId: string,
    ownerId: string,
    deviceName: string,
    authSecretHash: string,
    infoJson?: string
  ): Promise<void> {
    const now = Date.now();
    await this.db
      .prepare(`INSERT INTO devices (device_id, owner_id, device_name, auth_secret_hash, is_active, last_heartbeat, device_info, created_at)
        VALUES (?, ?, ?, ?, 1, ?, ?, ?)
        ON CONFLICT(device_id) DO UPDATE SET
          last_heartbeat = ?,
          device_info = COALESCE(?, device_info),
          auth_secret_hash = CASE WHEN ? != '' THEN ? ELSE auth_secret_hash END,
          is_active = 1`)
      .bind(deviceId, ownerId, deviceName, authSecretHash, now, infoJson || null, now, now, infoJson || null, authSecretHash, authSecretHash)
      .run();
  }

  /**
   * Validates device authentication against stored SHA-256 hash
   */
  public async checkDeviceAuth(
    deviceId: string,
    presentedToken: string | null | undefined
  ): Promise<{ authorized: boolean; ownerId?: string }> {
    if (!deviceId || !presentedToken) {
      return { authorized: false };
    }

    const device = await this.db
      .prepare('SELECT device_id, owner_id, auth_secret_hash, is_active FROM devices WHERE device_id = ?')
      .bind(deviceId)
      .first<{ device_id: string; owner_id: string; auth_secret_hash: string; is_active: number }>();

    if (!device || device.is_active !== 1) {
      return { authorized: false };
    }

    const isValid = await DeviceAuthGuard.verifyToken(presentedToken, device.auth_secret_hash);
    if (!isValid) {
      return { authorized: false };
    }

    return { authorized: true, ownerId: device.owner_id };
  }

  /**
   * Verifies if a given device currently holds the lease for a task
   */
  public async verifyTaskOwnership(taskId: string, deviceId: string): Promise<boolean> {
    const lease = await this.db
      .prepare('SELECT task_id, device_id FROM task_leases WHERE task_id = ? AND device_id = ?')
      .bind(taskId, deviceId)
      .first<{ task_id: string; device_id: string }>();

    return Boolean(lease);
  }

  /**
   * Atomically records update_id to prevent duplicate update execution
   */
  public async markUpdateProcessed(updateId: number): Promise<boolean> {
    try {
      await this.db
        .prepare('INSERT INTO processed_updates (update_id, processed_at) VALUES (?, ?)')
        .bind(updateId, Date.now())
        .run();
      return true;
    } catch {
      // Primary key constraint collision means duplicate update
      return false;
    }
  }

  /**
   * Atomically leases the next available task using a conditional UPDATE
   */
  public async leaseNextLocalTask(deviceId: string): Promise<TaskRecord | null> {
    const now = Date.now();
    const candidate = await this.db
      .prepare(`SELECT id FROM tasks
        WHERE execution_target = 'LOCAL_MAC'
          AND status IN ('PENDING', 'QUEUED')
        ORDER BY priority = 'CRITICAL' DESC, priority = 'HIGH' DESC, created_at ASC
        LIMIT 1`)
      .first<{ id: string }>();

    if (!candidate) return null;

    // Atomic conditional status transition
    const updateResult = await this.db
      .prepare("UPDATE tasks SET status = 'RUNNING', updated_at = ? WHERE id = ? AND status IN ('PENDING', 'QUEUED')")
      .bind(now, candidate.id)
      .run();

    if (!updateResult.meta || updateResult.meta.changes === 0) {
      return null;
    }

    const leaseExpires = now + 60000; // 60-second lease
    await this.db
      .prepare('INSERT OR REPLACE INTO task_leases (task_id, device_id, leased_at, expires_at) VALUES (?, ?, ?, ?)')
      .bind(candidate.id, deviceId, now, leaseExpires)
      .run();

    return this.getTask(candidate.id);
  }

  // Audit Logs
  public async logAudit(
    userId: string | undefined,
    action: string,
    resource: string | undefined,
    status: 'SUCCESS' | 'DENIED' | 'FLAGGED',
    riskTier: string,
    details?: Record<string, unknown>
  ): Promise<void> {
    const id = `aud_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
    await this.db
      .prepare('INSERT INTO audit_logs (id, user_id, action, resource, status, risk_tier, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(id, userId || null, action, resource || null, status, riskTier, details ? JSON.stringify(details) : null, Date.now())
      .run();
  }
}
