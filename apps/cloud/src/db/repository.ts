import { ApprovalRecord, TaskRecord } from '@lucifer/shared-types';
import { DeviceAuthGuard, SecretRedactor } from '@lucifer/security';

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
      .bind(id, 'Asia/Kolkata', 'FREE_ONLY', 0, now, now)
      .run();

    return { id, telegramId };
  }

  /**
   * Retrieves whether Tier 1 actions are auto-approved for a user.
   * Defaults to false (secure fail-closed) if setting row is absent or null.
   */
  public async getUserTier1AutoApprove(userId: string): Promise<boolean> {
    const row = await this.db
      .prepare('SELECT auto_approve_tier1 FROM user_settings WHERE user_id = ?')
      .bind(userId)
      .first<{ auto_approve_tier1: number | null | undefined }>();
    if (!row || row.auto_approve_tier1 === null || row.auto_approve_tier1 === undefined) {
      return false; // Secure default fallback
    }
    return Number(row.auto_approve_tier1) === 1;
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
    // Sanitize credentials from content before database persistence
    const sanitizedContent = SecretRedactor.redact(content);
    await this.db
      .prepare('INSERT INTO messages (id, conversation_id, role, content, tool_calls, tool_call_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .bind(id, conversationId, role, sanitizedContent, toolCalls || null, toolCallId || null, now)
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
    const sanitizedDesc = SecretRedactor.redact(task.description);
    const sanitizedPayload = task.payload ? SecretRedactor.redact(JSON.stringify(task.payload)) : null;

    await this.db
      .prepare(`INSERT INTO tasks (
        id, owner_id, description, type, priority, status, execution_target,
        required_tools, approval_id, progress, retries, max_retries, result, error,
        correlation_id, payload, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(
        task.id,
        task.ownerId,
        sanitizedDesc,
        task.type,
        task.priority,
        task.status,
        task.executionTarget,
        JSON.stringify(task.requiredTools || []),
        task.approvalId || null,
        task.progress,
        task.retries,
        task.maxRetries,
        task.result ? SecretRedactor.redact(task.result) : null,
        task.error ? SecretRedactor.redact(task.error) : null,
        task.correlationId,
        sanitizedPayload,
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
    const sanitizedResult = result ? SecretRedactor.redact(result) : null;
    const sanitizedError = error ? SecretRedactor.redact(error) : null;

    await this.db
      .prepare('UPDATE tasks SET status = ?, result = COALESCE(?, result), error = COALESCE(?, error), progress = COALESCE(?, progress), updated_at = ? WHERE id = ?')
      .bind(status, sanitizedResult, sanitizedError, progress ?? null, now, taskId)
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

    const rows = await this.db
      .prepare(query)
      .bind(...params)
      .all<any>();

    return (rows.results || []).map((row) => ({
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
    }));
  }

  // Approvals
  public async createApproval(approval: ApprovalRecord): Promise<void> {
    await this.db
      .prepare(`INSERT INTO approvals (
        id, task_id, user_id, action_name, action_details, state, created_at, expires_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
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
    const sanitizedVal = SecretRedactor.redact(value);
    await this.db
      .prepare('INSERT INTO memories (id, user_id, key, value, category, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET value = ?, updated_at = ?')
      .bind(id, userId, key, sanitizedVal, category, now, now, sanitizedVal, now)
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

  // =========================================================================
  // DEVICE PAIRING & AUTHENTICATION (CHECKPOINT B)
  // =========================================================================

  public async getDevice(deviceId: string): Promise<{ device_id: string; owner_id: string; auth_secret_hash: string; is_active: number } | null> {
    const row = await this.db
      .prepare('SELECT device_id, owner_id, auth_secret_hash, is_active FROM devices WHERE device_id = ?')
      .bind(deviceId)
      .first<{ device_id: string; owner_id: string; auth_secret_hash: string; is_active: number }>();
    return row || null;
  }

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

  public async rotateDeviceToken(deviceId: string, newSecretHash: string): Promise<boolean> {
    const now = Date.now();
    const res = await this.db
      .prepare('UPDATE devices SET auth_secret_hash = ?, last_heartbeat = ? WHERE device_id = ? AND is_active = 1')
      .bind(newSecretHash, now, deviceId)
      .run();
    return Boolean(res.meta && res.meta.changes > 0);
  }

  public async revokeDevice(deviceId: string): Promise<boolean> {
    const res = await this.db
      .prepare('UPDATE devices SET is_active = 0 WHERE device_id = ?')
      .bind(deviceId)
      .run();
    return Boolean(res.meta && res.meta.changes > 0);
  }

  public async createPairingCode(ownerId: string, code: string, ttlSeconds = 300): Promise<void> {
    const codeHash = await DeviceAuthGuard.hashToken(code);
    const now = Date.now();
    const expiresAt = now + ttlSeconds * 1000;
    await this.db
      .prepare('INSERT INTO pairing_codes (code_hash, owner_id, expires_at) VALUES (?, ?, ?)')
      .bind(codeHash, ownerId, expiresAt)
      .run();
  }

  public async consumePairingCode(code: string): Promise<{ valid: boolean; ownerId?: string }> {
    const codeHash = await DeviceAuthGuard.hashToken(code);
    const now = Date.now();
    const row = await this.db
      .prepare('SELECT code_hash, owner_id, expires_at, used_at FROM pairing_codes WHERE code_hash = ?')
      .bind(codeHash)
      .first<{ code_hash: string; owner_id: string; expires_at: number; used_at: number | null }>();

    if (!row || row.used_at !== null || row.expires_at < now) {
      return { valid: false };
    }

    const res = await this.db
      .prepare('UPDATE pairing_codes SET used_at = ? WHERE code_hash = ? AND used_at IS NULL')
      .bind(now, codeHash)
      .run();

    if (!res.meta || res.meta.changes === 0) {
      return { valid: false };
    }
    return { valid: true, ownerId: row.owner_id };
  }

  public async checkDeviceAuth(
    deviceId: string,
    presentedToken: string | null | undefined
  ): Promise<{ authorized: boolean; ownerId?: string }> {
    if (!deviceId || !presentedToken) {
      return { authorized: false };
    }

    const device = await this.getDevice(deviceId);
    if (!device || device.is_active !== 1) {
      return { authorized: false };
    }

    const isValid = await DeviceAuthGuard.verifyToken(presentedToken, device.auth_secret_hash);
    if (!isValid) {
      return { authorized: false };
    }

    return { authorized: true, ownerId: device.owner_id };
  }

  // =========================================================================
  // TASK LEASE LIFECYCLE & RECOVERY REAPER (CHECKPOINT C)
  // =========================================================================

  /**
   * Reclaims expired leases by resetting recoverable tasks to QUEUED and marking
   * retry-exhausted tasks as FAILED. Cleans up stale lease records.
   */
  public async reclaimExpiredLeases(): Promise<{ recovered: number; failed: number }> {
    const now = Date.now();
    // 1. Recover expired leases with retries remaining
    const recRes = await this.db
      .prepare(`UPDATE tasks SET status = 'QUEUED', retries = retries + 1, updated_at = ?
        WHERE execution_target = 'LOCAL_MAC'
          AND status = 'RUNNING'
          AND id IN (SELECT task_id FROM task_leases WHERE expires_at < ?)
          AND retries < max_retries`)
      .bind(now, now)
      .run();
    const recovered = recRes.meta?.changes || 0;

    // 2. Fail expired leases that exceeded max_retries
    const failRes = await this.db
      .prepare(`UPDATE tasks SET status = 'FAILED', error = 'Task lease expired and exceeded max retries', updated_at = ?
        WHERE execution_target = 'LOCAL_MAC'
          AND status = 'RUNNING'
          AND id IN (SELECT task_id FROM task_leases WHERE expires_at < ?)
          AND retries >= max_retries`)
      .bind(now, now)
      .run();
    const failed = failRes.meta?.changes || 0;

    // 3. Delete expired lease records
    await this.db
      .prepare('DELETE FROM task_leases WHERE expires_at < ?')
      .bind(now)
      .run();

    return { recovered, failed };
  }

  /**
   * Atomically leases next available task after reclaiming any expired leases.
   */
  public async leaseNextLocalTask(deviceId: string): Promise<TaskRecord | null> {
    const now = Date.now();
    // Step 1: Reclaim expired leases first
    await this.reclaimExpiredLeases();

    // Step 2: Select candidate pending/queued task
    const candidate = await this.db
      .prepare(`SELECT id FROM tasks
        WHERE execution_target = 'LOCAL_MAC'
          AND status IN ('PENDING', 'QUEUED')
        ORDER BY priority = 'CRITICAL' DESC, priority = 'HIGH' DESC, created_at ASC
        LIMIT 1`)
      .first<{ id: string }>();

    if (!candidate) return null;

    // Step 3: Atomic conditional status transition
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

  /**
   * Verifies if a given device currently holds an ACTIVE, UNEXPIRED lease for a task.
   */
  public async verifyTaskOwnership(taskId: string, deviceId: string): Promise<boolean> {
    const now = Date.now();
    const lease = await this.db
      .prepare('SELECT task_id, device_id, expires_at FROM task_leases WHERE task_id = ? AND device_id = ? AND expires_at > ?')
      .bind(taskId, deviceId, now)
      .first<{ task_id: string; device_id: string; expires_at: number }>();

    return Boolean(lease);
  }

  /**
   * Renews an active task lease by extensionMs if the lease is currently active.
   */
  public async renewTaskLease(taskId: string, deviceId: string, extensionMs = 60000): Promise<boolean> {
    const now = Date.now();
    const newExpiry = now + extensionMs;
    const res = await this.db
      .prepare('UPDATE task_leases SET expires_at = ? WHERE task_id = ? AND device_id = ? AND expires_at > ?')
      .bind(newExpiry, taskId, deviceId, now)
      .run();
    return Boolean(res.meta && res.meta.changes > 0);
  }

  // =========================================================================
  // TELEGRAM DURABLE UPDATE PROCESSING STATE MACHINE (CHECKPOINT D)
  // =========================================================================

  /**
   * Durable update idempotency guard:
   * RECEIVED / PROCESSING -> COMPLETED / FAILED
   */
  public async startUpdateProcessing(updateId: number): Promise<{ canProcess: boolean; reason?: string }> {
    const now = Date.now();
    const existing = await this.db
      .prepare('SELECT update_id, status, updated_at FROM processed_updates WHERE update_id = ?')
      .bind(updateId)
      .first<{ update_id: number; status: string; updated_at: number }>();

    if (existing) {
      if (existing.status === 'COMPLETED') {
        return { canProcess: false, reason: 'ALREADY_COMPLETED' };
      }
      if (existing.status === 'PROCESSING') {
        // If claimed within last 60 seconds, treat as concurrent duplicate in flight
        if (now - existing.updated_at < 60000) {
          return { canProcess: false, reason: 'CONCURRENT_IN_FLIGHT' };
        }
        // If > 60 seconds, previous worker timed out or crashed; allow safe retry!
        await this.db
          .prepare("UPDATE processed_updates SET updated_at = ?, status = 'PROCESSING' WHERE update_id = ?")
          .bind(now, updateId)
          .run();
        return { canProcess: true, reason: 'RETRY_AFTER_TIMEOUT' };
      }
      if (existing.status === 'FAILED') {
        await this.db
          .prepare("UPDATE processed_updates SET updated_at = ?, status = 'PROCESSING' WHERE update_id = ?")
          .bind(now, updateId)
          .run();
        return { canProcess: true, reason: 'RETRY_AFTER_FAILURE' };
      }
    }

    try {
      await this.db
        .prepare("INSERT INTO processed_updates (update_id, status, processed_at, updated_at) VALUES (?, 'PROCESSING', ?, ?)")
        .bind(updateId, now, now)
        .run();
      return { canProcess: true };
    } catch (err: any) {
      const msg = String(err?.message || err);
      if (msg.includes('UNIQUE constraint failed')) {
        return { canProcess: false, reason: 'CONCURRENT_IN_FLIGHT' };
      }
      // Re-throw genuine database connection errors so worker returns 500 and Telegram retries safely!
      throw err;
    }
  }

  public async completeUpdateProcessing(updateId: number): Promise<void> {
    const now = Date.now();
    await this.db
      .prepare("UPDATE processed_updates SET status = 'COMPLETED', updated_at = ? WHERE update_id = ?")
      .bind(now, updateId)
      .run();
  }

  public async failUpdateProcessing(updateId: number, error: string): Promise<void> {
    const now = Date.now();
    const sanitizedErr = SecretRedactor.redact(error);
    await this.db
      .prepare("UPDATE processed_updates SET status = 'FAILED', error = ?, updated_at = ? WHERE update_id = ?")
      .bind(sanitizedErr, now, updateId)
      .run();
  }

  // Backwards-compatible alias for existing code
  public async markUpdateProcessed(updateId: number): Promise<boolean> {
    const res = await this.startUpdateProcessing(updateId);
    return res.canProcess;
  }

  // =========================================================================
  // AUDIT LOGS (CHECKPOINT F)
  // =========================================================================

  public async logAudit(
    userId: string | undefined,
    action: string,
    resource: string | undefined,
    status: 'SUCCESS' | 'DENIED' | 'FLAGGED',
    riskTier: string,
    details?: Record<string, unknown>
  ): Promise<void> {
    const id = `aud_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
    const sanitizedResource = resource ? SecretRedactor.redact(resource) : null;
    const sanitizedDetails = details ? SecretRedactor.redact(JSON.stringify(details)) : null;

    await this.db
      .prepare('INSERT INTO audit_logs (id, user_id, action, resource, status, risk_tier, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(id, userId || null, action, sanitizedResource, status, riskTier, sanitizedDetails, Date.now())
      .run();
  }
}
