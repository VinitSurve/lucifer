import { describe, it, expect, vi, beforeEach } from 'vitest';
import worker from '../src/index';
import { DeviceAuthGuard, SecretRedactor, SlidingWindowRateLimiter } from '@lucifer/security';
import { TelegramBotClient } from '../src/telegram/client';
import { LuciferDbRepository } from '../src/db/repository';

// Enhanced Mock D1 Database implementation supporting Phase 2 security state machines
class MockD1PreparedStatement {
  private query: string;
  private params: any[] = [];
  public static store: {
    users: any[];
    tasks: any[];
    approvals: any[];
    memories: any[];
    devices: any[];
    taskLeases: any[];
    processedUpdates: Map<number, { status: string; processed_at: number; updated_at: number }>;
    auditLogs: any[];
    pairingCodes: any[];
  } = {
    users: [],
    tasks: [],
    approvals: [],
    memories: [],
    devices: [],
    taskLeases: [],
    processedUpdates: new Map(),
    auditLogs: [],
    pairingCodes: []
  };

  constructor(query: string) {
    this.query = query;
  }

  bind(...params: any[]) {
    this.params = params;
    return this;
  }

  async first<T = any>(): Promise<T | null> {
    if (this.query.includes('SELECT id, telegram_id as telegramId FROM users')) {
      const u = MockD1PreparedStatement.store.users.find((x) => x.telegramId === this.params[0]);
      return (u as T) || null;
    }
    if (this.query.includes('SELECT * FROM approvals WHERE id = ?')) {
      const a = MockD1PreparedStatement.store.approvals.find((x) => x.id === this.params[0]);
      return (a as T) || null;
    }
    if (this.query.includes('SELECT * FROM tasks WHERE id = ?')) {
      const t = MockD1PreparedStatement.store.tasks.find((x) => x.id === this.params[0]);
      return (t as T) || null;
    }
    if (this.query.includes('SELECT id FROM tasks WHERE execution_target')) {
      const t = MockD1PreparedStatement.store.tasks.find(
        (x) => x.execution_target === 'LOCAL_MAC' && (x.status === 'PENDING' || x.status === 'QUEUED')
      );
      return (t ? { id: t.id } : null) as T;
    }
    if (this.query.includes('SELECT device_id, owner_id, auth_secret_hash, is_active FROM devices WHERE device_id = ?')) {
      const d = MockD1PreparedStatement.store.devices.find((x) => x.device_id === this.params[0]);
      return (d as T) || null;
    }
    if (this.query.includes('FROM task_leases WHERE task_id = ? AND device_id = ?')) {
      const minExpiry = this.params[2];
      const l = MockD1PreparedStatement.store.taskLeases.find(
        (x) => x.taskId === this.params[0] && x.deviceId === this.params[1] && (!minExpiry || x.expiresAt > minExpiry)
      );
      return (l ? { task_id: l.taskId, device_id: l.deviceId, expires_at: l.expiresAt } : null) as T;
    }
    if (this.query.includes('SELECT update_id, status, updated_at FROM processed_updates WHERE update_id = ?')) {
      const pu = MockD1PreparedStatement.store.processedUpdates.get(this.params[0]);
      return (pu ? { update_id: this.params[0], status: pu.status, updated_at: pu.updated_at } : null) as T;
    }
    if (this.query.includes('SELECT code_hash, owner_id, expires_at, used_at FROM pairing_codes WHERE code_hash = ?')) {
      const pc = MockD1PreparedStatement.store.pairingCodes.find((x) => x.code_hash === this.params[0]);
      return (pc as T) || null;
    }
    return null;
  }

  async all<T = any>(): Promise<{ results: T[] }> {
    if (this.query.includes('SELECT key, value, category FROM memories')) {
      return { results: MockD1PreparedStatement.store.memories as T[] };
    }
    if (this.query.includes('SELECT * FROM tasks')) {
      return { results: MockD1PreparedStatement.store.tasks as T[] };
    }
    return { results: [] };
  }

  async run(): Promise<{ meta: { changes: number } }> {
    if (this.query.includes('INSERT INTO processed_updates')) {
      const updateId = this.params[0];
      if (MockD1PreparedStatement.store.processedUpdates.has(updateId)) {
        throw new Error(`UNIQUE constraint failed: processed_updates.update_id: ${updateId}`);
      }
      MockD1PreparedStatement.store.processedUpdates.set(updateId, {
        status: this.params[1] || 'PROCESSING',
        processed_at: this.params[2] || Date.now(),
        updated_at: this.params[3] || Date.now()
      });
      return { meta: { changes: 1 } };
    }
    if (this.query.includes('UPDATE processed_updates SET status = ?')) {
      const updateId = this.params[2];
      const pu = MockD1PreparedStatement.store.processedUpdates.get(updateId);
      if (pu) {
        pu.status = this.params[0];
        pu.updated_at = this.params[1];
        return { meta: { changes: 1 } };
      }
      return { meta: { changes: 0 } };
    }
    if (this.query.includes('INSERT INTO users')) {
      MockD1PreparedStatement.store.users.push({
        id: this.params[0],
        telegramId: this.params[1]
      });
      return { meta: { changes: 1 } };
    }
    if (this.query.includes('INSERT INTO devices')) {
      const existing = MockD1PreparedStatement.store.devices.find((x) => x.device_id === this.params[0]);
      if (existing) {
        if (this.params[3] && this.params[3] !== '') existing.auth_secret_hash = this.params[3];
        existing.last_heartbeat = this.params[4];
      } else {
        MockD1PreparedStatement.store.devices.push({
          device_id: this.params[0],
          owner_id: this.params[1],
          device_name: this.params[2],
          auth_secret_hash: this.params[3],
          is_active: 1,
          last_heartbeat: this.params[4]
        });
      }
      return { meta: { changes: 1 } };
    }
    if (this.query.includes('UPDATE devices SET auth_secret_hash = ?')) {
      const d = MockD1PreparedStatement.store.devices.find((x) => x.device_id === this.params[2] && x.is_active === 1);
      if (d) {
        d.auth_secret_hash = this.params[0];
        return { meta: { changes: 1 } };
      }
      return { meta: { changes: 0 } };
    }
    if (this.query.includes('UPDATE devices SET is_active = 0 WHERE device_id = ?')) {
      const d = MockD1PreparedStatement.store.devices.find((x) => x.device_id === this.params[0]);
      if (d) {
        d.is_active = 0;
        return { meta: { changes: 1 } };
      }
      return { meta: { changes: 0 } };
    }
    if (this.query.includes('INSERT INTO tasks')) {
      MockD1PreparedStatement.store.tasks.push({
        id: this.params[0],
        owner_id: this.params[1],
        description: this.params[2],
        type: this.params[3],
        priority: this.params[4],
        status: this.params[5],
        execution_target: this.params[6],
        required_tools: this.params[7],
        retries: this.params[10] || 0,
        max_retries: this.params[11] || 3,
        created_at: this.params[16],
        updated_at: this.params[17]
      });
      return { meta: { changes: 1 } };
    }
    if (this.query.includes('INSERT OR REPLACE INTO task_leases')) {
      const existing = MockD1PreparedStatement.store.taskLeases.find((x) => x.taskId === this.params[0]);
      if (existing) {
        existing.deviceId = this.params[1];
        existing.leasedAt = this.params[2];
        existing.expiresAt = this.params[3];
      } else {
        MockD1PreparedStatement.store.taskLeases.push({
          taskId: this.params[0],
          deviceId: this.params[1],
          leasedAt: this.params[2],
          expiresAt: this.params[3]
        });
      }
      return { meta: { changes: 1 } };
    }
    if (this.query.includes("UPDATE tasks SET status = 'QUEUED', retries = retries + 1")) {
      let count = 0;
      const now = this.params[0];
      const expiredThreshold = this.params[1];
      for (const t of MockD1PreparedStatement.store.tasks) {
        if (t.execution_target === 'LOCAL_MAC' && t.status === 'RUNNING') {
          const lease = MockD1PreparedStatement.store.taskLeases.find((l) => l.taskId === t.id);
          if (lease && lease.expiresAt < expiredThreshold && (t.retries || 0) < (t.max_retries || 3)) {
            t.status = 'QUEUED';
            t.retries = (t.retries || 0) + 1;
            t.updated_at = now;
            count++;
          }
        }
      }
      return { meta: { changes: count } };
    }
    if (this.query.includes('DELETE FROM task_leases WHERE expires_at < ?')) {
      const threshold = this.params[0];
      const initial = MockD1PreparedStatement.store.taskLeases.length;
      MockD1PreparedStatement.store.taskLeases = MockD1PreparedStatement.store.taskLeases.filter((l) => l.expiresAt >= threshold);
      return { meta: { changes: initial - MockD1PreparedStatement.store.taskLeases.length } };
    }
    if (this.query.includes("UPDATE tasks SET status = 'RUNNING'")) {
      const targetId = this.params[1];
      const task = MockD1PreparedStatement.store.tasks.find((x) => x.id === targetId && (x.status === 'PENDING' || x.status === 'QUEUED'));
      if (task) {
        task.status = 'RUNNING';
        return { meta: { changes: 1 } };
      }
      return { meta: { changes: 0 } };
    }
    if (this.query.includes('UPDATE tasks SET status = ?')) {
      const targetId = this.params[5];
      const task = MockD1PreparedStatement.store.tasks.find((x) => x.id === targetId);
      if (task) {
        task.status = this.params[0];
        task.result = this.params[1] || task.result;
        task.error = this.params[2] || task.error;
        return { meta: { changes: 1 } };
      }
      return { meta: { changes: 0 } };
    }
    if (this.query.includes('INSERT INTO audit_logs')) {
      MockD1PreparedStatement.store.auditLogs.push({
        id: this.params[0],
        user_id: this.params[1],
        action: this.params[2],
        resource: this.params[3],
        status: this.params[4],
        risk_tier: this.params[5],
        details: this.params[6],
        created_at: this.params[7]
      });
      return { meta: { changes: 1 } };
    }
    return { meta: { changes: 1 } };
  }
}

class MockD1Database {
  prepare(query: string) {
    return new MockD1PreparedStatement(query);
  }
}

describe('Lucifer Cloud Worker — Phase 2 Security Hardening Tests', () => {
  let mockEnv: any;
  let mockCtx: any;

  beforeEach(() => {
    MockD1PreparedStatement.store = {
      users: [],
      tasks: [],
      approvals: [],
      memories: [],
      devices: [],
      taskLeases: [],
      processedUpdates: new Map(),
      auditLogs: [],
      pairingCodes: []
    };

    mockEnv = {
      DB: new MockD1Database() as any,
      TELEGRAM_BOT_TOKEN: '123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ',
      TELEGRAM_WEBHOOK_SECRET: 'test-webhook-secret',
      TELEGRAM_OWNER_ID: '123456789',
      DEVICE_PAIRING_SECRET: 'pair-secret-999',
      BUDGET_MODE: 'FREE_ONLY'
    };

    mockCtx = {
      waitUntil: vi.fn(),
      passThroughOnException: vi.fn()
    };
  });

  it('responds with 200 on /health', async () => {
    const req = new Request('https://lucifer.local/health');
    const resp = await worker.fetch(req, mockEnv, mockCtx);
    expect(resp.status).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe('ok');
    expect(data.service).toBe('Lucifer Cloud Core');
  });

  it('rejects webhook requests with invalid secret token', async () => {
    const req = new Request('https://lucifer.local/webhook/telegram', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Telegram-Bot-Api-Secret-Token': 'wrong-secret'
      },
      body: JSON.stringify({ update_id: 123 })
    });

    const resp = await worker.fetch(req, mockEnv, mockCtx);
    expect(resp.status).toBe(401);
  });

  // Checkpoint D: Durable update deduplication
  it('deduplicates Telegram updates (rejects replayed update_id)', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ ok: true, result: {} }),
      text: async () => 'ok'
    } as any);

    const update = {
      update_id: 777,
      message: {
        message_id: 1,
        from: { id: 123456789, is_bot: false, first_name: 'Owner' },
        chat: { id: 123456789, type: 'private' },
        date: Math.floor(Date.now() / 1000),
        text: '/status'
      }
    };

    const makeReq = () =>
      new Request('https://lucifer.local/webhook/telegram', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Telegram-Bot-Api-Secret-Token': 'test-webhook-secret'
        },
        body: JSON.stringify(update)
      });

    // First arrival: successfully processed
    const resp1 = await worker.fetch(makeReq(), mockEnv, mockCtx);
    expect(resp1.status).toBe(200);

    // Second arrival of identical update_id: acknowledged with 200 without reprocessing
    const resp2 = await worker.fetch(makeReq(), mockEnv, mockCtx);
    expect(resp2.status).toBe(200);
    expect(MockD1PreparedStatement.store.processedUpdates.has(777)).toBe(true);
  });

  it('rejects unauthenticated local agent heartbeat with 401', async () => {
    const req = new Request('https://lucifer.local/api/agent/heartbeat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        deviceId: 'mac-unauth-01',
        deviceName: 'Unauthenticated MacBook'
      })
    });

    const resp = await worker.fetch(req, mockEnv, mockCtx);
    expect(resp.status).toBe(401);
  });

  it('pairs device with valid pairing token and authenticates subsequent requests', async () => {
    const pairReq = new Request('https://lucifer.local/api/agent/pair', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        deviceId: 'mac-air-01',
        deviceName: "Vinit's MacBook Air",
        pairingToken: 'pair-secret-999'
      })
    });

    const pairResp = await worker.fetch(pairReq, mockEnv, mockCtx);
    expect(pairResp.status).toBe(200);
    const pairData = await pairResp.json();
    expect(pairData.status).toBe('paired');
    expect(pairData.token).toBeDefined();

    const deviceToken = pairData.token;

    // Authenticated heartbeat using token
    const heartbeatReq = new Request('https://lucifer.local/api/agent/heartbeat', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${deviceToken}`
      },
      body: JSON.stringify({
        deviceId: 'mac-air-01',
        deviceName: "Vinit's MacBook Air"
      })
    });

    const hbResp = await worker.fetch(heartbeatReq, mockEnv, mockCtx);
    expect(hbResp.status).toBe(200);
  });

  // Checkpoint B: Anti-hijacking (ADV-HIGH-05)
  it('rejects device pairing when deviceId already exists (409 Conflict)', async () => {
    MockD1PreparedStatement.store.devices.push({
      device_id: 'mac-existing',
      owner_id: '123456789',
      auth_secret_hash: 'hash123',
      is_active: 1
    });

    const req = new Request('https://lucifer.local/api/agent/pair', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        deviceId: 'mac-existing',
        deviceName: 'Rogue Device Hijacker',
        pairingToken: 'pair-secret-999'
      })
    });

    const resp = await worker.fetch(req, mockEnv, mockCtx);
    expect(resp.status).toBe(409);
    const data = await resp.json();
    expect(data.error).toContain('already registered');
  });

  // Checkpoint B: No fallback to Telegram secret
  it('rejects device pairing using TELEGRAM_WEBHOOK_SECRET when DEVICE_PAIRING_SECRET is omitted', async () => {
    mockEnv.DEVICE_PAIRING_SECRET = undefined;
    const req = new Request('https://lucifer.local/api/agent/pair', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        deviceId: 'mac-new',
        deviceName: 'Test Device',
        pairingToken: 'test-webhook-secret'
      })
    });

    const resp = await worker.fetch(req, mockEnv, mockCtx);
    expect(resp.status).toBe(401);
  });

  // Checkpoint B: Token rotation
  it('allows authenticated device to rotate its token', async () => {
    const rawToken = 'original-secret-token-123';
    const hash = await DeviceAuthGuard.hashToken(rawToken);
    MockD1PreparedStatement.store.devices.push({
      device_id: 'mac-rotate-01',
      owner_id: '123456789',
      auth_secret_hash: hash,
      is_active: 1
    });

    const req = new Request('https://lucifer.local/api/agent/rotate-token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${rawToken}`
      },
      body: JSON.stringify({ deviceId: 'mac-rotate-01' })
    });

    const resp = await worker.fetch(req, mockEnv, mockCtx);
    expect(resp.status).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe('rotated');
    expect(data.token).toBeDefined();
    expect(data.token).not.toBe(rawToken);
  });

  // Checkpoint B: Device revocation
  it('revokes device and blocks subsequent authenticated requests', async () => {
    const rawToken = 'revoked-token-123';
    const hash = await DeviceAuthGuard.hashToken(rawToken);
    MockD1PreparedStatement.store.devices.push({
      device_id: 'mac-revoke-01',
      owner_id: '123456789',
      auth_secret_hash: hash,
      is_active: 1
    });

    // Revoke device
    const revokeReq = new Request('https://lucifer.local/api/agent/revoke', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${rawToken}`
      },
      body: JSON.stringify({ deviceId: 'mac-revoke-01' })
    });
    const revResp = await worker.fetch(revokeReq, mockEnv, mockCtx);
    expect(revResp.status).toBe(200);

    // Heartbeat using revoked device must return 401
    const hbReq = new Request('https://lucifer.local/api/agent/heartbeat', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${rawToken}`
      },
      body: JSON.stringify({ deviceId: 'mac-revoke-01' })
    });
    const hbResp = await worker.fetch(hbReq, mockEnv, mockCtx);
    expect(hbResp.status).toBe(401);
  });

  // Checkpoint C: Reclaim expired leases (ADV-HIGH-06)
  it('reclaims expired leases and resets tasks to QUEUED', async () => {
    const repo = new LuciferDbRepository(mockEnv.DB);
    const now = Date.now();

    // Create a stranded running task with an expired lease (expired 1 hour ago)
    MockD1PreparedStatement.store.tasks.push({
      id: 'task_stranded_1',
      owner_id: '123456789',
      description: 'Stranded task',
      type: 'mac_read_file',
      priority: 'HIGH',
      status: 'RUNNING',
      execution_target: 'LOCAL_MAC',
      retries: 0,
      max_retries: 3,
      created_at: now - 3600000,
      updated_at: now - 3600000
    });
    MockD1PreparedStatement.store.taskLeases.push({
      taskId: 'task_stranded_1',
      deviceId: 'mac_offline',
      leasedAt: now - 3600000,
      expiresAt: now - 3540000 // expired
    });

    const result = await repo.reclaimExpiredLeases();
    expect(result.recovered).toBe(1);

    const task = await repo.getTask('task_stranded_1');
    expect(task?.status).toBe('QUEUED');
    expect(task?.retries).toBe(1);
  });

  // Checkpoint C: Expired lease rejection on result submission (ADV-MED-01)
  it('rejects task result submission when lease has expired with 403', async () => {
    const token = 'active-agent-token';
    const hash = await DeviceAuthGuard.hashToken(token);
    MockD1PreparedStatement.store.devices.push({
      device_id: 'mac-expired-agent',
      owner_id: '123456789',
      auth_secret_hash: hash,
      is_active: 1
    });

    const now = Date.now();
    MockD1PreparedStatement.store.tasks.push({
      id: 'task_exp_1',
      owner_id: '123456789',
      description: 'Test task',
      type: 'mac_read_file',
      priority: 'NORMAL',
      status: 'RUNNING',
      execution_target: 'LOCAL_MAC',
      created_at: now - 100000,
      updated_at: now - 100000
    });
    // Lease expired 30 seconds ago
    MockD1PreparedStatement.store.taskLeases.push({
      taskId: 'task_exp_1',
      deviceId: 'mac-expired-agent',
      leasedAt: now - 90000,
      expiresAt: now - 30000
    });

    const req = new Request('https://lucifer.local/api/agent/result', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({
        deviceId: 'mac-expired-agent',
        taskId: 'task_exp_1',
        success: true
      })
    });

    const resp = await worker.fetch(req, mockEnv, mockCtx);
    expect(resp.status).toBe(403);
  });

  // Checkpoint C: Idempotent duplicate result submission (ADV-LOW-02)
  it('idempotently handles duplicate result submissions without re-notifying', async () => {
    let telegramCount = 0;
    global.fetch = vi.fn().mockImplementation(async (url, init) => {
      telegramCount++;
      return { ok: true, json: async () => ({ ok: true }), text: async () => 'ok' };
    });

    const token = 'token-idempotent';
    const hash = await DeviceAuthGuard.hashToken(token);
    MockD1PreparedStatement.store.devices.push({
      device_id: 'mac-idem',
      owner_id: '123456789',
      auth_secret_hash: hash,
      is_active: 1
    });

    const now = Date.now();
    MockD1PreparedStatement.store.tasks.push({
      id: 'task_idem_1',
      owner_id: '123456789',
      description: 'Idempotency task',
      type: 'mac_read_file',
      priority: 'NORMAL',
      status: 'RUNNING',
      execution_target: 'LOCAL_MAC',
      created_at: now,
      updated_at: now
    });
    MockD1PreparedStatement.store.taskLeases.push({
      taskId: 'task_idem_1',
      deviceId: 'mac-idem',
      leasedAt: now,
      expiresAt: now + 60000
    });

    const makeResultReq = () =>
      new Request('https://lucifer.local/api/agent/result', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ deviceId: 'mac-idem', taskId: 'task_idem_1', success: true })
      });

    // 1st result submission: Accepted and sent notification
    const res1 = await worker.fetch(makeResultReq(), mockEnv, mockCtx);
    expect(res1.status).toBe(200);

    // 2nd duplicate result submission: Returns already_processed, sends NO duplicate notification
    const res2 = await worker.fetch(makeResultReq(), mockEnv, mockCtx);
    expect(res2.status).toBe(200);
    const data2 = await res2.json();
    expect(data2.status).toBe('already_processed');
    expect(telegramCount).toBe(1); // Only 1 notification dispatched!
  });

  // Checkpoint F: Secret sanitization before D1 audit log persistence
  it('sanitizes credentials from audit log details and messages before D1 persistence', async () => {
    const repo = new LuciferDbRepository(mockEnv.DB);
    const secretInPayload = {
      apiKey: 'AIzaSyD9ABCDEF1234567890abcdefghijklm',
      botToken: '123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ12345678'
    };

    await repo.logAudit('usr_test', 'TEST_ACTION', 'https://api.example.com', 'DENIED', 'TIER_3', secretInPayload);
    expect(MockD1PreparedStatement.store.auditLogs.length).toBe(1);
    const storedDetails = MockD1PreparedStatement.store.auditLogs[0].details;

    expect(storedDetails).not.toContain('AIzaSyD9');
    expect(storedDetails).toContain('[REDACTED_GEMINI_KEY]');
    expect(storedDetails).not.toContain('123456789:ABCdef');
    expect(storedDetails).toContain('[REDACTED_TELEGRAM_TOKEN]');
  });

  // Checkpoint F: Secret redaction in Telegram client
  it('redacts sensitive tokens in outgoing Telegram messages', async () => {
    let capturedBody: any = null;
    global.fetch = vi.fn().mockImplementation(async (url, init) => {
      capturedBody = JSON.parse(init.body);
      return {
        ok: true,
        json: async () => ({ ok: true, result: {} }),
        text: async () => 'ok'
      };
    });

    const bot = new TelegramBotClient('123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ12345678');
    await bot.sendMessage(
      123456789,
      'Internal error with key AIzaSyD9ABCDEF1234567890abcdefghijklm and bot token 987654321:XYZdefGhIJKlmNoPQRsTUVwxyZ12345678'
    );

    expect(capturedBody).toBeDefined();
    expect(capturedBody.text).not.toContain('AIzaSyD9');
    expect(capturedBody.text).toContain('[REDACTED_GEMINI_KEY]');
    expect(capturedBody.text).not.toContain('987654321:XYZ');
    expect(capturedBody.text).toContain('[REDACTED_TELEGRAM_TOKEN]');
  });
});
