import { describe, it, expect, vi, beforeEach } from 'vitest';
import worker from '../src/index';
import { DeviceAuthGuard, SecretRedactor } from '@lucifer/security';
import { TelegramBotClient } from '../src/telegram/client';

// Mock D1 Database implementation
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
    processedUpdates: Set<number>;
  } = {
    users: [],
    tasks: [],
    approvals: [],
    memories: [],
    devices: [],
    taskLeases: [],
    processedUpdates: new Set()
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
      const t = MockD1PreparedStatement.store.tasks.find((x) => x.execution_target === 'LOCAL_MAC' && (x.status === 'PENDING' || x.status === 'QUEUED'));
      return (t ? { id: t.id } : null) as T;
    }
    if (this.query.includes('SELECT device_id, owner_id, auth_secret_hash, is_active FROM devices WHERE device_id = ?')) {
      const d = MockD1PreparedStatement.store.devices.find((x) => x.device_id === this.params[0]);
      return (d as T) || null;
    }
    if (this.query.includes('SELECT task_id, device_id FROM task_leases WHERE task_id = ? AND device_id = ?')) {
      const l = MockD1PreparedStatement.store.taskLeases.find((x) => x.taskId === this.params[0] && x.deviceId === this.params[1]);
      return (l as T) || null;
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
      MockD1PreparedStatement.store.processedUpdates.add(updateId);
      return { meta: { changes: 1 } };
    }
    if (this.query.includes('INSERT INTO users')) {
      MockD1PreparedStatement.store.users.push({
        id: this.params[0],
        telegramId: this.params[1]
      });
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
        created_at: this.params[16],
        updated_at: this.params[17]
      });
    }
    if (this.query.includes('INSERT OR REPLACE INTO task_leases')) {
      MockD1PreparedStatement.store.taskLeases.push({
        taskId: this.params[0],
        deviceId: this.params[1],
        leasedAt: this.params[2],
        expiresAt: this.params[3]
      });
    }
    if (this.query.includes('UPDATE tasks SET status =')) {
      // Check if atomic conditional query: WHERE id = ? AND status IN ('PENDING', 'QUEUED')
      const targetId = this.params[1];
      const task = MockD1PreparedStatement.store.tasks.find((x) => x.id === targetId && (x.status === 'PENDING' || x.status === 'QUEUED'));
      if (task) {
        task.status = 'RUNNING';
        return { meta: { changes: 1 } };
      }
      return { meta: { changes: 0 } };
    }
    return { meta: { changes: 1 } };
  }
}

const mockD1: any = {
  prepare: (query: string) => new MockD1PreparedStatement(query)
};

const mockEnv: any = {
  DB: mockD1,
  TELEGRAM_OWNER_ID: '123456789',
  TELEGRAM_BOT_TOKEN: '123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ12345678',
  TELEGRAM_WEBHOOK_SECRET: 'test-webhook-secret',
  DEVICE_PAIRING_SECRET: 'pair-secret-999',
  BUDGET_MODE: 'FREE_ONLY'
};

const mockCtx: any = {
  waitUntil: vi.fn(),
  passThroughOnException: vi.fn()
};

describe('Lucifer Cloud Worker — Security Remediation Tests', () => {
  beforeEach(() => {
    MockD1PreparedStatement.store = {
      users: [],
      tasks: [],
      approvals: [],
      memories: [],
      devices: [],
      taskLeases: [],
      processedUpdates: new Set()
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
        'X-Telegram-Bot-Api-Secret-Token': 'wrong-token'
      },
      body: JSON.stringify({ update_id: 1 })
    });

    const resp = await worker.fetch(req, mockEnv, mockCtx);
    expect(resp.status).toBe(401);
  });

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
        deviceName: "Unauthenticated MacBook"
      })
    });

    const resp = await worker.fetch(req, mockEnv, mockCtx);
    expect(resp.status).toBe(401);
  });

  it('pairs device with valid pairing token and authenticates subsequent requests', async () => {
    // 1. Pair device
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

    // 2. Authenticated heartbeat using token
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

  it('rejects task result submission from device not holding the task lease', async () => {
    // Register device
    const token = 'valid-token-123';
    const hash = await DeviceAuthGuard.hashToken(token);
    MockD1PreparedStatement.store.devices.push({
      device_id: 'mac-rogue',
      owner_id: '123456789',
      auth_secret_hash: hash,
      is_active: 1
    });

    const resultReq = new Request('https://lucifer.local/api/agent/result', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({
        deviceId: 'mac-rogue',
        taskId: 'tsk_unowned_999',
        success: true
      })
    });

    const resp = await worker.fetch(resultReq, mockEnv, mockCtx);
    // Must be rejected with 403 Forbidden because mac-rogue does not own lease
    expect(resp.status).toBe(403);
  });

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
