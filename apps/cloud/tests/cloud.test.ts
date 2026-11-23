import { describe, it, expect, vi } from 'vitest';
import worker from '../src/index';

// Mock D1 Database implementation
class MockD1PreparedStatement {
  private query: string;
  private params: any[] = [];
  private static store: {
    users: any[];
    tasks: any[];
    approvals: any[];
    memories: any[];
    devices: any[];
  } = { users: [], tasks: [], approvals: [], memories: [], devices: [] };

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
    if (this.query.includes('SELECT * FROM tasks WHERE execution_target')) {
      const t = MockD1PreparedStatement.store.tasks.find((x) => x.execution_target === 'LOCAL_MAC');
      return (t as T) || null;
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
    if (this.query.includes('INSERT INTO users')) {
      MockD1PreparedStatement.store.users.push({
        id: this.params[0],
        telegramId: this.params[1]
      });
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
    if (this.query.includes('INSERT INTO approvals')) {
      MockD1PreparedStatement.store.approvals.push({
        id: this.params[0],
        task_id: this.params[1],
        user_id: this.params[2],
        action_name: this.params[3],
        action_details: this.params[4],
        state: this.params[5],
        created_at: this.params[6],
        expires_at: this.params[7]
      });
    }
    if (this.query.includes('UPDATE tasks SET status =')) {
      const t = MockD1PreparedStatement.store.tasks.find((x) => x.id === this.params[5] || x.id === this.params[1]);
      if (t) t.status = this.params[0];
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
  BUDGET_MODE: 'FREE_ONLY'
};

const mockCtx: any = {
  waitUntil: vi.fn(),
  passThroughOnException: vi.fn()
};

describe('Lucifer Cloud Worker', () => {
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

  it('accepts valid webhook update from authorized owner', async () => {
    // Mock global fetch for Telegram API calls
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ ok: true, result: {} }),
      text: async () => 'ok'
    } as any);

    const update = {
      update_id: 100,
      message: {
        message_id: 1,
        from: { id: 123456789, is_bot: false, first_name: 'Owner' },
        chat: { id: 123456789, type: 'private' },
        date: Math.floor(Date.now() / 1000),
        text: '/status'
      }
    };

    const req = new Request('https://lucifer.local/webhook/telegram', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Telegram-Bot-Api-Secret-Token': 'test-webhook-secret'
      },
      body: JSON.stringify(update)
    });

    const resp = await worker.fetch(req, mockEnv, mockCtx);
    expect(resp.status).toBe(200);
  });

  it('handles local agent heartbeat endpoint', async () => {
    const req = new Request('https://lucifer.local/api/agent/heartbeat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        deviceId: 'mac-air-01',
        deviceName: "Vinit's MacBook Air",
        info: { os: 'Darwin arm64', pythonVersion: '3.14.7' }
      })
    });

    const resp = await worker.fetch(req, mockEnv, mockCtx);
    expect(resp.status).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe('ok');
  });

  it('handles local agent task polling endpoint', async () => {
    const req = new Request('https://lucifer.local/api/agent/poll', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ deviceId: 'mac-air-01' })
    });

    const resp = await worker.fetch(req, mockEnv, mockCtx);
    expect(resp.status).toBe(200);
    const data = await resp.json();
    expect(data).toHaveProperty('task');
  });
});
