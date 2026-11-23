import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { LuciferDbRepository } from '../src/db/repository';
import { TaskRecord } from '@lucifer/shared-types';
import { ToolPermissionGuard } from '@lucifer/tool-contracts';

class RealSqliteD1PreparedStatement {
  private db: DatabaseSync;
  private sql: string;
  private params: any[] = [];

  constructor(db: DatabaseSync, sql: string) {
    this.db = db;
    this.sql = sql;
  }

  bind(...values: any[]) {
    // Convert undefined to null for sqlite
    this.params = values.map((v) => (v === undefined ? null : v));
    return this;
  }

  async first<T = any>(colName?: string): Promise<T | null> {
    const stmt = this.db.prepare(this.sql);
    const row = stmt.get(...this.params) as any;
    if (!row) return null;
    if (colName) return row[colName] as T;
    return row as T;
  }

  async all<T = any>(): Promise<{ results: T[]; success: boolean; meta: any }> {
    const stmt = this.db.prepare(this.sql);
    const rows = stmt.all(...this.params) as T[];
    return { results: rows, success: true, meta: { changes: 0 } };
  }

  async run(): Promise<{ success: boolean; meta: { changes: number } }> {
    const stmt = this.db.prepare(this.sql);
    const info = stmt.run(...this.params);
    return { success: true, meta: { changes: Number(info.changes) } };
  }
}

class RealSqliteD1Database {
  public db: DatabaseSync;

  constructor(db?: DatabaseSync) {
    this.db = db || new DatabaseSync(':memory:');
  }

  prepare(query: string) {
    return new RealSqliteD1PreparedStatement(this.db, query);
  }

  async exec(query: string) {
    this.db.exec(query);
    return { count: 1, duration: 0 };
  }
}

describe('Real SQLite Engine — D1 Migrations and Schema Validation', () => {
  const migrationsDir = path.resolve(__dirname, '../migrations');
  const mig1Sql = fs.readFileSync(path.join(migrationsDir, '0001_initial_schema.sql'), 'utf-8');
  const mig2Sql = fs.readFileSync(path.join(migrationsDir, '0002_security_remediation.sql'), 'utf-8');
  const mig3Sql = fs.readFileSync(path.join(migrationsDir, '0003_phase2_security_hardening.sql'), 'utf-8');

  it('Scenario A: applies every migration sequentially to fresh database without errors', () => {
    const sqlite = new DatabaseSync(':memory:');

    // Apply 0001
    expect(() => sqlite.exec(mig1Sql)).not.toThrow();
    // Apply 0002
    expect(() => sqlite.exec(mig2Sql)).not.toThrow();
    // Apply 0003
    expect(() => sqlite.exec(mig3Sql)).not.toThrow();

    // Verify all 12 tables exist in SQLite master
    const tables = sqlite
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
      .all()
      .map((r: any) => r.name);

    expect(tables).toContain('users');
    expect(tables).toContain('user_settings');
    expect(tables).toContain('conversations');
    expect(tables).toContain('messages');
    expect(tables).toContain('memories');
    expect(tables).toContain('tasks');
    expect(tables).toContain('approvals');
    expect(tables).toContain('devices');
    expect(tables).toContain('task_leases');
    expect(tables).toContain('audit_logs');
    expect(tables).toContain('processed_updates');
    expect(tables).toContain('pairing_codes');

    // Verify column definitions on processed_updates
    const puCols = sqlite
      .prepare('PRAGMA table_info(processed_updates)')
      .all()
      .map((r: any) => r.name);
    expect(puCols).toEqual(['update_id', 'processed_at', 'status', 'updated_at', 'error']);

    // Verify column definitions on pairing_codes
    const pcCols = sqlite
      .prepare('PRAGMA table_info(pairing_codes)')
      .all()
      .map((r: any) => r.name);
    expect(pcCols).toEqual(['code_hash', 'owner_id', 'expires_at', 'used_at']);
  });

  it('Scenario B: preserves existing data when upgrading an existing database schema', () => {
    const sqlite = new DatabaseSync(':memory:');

    // 1. Initial schema applied
    sqlite.exec(mig1Sql);
    sqlite.exec(
      "INSERT INTO users (id, telegram_id, username, created_at) VALUES ('usr_1', '123456', 'testuser', 1700000000)"
    );
    sqlite.exec(
      "INSERT INTO tasks (id, owner_id, description, type, priority, status, execution_target, correlation_id, created_at, updated_at) VALUES ('tsk_1', 'usr_1', 'existing task', 'mac_sysinfo', 'NORMAL', 'PENDING', 'LOCAL_MAC', 'c1', 1700000000, 1700000000)"
    );

    // 2. Apply migration 0002
    sqlite.exec(mig2Sql);
    sqlite.exec("INSERT INTO processed_updates (update_id, processed_at) VALUES (1001, 1700000100)");

    // 3. Apply migration 0003
    sqlite.exec(mig3Sql);

    // Verify pre-existing data is preserved
    const user = sqlite.prepare("SELECT * FROM users WHERE id = 'usr_1'").get() as any;
    expect(user.telegram_id).toBe('123456');

    const task = sqlite.prepare("SELECT * FROM tasks WHERE id = 'tsk_1'").get() as any;
    expect(task.description).toBe('existing task');

    const update = sqlite.prepare('SELECT * FROM processed_updates WHERE update_id = 1001').get() as any;
    expect(update.processed_at).toBe(1700000100);
    expect(update.status).toBe('COMPLETED'); // Default value from ALTER TABLE
    expect(update.updated_at).toBe(0);
    expect(update.error).toBeNull();
  });

  it('Scenario C: verifies real SQLite repository operations and constraints', async () => {
    const sqlite = new DatabaseSync(':memory:');
    sqlite.exec(mig1Sql);
    sqlite.exec(mig2Sql);
    sqlite.exec(mig3Sql);

    const d1Adapter = new RealSqliteD1Database(sqlite);
    const repo = new LuciferDbRepository(d1Adapter as any);

    // 1. User creation and retrieval
    const user = await repo.getOrCreateUser('999888', 'real_sqlite_user');
    expect(user.telegramId).toBe('999888');
    const existing = await repo.getOrCreateUser('999888');
    expect(existing.id).toBe(user.id);

    // 2. Task creation and leasing lifecycle
    const task: TaskRecord = {
      id: 'tsk_real_1',
      ownerId: user.id,
      description: 'real sqlite task',
      type: 'mac_sysinfo',
      priority: 'HIGH',
      status: 'PENDING',
      executionTarget: 'LOCAL_MAC',
      requiredTools: ['mac_sysinfo'],
      progress: 0,
      retries: 0,
      maxRetries: 2,
      correlationId: 'corr_1',
      createdAt: Date.now(),
      updatedAt: Date.now()
    };
    await repo.createTask(task);

    const leased = await repo.leaseNextLocalTask('device_mac_01');
    expect(leased).not.toBeNull();
    expect(leased?.id).toBe('tsk_real_1');

    // 3. Verify task lease ownership
    const hasActiveLease = await repo.verifyTaskOwnership('tsk_real_1', 'device_mac_01');
    expect(hasActiveLease).toBe(true);

    const wrongDeviceLease = await repo.verifyTaskOwnership('tsk_real_1', 'device_mac_99');
    expect(wrongDeviceLease).toBe(false);

    // 4. Duplicate Telegram update idempotency with real SQLite UNIQUE constraint
    const firstCheck = await repo.startUpdateProcessing(2001);
    expect(firstCheck.canProcess).toBe(true);

    const duplicateCheck = await repo.startUpdateProcessing(2001);
    expect(duplicateCheck.canProcess).toBe(false);
    expect(duplicateCheck.reason).toBe('CONCURRENT_IN_FLIGHT');

    await repo.completeUpdateProcessing(2001);
    const completedCheck = await repo.startUpdateProcessing(2001);
    expect(completedCheck.canProcess).toBe(false);
    expect(completedCheck.reason).toBe('ALREADY_COMPLETED');

    // 5. Single-use pairing code consumption in real SQLite
    await repo.createPairingCode(user.id, 'pair_code_abc_123', 300);
    const firstConsume = await repo.consumePairingCode('pair_code_abc_123');
    expect(firstConsume.valid).toBe(true);
    expect(firstConsume.ownerId).toBe(user.id);

    // Second consumption must fail (single-use constraint)
    const secondConsume = await repo.consumePairingCode('pair_code_abc_123');
    expect(secondConsume.valid).toBe(false);
  });

  it('Scenario D: verifies P47-CFG-01 secure Tier 1 defaults and settings lifecycle', async () => {
    const sqlite = new DatabaseSync(':memory:');
    sqlite.exec(mig1Sql);
    sqlite.exec(mig2Sql);
    sqlite.exec(mig3Sql);

    const d1Adapter = new RealSqliteD1Database(sqlite);
    const repo = new LuciferDbRepository(d1Adapter as any);

    // 1. Fresh database schema default for auto_approve_tier1 is 0
    const schemaInfo = sqlite.prepare('PRAGMA table_info(user_settings)').all() as any[];
    const tier1Col = schemaInfo.find((col) => col.name === 'auto_approve_tier1');
    expect(tier1Col).toBeDefined();
    expect(String(tier1Col.dflt_value)).toBe('0');

    // 2. New user creation records default to auto_approve_tier1 = 0
    const userA = await repo.getOrCreateUser('111222', 'alice');
    const autoApproveA = await repo.getUserTier1AutoApprove(userA.id);
    expect(autoApproveA).toBe(false);

    // 3. Approval behavior reflects disabled Tier 1 (requires confirmation)
    const permA = ToolPermissionGuard.evaluate('TIER_1_LOW_RISK', autoApproveA);
    expect(permA.requiresApproval).toBe(true);

    // 4. Missing/non-existent user settings fails closed to secure default false
    const missingAutoApprove = await repo.getUserTier1AutoApprove('usr_non_existent');
    expect(missingAutoApprove).toBe(false);
    const permMissing = ToolPermissionGuard.evaluate('TIER_1_LOW_RISK', missingAutoApprove);
    expect(permMissing.requiresApproval).toBe(true);

    // 5. Existing user with explicit auto_approve_tier1 = 1 is preserved and not overwritten
    sqlite.exec("INSERT INTO users (id, telegram_id, username, created_at) VALUES ('usr_bob', '333444', 'bob', 1700000000)");
    sqlite.exec("INSERT INTO user_settings (user_id, timezone, budget_mode, auto_approve_tier1, created_at, updated_at) VALUES ('usr_bob', 'UTC', 'FREE_ONLY', 1, 1700000000, 1700000000)");

    const autoApproveBob = await repo.getUserTier1AutoApprove('usr_bob');
    expect(autoApproveBob).toBe(true);
    const permBob = ToolPermissionGuard.evaluate('TIER_1_LOW_RISK', autoApproveBob);
    expect(permBob.requiresApproval).toBe(false);

    // 6. User settings with explicit 0 remains 0
    sqlite.exec("INSERT INTO users (id, telegram_id, username, created_at) VALUES ('usr_charlie', '555666', 'charlie', 1700000000)");
    sqlite.exec("INSERT INTO user_settings (user_id, timezone, budget_mode, auto_approve_tier1, created_at, updated_at) VALUES ('usr_charlie', 'UTC', 'FREE_ONLY', 0, 1700000000, 1700000000)");

    const autoApproveCharlie = await repo.getUserTier1AutoApprove('usr_charlie');
    expect(autoApproveCharlie).toBe(false);

    // 7. Corrupted/null setting fails securely
    sqlite.exec("INSERT INTO users (id, telegram_id, username, created_at) VALUES ('usr_null', '777888', 'nulluser', 1700000000)");
    sqlite.exec("INSERT INTO user_settings (user_id, timezone, budget_mode, auto_approve_tier1, created_at, updated_at) VALUES ('usr_null', 'UTC', 'FREE_ONLY', NULL, 1700000000, 1700000000)");
    const autoApproveNull = await repo.getUserTier1AutoApprove('usr_null');
    expect(autoApproveNull).toBe(false);
  });
});
