import { describe, it, expect } from 'vitest';
import {
  BUILTIN_TOOLS,
  ToolValidator,
  ToolPermissionGuard,
  ToolLoopGuard
} from '../src';

describe('Built-in Tool Contracts', () => {
  it('registers essential tools', () => {
    expect(BUILTIN_TOOLS['web_search']).toBeDefined();
    expect(BUILTIN_TOOLS['fetch_url']).toBeDefined();
    expect(BUILTIN_TOOLS['email_search']).toBeDefined();
    expect(BUILTIN_TOOLS['email_send']).toBeDefined();
    expect(BUILTIN_TOOLS['calendar_list_events']).toBeDefined();
    expect(BUILTIN_TOOLS['github_list_repos']).toBeDefined();
    expect(BUILTIN_TOOLS['mac_sysinfo']).toBeDefined();
    expect(BUILTIN_TOOLS['mac_run_command']).toBeDefined();
  });

  it('assigns correct risk tiers', () => {
    expect(BUILTIN_TOOLS['web_search'].riskTier).toBe('TIER_0_READ_ONLY');
    expect(BUILTIN_TOOLS['email_create_draft'].riskTier).toBe('TIER_1_LOW_RISK');
    expect(BUILTIN_TOOLS['mac_read_file'].riskTier).toBe('TIER_1_LOW_RISK');
    expect(BUILTIN_TOOLS['email_send'].riskTier).toBe('TIER_2_SENSITIVE');
    expect(BUILTIN_TOOLS['mac_run_command'].riskTier).toBe('TIER_3_DANGEROUS');
  });
});

describe('ToolValidator', () => {
  it('validates required parameters', () => {
    const schema = BUILTIN_TOOLS['web_search'].parameters;
    expect(ToolValidator.validate(schema, { query: 'test' }).valid).toBe(true);
    expect(ToolValidator.validate(schema, {}).valid).toBe(false);
  });

  it('validates argument types', () => {
    const schema = BUILTIN_TOOLS['web_search'].parameters;
    expect(ToolValidator.validate(schema, { query: 12345 as unknown as string }).valid).toBe(false);
  });
});

describe('ToolPermissionGuard', () => {
  it('auto-allows Tier 0 read operations', () => {
    const res = ToolPermissionGuard.evaluate('TIER_0_READ_ONLY');
    expect(res.allowed).toBe(true);
    expect(res.requiresApproval).toBe(false);
  });

  it('requires approval for Tier 2 sensitive actions', () => {
    const res = ToolPermissionGuard.evaluate('TIER_2_SENSITIVE');
    expect(res.allowed).toBe(false);
    expect(res.requiresApproval).toBe(true);
  });

  it('strictly requires approval for Tier 3 dangerous actions', () => {
    const res = ToolPermissionGuard.evaluate('TIER_3_DANGEROUS');
    expect(res.allowed).toBe(false);
    expect(res.requiresApproval).toBe(true);
  });
});

describe('ToolLoopGuard', () => {
  it('allows normal tool sequences', () => {
    const loopGuard = new ToolLoopGuard(5, 3);
    expect(loopGuard.recordCall('web_search').allowed).toBe(true);
    expect(loopGuard.recordCall('fetch_url').allowed).toBe(true);
  });

  it('stops repeating tool beyond limit', () => {
    const loopGuard = new ToolLoopGuard(10, 2);
    expect(loopGuard.recordCall('web_search').allowed).toBe(true);
    expect(loopGuard.recordCall('web_search').allowed).toBe(true);
    const third = loopGuard.recordCall('web_search');
    expect(third.allowed).toBe(false);
    expect(third.reason).toContain('exceeding single-tool repeat threshold');
  });

  it('stops excessive total executions', () => {
    const loopGuard = new ToolLoopGuard(3, 3);
    expect(loopGuard.recordCall('tool1').allowed).toBe(true);
    expect(loopGuard.recordCall('tool2').allowed).toBe(true);
    expect(loopGuard.recordCall('tool3').allowed).toBe(true);
    const fourth = loopGuard.recordCall('tool4');
    expect(fourth.allowed).toBe(false);
    expect(fourth.reason).toContain('maximum total tool executions');
  });
});
