/**
 * Protects against infinite loops, runaway tool recursion, or tool denial of service
 */
export class ToolLoopGuard {
  private callCounts: Map<string, number> = new Map();
  private maxTotalCalls: number;
  private maxRepeatedCallsPerTool: number;
  private totalCalls = 0;

  constructor(maxTotalCalls = 8, maxRepeatedCallsPerTool = 4) {
    this.maxTotalCalls = maxTotalCalls;
    this.maxRepeatedCallsPerTool = maxRepeatedCallsPerTool;
  }

  public recordCall(toolName: string): { allowed: boolean; reason?: string } {
    this.totalCalls++;
    if (this.totalCalls > this.maxTotalCalls) {
      return {
        allowed: false,
        reason: `Exceeded maximum total tool executions (${this.maxTotalCalls}) for a single turn`
      };
    }

    const current = (this.callCounts.get(toolName) || 0) + 1;
    this.callCounts.set(toolName, current);

    if (current > this.maxRepeatedCallsPerTool) {
      return {
        allowed: false,
        reason: `Tool '${toolName}' executed ${current} times, exceeding single-tool repeat threshold (${this.maxRepeatedCallsPerTool})`
      };
    }

    return { allowed: true };
  }

  public getTotalCalls(): number {
    return this.totalCalls;
  }
}
