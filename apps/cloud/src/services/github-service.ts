export interface GitHubRepoSummary {
  name: string;
  fullName: string;
  private: boolean;
  htmlUrl: string;
  description: string;
  updatedAt: string;
}

export interface WorkflowRunSummary {
  id: number;
  name: string;
  status: string;
  conclusion: string | null;
  htmlUrl: string;
  createdAt: string;
}

export class GitHubService {
  /**
   * Allowlisted repository-to-workflow mapping to prevent arbitrary execution
   */
  private static APPROVED_WORKFLOWS: Record<string, string[]> = {
    'reelix': ['build.yml', 'ci.yml', 'release.yml'],
    'hiddendevtools': ['test.yml', 'ci.yml'],
    'lucifer': ['ci.yml']
  };

  public static isWorkflowApproved(repoName: string, workflowId: string): boolean {
    const key = repoName.toLowerCase();
    const approvedList = this.APPROVED_WORKFLOWS[key];
    if (!approvedList) return false;
    return approvedList.includes(workflowId.toLowerCase());
  }

  public static async listRepos(token?: string): Promise<{ authenticated: boolean; repos: GitHubRepoSummary[]; messageText?: string }> {
    if (!token) {
      return {
        authenticated: false,
        repos: [],
        messageText: 'GitHub integration requires GITHUB_TOKEN. Set your fine-grained token in settings.'
      };
    }

    try {
      const resp = await fetch('https://api.github.com/user/repos?sort=updated&per_page=10', {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'application/vnd.github.v3+json',
          'User-Agent': 'Lucifer-Assistant'
        },
        signal: AbortSignal.timeout(8000)
      });

      if (!resp.ok) {
        return { authenticated: false, repos: [], messageText: `GitHub API error: status ${resp.status}` };
      }

      const data = (await resp.json()) as any[];
      const repos = data.map((r) => ({
        name: r.name,
        fullName: r.full_name,
        private: r.private,
        htmlUrl: r.html_url,
        description: r.description || '',
        updatedAt: r.updated_at
      }));

      return { authenticated: true, repos };
    } catch (err: any) {
      return { authenticated: false, repos: [], messageText: `GitHub error: ${err.message}` };
    }
  }

  public static async getWorkflowRuns(
    owner: string,
    repo: string,
    token?: string
  ): Promise<{ authenticated: boolean; runs: WorkflowRunSummary[]; messageText?: string }> {
    if (!token) {
      return { authenticated: false, runs: [], messageText: 'GitHub token required.' };
    }

    const url = `https://api.github.com/repos/${owner}/${repo}/actions/runs?per_page=5`;
    try {
      const resp = await fetch(url, {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'application/vnd.github.v3+json',
          'User-Agent': 'Lucifer-Assistant'
        },
        signal: AbortSignal.timeout(8000)
      });

      if (!resp.ok) {
        return { authenticated: false, runs: [], messageText: `Failed to fetch runs: status ${resp.status}` };
      }

      const data = (await resp.json()) as any;
      const runs = (data.workflow_runs || []).map((r: any) => ({
        id: r.id,
        name: r.name,
        status: r.status,
        conclusion: r.conclusion,
        htmlUrl: r.html_url,
        createdAt: r.created_at
      }));

      return { authenticated: true, runs };
    } catch (err: any) {
      return { authenticated: false, runs: [], messageText: `Error: ${err.message}` };
    }
  }

  public static async dispatchWorkflow(
    owner: string,
    repo: string,
    workflowId: string,
    ref = 'main',
    token?: string
  ): Promise<{ success: boolean; message: string }> {
    if (!token) return { success: false, message: 'GitHub token required.' };

    if (!this.isWorkflowApproved(repo, workflowId)) {
      return {
        success: false,
        message: `Workflow '${workflowId}' on '${repo}' is not on the approved workflow registry allowlist.`
      };
    }

    const url = `https://api.github.com/repos/${owner}/${repo}/actions/workflows/${workflowId}/dispatches`;
    try {
      const resp = await fetch(url, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'application/vnd.github.v3+json',
          'User-Agent': 'Lucifer-Assistant',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ ref }),
        signal: AbortSignal.timeout(10000)
      });

      if (resp.status === 204) {
        return { success: true, message: `Dispatched workflow '${workflowId}' on '${owner}/${repo}' (ref: ${ref})` };
      }

      const errText = await resp.text();
      return { success: false, message: `Dispatch failed (${resp.status}): ${errText}` };
    } catch (err: any) {
      return { success: false, message: `Error dispatching workflow: ${err.message}` };
    }
  }
}
