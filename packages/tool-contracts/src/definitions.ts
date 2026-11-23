import { ToolDefinition } from '@lucifer/shared-types';

export const BUILTIN_TOOLS: Record<string, ToolDefinition> = {
  // Web Research
  web_search: {
    name: 'web_search',
    description: 'Searches the web for up-to-date information, documentation, news, or articles.',
    riskTier: 'TIER_0_READ_ONLY',
    executionTarget: 'CLOUD',
    timeoutMs: 15000,
    parameters: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'The search query to look up' },
        numResults: { type: 'number', description: 'Number of results to return (max 10)' }
      },
      required: ['query']
    }
  },
  fetch_url: {
    name: 'fetch_url',
    description: 'Safely fetches webpage text content for analysis, parsing, and citations.',
    riskTier: 'TIER_0_READ_ONLY',
    executionTarget: 'CLOUD',
    timeoutMs: 15000,
    parameters: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'The public HTTP/HTTPS URL to fetch' }
      },
      required: ['url']
    }
  },

  // Gmail
  email_search: {
    name: 'email_search',
    description: 'Searches unread or recent emails with query filters.',
    riskTier: 'TIER_0_READ_ONLY',
    executionTarget: 'CLOUD',
    timeoutMs: 10000,
    parameters: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Gmail query string, e.g. "is:unread label:important"' },
        maxResults: { type: 'number', description: 'Maximum emails to retrieve (default 5)' }
      }
    }
  },
  email_create_draft: {
    name: 'email_create_draft',
    description: 'Creates a draft email in Gmail without sending it.',
    riskTier: 'TIER_1_LOW_RISK',
    executionTarget: 'CLOUD',
    timeoutMs: 10000,
    parameters: {
      type: 'object',
      properties: {
        to: { type: 'string', description: 'Recipient email address' },
        subject: { type: 'string', description: 'Email subject' },
        bodyText: { type: 'string', description: 'Draft body content' }
      },
      required: ['to', 'subject', 'bodyText']
    }
  },
  email_send: {
    name: 'email_send',
    description: 'Sends an email to a recipient. Requires user confirmation.',
    riskTier: 'TIER_2_SENSITIVE',
    executionTarget: 'CLOUD',
    timeoutMs: 10000,
    parameters: {
      type: 'object',
      properties: {
        to: { type: 'string', description: 'Recipient email address' },
        subject: { type: 'string', description: 'Email subject' },
        bodyText: { type: 'string', description: 'Email content' }
      },
      required: ['to', 'subject', 'bodyText']
    }
  },

  // Google Calendar
  calendar_list_events: {
    name: 'calendar_list_events',
    description: 'Lists upcoming calendar events and meetings.',
    riskTier: 'TIER_0_READ_ONLY',
    executionTarget: 'CLOUD',
    timeoutMs: 10000,
    parameters: {
      type: 'object',
      properties: {
        timeMin: { type: 'string', description: 'ISO start date-time string' },
        timeMax: { type: 'string', description: 'ISO end date-time string' }
      }
    }
  },
  calendar_create_event: {
    name: 'calendar_create_event',
    description: 'Creates a new event or meeting on Google Calendar.',
    riskTier: 'TIER_2_SENSITIVE',
    executionTarget: 'CLOUD',
    timeoutMs: 10000,
    parameters: {
      type: 'object',
      properties: {
        summary: { type: 'string', description: 'Event title' },
        startTime: { type: 'string', description: 'ISO start time' },
        endTime: { type: 'string', description: 'ISO end time' },
        description: { type: 'string', description: 'Optional event description' }
      },
      required: ['summary', 'startTime', 'endTime']
    }
  },

  // Google Drive
  drive_search_files: {
    name: 'drive_search_files',
    description: 'Searches files, assignment documents, spreadsheets in Google Drive.',
    riskTier: 'TIER_0_READ_ONLY',
    executionTarget: 'CLOUD',
    timeoutMs: 10000,
    parameters: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Search term or title' }
      },
      required: ['query']
    }
  },

  // GitHub
  github_list_repos: {
    name: 'github_list_repos',
    description: 'Lists authenticated user repositories and metadata.',
    riskTier: 'TIER_0_READ_ONLY',
    executionTarget: 'CLOUD',
    timeoutMs: 10000,
    parameters: { type: 'object' }
  },
  github_workflow_status: {
    name: 'github_workflow_status',
    description: 'Checks status and recent runs for GitHub Actions workflows in a repository.',
    riskTier: 'TIER_0_READ_ONLY',
    executionTarget: 'CLOUD',
    timeoutMs: 10000,
    parameters: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner/organization' },
        repo: { type: 'string', description: 'Repository name' }
      },
      required: ['owner', 'repo']
    }
  },
  github_dispatch_workflow: {
    name: 'github_dispatch_workflow',
    description: 'Dispatches an approved GitHub Actions workflow in an allowlisted repository.',
    riskTier: 'TIER_2_SENSITIVE',
    executionTarget: 'CLOUD',
    timeoutMs: 15000,
    parameters: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner' },
        repo: { type: 'string', description: 'Repository name' },
        workflowId: { type: 'string', description: 'Workflow filename (e.g. build.yml)' },
        ref: { type: 'string', description: 'Git branch or tag (default: main)' }
      },
      required: ['owner', 'repo', 'workflowId']
    }
  },

  // Local Mac Agent
  mac_sysinfo: {
    name: 'mac_sysinfo',
    description: 'Retrieves local Mac hardware, CPU, RAM, disk usage, and Ollama status.',
    riskTier: 'TIER_0_READ_ONLY',
    executionTarget: 'LOCAL_MAC',
    timeoutMs: 10000,
    parameters: { type: 'object' }
  },
  mac_git_status: {
    name: 'mac_git_status',
    description: 'Checks git status in an approved local project directory.',
    riskTier: 'TIER_0_READ_ONLY',
    executionTarget: 'LOCAL_MAC',
    timeoutMs: 10000,
    parameters: {
      type: 'object',
      properties: {
        repoPath: { type: 'string', description: 'Relative path of approved project repo' }
      },
      required: ['repoPath']
    }
  },
  mac_read_file: {
    name: 'mac_read_file',
    description: 'Reads a source code or config file from an approved project directory.',
    riskTier: 'TIER_1_LOW_RISK',
    executionTarget: 'LOCAL_MAC',
    timeoutMs: 10000,
    parameters: {
      type: 'object',
      properties: {
        filePath: { type: 'string', description: 'Path within allowed projects directory' }
      },
      required: ['filePath']
    }
  },
  mac_run_command: {
    name: 'mac_run_command',
    description: 'Executes an approved, structured command on local Mac. Requires strict owner approval.',
    riskTier: 'TIER_3_DANGEROUS',
    executionTarget: 'LOCAL_MAC',
    timeoutMs: 30000,
    parameters: {
      type: 'object',
      properties: {
        command: { type: 'string', description: 'Approved command name (e.g. pytest, npm test)' },
        args: { type: 'array', description: 'Command arguments array' },
        cwd: { type: 'string', description: 'Working directory inside allowed projects' }
      },
      required: ['command', 'args']
    }
  }
};
