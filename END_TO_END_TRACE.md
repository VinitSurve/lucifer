# Project Lucifer — End-to-End Request Trace Audit

This document traces the actual code execution path of an incoming Telegram message through Project Lucifer, identifying working components, broken links, stubs, and missing background workers.

---

## 1. Trace Overview

```text
[ Telegram Message Inbound ]
            │
            ▼
    apps/cloud/src/index.ts (POST /webhook/telegram)
            │
    ├── Step 1: Webhook Secret Validation (TelegramAuthGuard)
    ├── Step 2: User Authorization (TelegramAuthGuard)
    ├── Step 3: Duplicate Update Check [MISSING]
            │
            ├── [If text starts with '/'] ──► TelegramCommandHandler (apps/cloud/src/telegram/handlers.ts)
            │                                     ├── /start, /help, /status, /models, /usage, /tasks
            │                                     ├── /morning (SchedulerService)
            │                                     ├── /research (ResearchService -> DuckDuckGo [BOT CHALLENGE BLOCK])
            │                                     ├── /github (GitHubService [Works if GITHUB_TOKEN set])
            │                                     └── /email, /calendar [UNAUTHENTICATED STUB - No OAuth tokens]
            │
            └── [If natural language] ────► TelegramOrchestrator (apps/cloud/src/telegram/orchestrator.ts)
                                                  │
                                                  ├── 1. Persist user message in D1 `messages`
                                                  ├── 2. Retrieve recent 6 messages from D1
                                                  ├── 3. Build tool list from `BUILTIN_TOOLS`
                                                  ├── 4. Call ModelRouter.executeWithFallback()
                                                  │         │
                                                  │         ├── Evaluate Task Class & Privacy
                                                  │         ├── Score Providers (Gemini, Groq, OpenRouter, Workers AI, Ollama)
                                                  │         └── Execute Primary Provider with Fallback
                                                  │
                                                  ├── 5. Model returns toolCalls?
                                                  │         ├── NO: Persist assistant message in D1, send to Telegram.
                                                  │         └── YES: Loop through tool calls (ToolLoopGuard: max 5 total, 3 repeat)
                                                  │
                                                  ├── 6. Permission Guard (ToolPermissionGuard)
                                                  │         ├── If Tier 2 / Tier 3 (Sensitive / Dangerous):
                                                  │         │     ├── Create TaskRecord in D1 (WAITING_APPROVAL)
                                                  │         │     ├── Create ApprovalRecord in D1 (PENDING)
                                                  │         │     └── Send Inline Approval Keyboard to Telegram
                                                  │         │           │
                                                  │         │           └── User clicks [Approve]:
                                                  │         │                 ├── Approval marked APPROVED
                                                  │         │                 ├── Task marked QUEUED
                                                  │         │                 └── [BROKEN LINK]: No Cloud Task Worker to execute QUEUED cloud tasks!
                                                  │         │
                                                  │         └── If Tier 0 (Read-Only Auto-Executable):
                                                  │               ├── 'web_search': ResearchService.webSearch() [Fails live due to DDG bot challenge]
                                                  │               ├── 'fetch_url': ResearchService.fetchAndExtractUrl() [SSRF checked & wrapped]
                                                  │               └── ALL OTHER TOOLS ('email_search', 'calendar_list_events', 'drive_search_files', 'github_list_repos', 'mac_sysinfo'):
                                                  │                     └── [STUBBED LINE 154]: Returns hardcoded string: `Executed ${tc.name} successfully.`
                                                  │
                                                  └── 7. Feed tool output back to Model -> Send final response to Telegram
```

---

## 2. Detailed Step-by-Step Code Path Analysis

### Step 1: Webhook Secret Validation
- **Location:** `apps/cloud/src/index.ts:44-51`
- **Code:**
  ```typescript
  const headerSecret = request.headers.get('X-Telegram-Bot-Api-Secret-Token');
  if (env.TELEGRAM_WEBHOOK_SECRET && !authGuard.validateWebhookSecret(headerSecret)) {
    return new Response('Unauthorized', { status: 401 });
  }
  ```
- **Finding:** If `env.TELEGRAM_WEBHOOK_SECRET` is unset in Worker secrets, the validation is skipped, allowing any unauthenticated POST request to reach the message handler.

### Step 2: Sender Authorization
- **Location:** `apps/cloud/src/index.ts:88-92`
- **Code:**
  ```typescript
  if (!authGuard.isUserAuthorized(senderId)) {
    await repo.logAudit(String(senderId), 'UNAUTHORIZED_MESSAGE', undefined, 'DENIED', 'TIER_2_SENSITIVE');
    return new Response('OK', { status: 200 });
  }
  ```
- **Finding:** Works correctly. Unauthorized senders receive a silent 200 OK (preventing Telegram webhook retries) and an audit log entry is written to D1.

### Step 3: Message Deduplication
- **Finding:** **MISSING**. Telegram `update.update_id` is parsed but never stored or checked against previous updates. If Telegram retries a webhook delivery due to edge latency, the message and its associated tasks are processed multiple times.

### Step 4: Natural Language Tool Execution
- **Location:** `apps/cloud/src/telegram/orchestrator.ts:144-155`
- **Code:**
  ```typescript
  let toolOutputText = '';
  if (tc.name === 'web_search') {
    const q = (tc.arguments.query as string) || '';
    const results = await ResearchService.webSearch(q, 3);
    toolOutputText = JSON.stringify(results);
  } else if (tc.name === 'fetch_url') {
    const url = (tc.arguments.url as string) || '';
    const fetched = await ResearchService.fetchAndExtractUrl(url);
    toolOutputText = fetched.content;
  } else {
    toolOutputText = `Executed ${tc.name} successfully.`;
  }
  ```
- **Finding:**
  - `web_search` attempts to scrape DuckDuckGo HTML, which live testing confirms returns a bot challenge block (`Unfortunately, bots use DuckDuckGo too.`).
  - `fetch_url` works as designed with SSRF filtering and prompt injection boundaries.
  - **All other tools** (`email_search`, `email_create_draft`, `calendar_list_events`, `drive_search_files`, `github_list_repos`, `mac_sysinfo`) are not dispatched to their respective services; they return the static string `"Executed <tool_name> successfully."`.

### Step 5: Post-Approval Cloud Task Execution
- **Location:** `apps/cloud/src/telegram/orchestrator.ts:221-229`
- **Code:**
  ```typescript
  await this.repo.updateApprovalState(approvalId, 'APPROVED', 'User confirmed in Telegram');
  await this.repo.updateTaskStatus(approval.taskId, 'QUEUED');
  await this.bot.sendMessage(chatId, `✅ Action \`${approval.actionName}\` approved. Task \`${approval.taskId.slice(0, 8)}\` is now running.`);
  ```
- **Finding:** Once approved, the task status is set to `QUEUED`. For local Mac tasks (`executionTarget: 'LOCAL_MAC'`), the local agent polls and executes the task. However, for cloud tasks (`executionTarget: 'CLOUD'`, such as `email_send` or `calendar_create_event`), there is no queue worker, Cloudflare Queue consumer, or background handler to execute the task. It remains in D1 as `QUEUED` indefinitely.
