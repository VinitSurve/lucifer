# Project Lucifer — Security & Threat Model Audit

This security audit was conducted by inspecting the source code and testing attack surfaces against Project Lucifer.

---

## 1. Prioritized Vulnerability Report

### [CRITICAL-1] Unauthenticated Outbound Polling & Task Injection Endpoints
- **Location:** `apps/cloud/src/index.ts:148-202`
- **Threat:** Any unauthenticated entity on the internet can make POST requests to:
  - `/api/agent/heartbeat`: Register or overwrite device status.
  - `/api/agent/poll`: Lease pending `LOCAL_MAC` tasks and view task payloads.
  - `/api/agent/result`: Inject arbitrary completion or failure statuses for tasks.
- **Root Cause:** Device `authSecretHash` is stored in the database but never verified against an incoming Bearer token, HMAC signature, or header.
- **Impact:** Complete compromise of local task queue; unauthorized extraction of tasks and spoofing of execution results.

---

### [CRITICAL-2] Arbitrary Code Execution on Local Mac via Allowlisted `python3`
- **Location:** `apps/local-agent/src/lucifer_agent/executor.py:16`
- **Threat:** `python3` is listed in `ControlledExecutor.ALLOWED_COMMANDS`.
- **Evidence Tested:**
  ```python
  ex = ControlledExecutor([str(Path.home() / 'Vinit')])
  res = ex.execute_command('python3', ['-c', 'import sys; print("executed arbitrary code")'], str(Path.home() / 'Vinit'))
  # Output: {'success': True, 'returncode': 0, 'stdout': 'executed arbitrary code\n', 'stderr': ''}
  ```
- **Root Cause:** While `subprocess.run(shell=False)` prevents shell metacharacter injection (`|`, `;`, `&&`), the command allowlist permits `python3` with arbitrary arguments. Passing `-c "<python_code>"` executes arbitrary system calls via `os.system()` or `subprocess`.
- **Impact:** An attacker who compromises the LLM prompt or injects a tool call can achieve full arbitrary code execution on the user's Mac.

---

### [HIGH-1] Missing Rate Limiting on Edge Webhook
- **Location:** `apps/cloud/src/index.ts`
- **Threat:** A denial of service attack or repeated webhook flooding.
- **Root Cause:** `SlidingWindowRateLimiter` was implemented and tested in `@lucifer/security/src/rate-limiter.ts`, but is never instantiated or called in `apps/cloud/src/index.ts`.
- **Impact:** No rate limiting is enforced on incoming webhook updates.

---

### [HIGH-2] Missing Secret Redaction in Outgoing Telegram Responses
- **Location:** `apps/cloud/src/telegram/client.ts`
- **Threat:** Sensitive tokens, keys, or credentials leaked via LLM outputs or error stack traces.
- **Root Cause:** `SecretRedactor` was implemented and tested in `@lucifer/security/src/secret-redactor.ts`, but is never invoked prior to calling `TelegramBotClient.sendMessage()`.
- **Impact:** Error messages containing API keys or tokens are delivered unredacted to Telegram chats.

---

### [HIGH-3] Missing Telegram Update Deduplication (Replay Vulnerability)
- **Location:** `apps/cloud/src/index.ts:53-145`
- **Threat:** Duplicate update processing and task re-execution.
- **Root Cause:** Telegram `update_id` is parsed but not checked against an idempotency store or processed updates table.
- **Impact:** Telegram retries (caused by network jitter or worker execution latency) re-execute state transitions, duplicate task creation, and re-send responses.

---

### [MEDIUM-1] Conditional Webhook Secret Token Verification
- **Location:** `apps/cloud/src/index.ts:46`
- **Threat:** Unauthenticated webhook POST requests if secret is omitted.
- **Root Cause:** `if (env.TELEGRAM_WEBHOOK_SECRET && !authGuard.validateWebhookSecret(headerSecret))` allows requests through if `TELEGRAM_WEBHOOK_SECRET` is unset in the worker environment.
- **Impact:** In development or misconfigured production, the webhook endpoint is exposed without secret verification.

---

### [MEDIUM-2] Non-Atomic Task Leasing in D1
- **Location:** `apps/cloud/src/db/repository.ts:284-306`
- **Threat:** Race conditions during concurrent local agent polling.
- **Root Cause:** `leaseNextLocalTask` executes three separate statements (`SELECT`, `INSERT task_leases`, `UPDATE tasks`) sequentially instead of using `db.batch()` to guarantee an atomic transaction.
- **Impact:** Multiple concurrent poll requests can lease the same task simultaneously.

---

### [LOW-1] OpenRouter Pricing Metadata is Statically Assumed
- **Location:** `packages/provider-registry/src/adapters/openrouter.ts`
- **Threat:** Risk of incurring paid model charges if an OpenRouter model changes pricing.
- **Root Cause:** Models with `:free` suffix are statically hardcoded as `isFreeTier: true` without querying OpenRouter's live `/api/v1/models` pricing endpoint.
- **Impact:** Model pricing shifts are not detected dynamically.

---

## 2. Security Defense Audit Summary

| Security Mechanism | Implementation Location | Actual Status |
|---|---|---|
| Telegram Owner Auth | `packages/security/src/telegram-auth.ts` | **ACTIVE & VERIFIED** |
| Constant-Time Webhook Secret | `packages/security/src/telegram-auth.ts` | **ACTIVE & VERIFIED** |
| SSRF Guard | `packages/security/src/ssrf-filter.ts` | **ACTIVE & VERIFIED** |
| Prompt Injection Boundary | `packages/security/src/prompt-injection.ts` | **ACTIVE & VERIFIED** |
| Secret Redaction | `packages/security/src/secret-redactor.ts` | **IMPLEMENTED BUT UNWIRED IN CLOUD** |
| Rate Limiting | `packages/security/src/rate-limiter.ts` | **IMPLEMENTED BUT UNWIRED IN CLOUD** |
| Local Path Traversal Protection | `apps/local-agent/src/lucifer_agent/executor.py` | **ACTIVE & VERIFIED** |
| Local Command Allowlist | `apps/local-agent/src/lucifer_agent/executor.py` | **FLAWED (`python3` allows arbitrary code)** |
| Local Agent Endpoint Auth | `apps/cloud/src/index.ts` | **MISSING (Unauthenticated)** |
