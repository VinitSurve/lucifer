# Project Lucifer — Security & Threat Model Audit

This security audit was conducted by inspecting the source code and testing attack surfaces against Project Lucifer.

---

## 1. Prioritized Vulnerability Report

### [CRITICAL-1] Unauthenticated Outbound Polling & Task Injection Endpoints [REMEDIATED - PHASE 1]
- **Location:** `apps/cloud/src/index.ts:148-202`
- **Threat:** Any unauthenticated entity on the internet can make POST requests to:
  - `/api/agent/heartbeat`: Register or overwrite device status.
  - `/api/agent/poll`: Lease pending `LOCAL_MAC` tasks and view task payloads.
  - `/api/agent/result`: Inject arbitrary completion or failure statuses for tasks.
- **Root Cause:** Device `authSecretHash` is stored in the database but never verified against an incoming Bearer token, HMAC signature, or header.
- **Remediation Status:** **REMEDIATED (PHASE 1)**. Implemented `DeviceAuthGuard` with SHA-256 token verification and constant-time comparison. Added `/api/agent/pair` provisioning route requiring `DEVICE_PAIRING_SECRET`. Enforced device auth on `/api/agent/heartbeat`, `/api/agent/poll`, and `/api/agent/result` (401 on missing/invalid token). Enforced task lease ownership check on `/api/agent/result` (403 on mismatched device). Covered by automated tests.

---

### [CRITICAL-2] Arbitrary Code Execution on Local Mac via Allowlisted `python3` [REMEDIATED - PHASE 1]
- **Location:** `apps/local-agent/src/lucifer_agent/executor.py:16`
- **Threat:** `python3` was listed in `ControlledExecutor.ALLOWED_COMMANDS`.
- **Root Cause:** While `subprocess.run(shell=False)` prevents shell metacharacter injection (`|`, `;`, `&&`), the command allowlist permitted `python3` with arbitrary arguments. Passing `-c "<python_code>"` executed arbitrary system calls.
- **Remediation Status:** **REMEDIATED (PHASE 1)**. Completely removed `python3` from the allowlist. Implemented regex checks blocking shell metacharacters and path traversal `..`. Enforced strict capability allowlists on remaining CLI tools (`git`, `pytest`, `npm`, `pnpm`, `uv`) and blocked access to sensitive files (`.env`, `.git/config`, SSH keys). Verified with 4 new security tests in pytest.

---

### [HIGH-1] Missing Rate Limiting on Edge Webhook [REMEDIATED - PHASE 1]
- **Location:** `apps/cloud/src/index.ts`
- **Threat:** A denial of service attack or repeated webhook flooding.
- **Root Cause:** `SlidingWindowRateLimiter` was implemented and tested in `@lucifer/security/src/rate-limiter.ts`, but was never instantiated or called in `apps/cloud/src/index.ts`.
- **Remediation Status:** **REMEDIATED (PHASE 1)**. Instantiated `webhookRateLimiter` (60 req/min, burst 10) and `agentRateLimiter` (60 req/min, burst 15) in `apps/cloud/src/index.ts`. Wired into `/webhook/telegram` and `/api/agent/*` routes. Trips return HTTP 429 with `Retry-After: 60`. Note: In-memory rate limiting is isolate-local in Cloudflare Workers.

---

### [HIGH-2] Missing Secret Redaction in Outgoing Telegram Responses [REMEDIATED - PHASE 1]
- **Location:** `apps/cloud/src/telegram/client.ts`
- **Threat:** Sensitive tokens, keys, or credentials leaked via LLM outputs or error stack traces.
- **Root Cause:** `SecretRedactor` was implemented and tested in `@lucifer/security/src/secret-redactor.ts`, but was never invoked prior to calling `TelegramBotClient.sendMessage()`.
- **Remediation Status:** **REMEDIATED (PHASE 1)**. Wired `SecretRedactor.redact()` directly into `sendMessage()` and `editMessageText()` in `TelegramBotClient`, and into orchestrator error handlers. Verified with automated test redacting bot tokens, Gemini keys, and Bearer tokens.

---

### [HIGH-3] Missing Telegram Update Deduplication (Replay Vulnerability) [REMEDIATED - PHASE 1]
- **Location:** `apps/cloud/src/index.ts:53-145`
- **Threat:** Duplicate update processing and task re-execution.
- **Root Cause:** Telegram `update_id` was parsed but not checked against an idempotency store or processed updates table.
- **Remediation Status:** **REMEDIATED (PHASE 1)**. Added `processed_updates` table to D1. Implemented atomic primary-key collision check in `markUpdateProcessed()`. Webhook handler immediately drops duplicate updates with HTTP 200 `{ ok: true, note: 'Duplicate update ignored' }`. Verified with automated test.

---

### [MEDIUM-1] Conditional Webhook Secret Token Verification
- **Location:** `apps/cloud/src/index.ts:46`
- **Threat:** Unauthenticated webhook POST requests if secret is omitted.
- **Root Cause:** `if (env.TELEGRAM_WEBHOOK_SECRET && !authGuard.validateWebhookSecret(headerSecret))` allows requests through if `TELEGRAM_WEBHOOK_SECRET` is unset in the worker environment.
- **Impact:** In development or misconfigured production, the webhook endpoint is exposed without secret verification.

---

### [MEDIUM-2] Non-Atomic Task Leasing in D1 [REMEDIATED - PHASE 1]
- **Location:** `apps/cloud/src/db/repository.ts:284-306`
- **Threat:** Race conditions during concurrent local agent polling.
- **Root Cause:** `leaseNextLocalTask` executed separate statements without conditional updates.
- **Remediation Status:** **REMEDIATED (PHASE 1)**. Implemented conditional update `WHERE id = ? AND status IN ('PENDING', 'QUEUED')` and checked `meta.changes === 1` before creating task lease. Added `verifyTaskOwnership` check on task result submission.

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
| Secret Redaction | `packages/security/src/secret-redactor.ts` & `apps/cloud/src/telegram/client.ts` | **ACTIVE & VERIFIED (REMEDIATED)** |
| Rate Limiting | `packages/security/src/rate-limiter.ts` & `apps/cloud/src/index.ts` | **ACTIVE & VERIFIED (REMEDIATED)** |
| Local Path Traversal Protection | `apps/local-agent/src/lucifer_agent/executor.py` | **ACTIVE & VERIFIED** |
| Local Command Allowlist | `apps/local-agent/src/lucifer_agent/executor.py` | **HARDENED & VERIFIED (REMEDIATED - `python3` removed)** |
| Local Agent Endpoint Auth | `apps/cloud/src/index.ts` & `packages/security/src/device-auth.ts` | **ACTIVE & VERIFIED (REMEDIATED - 401 & 403 enforced)** |
| Telegram Update Deduplication | `apps/cloud/migrations/0002_security_remediation.sql` & `apps/cloud/src/index.ts` | **ACTIVE & VERIFIED (REMEDIATED - atomic D1 PK)** |
