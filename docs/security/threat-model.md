# Lucifer Security Architecture & Threat Model

## 1. Threat Mitigation Matrix

| Threat | Mitigation Strategy | Component |
|---|---|---|
| Unauthorized Telegram users | Numerical Telegram User ID allowlist strictly enforced | `TelegramAuthGuard` |
| Webhook spoofing / replay | Secret token header verification via constant-time comparison | `TelegramAuthGuard` |
| Prompt injection via email / web | Data wrapped in `<untrusted_external_content>` isolation boundary | `PromptInjectionDefense` |
| Server-Side Request Forgery (SSRF) | Rejection of private IPv4/IPv6, cloud metadata, link-local IPs | `SsrfFilter` |
| Secret leakage in logs / chats | Regex redaction for API keys, bot tokens, and auth headers | `SecretRedactor` |
| Remote code execution on Mac | Strictly allowlisted commands without shell interpolation | `ControlledExecutor` |
| Unauthorized filesystem access | Path containment check ensuring execution stays inside allowed paths | `ControlledExecutor` |
| Runaway LLM tool recursion | Loop guard enforcing max 8 total calls and max 4 repeats | `ToolLoopGuard` |
| Accidental paid billing | Strict `BUDGET_MODE=FREE_ONLY` default blocking non-free models | `ModelRouter` |

## 2. Permission Tiers
- **Tier 0 (Read-Only):** Safe queries (search emails, list calendar, check git status). Auto-executed.
- **Tier 1 (Low-Risk):** Draft creation, benign reminders. Auto-approved if configured.
- **Tier 2 (Sensitive):** Sending emails, creating meetings, dispatching GitHub workflows. Requires Telegram inline confirmation.
- **Tier 3 (Dangerous):** Command execution on Mac, system changes. Requires explicit owner confirmation with payload preview.
