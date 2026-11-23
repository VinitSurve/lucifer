# Lucifer Architecture Overview

Lucifer is built as a hybrid cloud and local-first autonomous command center.

## Core Architectural Principles

1. **Free-Tier-First & $0 Budget:** Defaults to `BUDGET_MODE=FREE_ONLY`. Paid models or endpoints are blocked from automatic invocation.
2. **Hybrid Cloud + Local Workstation:**
   - **Cloudflare Worker & D1:** Handles 24/7 Telegram webhooks, async queue, persistence, and proactive cron jobs (e.g. morning briefing).
   - **Local macOS Agent:** Connects outbound over HTTPS. Never exposes open ports to the public internet. Executes local code analysis, git status, and local Ollama inference.
3. **Multi-Model Provider Abstraction:**
   - Unified interface for Google Gemini, Groq Cloud, OpenRouter, Cloudflare Workers AI, and local Ollama.
   - Dynamic health tracking with exponential backoff, circuit breaking, and automatic fallback.
4. **Defense in Depth Security:**
   - Strict Telegram owner ID allowlist.
   - Constant-time webhook secret token validation.
   - Server-Side Request Forgery (SSRF) guard.
   - Prompt injection isolation envelopes (`<untrusted_external_content>`).
   - Secret redaction for keys and tokens.
   - 4-Tier Permission Guard with Telegram interactive confirmation dialogs for sensitive or dangerous operations.

```
Telegram User (Owner Only)
         │
         ▼
[ Cloudflare Worker Edge ]
   ├── TelegramAuthGuard (Secret token & Owner ID allowlist)
   ├── RateLimiter & SecretRedactor
   ├── D1 Database (Conversations, Tasks, Approvals, Devices)
   ├── ModelRouter (Task classification & Provider fallback)
   │     ├── Google Gemini API (2.0 Flash)
   │     ├── Groq Cloud (Llama 3.3 70B)
   │     ├── OpenRouter (Free models)
   │     └── Workers AI (Llama 3.1 8B)
   └── Outbound Task Queue
         │
         │ (Outbound HTTPS Polling)
         ▼
[ Local macOS Agent ]
   ├── ControlledExecutor (Allowlisted paths & commands)
   ├── Hardware & OS Metrics
   └── Local Ollama (100% Private, offline LLMs)
```
