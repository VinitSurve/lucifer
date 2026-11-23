# 😈 PROJECT LUCIFER — Private AI Command Center

> *"Your private, personal AI command center."*

Lucifer is a private, multi-model personal assistant and autonomous agent accessible primarily through Telegram. Engineered with a hybrid cloud + local macOS architecture, Lucifer delivers high-performance AI capabilities, automated briefings, web research, code execution, and digital service integrations with a strict **$0-budget, free-tier-first** philosophy.

---

## ⚡ Key Highlights

> [!NOTE]
> **Reality Audit Notice:** For a complete, skeptical breakdown of implemented features, mock stubs, and security findings, see [AUDIT_REPORT.md](file:///Users/vinit/Vinit/Lucifer/AUDIT_REPORT.md) and [INTEGRATION_STATUS.md](file:///Users/vinit/Vinit/Lucifer/INTEGRATION_STATUS.md).

- **Telegram Interface:** Full personal command center with commands, inline buttons, confirmation dialogs, and natural conversation.
- **Hybrid Cloudflare + macOS:**
  - **Cloud:** Cloudflare Workers, D1 SQL Database, and Cron Triggers. Runs 24/7 at $0 cost.
  - **Local Mac:** Outbound-polling Python agent (`uv`), local Ollama integration, and safe project file inspection.
- **Intelligent Model Router:**
  - Dynamically classifies tasks (FAST, RESEARCH, REASONING, CODING, PRIVATE).
  - Routes among **Google Gemini 2.0 Flash**, **Groq Cloud (Llama 3.3 70B)**, **OpenRouter (Free tier)**, **Cloudflare Workers AI**, and **Local Ollama**.
  - Automatic fallback with circuit breaking and exponential backoff.
- **Risk-Based Approval Gates:**
  - 4-Tier security model (Tier 0 to Tier 3).
  - Sensitive operations (sending emails, modifying calendar, dispatching GitHub workflows, running Mac commands) require interactive Telegram confirmation.
- **Connected Services:**
  - **Gmail:** Read, search, unread thread summarization, safe draft creation.
  - **Google Calendar:** Today's schedule, upcoming meetings, conflict detection.
  - **Google Drive:** Document search and metadata discovery.
  - **GitHub:** Repositories, Actions workflow status, and controlled workflow dispatching.
  - **Web Research:** Safe web search, SSRF-filtered page fetching, citation extraction.
- **Security & Privacy First:**
  - Telegram Owner ID allowlist.
  - Constant-time webhook token verification.
  - Secret redaction in logs and Telegram output.
  - Strict command allowlists and path containment checks on macOS.
  - Prompt injection isolation via `<untrusted_external_content>` tags.

---

## 📁 Monorepo Structure

```text
lucifer/
│
├── apps/
│   ├── cloud/               # Cloudflare Worker backend (TypeScript, D1, Cron, Webhook)
│   ├── local-agent/         # macOS Local Agent (Python, uv, Ollama bridge, Controlled executor)
│   └── cli/                 # Diagnostic & Management CLI
│
├── packages/
│   ├── shared-types/        # Domain entities (Tasks, Approvals, Tools, Providers, Telegram)
│   ├── security/            # Telegram auth, SSRF filter, Secret redactor, Prompt injection defense
│   ├── tool-contracts/      # Tool schemas, permission tiers (0-3), Loop guard
│   └── provider-registry/   # Gemini, Groq, OpenRouter, Workers AI, Ollama & ModelRouter
│
├── docs/                    # Architecture, deployment, integrations, security, troubleshooting
├── scripts/                 # dev.sh, doctor.sh, test-all.sh
└── .github/workflows/       # CI test & build pipeline, CD deploy workflow
```

---

## 🚀 Quick Start

### 1. Clone & Install
```bash
git clone https://github.com/vinit/Lucifer.git
cd Lucifer

# Install TypeScript workspace dependencies
pnpm install

# Build all packages
pnpm build
```

### 2. Run Diagnostics
```bash
./scripts/doctor.sh
```

### 3. Run All Tests
```bash
./scripts/test-all.sh
```

### 4. Start Local macOS Agent
```bash
cd apps/local-agent
uv sync
uv run lucifer-agent status
uv run lucifer-agent run
```

---

## 🤖 Telegram Commands

| Command | Description |
|---|---|
| `/start` | Welcome overview & interactive command menu |
| `/help` | Complete commands manual |
| `/status` | Cloud backend, D1 database, provider health & Mac agent status |
| `/health` | Real-time AI provider latency and cooldown telemetry |
| `/models` | List available models, context windows, and free-tier status |
| `/usage` | Operating cost ($0.00) and token metrics |
| `/tasks` | View active, queued, and completed tasks |
| `/morning` | Instant morning briefing with tasks, emails, and calendar |
| `/email` | Search unread emails or summarize threads |
| `/calendar` | Check today's events and detect overlapping meetings |
| `/github` | View repositories and GitHub Actions CI workflow runs |
| `/research <query>` | Multi-source web research with source links and citations |
| `/agent` or `/local` | Check Mac hardware metrics, CPU/RAM, and Ollama status |
| `/memory` | Inspect long-term persistent remembered facts |
| `/forget <key>` | Delete a stored memory |

---

## 🛡️ License
Private project. All rights reserved.
