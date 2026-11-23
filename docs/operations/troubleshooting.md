# Lucifer Operations and Troubleshooting

## Diagnostics Commands

Run the monorepo diagnostic doctor:
```bash
./scripts/doctor.sh
```

Run local Mac agent status:
```bash
cd apps/local-agent
uv run lucifer-agent status
```

Run local agent diagnostics:
```bash
cd apps/local-agent
uv run lucifer-agent doctor
```

## Common Scenarios & Resolutions

### 1. Local Mac Agent is Offline
- Symptom: `/status` on Telegram shows Mac Agent offline.
- Resolution: Start the agent daemon on your Mac:
  ```bash
  cd apps/local-agent
  uv run lucifer-agent run --cloud-url https://<your_worker>.workers.dev
  ```

### 2. Ollama is Offline
- Symptom: Local agent doctor warns "Local Ollama Daemon: Not responding on 127.0.0.1:11434".
- Resolution: Start Ollama in a terminal:
  ```bash
  ollama serve
  ```

### 3. Telegram Webhook Returns 401 Unauthorized
- Symptom: Updates fail to reach Lucifer.
- Resolution: Ensure `X-Telegram-Bot-Api-Secret-Token` matches the `TELEGRAM_WEBHOOK_SECRET` secret configured in Cloudflare Workers.
