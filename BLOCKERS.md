# Lucifer Blockers and Credentials Checklist

This file tracks external dependencies and required credentials. Core system components are built to run in mock/test mode without credentials and activate live integrations seamlessly once provided.

| Service | Credential Required | Purpose | Status | Impact / Workaround |
|---|---|---|---|---|
| Telegram Bot | `TELEGRAM_BOT_TOKEN` | Incoming bot messages & commands (Staging bot: `@LuciferStagingVinitBot`) | Awaiting User Setup | Local/mock testing enabled; CLI available |
| Telegram Owner | `TELEGRAM_OWNER_ID` | Access control allowlist (Operator's numeric ID from `@userinfobot`; usernames prohibited) | Awaiting User ID | Defaults to secure reject if unset |
| Telegram Webhook | `TELEGRAM_WEBHOOK_SECRET` | Header validation | Generated on deployment | Secure random string |
| Gemini API | `GEMINI_API_KEYS` | Free-tier Google AI model access | Awaiting User Key | Falls back to Groq, Workers AI or Ollama |
| Groq API | `GROQ_API_KEYS` | Fast free-tier Llama models | Awaiting User Key | Falls back to Gemini or Workers AI |
| OpenRouter | `OPENROUTER_API_KEYS` | Free tier models router | Awaiting User Key | Falls back to other providers |
| GitHub | `GITHUB_TOKEN` | Fine-grained token for issues/actions | Awaiting User Token | Read/dispatch mocked in tests |
| Google OAuth | `GOOGLE_CLIENT_ID` / `SECRET` | Gmail, Calendar, Drive access | Awaiting GCP App Setup | Read-only OAuth flow ready; unit tests cover protocol |
| Cloudflare | Account & D1 ID | Cloudflare Workers deployment | Awaiting Deployment Action | Local Wrangler testing enabled |
