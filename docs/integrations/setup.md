# Integrations and Credentials Setup

## 1. Telegram Bot (Primary Interface)
1. Message `@BotFather` on Telegram.
2. For staging, the dedicated bot is `@LuciferStagingVinitBot`.
3. Note the generated `TELEGRAM_BOT_TOKEN`.
4. Message `@userinfobot` to retrieve the operator's primary Telegram numerical user ID. Set this as `TELEGRAM_OWNER_ID`.
   > [!IMPORTANT]
   > Authorization strictly enforces immutable numeric Telegram User IDs (`from.id`). Telegram usernames/handles (`@username`) can change or be impersonated and are strictly rejected as authorization identifiers. Do not create a separate Telegram account for staging; use the operator's primary numeric account ID.

## 2. Free AI Providers

### Google Gemini API
1. Visit [Google AI Studio](https://aistudio.google.com/).
2. Click "Get API Key" and generate a free API key.
3. Configure `GEMINI_API_KEYS=<your_key>`.

### Groq Cloud API
1. Visit [Groq Console](https://console.groq.com/).
2. Create an API key.
3. Configure `GROQ_API_KEYS=<your_key>`.

### OpenRouter API
1. Visit [OpenRouter](https://openrouter.ai/).
2. Create an API key.
3. Lucifer will automatically restrict routing to `:free` models when `BUDGET_MODE=FREE_ONLY`.

## 3. Local Ollama (100% Private Mac Inference)
1. Install Ollama: `brew install ollama` (already installed on this Mac).
2. Start the daemon: `ollama serve`.
3. Pull an efficient model:
   ```bash
   ollama pull gemma2:2b
   # or
   ollama pull qwen2.5-coder:1.5b
   ```

## 4. GitHub Integration
1. Go to GitHub Settings -> Developer Settings -> Personal Access Tokens (Fine-Grained).
2. Grant read access to Repositories and read/write to Actions workflows.
3. Set `GITHUB_TOKEN`.
