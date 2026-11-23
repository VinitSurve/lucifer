# Cloudflare Deployment Guide

Lucifer is engineered to run completely within Cloudflare's free tier.

## 1. Prerequisites
- Cloudflare account (Free plan)
- Node.js 24 and pnpm installed
- Wrangler CLI (included in devDependencies)

## 2. D1 Database Setup
Create your D1 database using Wrangler:
```bash
pnpm dlx wrangler d1 create lucifer-db
```
Copy the output database ID into `apps/cloud/wrangler.toml`:
```toml
[[d1_databases]]
binding = "DB"
database_name = "lucifer-db"
database_id = "<YOUR_D1_DATABASE_ID>"
```

Apply database migrations:
```bash
# Local development
pnpm --filter @lucifer/cloud run db:migrate:local

# Production
pnpm --filter @lucifer/cloud run db:migrate:prod
```

## 3. Set Production Secrets
Set your required production secrets:
```bash
pnpm dlx wrangler secret put TELEGRAM_BOT_TOKEN
pnpm dlx wrangler secret put TELEGRAM_OWNER_ID
pnpm dlx wrangler secret put TELEGRAM_WEBHOOK_SECRET
pnpm dlx wrangler secret put GEMINI_API_KEYS
pnpm dlx wrangler secret put GROQ_API_KEYS
```

## 4. Deploy the Worker
Deploy the Cloudflare Worker:
```bash
pnpm --filter @lucifer/cloud run deploy
```

## 5. Register Telegram Webhook
Register your webhook with Telegram using curl:
```bash
curl -F "url=https://<YOUR_WORKER_SUBDOMAIN>.workers.dev/webhook/telegram" \
     -F "secret_token=<YOUR_TELEGRAM_WEBHOOK_SECRET>" \
     https://api.telegram.org/bot<YOUR_TELEGRAM_BOT_TOKEN>/setWebhook
```
