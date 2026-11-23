import { TelegramAuthGuard } from '@lucifer/security';
import {
  GeminiProvider,
  GroqProvider,
  OpenRouterProvider,
  CloudflareAIProvider,
  OllamaProvider,
  ProviderHealthTracker,
  ModelRouter
} from '@lucifer/provider-registry';
import { CloudEnv } from './db/types';
import { LuciferDbRepository } from './db/repository';
import { TelegramBotClient } from './telegram/client';
import { TelegramCommandHandler } from './telegram/handlers';
import { TelegramOrchestrator } from './telegram/orchestrator';
import { SchedulerService } from './services/scheduler-service';

export default {
  async fetch(request: Request, env: CloudEnv, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Health check endpoint
    if (url.pathname === '/health' || url.pathname === '/') {
      return new Response(
        JSON.stringify({
          status: 'ok',
          service: 'Lucifer Cloud Core',
          env: env.LUCIFER_ENV || 'development',
          timestamp: Date.now()
        }),
        { headers: { 'Content-Type': 'application/json' } }
      );
    }

    const repo = new LuciferDbRepository(env.DB);

    // 1. Telegram Webhook Handler
    if (url.pathname === '/webhook/telegram' && request.method === 'POST') {
      const authGuard = new TelegramAuthGuard({
        ownerId: env.TELEGRAM_OWNER_ID || '',
        webhookSecret: env.TELEGRAM_WEBHOOK_SECRET
      });

      // Validate webhook secret token header
      const headerSecret = request.headers.get('X-Telegram-Bot-Api-Secret-Token');
      if (env.TELEGRAM_WEBHOOK_SECRET && !authGuard.validateWebhookSecret(headerSecret)) {
        await repo.logAudit(undefined, 'WEBHOOK_REQUEST', url.pathname, 'DENIED', 'TIER_3_DANGEROUS', {
          reason: 'Invalid or missing X-Telegram-Bot-Api-Secret-Token'
        });
        return new Response('Unauthorized', { status: 401 });
      }

      let update: any;
      try {
        update = await request.json();
      } catch {
        return new Response('Bad Request', { status: 400 });
      }

      const bot = new TelegramBotClient(env.TELEGRAM_BOT_TOKEN || '');
      const healthTracker = new ProviderHealthTracker();

      // Configure AI providers
      const geminiKeys = (env.GEMINI_API_KEYS || '').split(',').map((k) => k.trim());
      const groqKeys = (env.GROQ_API_KEYS || '').split(',').map((k) => k.trim());
      const openRouterKeys = (env.OPENROUTER_API_KEYS || '').split(',').map((k) => k.trim());

      const providers = [
        new GeminiProvider(geminiKeys),
        new GroqProvider(groqKeys),
        new OpenRouterProvider(openRouterKeys, env.BUDGET_MODE || 'FREE_ONLY'),
        new CloudflareAIProvider(env.CLOUDFLARE_ACCOUNT_ID, env.CLOUDFLARE_API_TOKEN, env.AI),
        new OllamaProvider(env.OLLAMA_URL || 'http://127.0.0.1:11434')
      ];

      const router = new ModelRouter(providers, healthTracker, {
        budgetMode: env.BUDGET_MODE || 'FREE_ONLY'
      });

      const cmdHandler = new TelegramCommandHandler(repo, bot, env);
      const orchestrator = new TelegramOrchestrator(repo, bot, router);

      // A. Message handler
      if (update.message) {
        const msg = update.message;
        const senderId = msg.from?.id;

        if (!authGuard.isUserAuthorized(senderId)) {
          await repo.logAudit(String(senderId), 'UNAUTHORIZED_MESSAGE', undefined, 'DENIED', 'TIER_2_SENSITIVE');
          // Silently acknowledge to avoid Telegram retry storm
          return new Response('OK', { status: 200 });
        }

        const user = await repo.getOrCreateUser(String(senderId), msg.from?.username);
        const text = (msg.text || '').trim();

        if (text.startsWith('/')) {
          const parts = text.split(/\s+/);
          const command = parts[0];
          const args = parts.slice(1);
          await cmdHandler.handleCommand(msg.chat.id, user.id, command, args);
        } else if (text.length > 0) {
          await orchestrator.handleNaturalLanguageMessage(msg.chat.id, user.id, text);
        }

        return new Response('OK', { status: 200 });
      }

      // B. Callback query handler (Inline buttons)
      if (update.callback_query) {
        const cq = update.callback_query;
        const senderId = cq.from?.id;

        if (!authGuard.isUserAuthorized(senderId)) {
          return new Response('OK', { status: 200 });
        }

        const user = await repo.getOrCreateUser(String(senderId), cq.from?.username);
        const data = cq.data || '';
        const chatId = cq.message?.chat?.id || senderId;

        if (data.startsWith('approve:')) {
          const approvalId = data.replace('approve:', '');
          await orchestrator.handleApprovalCallback(chatId, user.id, cq.id, 'approve', approvalId);
        } else if (data.startsWith('reject:')) {
          const approvalId = data.replace('reject:', '');
          await orchestrator.handleApprovalCallback(chatId, user.id, cq.id, 'reject', approvalId);
        } else if (data.startsWith('cmd:')) {
          const cmd = data.replace('cmd:', '');
          await bot.answerCallbackQuery(cq.id);
          await cmdHandler.handleCommand(chatId, user.id, `/${cmd}`, []);
        } else if (data.startsWith('set_model:')) {
          const modelPref = data.replace('set_model:', '');
          await repo.saveMemory(user.id, 'preferred_model', modelPref, 'settings');
          await bot.answerCallbackQuery(cq.id, `Selected: ${modelPref}`);
          await bot.sendMessage(chatId, `🤖 Preferred model set to: *${modelPref}*`, {
            parse_mode: 'Markdown'
          });
        }

        return new Response('OK', { status: 200 });
      }

      return new Response('OK', { status: 200 });
    }

    // 2. Local Mac Agent Endpoints (Outbound HTTPS Polling)
    if (url.pathname === '/api/agent/heartbeat' && request.method === 'POST') {
      const body = (await request.json()) as any;
      if (!body.deviceId) return new Response('Missing deviceId', { status: 400 });

      await repo.upsertDevice(
        body.deviceId,
        body.ownerId || env.TELEGRAM_OWNER_ID || 'default_owner',
        body.deviceName || 'MacBook',
        body.authSecretHash || 'default_hash',
        JSON.stringify(body.info || {})
      );

      return new Response(JSON.stringify({ status: 'ok', receivedAt: Date.now() }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (url.pathname === '/api/agent/poll' && request.method === 'POST') {
      const body = (await request.json()) as any;
      if (!body.deviceId) return new Response('Missing deviceId', { status: 400 });

      const task = await repo.leaseNextLocalTask(body.deviceId);
      return new Response(JSON.stringify({ task: task || null }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (url.pathname === '/api/agent/result' && request.method === 'POST') {
      const body = (await request.json()) as any;
      if (!body.taskId) return new Response('Missing taskId', { status: 400 });

      const finalStatus = body.success ? 'COMPLETED' : 'FAILED';
      await repo.updateTaskStatus(
        body.taskId,
        finalStatus,
        body.result ? JSON.stringify(body.result) : undefined,
        body.error,
        100
      );

      // Notify owner on Telegram if configured
      if (env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_OWNER_ID) {
        const bot = new TelegramBotClient(env.TELEGRAM_BOT_TOKEN);
        const icon = body.success ? '✅' : '❌';
        await bot.sendMessage(
          env.TELEGRAM_OWNER_ID,
          `${icon} *Local Task Complete:* \`${body.taskId.slice(0, 8)}\`\nStatus: *${finalStatus}*\n${body.error ? `Error: ${body.error}` : ''}`,
          { parse_mode: 'Markdown' }
        );
      }

      return new Response(JSON.stringify({ status: 'received' }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response('Not Found', { status: 404 });
  },

  // Cron Scheduled Handler
  async scheduled(event: ScheduledEvent, env: CloudEnv, ctx: ExecutionContext): Promise<void> {
    const repo = new LuciferDbRepository(env.DB);

    if (env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_OWNER_ID) {
      const bot = new TelegramBotClient(env.TELEGRAM_BOT_TOKEN);
      const briefing = await SchedulerService.generateMorningBriefing(
        env.TELEGRAM_OWNER_ID,
        repo,
        env.DEFAULT_TIMEZONE
      );
      await bot.sendMessage(env.TELEGRAM_OWNER_ID, briefing, { parse_mode: 'Markdown' });
    }
  }
};
