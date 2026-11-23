import { TelegramAuthGuard, DeviceAuthGuard, SecretRedactor, SlidingWindowRateLimiter } from '@lucifer/security';
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

// Bounded in-memory rate limiters (protects Worker isolates against burst floods and memory exhaustion)
const webhookRateLimiter = new SlidingWindowRateLimiter(60, 60000, 1000);   // 60 req/min per IP
const pairingRateLimiter = new SlidingWindowRateLimiter(5, 60000, 500);     // 5 pairing attempts/min per IP
const agentIpRateLimiter = new SlidingWindowRateLimiter(60, 60000, 1000);   // 60 req/min per IP
const agentDeviceRateLimiter = new SlidingWindowRateLimiter(60, 60000, 1000); // 60 req/min per authenticated device

export default {
  async fetch(request: Request, env: CloudEnv, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const clientIp = request.headers.get('CF-Connecting-IP') || '127.0.0.1';

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

    // =========================================================================
    // 1. TELEGRAM WEBHOOK INGRESS (DURABLE & IDEMPOTENT)
    // =========================================================================
    if (url.pathname === '/webhook/telegram' && request.method === 'POST') {
      // Edge rate limiting: 60 requests per minute per IP
      const rateCheck = webhookRateLimiter.isAllowed(clientIp);
      if (!rateCheck.allowed) {
        return new Response('Too Many Requests', {
          status: 429,
          headers: { 'Retry-After': String(Math.ceil(rateCheck.retryAfterMs / 1000)) }
        });
      }

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

      // Durable Update State Machine: Check if update can be processed
      if (update && typeof update.update_id === 'number') {
        const updateCheck = await repo.startUpdateProcessing(update.update_id);
        if (!updateCheck.canProcess) {
          await repo.logAudit(String(update.message?.from?.id || 'unknown'), 'DUPLICATE_UPDATE_IGNORED', undefined, 'FLAGGED', 'TIER_0_READ_ONLY', {
            updateId: update.update_id,
            reason: updateCheck.reason
          });
          return new Response(JSON.stringify({ ok: true, note: `Duplicate update ignored (${updateCheck.reason})` }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
          });
        }
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

      try {
        // A. Message handler
        if (update.message) {
          const msg = update.message;
          const senderId = msg.from?.id;

          if (!authGuard.isUserAuthorized(senderId)) {
            await repo.logAudit(String(senderId), 'UNAUTHORIZED_MESSAGE', undefined, 'DENIED', 'TIER_2_SENSITIVE');
            if (update && typeof update.update_id === 'number') {
              await repo.completeUpdateProcessing(update.update_id);
            }
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

          if (update && typeof update.update_id === 'number') {
            await repo.completeUpdateProcessing(update.update_id);
          }
          return new Response('OK', { status: 200 });
        }

        // B. Callback query handler (Inline buttons)
        if (update.callback_query) {
          const cq = update.callback_query;
          const senderId = cq.from?.id;

          if (!authGuard.isUserAuthorized(senderId)) {
            if (update && typeof update.update_id === 'number') {
              await repo.completeUpdateProcessing(update.update_id);
            }
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

          if (update && typeof update.update_id === 'number') {
            await repo.completeUpdateProcessing(update.update_id);
          }
          return new Response('OK', { status: 200 });
        }

        if (update && typeof update.update_id === 'number') {
          await repo.completeUpdateProcessing(update.update_id);
        }
        return new Response('OK', { status: 200 });
      } catch (err: any) {
        // Record failure so Telegram retry can re-attempt processing
        if (update && typeof update.update_id === 'number') {
          await repo.failUpdateProcessing(update.update_id, err?.message || String(err));
        }
        throw err;
      }
    }

    // =========================================================================
    // 2. LOCAL MAC AGENT API (CHECKPOINT B & C)
    // =========================================================================

    // Global IP rate check for agent endpoints to prevent unauthenticated DoS
    if (url.pathname.startsWith('/api/agent/')) {
      const ipCheck = agentIpRateLimiter.isAllowed(clientIp);
      if (!ipCheck.allowed) {
        return new Response('Too Many Requests', {
          status: 429,
          headers: { 'Retry-After': String(Math.ceil(ipCheck.retryAfterMs / 1000)) }
        });
      }
    }

    // Device Pairing Endpoint (CHECKPOINT B)
    if (url.pathname === '/api/agent/pair' && request.method === 'POST') {
      // 1. Dedicated IP rate limiting on pairing endpoint
      const pairRateCheck = pairingRateLimiter.isAllowed(clientIp);
      if (!pairRateCheck.allowed) {
        return new Response(JSON.stringify({ error: 'Too Many Requests' }), {
          status: 429,
          headers: {
            'Content-Type': 'application/json',
            'Retry-After': String(Math.ceil(pairRateCheck.retryAfterMs / 1000))
          }
        });
      }

      const body = (await request.json().catch(() => ({}))) as any;
      if (!body.deviceId || !body.deviceName) {
        return new Response(JSON.stringify({ error: 'Missing deviceId or deviceName' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      // 2. Check if device is already registered (Prevent Device Hijacking ADV-HIGH-05)
      const existingDevice = await repo.getDevice(body.deviceId);
      if (existingDevice) {
        await repo.logAudit(undefined, 'DEVICE_PAIRING_COLLISION', body.deviceId, 'DENIED', 'TIER_3_DANGEROUS');
        return new Response(
          JSON.stringify({
            error: 'Device ID is already registered. To rotate credentials, use /api/agent/rotate-token with your current token.'
          }),
          { status: 409, headers: { 'Content-Type': 'application/json' } }
        );
      }

      // 3. Pairing secret verification (NO fallback to TELEGRAM_WEBHOOK_SECRET!)
      const pairingToken = (body.pairingToken || '').trim();
      const expectedPairingSecret = (env.DEVICE_PAIRING_SECRET || '').trim();

      let isPairingAuthorized = false;
      let ownerId = env.TELEGRAM_OWNER_ID || 'default_owner';

      if (expectedPairingSecret && DeviceAuthGuard.constantTimeCompare(pairingToken, expectedPairingSecret)) {
        isPairingAuthorized = true;
      } else {
        // Support dynamic single-use pairing codes generated by owner
        const codeRes = await repo.consumePairingCode(pairingToken);
        if (codeRes.valid) {
          isPairingAuthorized = true;
          if (codeRes.ownerId) ownerId = codeRes.ownerId;
        }
      }

      if (!isPairingAuthorized) {
        await repo.logAudit(undefined, 'DEVICE_PAIRING_ATTEMPT', body.deviceId, 'DENIED', 'TIER_3_DANGEROUS');
        return new Response(JSON.stringify({ error: 'Invalid pairing token or pairing code expired' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      // 4. Generate high-entropy 32-byte device secret token
      const tokenBytes = new Uint8Array(32);
      crypto.getRandomValues(tokenBytes);
      const rawDeviceToken = Array.from(tokenBytes).map((b) => b.toString(16).padStart(2, '0')).join('');
      const hashedToken = await DeviceAuthGuard.hashToken(rawDeviceToken);

      await repo.upsertDevice(
        body.deviceId,
        ownerId,
        body.deviceName,
        hashedToken,
        JSON.stringify(body.info || {})
      );

      await repo.logAudit(ownerId, 'DEVICE_PAIRED', body.deviceId, 'SUCCESS', 'TIER_2_SENSITIVE');

      return new Response(
        JSON.stringify({ status: 'paired', deviceId: body.deviceId, token: rawDeviceToken }),
        { headers: { 'Content-Type': 'application/json' } }
      );
    }

    // Helper to authenticate agent requests
    const authenticateAgent = async (deviceId: string): Promise<{ authorized: boolean; ownerId?: string }> => {
      const authHeader = request.headers.get('Authorization');
      const customHeader = request.headers.get('X-Device-Token');
      const token = DeviceAuthGuard.extractToken(authHeader, customHeader);
      return repo.checkDeviceAuth(deviceId, token);
    };

    // Device Token Rotation Endpoint (CHECKPOINT B)
    if (url.pathname === '/api/agent/rotate-token' && request.method === 'POST') {
      const body = (await request.json().catch(() => ({}))) as any;
      if (!body.deviceId) return new Response('Missing deviceId', { status: 400 });

      const auth = await authenticateAgent(body.deviceId);
      if (!auth.authorized) {
        await repo.logAudit(undefined, 'AGENT_ROTATE_UNAUTHORIZED', body.deviceId, 'DENIED', 'TIER_3_DANGEROUS');
        return new Response('Unauthorized', { status: 401 });
      }

      // Generate new 32-byte secret
      const tokenBytes = new Uint8Array(32);
      crypto.getRandomValues(tokenBytes);
      const newRawToken = Array.from(tokenBytes).map((b) => b.toString(16).padStart(2, '0')).join('');
      const newHashedToken = await DeviceAuthGuard.hashToken(newRawToken);

      await repo.rotateDeviceToken(body.deviceId, newHashedToken);
      await repo.logAudit(auth.ownerId, 'DEVICE_TOKEN_ROTATED', body.deviceId, 'SUCCESS', 'TIER_2_SENSITIVE');

      return new Response(JSON.stringify({ status: 'rotated', token: newRawToken }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Device Revocation Endpoint (CHECKPOINT B)
    if (url.pathname === '/api/agent/revoke' && request.method === 'POST') {
      const body = (await request.json().catch(() => ({}))) as any;
      if (!body.deviceId) return new Response('Missing deviceId', { status: 400 });

      const auth = await authenticateAgent(body.deviceId);
      if (!auth.authorized) {
        return new Response('Unauthorized', { status: 401 });
      }

      await repo.revokeDevice(body.deviceId);
      await repo.logAudit(auth.ownerId, 'DEVICE_REVOKED', body.deviceId, 'SUCCESS', 'TIER_2_SENSITIVE');

      return new Response(JSON.stringify({ status: 'revoked', deviceId: body.deviceId }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Heartbeat Endpoint
    if (url.pathname === '/api/agent/heartbeat' && request.method === 'POST') {
      const body = (await request.json().catch(() => ({}))) as any;
      if (!body.deviceId) return new Response('Missing deviceId', { status: 400 });

      const auth = await authenticateAgent(body.deviceId);
      if (!auth.authorized) {
        await repo.logAudit(undefined, 'AGENT_HEARTBEAT_UNAUTHORIZED', body.deviceId, 'DENIED', 'TIER_3_DANGEROUS');
        return new Response('Unauthorized', { status: 401 });
      }

      // Authenticated device rate limiting
      const devRateCheck = agentDeviceRateLimiter.isAllowed(body.deviceId);
      if (!devRateCheck.allowed) {
        return new Response('Too Many Requests', {
          status: 429,
          headers: { 'Retry-After': String(Math.ceil(devRateCheck.retryAfterMs / 1000)) }
        });
      }

      await repo.upsertDevice(
        body.deviceId,
        auth.ownerId || env.TELEGRAM_OWNER_ID || 'default_owner',
        body.deviceName || 'MacBook',
        '', // Do not overwrite existing secret hash
        JSON.stringify(body.info || {})
      );

      return new Response(JSON.stringify({ status: 'ok', receivedAt: Date.now() }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Task Polling Endpoint (CHECKPOINT C - Expired Leases Reclaimed First)
    if (url.pathname === '/api/agent/poll' && request.method === 'POST') {
      const body = (await request.json().catch(() => ({}))) as any;
      if (!body.deviceId) return new Response('Missing deviceId', { status: 400 });

      const auth = await authenticateAgent(body.deviceId);
      if (!auth.authorized) {
        await repo.logAudit(undefined, 'AGENT_POLL_UNAUTHORIZED', body.deviceId, 'DENIED', 'TIER_3_DANGEROUS');
        return new Response('Unauthorized', { status: 401 });
      }

      // Authenticated device rate limiting
      const devRateCheck = agentDeviceRateLimiter.isAllowed(body.deviceId);
      if (!devRateCheck.allowed) {
        return new Response('Too Many Requests', {
          status: 429,
          headers: { 'Retry-After': String(Math.ceil(devRateCheck.retryAfterMs / 1000)) }
        });
      }

      const task = await repo.leaseNextLocalTask(body.deviceId);
      return new Response(JSON.stringify({ task: task || null }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Lease Renewal Endpoint (CHECKPOINT C)
    if (url.pathname === '/api/agent/renew-lease' && request.method === 'POST') {
      const body = (await request.json().catch(() => ({}))) as any;
      if (!body.taskId || !body.deviceId) return new Response('Missing taskId or deviceId', { status: 400 });

      const auth = await authenticateAgent(body.deviceId);
      if (!auth.authorized) return new Response('Unauthorized', { status: 401 });

      const renewed = await repo.renewTaskLease(body.taskId, body.deviceId, 60000);
      if (!renewed) {
        return new Response(JSON.stringify({ error: 'Lease expired or task not held by device' }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      return new Response(JSON.stringify({ status: 'renewed', taskId: body.taskId }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Task Result Submission Endpoint (CHECKPOINT C - Idempotent & Expired Check)
    if (url.pathname === '/api/agent/result' && request.method === 'POST') {
      const body = (await request.json().catch(() => ({}))) as any;
      if (!body.taskId || !body.deviceId) return new Response('Missing taskId or deviceId', { status: 400 });

      const auth = await authenticateAgent(body.deviceId);
      if (!auth.authorized) {
        await repo.logAudit(undefined, 'AGENT_RESULT_UNAUTHORIZED', body.deviceId, 'DENIED', 'TIER_3_DANGEROUS');
        return new Response('Unauthorized', { status: 401 });
      }

      // 1. Idempotency check: if task is already terminal (COMPLETED or FAILED), do not re-execute or resend Telegram
      const existingTask = await repo.getTask(body.taskId);
      if (existingTask && (existingTask.status === 'COMPLETED' || existingTask.status === 'FAILED')) {
        return new Response(
          JSON.stringify({ status: 'already_processed', taskId: body.taskId, currentStatus: existingTask.status }),
          { headers: { 'Content-Type': 'application/json' } }
        );
      }

      // 2. Verify that this device holds an ACTIVE, UNEXPIRED lease for this task
      const ownsActiveLease = await repo.verifyTaskOwnership(body.taskId, body.deviceId);
      if (!ownsActiveLease) {
        await repo.logAudit(body.deviceId, 'AGENT_RESULT_LEASE_MISMATCH', body.taskId, 'DENIED', 'TIER_3_DANGEROUS');
        return new Response('Forbidden: Task lease expired or not held by this device', { status: 403 });
      }

      const finalStatus = body.success ? 'COMPLETED' : 'FAILED';
      await repo.updateTaskStatus(
        body.taskId,
        finalStatus,
        body.result ? JSON.stringify(body.result) : undefined,
        body.error,
        100
      );

      // Notify owner on Telegram once
      if (env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_OWNER_ID) {
        const bot = new TelegramBotClient(env.TELEGRAM_BOT_TOKEN);
        const icon = body.success ? '✅' : '❌';
        await bot.sendMessage(
          env.TELEGRAM_OWNER_ID,
          `${icon} *Local Task Complete:* \`${body.taskId.slice(0, 8)}\`\nStatus: *${finalStatus}*\n${body.error ? `Error: ${body.error}` : ''}`,
          { parse_mode: 'Markdown' }
        );
      }

      return new Response(JSON.stringify({ status: 'received', taskId: body.taskId }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response('Not Found', { status: 404 });
  },

  // Cron Scheduled Handler: Periodic Morning Briefing and Stale Lease Cleanup
  async scheduled(event: ScheduledEvent, env: CloudEnv, ctx: ExecutionContext): Promise<void> {
    const repo = new LuciferDbRepository(env.DB);

    // Automatic lease reaper in background
    await repo.reclaimExpiredLeases();

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
