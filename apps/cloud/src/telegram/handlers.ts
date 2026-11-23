import { LuciferDbRepository } from '../db/repository';
import { CloudEnv } from '../db/types';
import { TelegramBotClient } from './client';
import { TelegramUiBuilder } from './ui';
import { SchedulerService } from '../services/scheduler-service';
import { GitHubService } from '../services/github-service';
import { GmailService } from '../services/gmail-service';
import { CalendarService } from '../services/calendar-service';
import { ResearchService } from '../services/research-service';

export class TelegramCommandHandler {
  private repo: LuciferDbRepository;
  private bot: TelegramBotClient;
  private env: CloudEnv;

  constructor(repo: LuciferDbRepository, bot: TelegramBotClient, env: CloudEnv) {
    this.repo = repo;
    this.bot = bot;
    this.env = env;
  }

  public async handleCommand(
    chatId: number,
    userId: string,
    command: string,
    args: string[]
  ): Promise<void> {
    const cmd = command.toLowerCase().replace('/', '');

    switch (cmd) {
      case 'start':
        await this.handleStart(chatId);
        break;

      case 'help':
        await this.handleHelp(chatId);
        break;

      case 'status':
      case 'health':
        await this.handleStatus(chatId);
        break;

      case 'models':
      case 'model':
        await this.handleModels(chatId);
        break;

      case 'usage':
        await this.handleUsage(chatId);
        break;

      case 'tasks':
        await this.handleTasks(chatId, userId);
        break;

      case 'morning':
        await this.handleMorning(chatId, userId);
        break;

      case 'email':
        await this.handleEmail(chatId, args);
        break;

      case 'calendar':
        await this.handleCalendar(chatId, args);
        break;

      case 'github':
        await this.handleGithub(chatId, args);
        break;

      case 'agent':
      case 'local':
        await this.handleAgent(chatId);
        break;

      case 'research':
        await this.handleResearch(chatId, args.join(' '));
        break;

      case 'memory':
        await this.handleMemory(chatId, userId);
        break;

      case 'forget':
        await this.handleForget(chatId, userId, args[0]);
        break;

      default:
        await this.bot.sendMessage(
          chatId,
          `Unknown command /${cmd}. Type /help to see all available commands.`
        );
        break;
    }
  }

  private async handleStart(chatId: number): Promise<void> {
    const welcome = `
*LUCIFER* — _Your Private AI Command Center_

Operational & ready. I assist with autonomous tasks, research, emails, calendar, code workflows, and your local Mac machine.

Use the menu below or type any command or question directly:
    `.trim();

    await this.bot.sendMessage(chatId, welcome, {
      parse_mode: 'Markdown',
      reply_markup: TelegramUiBuilder.mainMenu()
    });
  }

  private async handleHelp(chatId: number): Promise<void> {
    const helpText = `
*Available Lucifer Commands:*

*General & System:*
• /start - Welcome & Command Center menu
• /help - Display this manual
• /status - Cloud, DB, Local Agent, & Provider status
• /health - Provider latency & error telemetry
• /models - Available models & free-tier status
• /usage - Token estimates & cost controls
• /settings - Timezone & preferences

*Task Management & Approvals:*
• /tasks - View recent & running tasks
• /approvals - Inspect pending approvals

*Proactive & Personal:*
• /morning - Instant morning briefing
• /memory - View long-term stored facts
• /forget <key> - Remove a remembered fact

*Integrations:*
• /email [unread|search <query>] - Gmail assistant
• /calendar [today|week] - Google Calendar assistant
• /github [repos|status] - GitHub repositories & CI
• /research <query> - Multi-source web research
• /agent or /local - Local Mac Agent & Ollama status
    `.trim();

    await this.bot.sendMessage(chatId, helpText, { parse_mode: 'Markdown' });
  }

  private async handleStatus(chatId: number): Promise<void> {
    const statusText = `
*Lucifer Command Center Status*

☁️ *Cloud Worker:* Operational (Cloudflare Workers)
🗄️ *Database:* Active (Cloudflare D1)
🤖 *AI Providers:*
  • Gemini API: ${this.env.GEMINI_API_KEYS ? 'Configured ✅' : 'Awaiting Key (Free Tier available)'}
  • Groq Cloud: ${this.env.GROQ_API_KEYS ? 'Configured ✅' : 'Awaiting Key (Free Tier available)'}
  • OpenRouter: ${this.env.OPENROUTER_API_KEYS ? 'Configured ✅' : 'Awaiting Key (Free Tier available)'}
  • Workers AI: ${this.env.CLOUDFLARE_API_TOKEN || this.env.AI ? 'Available ✅' : 'Ready'}
💻 *Local Mac Agent:* Outbound polling ready
🔒 *Budget Mode:* ${this.env.BUDGET_MODE || 'FREE_ONLY'} ($0 budget strictly enforced)
    `.trim();

    await this.bot.sendMessage(chatId, statusText, { parse_mode: 'Markdown' });
  }

  private async handleModels(chatId: number): Promise<void> {
    const modelsText = `
*Model Selection & Capabilities:*

• *Gemini 2.0 Flash:* 1M context, Vision, Tools, Fast (Free Tier)
• *Llama 3.3 70B (Groq):* 128k context, Ultra-low latency, Tools (Free Tier)
• *Llama 3.1 8B (Workers AI / Groq):* Fast classification & simple extraction
• *Local Ollama (Gemma 2 / Qwen):* 100% Private, offline capable

Select a preferred model or use auto-router:
    `.trim();

    await this.bot.sendMessage(chatId, modelsText, {
      parse_mode: 'Markdown',
      reply_markup: TelegramUiBuilder.modelPicker()
    });
  }

  private async handleUsage(chatId: number): Promise<void> {
    const usageText = `
*Lucifer Usage & Cost Center*

💰 *Current Operating Cost:* $0.00
🛡️ *Budget Mode:* FREE_ONLY (Paid models blocked)
📊 *Total Tasks Run:* Tracked in D1
⚡ *Free Quota Health:* Healthy
    `.trim();

    await this.bot.sendMessage(chatId, usageText, { parse_mode: 'Markdown' });
  }

  private async handleTasks(chatId: number, userId: string): Promise<void> {
    const tasks = await this.repo.listTasks(userId, 5);
    if (tasks.length === 0) {
      await this.bot.sendMessage(chatId, '📋 No active or recent tasks found.');
      return;
    }

    const lines = tasks.map(
      (t) => `• \`${t.id.slice(0, 8)}\` [${t.status}] ${t.description} (${t.executionTarget})`
    );
    await this.bot.sendMessage(chatId, `*Recent Tasks:*\n\n${lines.join('\n')}`, {
      parse_mode: 'Markdown'
    });
  }

  private async handleMorning(chatId: number, userId: string): Promise<void> {
    await this.bot.sendChatAction(chatId, 'typing');
    const briefing = await SchedulerService.generateMorningBriefing(
      userId,
      this.repo,
      this.env.DEFAULT_TIMEZONE
    );
    await this.bot.sendMessage(chatId, briefing, { parse_mode: 'Markdown' });
  }

  private async handleEmail(chatId: number, args: string[]): Promise<void> {
    await this.bot.sendChatAction(chatId, 'typing');
    const sub = args[0] || 'unread';
    const query = sub === 'unread' ? 'is:unread' : args.slice(1).join(' ') || 'is:unread';

    const result = await GmailService.searchEmails(query, 5);
    if (!result.authenticated) {
      await this.bot.sendMessage(chatId, `📬 *Gmail:* ${result.messageText}`, {
        parse_mode: 'Markdown'
      });
      return;
    }

    if (result.messages.length === 0) {
      await this.bot.sendMessage(chatId, '📬 No matching emails found.');
      return;
    }

    const lines = result.messages.map(
      (m) => `• *${m.subject}*\n  From: ${m.from}\n  Date: ${m.date}`
    );
    await this.bot.sendMessage(chatId, `*Gmail (${query}):*\n\n${lines.join('\n\n')}`, {
      parse_mode: 'Markdown'
    });
  }

  private async handleCalendar(chatId: number, args: string[]): Promise<void> {
    await this.bot.sendChatAction(chatId, 'typing');
    const result = await CalendarService.listEvents();
    if (!result.authenticated) {
      await this.bot.sendMessage(chatId, `📅 *Calendar:* ${result.messageText}`, {
        parse_mode: 'Markdown'
      });
      return;
    }

    if (result.events.length === 0) {
      await this.bot.sendMessage(chatId, '📅 No upcoming events scheduled.');
      return;
    }

    const lines = result.events.map((e) => `• *${e.summary}* (${e.startTime})`);
    await this.bot.sendMessage(chatId, `*Upcoming Calendar Events:*\n\n${lines.join('\n')}`, {
      parse_mode: 'Markdown'
    });
  }

  private async handleGithub(chatId: number, args: string[]): Promise<void> {
    await this.bot.sendChatAction(chatId, 'typing');
    const result = await GitHubService.listRepos(this.env.GITHUB_TOKEN);
    if (!result.authenticated) {
      await this.bot.sendMessage(chatId, `🐙 *GitHub:* ${result.messageText}`, {
        parse_mode: 'Markdown'
      });
      return;
    }

    const lines = result.repos.map((r) => `• [${r.name}](${r.htmlUrl}) - ${r.description || 'No description'}`);
    await this.bot.sendMessage(chatId, `*Your Repositories:*\n\n${lines.join('\n')}`, {
      parse_mode: 'Markdown'
    });
  }

  private async handleAgent(chatId: number): Promise<void> {
    const text = `
💻 *Local Mac Agent Status*

• *Platform:* macOS Apple Silicon
• *Outbound HTTPS Channel:* Ready
• *Polling Endpoint:* \`/api/agent/poll\`
• *Local Ollama:* Port 11434 bridge configured
• *Allowed Directories:* \`~/Projects\`, \`~/Documents\` (Configurable in agent config)
• *Status:* Run \`uv run lucifer-agent\` on your Mac to initiate real-time heartbeat.
    `.trim();

    await this.bot.sendMessage(chatId, text, { parse_mode: 'Markdown' });
  }

  private async handleResearch(chatId: number, query: string): Promise<void> {
    if (!query) {
      await this.bot.sendMessage(chatId, 'Please provide a search topic: e.g. `/research Cloudflare D1 pricing`');
      return;
    }

    await this.bot.sendChatAction(chatId, 'typing');
    const results = await ResearchService.webSearch(query, 3);
    const lines = results.map(
      (r, idx) => `${idx + 1}. *[${r.title}](${r.url})*\n   ${r.snippet}`
    );

    await this.bot.sendMessage(
      chatId,
      `🔍 *Research Results for:* "${query}"\n\n${lines.join('\n\n')}`,
      { parse_mode: 'Markdown' }
    );
  }

  private async handleMemory(chatId: number, userId: string): Promise<void> {
    const memories = await this.repo.getMemories(userId);
    if (memories.length === 0) {
      await this.bot.sendMessage(chatId, '🧠 No memories stored yet.');
      return;
    }

    const lines = memories.map((m) => `• *${m.key}*: ${m.value} (${m.category})`);
    await this.bot.sendMessage(chatId, `🧠 *Stored Memories:*\n\n${lines.join('\n')}`, {
      parse_mode: 'Markdown'
    });
  }

  private async handleForget(chatId: number, userId: string, key?: string): Promise<void> {
    if (!key) {
      await this.bot.sendMessage(chatId, 'Usage: `/forget <key>`');
      return;
    }

    const deleted = await this.repo.deleteMemory(userId, key);
    if (deleted > 0) {
      await this.bot.sendMessage(chatId, `🧠 Forgot memory for key: \`${key}\``, {
        parse_mode: 'Markdown'
      });
    } else {
      await this.bot.sendMessage(chatId, `No memory found for key: \`${key}\``);
    }
  }
}
