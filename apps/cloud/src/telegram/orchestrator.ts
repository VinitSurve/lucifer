import {
  ApprovalRecord,
  ChatMessage,
  TaskRecord
} from '@lucifer/shared-types';
import { BUILTIN_TOOLS, ToolPermissionGuard, ToolLoopGuard } from '@lucifer/tool-contracts';
import { SecretRedactor, PromptInjectionDefense } from '@lucifer/security';
import { ModelRouter } from '@lucifer/provider-registry';
import { LuciferDbRepository } from '../db/repository';
import { TelegramBotClient } from './client';
import { TelegramUiBuilder } from './ui';
import { ResearchService } from '../services/research-service';

export class TelegramOrchestrator {
  private repo: LuciferDbRepository;
  private bot: TelegramBotClient;
  private router: ModelRouter;

  constructor(repo: LuciferDbRepository, bot: TelegramBotClient, router: ModelRouter) {
    this.repo = repo;
    this.bot = bot;
    this.router = router;
  }

  /**
   * Orchestrates natural language requests, tool execution, and approval gates
   */
  public async handleNaturalLanguageMessage(
    chatId: number,
    userId: string,
    userText: string
  ): Promise<void> {
    await this.bot.sendChatAction(chatId, 'typing');

    const conversationId = await this.repo.getOrCreateActiveConversation(userId);
    await this.repo.saveMessage(conversationId, 'user', userText);

    // Retrieve recent conversation context
    const recent = await this.repo.getRecentMessages(conversationId, 6);
    const messages: ChatMessage[] = [
      {
        role: 'system',
        content: `You are Lucifer, a private AI autonomous command center.
You assist the user with tasks, research, schedule, emails, and local Mac operations.
Be concise, proactive, highly accurate, and polite.
Do not fabricate information.
When executing actions, call the appropriate tools.`
      },
      ...recent.map((m) => ({
        role: m.role as any,
        content: m.content
      }))
    ];

    const toolsList = Object.values(BUILTIN_TOOLS).map((t) => ({
      name: t.name,
      description: t.description,
      parameters: t.parameters as unknown as Record<string, unknown>
    }));

    const loopGuard = new ToolLoopGuard(5, 3);

    try {
      // Step 1: Model generation
      const genResult = await this.router.executeWithFallback(messages, {
        tools: toolsList
      });

      // If no tool call, reply directly
      if (!genResult.toolCalls || genResult.toolCalls.length === 0) {
        await this.repo.saveMessage(conversationId, 'assistant', genResult.content);
        await this.bot.sendMessage(chatId, genResult.content);
        return;
      }

      // Process tool calls
      for (const tc of genResult.toolCalls) {
        const check = loopGuard.recordCall(tc.name);
        if (!check.allowed) {
          await this.bot.sendMessage(chatId, `⚠️ Tool execution stopped: ${check.reason}`);
          return;
        }

        const toolDef = BUILTIN_TOOLS[tc.name];
        const userAutoApprove = await this.repo.getUserTier1AutoApprove(userId);
        const perm = ToolPermissionGuard.evaluate(toolDef ? toolDef.riskTier : 'TIER_3_DANGEROUS', userAutoApprove);

        if (perm.requiresApproval) {
          // Pause execution, generate ApprovalRecord
          const taskId = `tsk_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
          const approvalId = `appr_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;

          const task: TaskRecord = {
            id: taskId,
            ownerId: userId,
            description: `Execute tool: ${tc.name}`,
            type: tc.name,
            priority: 'HIGH',
            status: 'WAITING_APPROVAL',
            executionTarget: toolDef?.executionTarget === 'LOCAL_MAC' ? 'LOCAL_MAC' : 'CLOUD',
            requiredTools: [tc.name],
            approvalId,
            progress: 0,
            retries: 0,
            maxRetries: 1,
            correlationId: taskId,
            payload: tc.arguments,
            createdAt: Date.now(),
            updatedAt: Date.now()
          };
          await this.repo.createTask(task);

          const approval: ApprovalRecord = {
            id: approvalId,
            taskId,
            userId,
            actionName: tc.name,
            actionDetails: tc.arguments,
            state: 'PENDING',
            createdAt: Date.now(),
            expiresAt: Date.now() + 15 * 60 * 1000 // 15 mins expiry
          };
          await this.repo.createApproval(approval);

          const approvalMessage = `
⚠️ *Action Approval Required*

*Tool:* \`${tc.name}\`
*Risk Tier:* \`${perm.tier}\`
*Details:*
\`\`\`json
${JSON.stringify(tc.arguments, null, 2)}
\`\`\`

Do you authorize Lucifer to perform this operation?
          `.trim();

          await this.bot.sendMessage(chatId, approvalMessage, {
            parse_mode: 'Markdown',
            reply_markup: TelegramUiBuilder.approvalKeyboard(approvalId)
          });
          return;
        }

        // Tier 0 auto-executable tools
        let toolOutputText = '';
        if (tc.name === 'web_search') {
          const q = (tc.arguments.query as string) || '';
          const results = await ResearchService.webSearch(q, 3);
          toolOutputText = PromptInjectionDefense.wrapUntrustedContent('web_search', JSON.stringify(results), {
            query: q,
            resultCount: String(results.length)
          });
        } else if (tc.name === 'fetch_url') {
          const url = (tc.arguments.url as string) || '';
          const fetched = await ResearchService.fetchAndExtractUrl(url);
          toolOutputText = fetched.content;
        } else {
          toolOutputText = `Executed ${tc.name} successfully.`;
        }

        // Feed tool output back to model
        messages.push({
          role: 'assistant',
          content: '',
          toolCalls: [
            {
              id: tc.id,
              type: 'function',
              function: {
                name: tc.name,
                arguments: JSON.stringify(tc.arguments)
              }
            }
          ]
        });

        messages.push({
          role: 'tool',
          content: toolOutputText,
          toolCallId: tc.id
        });

        const followUp = await this.router.executeWithFallback(messages);
        await this.repo.saveMessage(conversationId, 'assistant', followUp.content);
        await this.bot.sendMessage(chatId, followUp.content);
        return;
      }
    } catch (err: any) {
      await this.bot.sendMessage(chatId, SecretRedactor.redact(`⚠️ Lucifer encountered an error: ${err.message}`));
    }
  }

  /**
   * Handles approval callback queries: approve:<id> or reject:<id>
   */
  public async handleApprovalCallback(
    chatId: number,
    userId: string,
    callbackQueryId: string,
    action: 'approve' | 'reject',
    approvalId: string
  ): Promise<void> {
    const approval = await this.repo.getApproval(approvalId);
    if (!approval) {
      await this.bot.answerCallbackQuery(callbackQueryId, 'Approval record not found or expired.', true);
      return;
    }

    if (approval.userId !== userId) {
      await this.bot.answerCallbackQuery(callbackQueryId, 'Unauthorized: you cannot decide this approval.', true);
      return;
    }

    if (approval.state !== 'PENDING') {
      await this.bot.answerCallbackQuery(callbackQueryId, `Approval already ${approval.state}.`, true);
      return;
    }

    if (Date.now() > approval.expiresAt) {
      await this.repo.updateApprovalState(approvalId, 'EXPIRED', 'Timed out');
      await this.bot.answerCallbackQuery(callbackQueryId, 'This approval request has expired.', true);
      return;
    }

    if (action === 'approve') {
      await this.repo.updateApprovalState(approvalId, 'APPROVED', 'User confirmed in Telegram');
      await this.repo.updateTaskStatus(approval.taskId, 'QUEUED');
      await this.bot.answerCallbackQuery(callbackQueryId, 'Approved! Action queued.');
      await this.bot.sendMessage(
        chatId,
        `✅ Action \`${approval.actionName}\` approved. Task \`${approval.taskId.slice(0, 8)}\` is now running.`,
        { parse_mode: 'Markdown' }
      );
    } else {
      await this.repo.updateApprovalState(approvalId, 'REJECTED', 'User denied in Telegram');
      await this.repo.updateTaskStatus(approval.taskId, 'CANCELLED', undefined, 'User rejected approval');
      await this.bot.answerCallbackQuery(callbackQueryId, 'Rejected.');
      await this.bot.sendMessage(
        chatId,
        `❌ Action \`${approval.actionName}\` was rejected by user.`,
        { parse_mode: 'Markdown' }
      );
    }
  }
}
