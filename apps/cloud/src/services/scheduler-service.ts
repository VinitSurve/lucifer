import { LuciferDbRepository } from '../db/repository';

export class SchedulerService {
  /**
   * Generates morning briefing synthesis
   */
  public static async generateMorningBriefing(
    userId: string,
    repo: LuciferDbRepository,
    timezone = 'Asia/Kolkata'
  ): Promise<string> {
    const todayStr = new Intl.DateTimeFormat('en-US', {
      timeZone: timezone,
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    }).format(new Date());

    // Fetch active tasks
    const tasks = await repo.listTasks(userId, 5, 'PENDING');
    const memories = await repo.getMemories(userId);

    const taskLines = tasks.length > 0
      ? tasks.map((t) => `• [${t.priority}] ${t.description}`).join('\n')
      : '• No pending tasks scheduled.';

    const briefing = `
☀️ *Good morning! Project Lucifer Daily Briefing*
📅 *${todayStr}*

📋 *Pending Tasks:*
${taskLines}

🔗 *Integrations Status:*
• Gmail: ${memories.some(m => m.key === 'gmail_connected') ? 'Connected' : 'Awaiting OAuth'}
• Google Calendar: ${memories.some(m => m.key === 'calendar_connected') ? 'Connected' : 'Awaiting OAuth'}
• GitHub: Configured for safe repository checks
• Local Mac Agent: Outbound polling enabled

💡 Tip: Type /email to check unread emails, or /calendar for today's schedule.
    `.trim();

    return briefing;
  }
}
