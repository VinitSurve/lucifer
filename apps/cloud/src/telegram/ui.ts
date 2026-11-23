export class TelegramUiBuilder {
  /**
   * Main Menu keyboard
   */
  public static mainMenu() {
    return {
      inline_keyboard: [
        [
          { text: '☀️ Morning Briefing', callback_data: 'cmd:morning' },
          { text: '📊 Status & Health', callback_data: 'cmd:status' }
        ],
        [
          { text: '📬 Email', callback_data: 'cmd:email' },
          { text: '📅 Calendar', callback_data: 'cmd:calendar' },
          { text: '🐙 GitHub', callback_data: 'cmd:github' }
        ],
        [
          { text: '📋 Tasks', callback_data: 'cmd:tasks' },
          { text: '💻 Mac Agent', callback_data: 'cmd:agent' },
          { text: '⚙️ Settings', callback_data: 'cmd:settings' }
        ]
      ]
    };
  }

  /**
   * Approval confirmation card keyboard
   */
  public static approvalKeyboard(approvalId: string) {
    return {
      inline_keyboard: [
        [
          { text: '✅ Approve & Execute', callback_data: `approve:${approvalId}` },
          { text: '❌ Reject', callback_data: `reject:${approvalId}` }
        ]
      ]
    };
  }

  /**
   * Model selector keyboard
   */
  public static modelPicker() {
    return {
      inline_keyboard: [
        [
          { text: '⚡ Groq (Llama 3.3)', callback_data: 'set_model:groq' },
          { text: '🧠 Gemini 2.0 Flash', callback_data: 'set_model:gemini' }
        ],
        [
          { text: '🌐 OpenRouter (Free)', callback_data: 'set_model:openrouter' },
          { text: '🔒 Ollama (Local Mac)', callback_data: 'set_model:ollama' }
        ],
        [{ text: '🔄 Auto Intelligent Router', callback_data: 'set_model:auto' }]
      ]
    };
  }
}
