#!/usr/bin/env node
import { SecretRedactor, TelegramAuthGuard } from '@lucifer/security';
import { ProviderHealthTracker, OllamaProvider } from '@lucifer/provider-registry';

async function runDoctor() {
  console.log('\n===========================================');
  console.log('       PROJECT LUCIFER - SYSTEM DOCTOR     ');
  console.log('===========================================\n');

  // Check Node & Platform
  console.log(`[✓] Node.js Runtime: ${process.version}`);
  console.log(`[✓] Platform: ${process.platform} (${process.arch})`);

  // Check Environment Variables securely (never print secrets)
  const requiredVars = [
    { name: 'TELEGRAM_BOT_TOKEN', optional: false },
    { name: 'TELEGRAM_OWNER_ID', optional: false },
    { name: 'TELEGRAM_WEBHOOK_SECRET', optional: true },
    { name: 'GEMINI_API_KEYS', optional: true },
    { name: 'GROQ_API_KEYS', optional: true },
    { name: 'OPENROUTER_API_KEYS', optional: true },
    { name: 'GITHUB_TOKEN', optional: true }
  ];

  console.log('\n--- Environment & Secrets Status ---');
  for (const v of requiredVars) {
    const val = process.env[v.name];
    if (val && val.trim().length > 0) {
      if (v.name === 'TELEGRAM_OWNER_ID' && !TelegramAuthGuard.isValidNumericTelegramId(val)) {
        console.log(`  [!] ${v.name}: INVALID (Must be an immutable numeric Telegram user ID from @userinfobot, not a username or handle)`);
      } else {
        console.log(`  [✓] ${v.name}: Configured (Length: ${val.length})`);
      }
    } else if (v.optional) {
      console.log(`  [-] ${v.name}: Not set (Optional free-tier provider/integration)`);
    } else {
      console.log(`  [!] ${v.name}: MISSING (Required for production Telegram webhook)`);
    }
  }

  // Check Local Ollama
  console.log('\n--- Local Ollama Connectivity ---');
  const ollama = new OllamaProvider(process.env.OLLAMA_URL || 'http://127.0.0.1:11434');
  const health = await ollama.healthCheck();
  if (health.status === 'HEALTHY') {
    console.log('  [✓] Ollama: Online on http://127.0.0.1:11434');
  } else {
    console.log(`  [-] Ollama: Not responding (${health.lastErrorMessage || 'Service offline'}). To enable local models, run 'ollama serve'.`);
  }

  console.log('\n===========================================');
  console.log('Diagnostics complete.\n');
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0] || 'doctor';

  if (command === 'doctor') {
    await runDoctor();
  } else if (command === 'help') {
    console.log('Usage: lucifer [doctor|help]');
  } else {
    console.log(`Unknown command: ${command}. Run 'lucifer help' for options.`);
  }
}

main().catch((err) => {
  console.error('Lucifer CLI Error:', err);
  process.exit(1);
});
