# Security Policy

## Responsible Disclosure
If you discover a security vulnerability in Project Lucifer, please report it directly to the repository maintainer. Do not disclose vulnerabilities publicly until patched.

## Security Guarantees
- Project Lucifer strictly checks Telegram user IDs against the owner allowlist.
- Secrets and tokens are never printed in logs or sent back to Telegram messages.
- Arbitrary shell execution is forbidden; only structured, allowlisted commands are supported.
- Free-tier enforcement guarantees no unintended credit card charges.
