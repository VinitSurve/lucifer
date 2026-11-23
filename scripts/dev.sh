#!/usr/bin/env bash
set -e

echo "=== Starting Lucifer Development Environment ==="
echo "1. Cloud Worker running on http://127.0.0.1:8787"
pnpm --filter @lucifer/cloud dev
