#!/usr/bin/env bash
set -e

echo "=== Running Lucifer Doctor ==="
pnpm --filter @lucifer/cli run start doctor
