#!/usr/bin/env bash
set -e

echo "==========================================="
echo "     RUNNING COMPLETE LUCIFER TEST SUITE   "
echo "==========================================="

echo "--- 1. Testing TypeScript Packages and Cloud Worker ---"
pnpm -r run test

echo "--- 2. Testing Python Local Mac Agent ---"
cd apps/local-agent
uv run pytest

echo "==========================================="
echo "       ALL TESTS COMPLETED SUCCESSFULLY    "
echo "==========================================="
