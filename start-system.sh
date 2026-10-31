#!/usr/bin/env bash
# ==============================================================================
# AegisCampus IDS — Linux / Raspberry Pi Native Launcher (Zero-Docker)
# ==============================================================================

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
echo "======================================================================"
echo " AegisCampus IDS — Native Bare-Metal Launcher"
echo " Problem Statement: CTBF-CS-03 (Raspberry Pi Compliant)"
echo "======================================================================"

echo "[1/3] Starting Backend API in background on port 3001..."
cd "$DIR/backend"
npm start &
BACKEND_PID=$!
sleep 2

echo "[2/3] Starting Next.js SOC Frontend on port 3000..."
cd "$DIR/frontend"
npm run dev &
FRONTEND_PID=$!
sleep 3

echo "[3/3] System online!"
echo "SOC Console: http://localhost:3000"
echo "Backend API: http://localhost:3001"
echo ""
echo "Press Ctrl+C to stop all services."

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" SIGINT SIGTERM
wait

