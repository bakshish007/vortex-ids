#!/usr/bin/env bash
# ==============================================================================
# AegisCampus IDS — Red Team Attack Simulator: Port Scan
# Purpose: Generate rapid TCP SYN packets across multiple ports within 2 seconds
# Rule Trigger Threshold: > 15 distinct ports in 2.0s
# Expected Alert: CRITICAL - High-Frequency Port Scan
# ==============================================================================

set -e

TARGET="${1:-127.0.0.1}"
echo "======================================================================"
echo "[RED-TEAM] Initiating Aggressive SYN Port Scan against ${TARGET}..."
echo "======================================================================"

# Primary Vector: nmap fast SYN scan
if command -v nmap &>/dev/null; then
  echo "[+] nmap detected. Running high-frequency SYN probe (-T5)..."
  sudo nmap -sS -p 1-1000 -T5 --max-retries 1 "${TARGET}"
elif command -v nc &>/dev/null; then
  echo "[+] nmap not found. Executing rapid netcat port probe fallback..."
  for port in $(seq 20 50); do
    nc -z -w 1 "${TARGET}" "${port}" 2>/dev/null &
  done
  wait
else
  echo "[+] Executing pure bash TCP socket iteration fallback..."
  for port in $(seq 100 130); do
    (exec 3<>/dev/tcp/"${TARGET}"/"${port}") 2>/dev/null || true
  done
fi

echo "======================================================================"
echo "[RED-TEAM] Port scan burst transmitted. Verify SOC Dashboard ticker."
echo "======================================================================"

