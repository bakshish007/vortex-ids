#!/usr/bin/env bash
# ==============================================================================
# AegisCampus IDS — Red Team Attack Simulator: SSH Brute Force
# Purpose: Flood Port 22 with rapid TCP SYN attempts within 10 seconds
# Rule Trigger Threshold: > 5 attempts to Port 22 in 10s
# Expected Alert: HIGH - SSH Brute Force
# ==============================================================================

set -e

TARGET="${1:-127.0.0.1}"
echo "======================================================================"
echo "[RED-TEAM] Initiating SSH Brute Force Simulation against ${TARGET}:22..."
echo "======================================================================"

# Primary Vector: hping3 rapid SYN flood to Port 22
if command -v hping3 &>/dev/null; then
  echo "[+] hping3 detected. Firing 15 SYN packets with 100ms micro-interval..."
  sudo hping3 -S -p 22 -c 15 -i u100000 "${TARGET}"
elif command -v nc &>/dev/null; then
  echo "[+] hping3 not found. Firing rapid netcat connections at Port 22..."
  for i in $(seq 1 12); do
    nc -z -w 1 "${TARGET}" 22 2>/dev/null || true
    sleep 0.1
  done
else
  echo "[+] Firing pure bash loop connections at Port 22..."
  for i in $(seq 1 12); do
    (exec 3<>/dev/tcp/"${TARGET}"/22) 2>/dev/null || true
    sleep 0.1
  done
fi

echo "======================================================================"
echo "[RED-TEAM] SSH Brute Force burst completed. Verify SOC Dashboard ticker."
echo "======================================================================"

