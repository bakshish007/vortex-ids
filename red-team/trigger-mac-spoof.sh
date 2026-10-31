#!/usr/bin/env bash
# ==============================================================================
# AegisCampus IDS — Red Team Attack Simulator: MAC Spoofing / ARP Anomaly
# Purpose: Alter hardware MAC address for the current IP and transmit traffic
# Rule Trigger Threshold: Existing IP presenting an altered MAC address
# Expected Alert: CRITICAL - MAC Spoofing / ARP Poisoning
# ==============================================================================

set -e

IFACE="${1:-eth0}"
TARGET="${2:-127.0.0.1}"

echo "======================================================================"
echo "[RED-TEAM] Initiating MAC Spoofing Simulation on interface: ${IFACE}..."
echo "======================================================================"

# Step 1: Send baseline frame
echo "[+] Transmitting baseline packet with original MAC..."
ping -c 2 "${TARGET}" 2>/dev/null || true

# Step 2: Temporarily spoof MAC
ORIG_MAC=$(cat /sys/class/net/"${IFACE}"/address 2>/dev/null || echo "00:11:22:33:44:55")
SPOOFED_MAC="02:00:$(printf '%02x:%02x:%02x:%02x' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))"

echo "[+] Original MAC: ${ORIG_MAC}"
echo "[+] Spoofed MAC:  ${SPOOFED_MAC}"

if command -v macchanger &>/dev/null; then
  sudo ip link set dev "${IFACE}" down
  sudo macchanger -m "${SPOOFED_MAC}" "${IFACE}"
  sudo ip link set dev "${IFACE}" up
elif command -v ip &>/dev/null; then
  sudo ip link set dev "${IFACE}" down
  sudo ip link set dev "${IFACE}" address "${SPOOFED_MAC}"
  sudo ip link set dev "${IFACE}" up
fi

# Step 3: Transmit anomalous packet with new MAC
echo "[+] Transmitting second packet from identical IP under spoofed MAC..."
ping -c 2 "${TARGET}" 2>/dev/null || true

# Step 4: Revert to original MAC
echo "[+] Restoring interface hardware address..."
if command -v ip &>/dev/null; then
  sudo ip link set dev "${IFACE}" down
  sudo ip link set dev "${IFACE}" address "${ORIG_MAC}"
  sudo ip link set dev "${IFACE}" up
fi

echo "======================================================================"
echo "[RED-TEAM] MAC Spoof sequence finished. Verify SOC Dashboard ticker."
echo "======================================================================"

