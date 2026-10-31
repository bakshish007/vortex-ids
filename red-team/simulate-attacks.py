#!/usr/bin/env python3
"""
================================================================================
AegisCampus IDS — Cross-Platform Attack & Telemetry Simulator
Problem Statement: CTBF-CS-03
Runs on Windows, macOS, and Linux without needing nmap, hping3, or root privileges.
Emits exact realistic packet attack vectors directly to the Aegis Ingestion API.
================================================================================
"""

import sys
import time
import argparse
import random
import requests

DEFAULT_BACKEND = "http://localhost:3001"

ATTACK_PAYLOADS = {
    "scan": {
        "sourceIp": "192.168.1.185",
        "targetPort": 443,
        "attackType": "High-Frequency Port Scan",
        "details": {
            "uniquePortsHit": 24,
            "windowSeconds": 1.8,
            "technique": "TCP SYN probe (T5 aggressive)",
            "flagSummary": "SYN_ONLY",
        },
    },
    "ssh": {
        "sourceIp": "10.0.12.77",
        "targetPort": 22,
        "attackType": "SSH Brute Force",
        "details": {
            "attempts": 9,
            "windowSeconds": 8.5,
            "targetService": "OpenSSH_8.9p1",
            "technique": "Rapid credential spray dictionary probe",
        },
    },
    "rdp": {
        "sourceIp": "172.16.4.22",
        "targetPort": 3389,
        "attackType": "RDP Unauthorized Probe",
        "details": {
            "targetPort": 3389,
            "protocol": "MS-RDP",
            "technique": "External unauthenticated desktop endpoint sweep",
        },
    },
    "mac": {
        "sourceIp": "192.168.1.42",
        "targetPort": 80,
        "attackType": "MAC Spoofing / ARP Poisoning",
        "details": {
            "knownMac": "00:50:56:c0:00:08",
            "newMac": "de:ad:be:ef:13:37",
            "anomaly": "Layer-2 binding mismatch detected in stateful ARP cache",
        },
    },
}


def send_alert(backend_url: str, attack_key: str):
    data = ATTACK_PAYLOADS[attack_key].copy()
    data["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    url = f"{backend_url}/api/alerts"
    print(f"[+] Sending {data['attackType']} alert from {data['sourceIp']} to {url}...")
    try:
        res = requests.post(url, json=data, timeout=3)
        if res.status_code in (200, 201):
            body = res.json()
            alert = body.get("alert", {})
            print(f"    [SUCCESS] Alert created: ID={alert.get('_id')} Severity={alert.get('severity')}")
            print(f"    [PLAYBOOK] Deterministic mitigation script attached ({len(alert.get('mitigationScript', ''))} bytes)")
        else:
            print(f"    [FAIL] HTTP {res.status_code}: {res.text}")
    except Exception as e:
        print(f"    [ERROR] Connection failed: {e}")


def stream_telemetry(backend_url: str, duration_sec: int = 15):
    print(f"\n[+] Streaming realistic low-overhead telemetry to {backend_url} for {duration_sec}s...")
    url = f"{backend_url}/api/telemetry"
    start = time.time()

    while time.time() - start < duration_sec:
        # Realistic Pi 4 edge agent hardware metrics (<10% CPU footprint)
        cpu = round(random.uniform(1.8, 4.6), 1)
        ram = round(random.uniform(17.5, 19.8), 1)
        pps = random.randint(40, 180)

        payload = {
            "cpuUsage": cpu,
            "ramUsage": ram,
            "packetsPerSec": pps,
            "activeConnections": random.randint(3, 8),
        }
        try:
            res = requests.post(url, json=payload, timeout=2)
            print(f"    -> Telemetry streamed: CPU={cpu}% (Pi <10% compliant) | RAM={ram}% | PPS={pps}")
        except Exception as e:
            print(f"    -> Telemetry ping error: {e}")

        time.sleep(3)


def main():
    parser = argparse.ArgumentParser(description="AegisCampus IDS Attack & Telemetry Simulator")
    parser.add_argument("--backend", default=DEFAULT_BACKEND, help="Backend URL (default: http://localhost:3001)")
    parser.add_argument("--attack", choices=["scan", "ssh", "rdp", "mac"], help="Trigger a specific attack")
    parser.add_argument("--all", action="store_true", help="Sequentially trigger all attack scenarios with telemetry")
    parser.add_argument("--telemetry", action="store_true", help="Stream edge agent telemetry")
    args = parser.parse_args()

    print("======================================================================")
    print(" AegisCampus IDS — Red Team Incident Simulator (CTBF-CS-03)")
    print(f" Target Backend: {args.backend}")
    print("======================================================================\n")

    if args.attack:
        send_alert(args.backend, args.attack)
    elif args.all or len(sys.argv) == 1:
        print("[*] Running full attack suite...")
        for key in ["scan", "ssh", "rdp", "mac"]:
            send_alert(args.backend, key)
            time.sleep(1)
        stream_telemetry(args.backend, duration_sec=12)
    elif args.telemetry:
        stream_telemetry(args.backend, duration_sec=30)


if __name__ == "__main__":
    main()

