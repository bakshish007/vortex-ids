/**
 * AegisCampus IDS — Deterministic Playbook Engine
 * Strictly avoids Generative AI to guarantee zero-latency, sub-millisecond,
 * and deterministic, auditable mitigation scripts for campus network operators.
 */

function sanitizeIp(ip) {
  if (!ip || typeof ip !== 'string') return '0.0.0.0';
  // Allow only valid IPv4 characters to prevent bash injection in mitigation script
  return ip.replace(/[^0-9.]/g, '');
}

function getPlaybook(attackType, sourceIp, targetPort = 0) {
  const cleanIp = sanitizeIp(sourceIp);
  const typeNormalized = (attackType || '').toLowerCase().trim();
  const timestampIso = new Date().toISOString();

  // 1. Port Scan
  if (typeNormalized.includes('scan') || typeNormalized.includes('port')) {
    return {
      severity: 'CRITICAL',
      mitigationScript: `#!/bin/bash
# ==============================================================================
# AegisCampus IDS — Deterministic Mitigation Playbook
# Incident: Port Scan Detected
# Target Source IP: ${cleanIp}
# Timestamp: ${timestampIso}
# Engine: Rule-Based Deterministic (Zero GenAI)
# ==============================================================================

echo "[AEGIS-IDS] Applying quarantine for scanning host: ${cleanIp}"

# Step 1: Drop all ingress and forwarded traffic from offending host
iptables -A INPUT -s ${cleanIp} -j DROP
iptables -A FORWARD -s ${cleanIp} -j DROP

# Step 2: Rate limit logging to prevent syslog flooding
iptables -A INPUT -s ${cleanIp} -m limit --limit 5/min -j LOG --log-prefix "AEGIS-QUARANTINE-SCAN: "

# Step 3: Terminate established connections from this IP
conntrack -D -s ${cleanIp} 2>/dev/null || true

echo "[AEGIS-IDS] Host ${cleanIp} quarantined successfully via iptables."
exit 0
`,
    };
  }

  // 2. SSH Brute Force
  if (typeNormalized.includes('ssh') || typeNormalized.includes('brute')) {
    return {
      severity: 'HIGH',
      mitigationScript: `#!/bin/bash
# ==============================================================================
# AegisCampus IDS — Deterministic Mitigation Playbook
# Incident: SSH Brute Force Attack
# Target Source IP: ${cleanIp}
# Port: ${targetPort || 22}
# Timestamp: ${timestampIso}
# Engine: Rule-Based Deterministic (Zero GenAI)
# ==============================================================================

echo "[AEGIS-IDS] Mitigating SSH Brute Force from ${cleanIp}"

# Step 1: Immediately drop SSH traffic from offending host
iptables -A INPUT -p tcp --dport 22 -s ${cleanIp} -j DROP

# Step 2: Add to dynamic recent hitlist for stateful suppression (1-hour block)
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 3600 --hitcount 3 --name SSH_ATTACK -j DROP

# Step 3: Flush existing SSH sockets from source IP
ss -K dst :22 src ${cleanIp} 2>/dev/null || true

echo "[AEGIS-IDS] SSH protection active for ${cleanIp}."
exit 0
`,
    };
  }

  // 3. RDP Probe
  if (typeNormalized.includes('rdp') || targetPort === 3389) {
    return {
      severity: 'MEDIUM',
      mitigationScript: `#!/bin/bash
# ==============================================================================
# AegisCampus IDS — Deterministic Mitigation Playbook
# Incident: Unauthorized RDP Probe (Port 3389)
# Target Source IP: ${cleanIp}
# Timestamp: ${timestampIso}
# Engine: Rule-Based Deterministic (Zero GenAI)
# ==============================================================================

echo "[AEGIS-IDS] Blocking unauthorized RDP access from ${cleanIp}"

# Step 1: Reject RDP attempts cleanly to avoid hung socket allocations
iptables -A INPUT -p tcp --dport 3389 -s ${cleanIp} -j REJECT --reject-with tcp-reset

echo "[AEGIS-IDS] RDP Port 3389 blocked for ${cleanIp}."
exit 0
`,
    };
  }

  // 4. MAC Spoofing / ARP Poisoning
  if (typeNormalized.includes('mac') || typeNormalized.includes('spoof') || typeNormalized.includes('arp')) {
    return {
      severity: 'CRITICAL',
      mitigationScript: `#!/bin/bash
# ==============================================================================
# AegisCampus IDS — Deterministic Mitigation Playbook
# Incident: MAC Spoofing / ARP Cache Poisoning Anomaly
# Target Source IP: ${cleanIp}
# Timestamp: ${timestampIso}
# Engine: Rule-Based Deterministic (Zero GenAI)
# ==============================================================================

echo "[AEGIS-IDS] Isolating anomalous MAC/ARP binding for ${cleanIp}"

# Step 1: Filter poisoned ARP ingress frames
arptables -A INPUT --source-ip ${cleanIp} -j DROP 2>/dev/null || true

# Step 2: Invalidate local kernel ARP cache entry for this IP
ip neigh replace ${cleanIp} nud failed dev eth0 2>/dev/null || arp -d ${cleanIp} 2>/dev/null || true

# Step 3: Block layer-3 routing for this IP
iptables -A INPUT -s ${cleanIp} -j DROP

echo "[AEGIS-IDS] ARP cache purged and IP ${cleanIp} dropped."
exit 0
`,
    };
  }

  // 5. Default Suspicious Threshold Violation
  return {
    severity: 'LOW',
    mitigationScript: `#!/bin/bash
# ==============================================================================
# AegisCampus IDS — Deterministic Mitigation Playbook
# Incident: Suspicious Network Anomaly
# Target Source IP: ${cleanIp}
# Timestamp: ${timestampIso}
# Engine: Rule-Based Deterministic (Zero GenAI)
# ==============================================================================

echo "[AEGIS-IDS] Enforcing rate limit on suspicious host: ${cleanIp}"

# Step 1: Enforce rate limit (10 packets/second burst)
iptables -A INPUT -s ${cleanIp} -m limit --limit 10/second --limit-burst 20 -j ACCEPT
iptables -A INPUT -s ${cleanIp} -j DROP

echo "[AEGIS-IDS] Rate limiting applied to ${cleanIp}."
exit 0
`,
  };
}

module.exports = {
  getPlaybook,
  sanitizeIp,
};

