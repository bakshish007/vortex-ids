/**
 * AegisCampus IDS — Backend API & Socket.io Hub
 * High-performance, zero-GenAI intrusion detection ingestion and telemetry server.
 * Native Standalone Architecture: Zero Docker & Zero external DB required.
 */

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const { Parser } = require('json2csv');
const fs = require('fs');
const path = require('path');

const Alert = require('./models/Alert');
const Telemetry = require('./models/Telemetry');
const { getPlaybook } = require('./utils/playbook');

const app = express();
const server = http.createServer(app);

// Environment & Configuration
const PORT = process.env.PORT || 3001;
const MONGO_URI = process.env.MONGO_URI || null; // Optional: Only connect if explicitly provided

// Middleware
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// Native Embedded Storage Engine (Zero Docker requirement)
const DATA_DIR = path.join(__dirname, 'data');
const ALERTS_FILE = path.join(DATA_DIR, 'alerts.json');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

let localAlerts = [];
if (fs.existsSync(ALERTS_FILE)) {
  try {
    localAlerts = JSON.parse(fs.readFileSync(ALERTS_FILE, 'utf8'));
    console.log(`[AEGIS-STORAGE] Loaded ${localAlerts.length} alerts from local embedded store: ${ALERTS_FILE}`);
  } catch (err) {
    localAlerts = [];
  }
}

function persistLocalAlert(alert) {
  localAlerts.unshift(alert);
  if (localAlerts.length > 500) localAlerts.pop();
  try {
    fs.writeFileSync(ALERTS_FILE, JSON.stringify(localAlerts, null, 2));
  } catch (err) {
    console.error('[AEGIS-STORAGE] Failed writing to alerts.json:', err);
  }
}

// Socket.io initialization with open CORS for SOC Dashboard
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST'],
  },
});

let connectedSocClients = 0;

io.on('connection', (socket) => {
  connectedSocClients++;
  console.log(`[AEGIS-SOCKET] SOC client connected: ${socket.id} (Total: ${connectedSocClients})`);

  socket.emit('connection_status', {
    status: 'connected',
    serverTime: new Date().toISOString(),
    connectedClients: connectedSocClients,
  });

  socket.on('disconnect', () => {
    connectedSocClients = Math.max(0, connectedSocClients - 1);
    console.log(`[AEGIS-SOCKET] SOC client disconnected: ${socket.id} (Remaining: ${connectedSocClients})`);
  });
});

// Optional MongoDB Connection (falls back silently to Embedded File Store if not running)
let isDbConnected = false;

if (MONGO_URI) {
  mongoose
    .connect(MONGO_URI, { serverSelectionTimeoutMS: 2000 })
    .then(() => {
      isDbConnected = true;
      console.log(`[AEGIS-DB] Connected to MongoDB at ${MONGO_URI}`);
    })
    .catch((err) => {
      isDbConnected = false;
      console.log(`[AEGIS-DB] MongoDB unavailable (${err.message}). Using native embedded storage.`);
    });
} else {
  console.log(`[AEGIS-STORAGE] Standalone Mode: Zero Docker / Embedded JSON Storage active.`);
}

// ==============================================================================
// REST Endpoints
// ==============================================================================

/**
 * Health Check & System Status
 */
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'online',
    system: 'AegisCampus IDS Core',
    runtime: 'Native Standalone (Zero-Docker)',
    storageEngine: isDbConnected ? 'MongoDB' : 'Embedded JSON Store (alerts.json)',
    uptimeSeconds: Math.floor(process.uptime()),
    databaseConnected: isDbConnected,
    socClientsConnected: connectedSocClients,
    totalAlertsPersisted: localAlerts.length,
    timestamp: new Date().toISOString(),
  });
});

/**
 * POST /api/alerts
 * Ingestion point for the Python Edge Agent.
 * Zero-AI: Passes through deterministic playbook engine to generate raw mitigation bash scripts.
 */
app.post('/api/alerts', async (req, res) => {
  try {
    const { sourceIp, targetPort, attackType, details, timestamp } = req.body;

    if (!sourceIp || !attackType) {
      return res.status(400).json({
        error: 'Missing required fields: sourceIp and attackType are mandatory.',
      });
    }

    // Pass through Deterministic Playbook Engine
    const { severity, mitigationScript } = getPlaybook(attackType, sourceIp, targetPort);

    const alertData = {
      _id: 'alt_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6),
      sourceIp: String(sourceIp).trim(),
      targetPort: Number(targetPort) || 0,
      attackType: String(attackType).trim(),
      severity,
      mitigationScript,
      details: details || {},
      timestamp: timestamp ? new Date(timestamp).toISOString() : new Date().toISOString(),
    };

    let savedAlert = alertData;

    if (isDbConnected && mongoose.connection.readyState === 1) {
      try {
        const doc = new Alert(alertData);
        savedAlert = await doc.save();
      } catch (e) {
        persistLocalAlert(alertData);
      }
    } else {
      persistLocalAlert(alertData);
    }

    // Broadcast in real-time to all connected Next.js SOC Dashboards
    io.emit('new_alert', savedAlert);

    console.log(
      `[AEGIS-ALERT] [${severity}] ${savedAlert.attackType} from ${savedAlert.sourceIp} -> Emitted to ${connectedSocClients} SOC clients.`
    );

    return res.status(201).json({
      success: true,
      alert: savedAlert,
    });
  } catch (error) {
    console.error('[AEGIS-ALERT-ERROR]', error);
    return res.status(500).json({ error: 'Failed to process alert event.', details: error.message });
  }
});

/**
 * POST /api/telemetry
 * Ultra-lightweight telemetry ingestion from Edge Agent (CPU & RAM metrics).
 * Streams directly over WebSockets for zero latency.
 */
app.post('/api/telemetry', (req, res) => {
  try {
    const { cpuUsage, ramUsage, activeConnections, packetsPerSec } = req.body;

    const telemetryPayload = {
      cpuUsage: typeof cpuUsage === 'number' ? Number(cpuUsage.toFixed(1)) : 0,
      ramUsage: typeof ramUsage === 'number' ? Number(ramUsage.toFixed(1)) : 0,
      activeConnections: Number(activeConnections) || 0,
      packetsPerSec: Number(packetsPerSec) || 0,
      timestamp: new Date().toISOString(),
    };

    // Broadcast directly to SOC Dashboard via Socket.io
    io.emit('system_metrics', telemetryPayload);

    return res.status(200).json({
      status: 'telemetry_streamed',
      received: telemetryPayload,
    });
  } catch (error) {
    console.error('[AEGIS-TELEMETRY-ERROR]', error);
    return res.status(500).json({ error: 'Failed to stream telemetry' });
  }
});

/**
 * GET /api/alerts
 * Returns the 50 most recent alerts for the initial SOC state hydrate.
 */
app.get('/api/alerts', async (req, res) => {
  try {
    if (isDbConnected && mongoose.connection.readyState === 1) {
      const alerts = await Alert.find().sort({ timestamp: -1 }).limit(50).lean();
      return res.status(200).json(alerts);
    }
    return res.status(200).json(localAlerts.slice(0, 50));
  } catch (error) {
    console.error('[AEGIS-GET-ALERTS-ERROR]', error);
    return res.status(500).json({ error: 'Failed to retrieve alerts' });
  }
});

/**
 * GET /api/reports/csv
 * SOC Compliance Reporter: Generates formatted RFC 4180 CSV incident report for the last 24h.
 */
app.get('/api/reports/csv', async (req, res) => {
  try {
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    let alerts = [];

    if (isDbConnected && mongoose.connection.readyState === 1) {
      alerts = await Alert.find({ timestamp: { $gte: twentyFourHoursAgo } })
        .sort({ timestamp: -1 })
        .lean();

      if (alerts.length === 0) {
        alerts = await Alert.find().sort({ timestamp: -1 }).limit(100).lean();
      }
    } else {
      alerts = localAlerts.filter((a) => new Date(a.timestamp) >= twentyFourHoursAgo);
      if (alerts.length === 0) {
        alerts = localAlerts.slice(0, 100);
      }
    }

    const fields = [
      { label: 'Timestamp (UTC)', value: (row) => new Date(row.timestamp).toISOString() },
      { label: 'Severity', value: 'severity' },
      { label: 'Attack Type', value: 'attackType' },
      { label: 'Source IP', value: 'sourceIp' },
      { label: 'Target Port', value: 'targetPort' },
      { label: 'Mitigation Script', value: 'mitigationScript' },
    ];

    const json2csvParser = new Parser({ fields });
    const csvData = json2csvParser.parse(alerts);

    const filenameDate = new Date().toISOString().replace(/[:.]/g, '-');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="campus_threat_report_${filenameDate}.csv"`
    );

    return res.status(200).send(csvData);
  } catch (error) {
    console.error('[AEGIS-REPORT-ERROR]', error);
    return res.status(500).json({ error: 'Failed to generate compliance report', details: error.message });
  }
});

// Start Server
server.listen(PORT, '0.0.0.0', () => {
  console.log(`=======================================================`);
  console.log(` AegisCampus IDS Core Backend (Native Standalone)`);
  console.log(` Port: ${PORT} | WebSocket Hub: Active`);
  console.log(` Zero Docker Required | Storage: Native JSON Embedded`);
  console.log(` Compliance Reporter: GET /api/reports/csv`);
  console.log(`=======================================================`);
});
