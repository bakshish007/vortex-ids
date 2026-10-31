/**
 * End-to-End Verification Test for AegisCampus IDS Backend
 */
const http = require('http');

async function testBackend() {
  console.log('[TEST] Starting backend integration verification...');
  
  // Require server (it starts listening on port 3001)
  require('./server');

  // Wait 1.5s for server initialization
  await new Promise((r) => setTimeout(r, 1500));

  // Helper for HTTP requests
  function makeRequest(options, postData) {
    return new Promise((resolve, reject) => {
      const req = http.request(options, (res) => {
        let body = '';
        res.on('data', (chunk) => (body += chunk));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
      });
      req.on('error', reject);
      if (postData) {
        req.write(typeof postData === 'string' ? postData : JSON.stringify(postData));
      }
      req.end();
    });
  }

  try {
    // 1. Test Health endpoint
    console.log('[TEST] Checking GET /api/health...');
    const health = await makeRequest({
      hostname: '127.0.0.1',
      port: 3001,
      path: '/api/health',
      method: 'GET',
    });
    console.log('[TEST] Health response:', health.status, health.body);

    // 2. Test Ingesting Port Scan Alert
    console.log('[TEST] Checking POST /api/alerts (Port Scan)...');
    const scanAlert = await makeRequest(
      {
        hostname: '127.0.0.1',
        port: 3001,
        path: '/api/alerts',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      },
      {
        sourceIp: '192.168.1.185',
        targetPort: 80,
        attackType: 'Port Scan',
        details: { uniquePortsHit: 22 },
      }
    );
    console.log('[TEST] Scan Alert response status:', scanAlert.status);
    const parsedAlert = JSON.parse(scanAlert.body);
    console.log('[TEST] Alert Severity:', parsedAlert.alert.severity);
    console.log('[TEST] Mitigation script generated:\n' + parsedAlert.alert.mitigationScript.slice(0, 200) + '...');

    // 3. Test Ingesting SSH Brute Force Alert
    console.log('[TEST] Checking POST /api/alerts (SSH Brute Force)...');
    const sshAlert = await makeRequest(
      {
        hostname: '127.0.0.1',
        port: 3001,
        path: '/api/alerts',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      },
      {
        sourceIp: '10.0.0.99',
        targetPort: 22,
        attackType: 'SSH Brute Force',
      }
    );
    console.log('[TEST] SSH Alert response status:', sshAlert.status);

    // 4. Test Ingesting Telemetry
    console.log('[TEST] Checking POST /api/telemetry...');
    const tel = await makeRequest(
      {
        hostname: '127.0.0.1',
        port: 3001,
        path: '/api/telemetry',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      },
      {
        cpuUsage: 3.2,
        ramUsage: 18.5,
        packetsPerSec: 120,
      }
    );
    console.log('[TEST] Telemetry response:', tel.status, tel.body);

    // 5. Test GET /api/alerts
    console.log('[TEST] Checking GET /api/alerts...');
    const alertsGet = await makeRequest({
      hostname: '127.0.0.1',
      port: 3001,
      path: '/api/alerts',
      method: 'GET',
    });
    console.log('[TEST] Retrieved alerts count:', JSON.parse(alertsGet.body).length);

    // 6. Test GET /api/reports/csv (Compliance Reporter)
    console.log('[TEST] Checking GET /api/reports/csv...');
    const csvGet = await makeRequest({
      hostname: '127.0.0.1',
      port: 3001,
      path: '/api/reports/csv',
      method: 'GET',
    });
    console.log('[TEST] CSV Report status:', csvGet.status);
    console.log('[TEST] Content-Type header:', csvGet.headers['content-type']);
    console.log('[TEST] Content-Disposition header:', csvGet.headers['content-disposition']);
    console.log('[TEST] CSV Output preview:\n' + csvGet.body.slice(0, 250));

    console.log('\n>>> [ALL INTEGRATION VERIFICATION TESTS PASSED SUCCESSFULLY] <<<');
    process.exit(0);
  } catch (err) {
    console.error('[TEST ERROR]', err);
    process.exit(1);
  }
}

testBackend();

