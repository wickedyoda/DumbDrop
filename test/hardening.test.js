/**
 * Hardening tests for the non-CVE security audit findings:
 *  - DELETE /api/files/ must not wipe the upload root
 *  - the auth cookie must hold an opaque session token, never the PIN
 *  - request headers must not be able to choose the rate-limit/lockout identity
 *  - an x-batch-id header must not opt a client out of upload rate limiting
 *  - notification debug logging must not dump the PIN or the Apprise URL
 */

process.env.DISABLE_BATCH_CLEANUP = 'true';
process.env.DISABLE_SECURITY_CLEANUP = 'true';
process.env.DUMBDROP_PIN = '1234';
// Small, explicit buckets so the limiter tests stay fast
// Small, explicit buckets so the limiter tests stay fast. Default values are
// used for the batch/chunk tiers: the point of these tests is that the tiers
// exist at all, not their exact numbers.
process.env.UPLOAD_INIT_RATE_LIMIT = '2';
// Node runs test files in parallel over one checkout, so keep this suite's
// files out of the shared ./local_uploads directory.
process.env.LOCAL_UPLOAD_DIR = './local_uploads_hardening';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

function newBatchId() {
  return `${Date.now()}-${crypto.randomBytes(5).toString('hex').slice(0, 9)}`;
}

const { app, initialize, config } = require('../src/app');
const { SESSION_COOKIE, LEGACY_PIN_COOKIE } = require('../src/utils/authSessions');
const { getSecurityIdentity } = require('../src/utils/ipExtractor');

let server;
let port;

function request({ method = 'GET', urlPath, headers = {}, body }) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : JSON.stringify(body);
    const req = http.request(
      {
        host: 'localhost',
        port,
        method,
        path: urlPath,
        headers: {
          'Content-Type': 'application/json',
          ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
          ...headers,
        },
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          let parsed = null;
          try { parsed = JSON.parse(data); } catch { /* non-JSON body */ }
          resolve({
            status: res.statusCode,
            data: parsed,
            raw: data,
            headers: res.headers,
            cookies: res.headers['set-cookie'] || [],
          });
        });
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function cookieHeaderFrom(setCookieArr) {
  return setCookieArr.map((c) => c.split(';')[0]).join('; ');
}

before(async () => {
  await initialize();
  server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, () => {
    port = server.address().port;
    resolve();
  }));
});

after(async () => {
  if (server) await new Promise((resolve) => server.close(resolve));
});

describe('Upload root deletion guard', () => {
  it('rejects DELETE /api/files/ instead of wiping the storage root', async () => {
    const res = await request({ method: 'DELETE', urlPath: '/api/files/' , headers: { 'x-pin': '1234' } });

    assert.strictEqual(res.status, 400, `expected 400, got ${res.status}: ${res.raw}`);

    // The root must still be there and usable
    const entries = await fs.readdir(config.uploadDir);
    assert.ok(Array.isArray(entries), 'upload root still readable');
  });

  it('rejects deleting the internal .metadata directory', async () => {
    const res = await request({
      method: 'DELETE',
      urlPath: '/api/files/.metadata',
      headers: { 'x-pin': '1234' },
    });

    assert.strictEqual(res.status, 403, `expected 403, got ${res.status}`);
    await fs.access(path.join(config.uploadDir, '.metadata'));
  });

  it('still deletes an ordinary file', async () => {
    const target = path.join(config.uploadDir, 'hardening-delete-me.txt');
    await fs.writeFile(target, 'bye');

    const res = await request({
      method: 'DELETE',
      urlPath: '/api/files/hardening-delete-me.txt',
      headers: { 'x-pin': '1234' },
    });

    assert.strictEqual(res.status, 200, `expected 200, got ${res.status}: ${res.raw}`);
    await assert.rejects(() => fs.access(target));
  });
});

describe('Opaque session cookie instead of the PIN', () => {
  it('verify-pin sets a session token cookie, not the PIN', async () => {
    const res = await request({ method: 'POST', urlPath: '/api/auth/verify-pin', body: { pin: '1234' } });
    assert.strictEqual(res.status, 200, `expected 200, got ${res.status}: ${res.raw}`);

    const sessionCookie = res.cookies.find((c) => c.startsWith(`${SESSION_COOKIE}=`));
    assert.ok(sessionCookie, `Set-Cookie should contain ${SESSION_COOKIE}: ${JSON.stringify(res.cookies)}`);

    const token = sessionCookie.split(';')[0].split('=')[1];
    assert.notStrictEqual(token, '1234', 'cookie must not contain the PIN');
    assert.match(token, /^[0-9a-f]{32,}$/, 'token should be opaque hex');

    // HttpOnly + SameSite must survive on the new cookie
    assert.match(sessionCookie, /HttpOnly/i);
    assert.match(sessionCookie, /SameSite=Strict/i);

    // The legacy PIN cookie is explicitly expired
    assert.ok(
      res.cookies.some((c) => c.startsWith(`${LEGACY_PIN_COOKIE}=`) && /Expires=Thu, 01 Jan 1970|Max-Age=0/i.test(c)),
      `legacy cookie should be cleared: ${JSON.stringify(res.cookies)}`
    );
  });

  it('accepts the session cookie and rejects a raw-PIN cookie', async () => {
    const auth = await request({ method: 'POST', urlPath: '/api/auth/verify-pin', body: { pin: '1234' } });
    const sessionHeader = cookieHeaderFrom(auth.cookies);

    const ok = await request({ method: 'GET', urlPath: '/api/files/', headers: { Cookie: sessionHeader } });
    assert.strictEqual(ok.status, 200, `session cookie should authorise listing: ${ok.raw}`);

    const legacy = await request({
      method: 'GET',
      urlPath: '/api/files/',
      headers: { Cookie: `${LEGACY_PIN_COOKIE}=1234` },
    });
    assert.strictEqual(legacy.status, 401, 'a cookie holding the PIN must no longer authenticate');

    const anon = await request({ method: 'GET', urlPath: '/api/files/' });
    assert.strictEqual(anon.status, 401, 'no cookie must not authenticate');
  });

  it('issues a session for x-pin header clients', async () => {
    const res = await request({
      method: 'POST',
      urlPath: '/api/upload/init',
      headers: { 'x-pin': '1234', 'x-batch-id': newBatchId() },
      body: { filename: 'hardening-single.txt', fileSize: 4 },
    });

    assert.strictEqual(res.status, 200, `expected 200, got ${res.status}: ${res.raw}`);

    const sessionCookie = res.cookies.find((c) => c.startsWith(`${SESSION_COOKIE}=`));
    assert.ok(sessionCookie, 'x-pin auth should set the session cookie');
    const token = sessionCookie.split(';')[0].split('=')[1];
    assert.notStrictEqual(token, '1234', 'PIN must not be handed back in a cookie');
    assert.ok(!res.cookies.some((c) => c.startsWith(`${LEGACY_PIN_COOKIE}=1234`)), 'PIN must not be in a cookie');
  });
});

describe('Rate-limit identity ignores unverified proxy headers', () => {
  // config is frozen at module load, so the trust settings are injected
  const spoofedReq = {
    socket: { remoteAddress: '::ffff:10.0.0.5' },
    connection: { remoteAddress: '::ffff:10.0.0.5' },
    ip: '1.2.3.4', // what Express derives from X-Forwarded-For
  };

  it('uses the socket address when TRUST_PROXY is on with no whitelist', () => {
    assert.strictEqual(
      getSecurityIdentity(spoofedReq, { trustProxy: true, trustedProxyIps: null }),
      '10.0.0.5',
      'headers must not choose the identity when no proxy is whitelisted'
    );
  });

  it('ignores the header when the socket is not a whitelisted proxy', () => {
    assert.strictEqual(
      getSecurityIdentity(spoofedReq, { trustProxy: true, trustedProxyIps: ['192.0.2.1'] }),
      '10.0.0.5'
    );
  });

  it('honours the header only from a whitelisted proxy', () => {
    assert.strictEqual(
      getSecurityIdentity(spoofedReq, { trustProxy: true, trustedProxyIps: ['10.0.0.5'] }),
      '1.2.3.4'
    );
  });
});

describe('x-batch-id can no longer disable the upload limiter', () => {
  it('caps per-identity inits even when every request carries a fresh batch id', async () => {
    const statuses = [];
    for (let i = 0; i < 6; i++) {
      const res = await request({
        method: 'POST',
        urlPath: '/api/upload/init',
        headers: { 'x-pin': '1234', 'x-batch-id': newBatchId() },
        body: { filename: `spoofed-${i}.txt`, fileSize: 4 },
      });
      statuses.push(res.status);
    }

    assert.ok(
      statuses.includes(429),
      `rotating batch ids should hit the per-identity cap, got ${JSON.stringify(statuses)}`
    );
  });

  it('lets a real batch continue past the per-identity cap', async () => {
    const sharedBatch = newBatchId();
    const results = [];
    for (let i = 0; i < 8; i++) {
      const res = await request({
        method: 'POST',
        urlPath: '/api/upload/init',
        headers: { 'x-pin': '1234', 'x-batch-id': sharedBatch },
        body: { filename: `batched-${i}.txt`, fileSize: 4 },
      });
      results.push(res.status);
    }

    // The first couple are charged to the tiny per-identity bucket; the batch
    // tier must absorb the rest, so a genuine folder upload is not throttled
    // into failure. A single 429 is tolerable (bucket carry-over from the
    // previous test), a wall of them is not.
    const blocked = results.filter((s) => s === 429).length;
    assert.ok(blocked <= 2, `batch tier should keep a real batch moving, got ${JSON.stringify(results)}`);
    assert.ok(results.includes(200), `at least some inits must succeed: ${JSON.stringify(results)}`);
  });
});

describe('Notification logging does not dump secrets', () => {
  it('logs a redacted summary instead of the config object', async () => {
    const logger = require('../src/utils/logger');
    const originalDebug = logger.debug;
    const lines = [];
    logger.debug = (msg, ...args) => { lines.push(`${msg} ${args.join(' ')}`); };

    try {
      const { sendNotification } = require('../src/services/notifications');
      await sendNotification('secret-ish.txt', 1234, {
        pin: '1234',
        appriseUrl: 'tgram://123456:AAAABigSecretToken/apiBot/',
        appriseMessage: 'New file uploaded {filename} ({size}), Storage used {storage}',
        appriseSizeUnit: 'Auto',
        uploadDir: config.uploadDir,
      });
    } finally {
      logger.debug = originalDebug;
    }

    const joined = lines.join('\n');
    assert.ok(joined.length > 0, 'expected a debug line describing the notification');
    assert.ok(!joined.includes('AAAABigSecretToken'), 'must not log the Apprise token');
    assert.ok(!joined.includes('tgram://'), 'must not log the Apprise URL');
    assert.ok(!/\b1234\b/.test(joined.replace('1234 bytes', '')), 'must not log the PIN');
  });
});
