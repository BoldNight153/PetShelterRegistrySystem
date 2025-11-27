import crypto from 'crypto';
import request, { type SuperAgentTest } from 'supertest';

process.env.NODE_ENV ||= 'test';
process.env.DATABASE_URL ||= 'file:./dev.db';

const ADMIN_EMAIL = process.env.DEV_ADMIN_EMAIL || 'admin@example.com';
const ADMIN_PASSWORD = process.env.DEV_ADMIN_PASSWORD || 'Admin123!@#';
const DEVICE_FP = process.env.AUTH_SMOKE_DEVICE_FP || 'dev-smoke-device';
const DEVICE_NAME = process.env.AUTH_SMOKE_DEVICE_NAME || 'Dev Smoke Device';
const DEVICE_PLATFORM = process.env.AUTH_SMOKE_DEVICE_PLATFORM || process.platform;
const MENUS_SLUG = process.env.AUTH_SMOKE_MENUS || 'settings_main';

const log = (...args: unknown[]) => console.log('[auth-smoke]', ...args);

function deriveBackupCodes(email: string, total = 8): string[] {
  const codes: string[] = [];
  for (let i = 0; i < total; i++) {
    const hash = crypto.createHash('sha256').update(`backup:${email}:${i}`).digest('hex').toUpperCase();
    const chunk = hash.slice(0, 10);
    codes.push(`${chunk.slice(0, 5)}-${chunk.slice(5)}`);
  }
  return codes;
}

function extractCsrfCookie(setCookie: string[] | undefined): string | undefined {
  if (!setCookie) return undefined;
  for (const cookie of setCookie) {
    if (cookie.startsWith('csrfToken=')) {
      return cookie.split(';')[0];
    }
  }
  return undefined;
}

async function fetchCsrf(agent: SuperAgentTest) {
  const res = await agent.get('/auth/csrf');
  if (res.status !== 200) {
    throw new Error(`Expected /auth/csrf to return 200, received ${res.status}`);
  }
  const csrfToken = res.body?.csrfToken;
  if (!csrfToken) {
    throw new Error('CSRF token missing in response body');
  }
  const csrfCookie = extractCsrfCookie(res.headers['set-cookie']);
  if (!csrfCookie) {
    throw new Error('CSRF cookie missing in response headers');
  }
  return { csrfToken, csrfCookie };
}

async function run() {
  log('Starting smoke test with admin', ADMIN_EMAIL);
  log('NODE_ENV=', process.env.NODE_ENV, 'DATABASE_URL=', process.env.DATABASE_URL, 'passwordLen=', ADMIN_PASSWORD.length);

  const { default: app } = await import('../src/index');
  const agent = request.agent(app);
  const backupCodes = deriveBackupCodes(ADMIN_EMAIL);

  log('Step 1: Fetch CSRF token');
  const csrf1 = await fetchCsrf(agent);

  log('Step 2: POST /auth/login');
  const loginRes = await agent
    .post('/auth/login')
    .set('x-csrf-token', csrf1.csrfToken)
    .set('Cookie', csrf1.csrfCookie)
    .send({
      email: ADMIN_EMAIL,
      password: ADMIN_PASSWORD,
      deviceFingerprint: DEVICE_FP,
      deviceName: DEVICE_NAME,
      devicePlatform: DEVICE_PLATFORM,
      trustThisDevice: true,
    });
  log('login status', loginRes.status);
  if (loginRes.status !== 200 && loginRes.status !== 202) {
    throw new Error(`Unexpected login status: ${loginRes.status}`);
  }

  const challengeId: string | undefined = loginRes.body?.challenge?.id;
  if (challengeId) {
    log('Step 3: POST /auth/mfa/verify via backup code');
    const csrf2 = await fetchCsrf(agent);
    const mfaRes = await agent
      .post('/auth/mfa/verify')
      .set('x-csrf-token', csrf2.csrfToken)
      .set('Cookie', csrf2.csrfCookie)
      .send({
        challengeId,
        method: 'backup_code',
        backupCode: backupCodes[0],
        deviceFingerprint: DEVICE_FP,
        deviceName: DEVICE_NAME,
        devicePlatform: DEVICE_PLATFORM,
        trustThisDevice: true,
      });
    log('mfa verify status', mfaRes.status);
    if (mfaRes.status !== 200) {
      throw new Error(`MFA verify failed with status ${mfaRes.status}`);
    }
  } else {
    log('Login returned 200 without MFA challenge; continuing.');
  }

  log('Step 4: POST /auth/refresh');
  const csrf3 = await fetchCsrf(agent);
  const refreshRes = await agent
    .post('/auth/refresh')
    .set('x-csrf-token', csrf3.csrfToken)
    .set('Cookie', csrf3.csrfCookie)
    .send();
  log('refresh status', refreshRes.status);
  if (refreshRes.status !== 200) {
    throw new Error(`Refresh failed with status ${refreshRes.status}`);
  }

  log(`Step 5: GET /menus/${MENUS_SLUG}`);
  const menusRes = await agent.get(`/menus/${MENUS_SLUG}`);
  log('menus status', menusRes.status, 'items:', Array.isArray(menusRes.body?.items) ? menusRes.body.items.length : 'n/a');
  if (menusRes.status !== 200) {
    throw new Error(`Menus request failed with status ${menusRes.status}`);
  }

  log('Auth smoke test completed successfully.');
}

run().catch(err => {
  console.error('[auth-smoke] Flow failed:', err);
  process.exitCode = 1;
});
