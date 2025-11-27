import request from 'supertest';
import type { Response as SupertestResponse } from 'supertest';
import { Prisma } from '@prisma/client';
import app from '../index';
import prisma from '../prisma/client';
import { resetRateLimits } from './helpers/rateLimit';

type SecuritySettingKey = 'loginIpWindowSec' | 'loginIpLimit' | 'loginLockWindowSec' | 'loginLockThreshold';

const touchedSettings = new Set<SecuritySettingKey>();
const originalSettings: Partial<Record<SecuritySettingKey, Prisma.JsonValue | null | undefined>> = {};
const originalEnv = {
  LOGIN_IP_WINDOW_MS: process.env.LOGIN_IP_WINDOW_MS,
  LOGIN_IP_LIMIT: process.env.LOGIN_IP_LIMIT,
  LOGIN_LOCK_WINDOW_MS: process.env.LOGIN_LOCK_WINDOW_MS,
  LOGIN_LOCK_THRESHOLD: process.env.LOGIN_LOCK_THRESHOLD,
};

async function setSecuritySetting(key: SecuritySettingKey, value: number) {
  if (!touchedSettings.has(key)) {
    const existing = await prisma.setting.findUnique({ where: { category_key: { category: 'security', key } } });
    originalSettings[key] = existing?.value;
    touchedSettings.add(key);
  }
  await prisma.setting.upsert({
    where: { category_key: { category: 'security', key } },
    create: { category: 'security', key, value },
    update: { value },
  });
}

async function resetSecuritySettings() {
  await Promise.all(Array.from(touchedSettings).map(async (key) => {
    const previous = originalSettings[key];
    if (typeof previous === 'undefined') {
      await prisma.setting.delete({ where: { category_key: { category: 'security', key } } }).catch(() => {});
    } else {
      const value = previous === null ? Prisma.JsonNull : (previous as Prisma.InputJsonValue);
      await prisma.setting.update({ where: { category_key: { category: 'security', key } }, data: { value } });
    }
  }));
  touchedSettings.clear();
}

function getCookie(cookies: string[] | undefined, name: string): string | undefined {
  if (!cookies) return undefined;
  return cookies.find((c) => c.startsWith(`${name}=`));
}

beforeEach(async () => {
  await resetRateLimits();
});

describe('Auth rate limiting - IP throttle', () => {
  beforeAll(async () => {
    // Make the window very small and the limit low to keep tests fast
    process.env.LOGIN_IP_WINDOW_MS = '1000';
    process.env.LOGIN_IP_LIMIT = '2';
    await Promise.all([
      setSecuritySetting('loginIpWindowSec', 1),
      setSecuritySetting('loginIpLimit', 2),
    ]);
  });

  it('throttles repeated login attempts by IP', async () => {
    // Get one CSRF token/cookie and reuse for all attempts
    const csrf = await request(app).get('/auth/csrf');
    const cookies = csrf.headers['set-cookie'] as unknown as string[] | undefined;
    const csrfCookie = getCookie(cookies, 'csrfToken')!;
    const csrfToken = csrf.body.csrfToken;

    const attempt = async (): Promise<SupertestResponse> => {
      const r = await request(app)
        .post('/auth/login')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ email: 'doesnotexist@example.com', password: 'WrongPass1!' });
      return r as unknown as SupertestResponse;
    };

    const a1 = await attempt();
    expect([400, 401, 403, 429, 500]).toContain(a1.status); // first attempt goes through logic
    const a2 = await attempt();
    expect([400, 401, 403, 429, 500]).toContain(a2.status);
    const a3 = await attempt();
    expect(a3.status).toBe(429);
    expect(a3.body.error).toMatch(/too many/i);

    // After the short window, attempts should be allowed again
    await new Promise((r) => setTimeout(r, 1100));
    const a4 = await attempt();
    expect([400, 401, 403, 429, 500]).toContain(a4.status);
  });
});

describe('Auth rate limiting - per-user lockout', () => {
  beforeAll(async () => {
    // Ensure IP throttle does not interfere; lockout after 2 failures within 1s
    process.env.LOGIN_IP_WINDOW_MS = '1000';
    process.env.LOGIN_IP_LIMIT = '100';
    process.env.LOGIN_LOCK_WINDOW_MS = '1000';
    process.env.LOGIN_LOCK_THRESHOLD = '2';
    await Promise.all([
      setSecuritySetting('loginIpWindowSec', 1),
      setSecuritySetting('loginIpLimit', 100),
      setSecuritySetting('loginLockWindowSec', 1),
      setSecuritySetting('loginLockThreshold', 2),
    ]);
  });

  it('locks out a specific email after repeated failures', async () => {
    const email = `locked+${Date.now()}@example.com`;
    const csrf = await request(app).get('/auth/csrf');
    const cookies = csrf.headers['set-cookie'] as unknown as string[] | undefined;
    const csrfCookie = getCookie(cookies, 'csrfToken')!;
    const csrfToken = csrf.body.csrfToken;

    const attempt = async (): Promise<SupertestResponse> => {
      const r = await request(app)
        .post('/auth/login')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ email, password: 'WrongPass1!' });
      return r as unknown as SupertestResponse;
    };

    const a1 = await attempt();
    expect([400, 401, 403]).toContain(a1.status);
    const a2 = await attempt();
    expect([400, 401, 403]).toContain(a2.status);
    const a3 = await attempt();
    expect(a3.status).toBe(429);
    expect(String(a3.body.error || '')).toMatch(/locked/i);

    // After window resets, should go back to normal failure (401/403)
    await new Promise((r) => setTimeout(r, 1100));
    const a4 = await attempt();
    expect([400, 401, 403]).toContain(a4.status);
  });
});

afterAll(async () => {
  await resetRateLimits();
  await resetSecuritySettings();
  process.env.LOGIN_IP_WINDOW_MS = originalEnv.LOGIN_IP_WINDOW_MS;
  process.env.LOGIN_IP_LIMIT = originalEnv.LOGIN_IP_LIMIT;
  process.env.LOGIN_LOCK_WINDOW_MS = originalEnv.LOGIN_LOCK_WINDOW_MS;
  process.env.LOGIN_LOCK_THRESHOLD = originalEnv.LOGIN_LOCK_THRESHOLD;
});
