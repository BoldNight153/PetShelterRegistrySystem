import request from 'supertest';
import type { Response as SupertestResponse } from 'supertest';
import app from '../index';

function getCookie(cookies: string[] | undefined, name: string): string | undefined {
  if (!cookies) return undefined;
  return cookies.find((c) => c.startsWith(`${name}=`));
}

describe('Auth rate limiting - IP throttle', () => {
  beforeAll(() => {
    // Make the window very small and the limit low to keep tests fast
    process.env.LOGIN_IP_WINDOW_MS = '1000';
    process.env.LOGIN_IP_LIMIT = '2';
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
  beforeAll(() => {
    // Ensure IP throttle does not interfere; lockout after 2 failures within 1s
    process.env.LOGIN_IP_WINDOW_MS = '1000';
    process.env.LOGIN_IP_LIMIT = '100';
    process.env.LOGIN_LOCK_WINDOW_MS = '1000';
    process.env.LOGIN_LOCK_THRESHOLD = '2';
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
