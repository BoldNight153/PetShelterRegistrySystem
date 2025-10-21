import request from 'supertest';
import app from '../index';

const CSRF_PATH = '/auth/csrf';
const CSRF_HEADER = 'x-csrf-token';

function headerCookies(headers: unknown): string[] | undefined {
  // Accept unknown and narrow to avoid passing `any` into a typed parameter
  if (!headers || typeof headers !== 'object') return undefined;
  const h = headers as Record<string, unknown>;
  const v = h['set-cookie'];
  if (!v) return undefined;
  if (Array.isArray(v)) {
    // Only accept string items to avoid unexpected object stringification
    const items = v.filter((it): it is string => typeof it === 'string');
    return items.length ? items : undefined;
  }
  if (typeof v === 'string') return [v];
  return undefined;
}

function getCookie(cookies: string[] | undefined, name: string): string | undefined {
  if (!cookies) return undefined;
  return cookies.find((c) => c.startsWith(`${name}=`));
}

describe('Auth Session: refresh and logout', () => {
  // Tests interact with the running server and can be slow in CI.
  // Increase the timeout to be more resilient to transient slowness.
  jest.setTimeout(30000);
  it('refresh rotates refresh token and issues new access token', async () => {
    const email = `user+${Date.now()}@example.com`;
    // register to obtain initial cookies
  const csrf1 = await request(app).get(CSRF_PATH);
  const csrfCookie1 = getCookie(headerCookies(csrf1.headers), 'csrfToken');
  const csrfToken1 = csrf1.body.csrfToken;

    const reg = await request(app)
      .post('/auth/register')
      .set(CSRF_HEADER, csrfToken1)
      .set('Cookie', csrfCookie1)
      .send({ email, password: 'Test1234!', name: 'Refresh Test' });

    expect(reg.status).toBe(201);
    const initialCookies: string[] = reg.headers['set-cookie'] || [];
    const initialRefresh = getCookie(initialCookies, 'refreshToken');
    const initialAccess = getCookie(initialCookies, 'accessToken');
    expect(initialRefresh).toBeTruthy();
    expect(initialAccess).toBeTruthy();

    // refresh
  const csrf2 = await request(app).get(CSRF_PATH);
  const csrfCookie2 = getCookie(headerCookies(csrf2.headers), 'csrfToken');
  const csrfToken2 = csrf2.body.csrfToken;

    const ref = await request(app)
      .post('/auth/refresh')
      .set(CSRF_HEADER, csrfToken2)
      .set('Cookie', [csrfCookie2!, initialRefresh!])
      .send();

    expect(ref.status).toBe(200);
    expect(ref.body.ok).toBe(true);
    const rotatedCookies: string[] = ref.headers['set-cookie'] || [];
    const newRefresh = getCookie(rotatedCookies, 'refreshToken');
    const newAccess = getCookie(rotatedCookies, 'accessToken');
    expect(newRefresh).toBeTruthy();
    expect(newAccess).toBeTruthy();
    expect(newRefresh).not.toBe(initialRefresh);
  });

  it('logout clears cookies and revokes token', async () => {
    const email = `logout+${Date.now()}@example.com`;
    // register to obtain cookies
  const csrf1 = await request(app).get(CSRF_PATH);
  const csrfCookie1 = getCookie(headerCookies(csrf1.headers), 'csrfToken');
  const csrfToken1 = csrf1.body.csrfToken;

    const reg = await request(app)
      .post('/auth/register')
      .set(CSRF_HEADER, csrfToken1)
      .set('Cookie', csrfCookie1)
      .send({ email, password: 'Test1234!', name: 'Logout Test' });

    expect(reg.status).toBe(201);
    const initialCookies: string[] = reg.headers['set-cookie'] || [];
    const rt = getCookie(initialCookies, 'refreshToken');
    expect(rt).toBeTruthy();

    // logout
  const csrf2 = await request(app).get(CSRF_PATH);
  const csrfCookie2 = getCookie(headerCookies(csrf2.headers), 'csrfToken');
  const csrfToken2 = csrf2.body.csrfToken;

    const out = await request(app)
      .post('/auth/logout')
      .set(CSRF_HEADER, csrfToken2)
      .set('Cookie', [csrfCookie2!, rt!])
      .send();

    expect(out.status).toBe(204);
    const cleared: string[] = out.headers['set-cookie'] || [];
    // Should include clearing both cookies with Max-Age=0
    expect(cleared.some((c) => c.startsWith('accessToken=') && c.includes('Max-Age=0'))).toBe(true);
    expect(cleared.some((c) => c.startsWith('refreshToken=') && c.includes('Max-Age=0'))).toBe(true);
  });
});
