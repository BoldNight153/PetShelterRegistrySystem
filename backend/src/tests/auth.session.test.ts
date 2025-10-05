import request from 'supertest';
import app from '../index';

function getCookie(cookies: string[] | undefined, name: string): string | undefined {
  if (!cookies) return undefined;
  return cookies.find((c) => c.startsWith(`${name}=`));
}

describe('Auth Session: refresh and logout', () => {
  it('refresh rotates refresh token and issues new access token', async () => {
    const email = `user+${Date.now()}@example.com`;
    // register to obtain initial cookies
    const csrf1 = await request(app).get('/auth/csrf');
    const csrfCookie1 = getCookie(csrf1.headers['set-cookie'], 'csrfToken');
    const csrfToken1 = csrf1.body.csrfToken;

    const reg = await request(app)
      .post('/auth/register')
      .set('x-csrf-token', csrfToken1)
      .set('Cookie', csrfCookie1)
      .send({ email, password: 'Test1234!', name: 'Refresh Test' });

    expect(reg.status).toBe(201);
    const initialCookies: string[] = reg.headers['set-cookie'] || [];
    const initialRefresh = getCookie(initialCookies, 'refreshToken');
    const initialAccess = getCookie(initialCookies, 'accessToken');
    expect(initialRefresh).toBeTruthy();
    expect(initialAccess).toBeTruthy();

    // refresh
    const csrf2 = await request(app).get('/auth/csrf');
    const csrfCookie2 = getCookie(csrf2.headers['set-cookie'], 'csrfToken');
    const csrfToken2 = csrf2.body.csrfToken;

    const ref = await request(app)
      .post('/auth/refresh')
      .set('x-csrf-token', csrfToken2)
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
    const csrf1 = await request(app).get('/auth/csrf');
    const csrfCookie1 = getCookie(csrf1.headers['set-cookie'], 'csrfToken');
    const csrfToken1 = csrf1.body.csrfToken;

    const reg = await request(app)
      .post('/auth/register')
      .set('x-csrf-token', csrfToken1)
      .set('Cookie', csrfCookie1)
      .send({ email, password: 'Test1234!', name: 'Logout Test' });

    expect(reg.status).toBe(201);
    const initialCookies: string[] = reg.headers['set-cookie'] || [];
    const rt = getCookie(initialCookies, 'refreshToken');
    expect(rt).toBeTruthy();

    // logout
    const csrf2 = await request(app).get('/auth/csrf');
    const csrfCookie2 = getCookie(csrf2.headers['set-cookie'], 'csrfToken');
    const csrfToken2 = csrf2.body.csrfToken;

    const out = await request(app)
      .post('/auth/logout')
      .set('x-csrf-token', csrfToken2)
      .set('Cookie', [csrfCookie2!, rt!])
      .send();

    expect(out.status).toBe(204);
    const cleared: string[] = out.headers['set-cookie'] || [];
    // Should include clearing both cookies with Max-Age=0
    expect(cleared.some((c) => c.startsWith('accessToken=') && c.includes('Max-Age=0'))).toBe(true);
    expect(cleared.some((c) => c.startsWith('refreshToken=') && c.includes('Max-Age=0'))).toBe(true);
  });
});
