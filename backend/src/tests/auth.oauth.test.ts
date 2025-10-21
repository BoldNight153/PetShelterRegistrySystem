import request from 'supertest';
import app from '../index';

function getCookie(cookies: string[] | undefined, name: string): string | undefined {
  if (!cookies) return undefined;
  return cookies.find((c) => c.startsWith(`${name}=`));
}

describe('OAuth flows (google/github)', () => {
  const envBackup = { ...process.env } as any;

  beforeEach(() => {
    jest.restoreAllMocks();
    // Ensure callbacks know where to redirect
    process.env.OAUTH_SUCCESS_REDIRECT = '/auth-success';
    process.env.OAUTH_FAILURE_REDIRECT = '/login?error=oauth_failed';
  });

  afterAll(() => {
    process.env = envBackup;
  });

  it('google: start -> callback issues cookies and redirects success', async () => {
    process.env.GOOGLE_CLIENT_ID = 'test-google-client-id';
    process.env.GOOGLE_CLIENT_SECRET = 'test-google-client-secret';
    process.env.GOOGLE_REDIRECT_URI = 'http://localhost:4000/auth/oauth/google/callback';

    // Start
    const start = await request(app).get('/auth/oauth/google/start');
    expect(start.status).toBe(302);
    const stateCookie = getCookie(start.headers['set-cookie'], 'oauth_state');
    expect(stateCookie).toBeTruthy();
    const stateValue = (stateCookie || '').split(';')[0].split('=')[1];

    // Mock fetch for token exchange and userinfo
    const fetchMock = jest.fn(async (url: any, init?: any) => {
      const u = String(url);
      if (u.includes('oauth2.googleapis.com/token')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ access_token: 'g-access', id_token: 'id', token_type: 'Bearer' }),
        } as any;
      }
      if (u.includes('openidconnect.googleapis.com/v1/userinfo')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ sub: 'google-user-123', email: `g${Date.now()}@example.com`, email_verified: true, name: 'G User', picture: 'http://img' }),
        } as any;
      }
      throw new Error(`unexpected fetch to ${u} ${init ? JSON.stringify(init) : ''}`);
    });
    (global as any).fetch = fetchMock;

    const cb = await request(app)
      .get('/auth/oauth/google/callback')
      .query({ code: 'abc', state: stateValue })
      .set('Cookie', `oauth_state=${stateValue}`);
    expect(cb.status).toBe(302);
    expect(cb.headers.location).toBe('/auth-success');
    const setCookies: string[] = cb.headers['set-cookie'] || [];
    expect(getCookie(setCookies, 'accessToken')).toBeTruthy();
    expect(getCookie(setCookies, 'refreshToken')).toBeTruthy();
  });

  it('github: start -> callback issues cookies and redirects success', async () => {
    process.env.GITHUB_CLIENT_ID = 'test-github-client-id';
    process.env.GITHUB_CLIENT_SECRET = 'test-github-client-secret';
    process.env.GITHUB_REDIRECT_URI = 'http://localhost:4000/auth/oauth/github/callback';

    // Start
    const start = await request(app).get('/auth/oauth/github/start');
    expect(start.status).toBe(302);
    const stateCookie = getCookie(start.headers['set-cookie'], 'oauth_state');
    expect(stateCookie).toBeTruthy();
    const stateValue = (stateCookie || '').split(';')[0].split('=')[1];

    // Mock fetch for token exchange, user, and emails
    const fetchMock = jest.fn(async (url: any) => {
      const u = String(url);
      if (u.includes('github.com/login/oauth/access_token')) {
        return { ok: true, status: 200, json: async () => ({ access_token: 'gh-access', token_type: 'bearer', scope: 'read:user user:email' }) } as any;
      }
      if (u.endsWith('/user')) {
        return { ok: true, status: 200, json: async () => ({ id: 987654321, name: 'GH User', login: 'ghuser', avatar_url: 'http://img' }) } as any;
      }
      if (u.endsWith('/user/emails')) {
        return { ok: true, status: 200, json: async () => ([{ email: `gh${Date.now()}@example.com`, primary: true, verified: true }]) } as any;
      }
      throw new Error(`unexpected fetch to ${u}`);
    });
    (global as any).fetch = fetchMock;

    const cb = await request(app)
      .get('/auth/oauth/github/callback')
      .query({ code: 'def', state: stateValue })
      .set('Cookie', `oauth_state=${stateValue}`);
    expect(cb.status).toBe(302);
    expect(cb.headers.location).toBe('/auth-success');
    const setCookies: string[] = cb.headers['set-cookie'] || [];
    expect(getCookie(setCookies, 'accessToken')).toBeTruthy();
    expect(getCookie(setCookies, 'refreshToken')).toBeTruthy();
  });
});
