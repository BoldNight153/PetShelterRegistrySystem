import request from 'supertest';
import { PrismaClient } from '@prisma/client';
import app from '../index';

function getCookie(cookies: string[] | undefined, name: string): string | undefined {
  if (!cookies) return undefined;
  return cookies.find((c) => c.startsWith(`${name}=`));
}

const SUCCESS_REDIRECT = '/auth-success';
const FAILURE_REDIRECT = '/login?error=oauth_failed';
const STATE_COOKIE_NAME = 'oauth_state';

const prisma = new PrismaClient();

async function setProviderEnabled(provider: 'google' | 'github', enabled: boolean) {
  await prisma.setting.upsert({
    where: { category_key: { category: 'auth', key: provider } as any },
    create: { category: 'auth', key: provider, value: enabled },
    update: { value: enabled },
  });
}

type MockFetchResponse<T> = {
  ok: boolean;
  status: number;
  json: () => Promise<T>;
};

describe('OAuth flows (google/github)', () => {
  const envBackup = { ...process.env } as any;

  beforeEach(async () => {
    jest.restoreAllMocks();
    // Ensure callbacks know where to redirect
    process.env.OAUTH_SUCCESS_REDIRECT = SUCCESS_REDIRECT;
    process.env.OAUTH_FAILURE_REDIRECT = FAILURE_REDIRECT;
    await Promise.all([
      setProviderEnabled('google', true),
      setProviderEnabled('github', true),
    ]);
  });

  afterAll(async () => {
    process.env = envBackup;
    await prisma.$disconnect();
  });

  it('google: start -> callback issues cookies and redirects success', async () => {
    process.env.GOOGLE_CLIENT_ID = 'test-google-client-id';
    process.env.GOOGLE_CLIENT_SECRET = 'test-google-client-secret';
    process.env.GOOGLE_REDIRECT_URI = 'http://localhost:4000/auth/oauth/google/callback';

    // Start
    const start = await request(app).get('/auth/oauth/google/start');
    expect(start.status).toBe(302);
    const stateCookie = getCookie(start.headers['set-cookie'] as string[] | undefined, STATE_COOKIE_NAME);
    expect(stateCookie).toBeTruthy();
    const stateValue = (stateCookie || '').split(';')[0].split('=')[1];

    // Mock fetch for token exchange and userinfo
    const fetchMock = jest.fn((url: unknown, init?: unknown): Promise<MockFetchResponse<any>> => {
      const u = String(url);
      if (u.includes('oauth2.googleapis.com/token')) {
        const response: MockFetchResponse<{ access_token: string; id_token: string; token_type: string }> = {
          ok: true,
          status: 200,
          json: () => Promise.resolve({ access_token: 'g-access', id_token: 'id', token_type: 'Bearer' }),
        };
        return Promise.resolve(response);
      }
      if (u.includes('openidconnect.googleapis.com/v1/userinfo')) {
        const response: MockFetchResponse<{ sub: string; email: string; email_verified: boolean; name: string; picture: string }> = {
          ok: true,
          status: 200,
          json: () => Promise.resolve({ sub: 'google-user-123', email: `g${Date.now()}@example.com`, email_verified: true, name: 'G User', picture: 'http://img' }),
        };
        return Promise.resolve(response);
      }
      return Promise.reject(new Error(`unexpected fetch to ${u} ${init ? JSON.stringify(init) : ''}`));
    });
    (global as any).fetch = fetchMock;

    const cb = await request(app)
      .get('/auth/oauth/google/callback')
      .query({ code: 'abc', state: stateValue })
      .set('Cookie', `oauth_state=${stateValue}`);
    expect(cb.status).toBe(302);
    expect(cb.headers.location).toBe(SUCCESS_REDIRECT);
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
  const stateCookie = getCookie(start.headers['set-cookie'] as string[] | undefined, STATE_COOKIE_NAME);
    expect(stateCookie).toBeTruthy();
    const stateValue = (stateCookie || '').split(';')[0].split('=')[1];

    // Mock fetch for token exchange, user, and emails
    const fetchMock = jest.fn((url: unknown): Promise<MockFetchResponse<any>> => {
      const u = String(url);
      if (u.includes('github.com/login/oauth/access_token')) {
        const response: MockFetchResponse<{ access_token: string; token_type: string; scope: string }> = {
          ok: true,
          status: 200,
          json: () => Promise.resolve({ access_token: 'gh-access', token_type: 'bearer', scope: 'read:user user:email' }),
        };
        return Promise.resolve(response);
      }
      if (u.endsWith('/user')) {
        const response: MockFetchResponse<{ id: number; name: string; login: string; avatar_url: string }> = {
          ok: true,
          status: 200,
          json: () => Promise.resolve({ id: 987654321, name: 'GH User', login: 'ghuser', avatar_url: 'http://img' }),
        };
        return Promise.resolve(response);
      }
      if (u.endsWith('/user/emails')) {
        const response: MockFetchResponse<Array<{ email: string; primary: boolean; verified: boolean }>> = {
          ok: true,
          status: 200,
          json: () => Promise.resolve([{ email: `gh${Date.now()}@example.com`, primary: true, verified: true }]),
        };
        return Promise.resolve(response);
      }
      return Promise.reject(new Error(`unexpected fetch to ${u}`));
    });
    (global as any).fetch = fetchMock;

    const cb = await request(app)
      .get('/auth/oauth/github/callback')
      .query({ code: 'def', state: stateValue })
      .set('Cookie', `oauth_state=${stateValue}`);
  expect(cb.status).toBe(302);
  expect(cb.headers.location).toBe(SUCCESS_REDIRECT);
    const setCookies: string[] = cb.headers['set-cookie'] || [];
    expect(getCookie(setCookies, 'accessToken')).toBeTruthy();
    expect(getCookie(setCookies, 'refreshToken')).toBeTruthy();
  });
});
