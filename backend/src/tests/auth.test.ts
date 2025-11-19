import request from 'supertest';
import app from '../index';
import { PrismaClient } from '@prisma/client';

const CSRF_HEADER = 'x-csrf-token';
const CSRF_COOKIE_PREFIX = 'csrfToken=';
const CSRF_ROUTE = '/auth/csrf';
const REGISTER_ROUTE = '/auth/register';
const LOGIN_ROUTE = '/auth/login';
const PROFILE_ROUTE = '/auth/me';
const TEST_PASSWORD = 'Test1234!';

const unique = Date.now();
const testEmail = `testuser+${unique}@example.com`;
const prisma: any = new PrismaClient();

describe('Auth Phase 1', () => {
  it('issues CSRF token', async () => {
    const res = await request(app).get(CSRF_ROUTE);
    expect(res.status).toBe(200);
    expect(res.body.csrfToken).toBeTruthy();
    expect(res.headers['set-cookie']?.some((c: string) => c.startsWith(CSRF_COOKIE_PREFIX))).toBe(true);
  });

  it('registers a new user and sets cookies', async () => {
    const csrf = await request(app).get(CSRF_ROUTE);
    const csrfCookie = csrf.headers['set-cookie'].find((c: string) => c.startsWith(CSRF_COOKIE_PREFIX));
    const csrfToken = csrf.body.csrfToken;

    const res = await request(app)
      .post(REGISTER_ROUTE)
      .set(CSRF_HEADER, csrfToken)
      .set('Cookie', csrfCookie)
      .send({ email: testEmail, password: TEST_PASSWORD, name: 'Test User' });

    expect(res.status).toBe(201);
    expect(res.body.email).toBe(testEmail);
    const setCookies: string[] = res.headers['set-cookie'] || [];
    expect(setCookies.some(c => c.startsWith('accessToken='))).toBe(true);
    expect(setCookies.some(c => c.startsWith('refreshToken='))).toBe(true);
  });

  it('logs in an existing user and sets cookies', async () => {
    const csrf = await request(app).get(CSRF_ROUTE);
    const csrfCookie = csrf.headers['set-cookie'].find((c: string) => c.startsWith(CSRF_COOKIE_PREFIX));
    const csrfToken = csrf.body.csrfToken;

    await prisma.user.update({ where: { email: testEmail }, data: { emailVerified: new Date() } });

    const res = await request(app)
      .post(LOGIN_ROUTE)
      .set(CSRF_HEADER, csrfToken)
      .set('Cookie', csrfCookie)
      .send({ email: testEmail, password: TEST_PASSWORD });

    expect(res.status).toBe(200);
    const setCookies: string[] = res.headers['set-cookie'] || [];
    expect(setCookies.some(c => c.startsWith('accessToken='))).toBe(true);
    expect(setCookies.some(c => c.startsWith('refreshToken='))).toBe(true);
  });

  it('updates profile metadata via /auth/me', async () => {
    await prisma.user.update({ where: { email: testEmail }, data: { emailVerified: new Date() } });

    const loginCsrf = await request(app).get(CSRF_ROUTE);
    const loginCsrfCookie = loginCsrf.headers['set-cookie'].find((c: string) => c.startsWith(CSRF_COOKIE_PREFIX));
    const loginCsrfToken = loginCsrf.body.csrfToken;

    const login = await request(app)
      .post(LOGIN_ROUTE)
      .set(CSRF_HEADER, loginCsrfToken)
      .set('Cookie', loginCsrfCookie)
      .send({ email: testEmail, password: TEST_PASSWORD });

    expect(login.status).toBe(200);
    const authCookies = (login.headers['set-cookie'] || [])
      .filter(Boolean)
      .map((c: string) => c.split(';')[0]);

    const profileCsrf = await request(app).get(CSRF_ROUTE);
    const profileCsrfCookie = profileCsrf.headers['set-cookie'].find((c: string) => c.startsWith(CSRF_COOKIE_PREFIX));
    const profileCsrfToken = profileCsrf.body.csrfToken;
    const cookieHeader = [...authCookies, profileCsrfCookie?.split(';')[0]].filter(Boolean).join('; ');

    const res = await request(app)
      .put(PROFILE_ROUTE)
      .set(CSRF_HEADER, profileCsrfToken)
      .set('Cookie', cookieHeader)
      .send({ name: 'Updated Via Test', title: 'Director' });

    expect(res.status).toBe(200);
    expect(res.body.name).toBe('Updated Via Test');
    expect(res.body.metadata).toMatchObject({ title: 'Director' });
  });
});
