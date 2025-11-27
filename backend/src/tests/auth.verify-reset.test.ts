import request from 'supertest';
import app from '../index';
import { PrismaClient } from '@prisma/client';
import { resetRateLimits } from './helpers/rateLimit';

const prisma: any = new PrismaClient();
const HEADER_COOKIE = 'Cookie';
const HEADER_X_CSRF = 'x-csrf-token';
const COOKIE_CSRF = 'csrfToken';
const PATH_AUTH_CSRF = '/auth/csrf';
const PATH_AUTH_REGISTER = '/auth/register';
const PATH_AUTH_REQUEST_EMAIL_VERIFICATION = '/auth/request-email-verification';
const PATH_AUTH_VERIFY_EMAIL = '/auth/verify-email';
const PATH_AUTH_REQUEST_RESET = '/auth/request-password-reset';
const PATH_AUTH_RESET = '/auth/reset-password';
const PATH_AUTH_LOGIN = '/auth/login';
const TOKEN_TYPE_EMAIL_VERIFY = 'email_verify';
const TOKEN_TYPE_PASSWORD_RESET = 'password_reset';

function getCookie(cookies: string[] | string | undefined, name: string): string | undefined {
  if (!cookies) return undefined;
  const list = Array.isArray(cookies) ? cookies : [cookies];
  return list.find((c) => c.startsWith(`${name}=`));
}

function extractCookie(res: request.Response, name: string): string | undefined {
  const header = res.headers['set-cookie'] as string[] | string | undefined;
  return getCookie(header, name);
}

describe('Email verification and password reset', () => {
  beforeEach(async () => {
    await resetRateLimits();
  });

  it('issues verification token and verifies email', async () => {
    const email = `verify+${Date.now()}@example.com`;
    const csrf1 = await request(app).get(PATH_AUTH_CSRF);
    const csrfCookie1 = extractCookie(csrf1, COOKIE_CSRF);
    const csrfToken1 = csrf1.body.csrfToken;

    const reg = await request(app)
      .post(PATH_AUTH_REGISTER)
      .set(HEADER_X_CSRF, csrfToken1)
      .set(HEADER_COOKIE, csrfCookie1!)
      .send({ email, password: 'Test1234!', name: 'Verify' });
    expect(reg.status).toBe(201);

    const csrf2 = await request(app).get(PATH_AUTH_CSRF);
    const csrfCookie2 = extractCookie(csrf2, COOKIE_CSRF);
    const csrfToken2 = csrf2.body.csrfToken;

    const reqTok = await request(app)
      .post(PATH_AUTH_REQUEST_EMAIL_VERIFICATION)
      .set(HEADER_X_CSRF, csrfToken2)
      .set(HEADER_COOKIE, csrfCookie2!)
      .send({ email });
    expect(reqTok.status).toBe(200);
    expect(reqTok.body.ok).toBe(true);

    const vt = await prisma.verificationToken.findFirst({ where: { identifier: email, type: TOKEN_TYPE_EMAIL_VERIFY }, orderBy: { createdAt: 'desc' } });
    expect(vt).toBeTruthy();

    const csrf3 = await request(app).get(PATH_AUTH_CSRF);
    const csrfCookie3 = extractCookie(csrf3, COOKIE_CSRF);
    const csrfToken3 = csrf3.body.csrfToken;

    const verify = await request(app)
      .post(PATH_AUTH_VERIFY_EMAIL)
      .set(HEADER_X_CSRF, csrfToken3)
      .set(HEADER_COOKIE, csrfCookie3!)
      .send({ token: vt!.token });
    expect(verify.status).toBe(200);
    expect(verify.body.emailVerified).toBeTruthy();
    const setCookies: string[] = verify.headers['set-cookie'] || [];
    expect(getCookie(setCookies, 'accessToken')).toBeTruthy();
    expect(getCookie(setCookies, 'refreshToken')).toBeTruthy();
  });

  it('requests password reset and resets password', async () => {
    const email = `reset+${Date.now()}@example.com`;
    const csrf1 = await request(app).get(PATH_AUTH_CSRF);
    const csrfCookie1 = extractCookie(csrf1, COOKIE_CSRF);
    const csrfToken1 = csrf1.body.csrfToken;

    const reg = await request(app)
      .post(PATH_AUTH_REGISTER)
      .set(HEADER_X_CSRF, csrfToken1)
      .set(HEADER_COOKIE, csrfCookie1!)
      .send({ email, password: 'OldPass1!', name: 'Reset' });
    expect(reg.status).toBe(201);

    const csrf2 = await request(app).get(PATH_AUTH_CSRF);
    const csrfCookie2 = extractCookie(csrf2, COOKIE_CSRF);
    const csrfToken2 = csrf2.body.csrfToken;

    const reqReset = await request(app)
      .post(PATH_AUTH_REQUEST_RESET)
      .set(HEADER_X_CSRF, csrfToken2)
      .set(HEADER_COOKIE, csrfCookie2!)
      .send({ email });
    expect(reqReset.status).toBe(200);
    expect(reqReset.body.ok).toBe(true);

  const vt = await prisma.verificationToken.findFirst({ where: { identifier: email, type: TOKEN_TYPE_PASSWORD_RESET }, orderBy: { createdAt: 'desc' } });
    expect(vt).toBeTruthy();

    const csrf3 = await request(app).get(PATH_AUTH_CSRF);
    const csrfCookie3 = extractCookie(csrf3, COOKIE_CSRF);
    const csrfToken3 = csrf3.body.csrfToken;

    const reset = await request(app)
      .post(PATH_AUTH_RESET)
      .set(HEADER_X_CSRF, csrfToken3)
      .set(HEADER_COOKIE, csrfCookie3!)
      .send({ token: vt!.token, password: 'NewPass1!' });
    expect(reset.status).toBe(200);
    expect(reset.body.ok).toBe(true);

    // Login with new password works
    const csrf4 = await request(app).get(PATH_AUTH_CSRF);
    const csrfCookie4 = extractCookie(csrf4, COOKIE_CSRF);
    const csrfToken4 = csrf4.body.csrfToken;

    const login = await request(app)
      .post(PATH_AUTH_LOGIN)
      .set(HEADER_X_CSRF, csrfToken4)
      .set(HEADER_COOKIE, csrfCookie4!)
      .send({ email, password: 'NewPass1!' });
    expect(login.status).toBe(200);
  });
});
