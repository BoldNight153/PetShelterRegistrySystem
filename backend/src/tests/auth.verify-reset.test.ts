import request from 'supertest';
import app from '../index';
import { PrismaClient } from '@prisma/client';

const prisma: any = new PrismaClient();

function getCookie(cookies: string[] | undefined, name: string): string | undefined {
  if (!cookies) return undefined;
  return cookies.find((c) => c.startsWith(`${name}=`));
}

describe('Email verification and password reset', () => {
  it('issues verification token and verifies email', async () => {
    const email = `verify+${Date.now()}@example.com`;
    const csrf1 = await request(app).get('/auth/csrf');
    const csrfCookie1 = getCookie(csrf1.headers['set-cookie'], 'csrfToken');
    const csrfToken1 = csrf1.body.csrfToken;

    const reg = await request(app)
      .post('/auth/register')
      .set('x-csrf-token', csrfToken1)
      .set('Cookie', csrfCookie1!)
      .send({ email, password: 'Test1234!', name: 'Verify' });
    expect(reg.status).toBe(201);

    const csrf2 = await request(app).get('/auth/csrf');
    const csrfCookie2 = getCookie(csrf2.headers['set-cookie'], 'csrfToken');
    const csrfToken2 = csrf2.body.csrfToken;

    const reqTok = await request(app)
      .post('/auth/request-email-verification')
      .set('x-csrf-token', csrfToken2)
      .set('Cookie', csrfCookie2!)
      .send({ email });
    expect(reqTok.status).toBe(200);
    expect(reqTok.body.ok).toBe(true);

    const vt = await prisma.verificationToken.findFirst({ where: { identifier: email, type: 'email_verify' }, orderBy: { createdAt: 'desc' } });
    expect(vt).toBeTruthy();

    const csrf3 = await request(app).get('/auth/csrf');
    const csrfCookie3 = getCookie(csrf3.headers['set-cookie'], 'csrfToken');
    const csrfToken3 = csrf3.body.csrfToken;

    const verify = await request(app)
      .post('/auth/verify-email')
      .set('x-csrf-token', csrfToken3)
      .set('Cookie', csrfCookie3!)
      .send({ token: vt!.token });
    expect(verify.status).toBe(200);
    expect(verify.body.emailVerified).toBeTruthy();
    const setCookies: string[] = verify.headers['set-cookie'] || [];
    expect(getCookie(setCookies, 'accessToken')).toBeTruthy();
    expect(getCookie(setCookies, 'refreshToken')).toBeTruthy();
  });

  it('requests password reset and resets password', async () => {
    const email = `reset+${Date.now()}@example.com`;
    const csrf1 = await request(app).get('/auth/csrf');
    const csrfCookie1 = getCookie(csrf1.headers['set-cookie'], 'csrfToken');
    const csrfToken1 = csrf1.body.csrfToken;

    const reg = await request(app)
      .post('/auth/register')
      .set('x-csrf-token', csrfToken1)
      .set('Cookie', csrfCookie1!)
      .send({ email, password: 'OldPass1!', name: 'Reset' });
    expect(reg.status).toBe(201);

    const csrf2 = await request(app).get('/auth/csrf');
    const csrfCookie2 = getCookie(csrf2.headers['set-cookie'], 'csrfToken');
    const csrfToken2 = csrf2.body.csrfToken;

    const reqReset = await request(app)
      .post('/auth/request-password-reset')
      .set('x-csrf-token', csrfToken2)
      .set('Cookie', csrfCookie2!)
      .send({ email });
    expect(reqReset.status).toBe(200);
    expect(reqReset.body.ok).toBe(true);

    const vt = await prisma.verificationToken.findFirst({ where: { identifier: email, type: 'password_reset' }, orderBy: { createdAt: 'desc' } });
    expect(vt).toBeTruthy();

    const csrf3 = await request(app).get('/auth/csrf');
    const csrfCookie3 = getCookie(csrf3.headers['set-cookie'], 'csrfToken');
    const csrfToken3 = csrf3.body.csrfToken;

    const reset = await request(app)
      .post('/auth/reset-password')
      .set('x-csrf-token', csrfToken3)
      .set('Cookie', csrfCookie3!)
      .send({ token: vt!.token, password: 'NewPass1!' });
    expect(reset.status).toBe(200);
    expect(reset.body.ok).toBe(true);

    // Login with new password works
    const csrf4 = await request(app).get('/auth/csrf');
    const csrfCookie4 = getCookie(csrf4.headers['set-cookie'], 'csrfToken');
    const csrfToken4 = csrf4.body.csrfToken;

    const login = await request(app)
      .post('/auth/login')
      .set('x-csrf-token', csrfToken4)
      .set('Cookie', csrfCookie4!)
      .send({ email, password: 'NewPass1!' });
    expect(login.status).toBe(200);
  });
});
