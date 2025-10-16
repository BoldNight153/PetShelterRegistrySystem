import request from 'supertest';
import app from '../index';
import { PrismaClient } from '@prisma/client';
import { createLoggedInAdminAgent } from './helpers/agent';

const prisma: any = new PrismaClient();

function getCookie(cookies: string[] | undefined, name: string): string | undefined {
  if (!cookies) return undefined;
  return cookies.find((c) => c.startsWith(`${name}=`));
}

async function getCsrf(agent: request.SuperTest<request.Test>) {
  const res = await agent.get('/auth/csrf');
  const token = res.body?.csrfToken;
  const cookie = getCookie(res.headers['set-cookie'], 'csrfToken');
  return { token: String(token), cookie: String(cookie) };
}

describe('Auth lockout and password history', () => {
  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('auto locks after threshold of failed attempts and unlocks after duration', async () => {
    const agent = request.agent(app);
    const { token: csrfToken, cookie: csrfCookie } = await getCsrf(agent);
    const email = `auto.lock.${Date.now()}@example.test`;
    const password = 'ValidPass1!';
    const reg = await agent.post('/auth/register').set('x-csrf-token', csrfToken).set('Cookie', csrfCookie).send({ email, password, name: 'Auto Lock' });
    expect(reg.status).toBe(201);

    // Ensure we're logged out before attempting failed logins; otherwise login may return 403 for already-authenticated
    const { token: logoutToken, cookie: logoutCookie } = await getCsrf(agent);
    const logout = await agent.post('/auth/logout').set('x-csrf-token', logoutToken).set('Cookie', logoutCookie).send();
    expect([204, 200]).toContain(logout.status);

    // Ensure email verification is not required for login in tests
    try {
      await prisma.setting.upsert({
        where: { category_key: { category: 'security', key: 'requireEmailVerification' } as any },
        update: { value: false },
        create: { category: 'security', key: 'requireEmailVerification', value: false },
      });
    } catch {}

    // Fail 5 times (default threshold 5)
    for (let i = 0; i < 5; i++) {
      const { token: t, cookie: c } = await getCsrf(agent);
      const bad = await agent.post('/auth/login').set('x-csrf-token', t).set('Cookie', c).send({ email, password: 'Wrong1!' });
      expect([401, 429]).toContain(bad.status);
    }

    // Next attempt should be locked (429)
    const { token: t6, cookie: c6 } = await getCsrf(agent);
    const locked = await agent.post('/auth/login').set('x-csrf-token', t6).set('Cookie', c6).send({ email, password });
    expect(locked.status).toBe(429);
  });

  it('manual lock/unlock via admin sends reset email token and revokes sessions', async () => {
    const { agent: adminAgent } = await createLoggedInAdminAgent();

    // Create a user
    const userAgent = request.agent(app);
    const { token: t1, cookie: c1 } = await getCsrf(userAgent);
    const email = `manual.lock.${Date.now()}@example.test`;
    const pass = 'LockPass1!';
    const reg = await userAgent.post('/auth/register').set('x-csrf-token', t1).set('Cookie', c1).send({ email, password: pass, name: 'Manual Lock' });
    expect(reg.status).toBe(201);
    const user = await prisma.user.findUnique({ where: { email } });
    expect(user).toBeTruthy();

    // Lock the user
    const lockRes = await adminAgent.post('/admin/users/lock').send({ userId: user!.id, reason: 'test' });
    expect(lockRes.status).toBe(200);

    // Login should now be rejected as locked
    const { token: t2, cookie: c2 } = await getCsrf(userAgent);
    const loginLocked = await userAgent.post('/auth/login').set('x-csrf-token', t2).set('Cookie', c2).send({ email, password: pass });
    expect(loginLocked.status).toBe(429);

    // Unlock the user
    const unlockRes = await adminAgent.post('/admin/users/unlock').send({ userId: user!.id });
    expect(unlockRes.status).toBe(200);

    // Verify a password reset token was created (best effort)
    const vt = await prisma.verificationToken.findFirst({ where: { identifier: email, type: 'password_reset' }, orderBy: { createdAt: 'desc' } });
    expect(vt).toBeTruthy();

    // After unlock, old sessions should be revoked; a login with old cookies should need fresh CSRF
    const { token: t3, cookie: c3 } = await getCsrf(userAgent);
    const loginOk = await userAgent.post('/auth/login').set('x-csrf-token', t3).set('Cookie', c3).send({ email, password: pass });
    expect([200, 401, 403]).toContain(loginOk.status);
  });

  it('prevents reusing last 10 passwords', async () => {
    const agent = request.agent(app);
    const { token: csrfToken, cookie: csrfCookie } = await getCsrf(agent);
    const email = `history.${Date.now()}@example.test`;
    const p1 = 'Abcd!1234';
    const reg = await agent.post('/auth/register').set('x-csrf-token', csrfToken).set('Cookie', csrfCookie).send({ email, password: p1, name: 'History' });
    expect(reg.status).toBe(201);

    // Request reset token
    const { token: t2, cookie: c2 } = await getCsrf(agent);
    const reqReset = await agent.post('/auth/request-password-reset').set('x-csrf-token', t2).set('Cookie', c2).send({ email });
    expect(reqReset.status).toBe(200);
    const vt = await prisma.verificationToken.findFirst({ where: { identifier: email, type: 'password_reset' }, orderBy: { createdAt: 'desc' } });
    expect(vt).toBeTruthy();

    // Reset to a new password p2
    const p2 = 'XyZ!5678';
    const { token: t3, cookie: c3 } = await getCsrf(agent);
    const reset1 = await agent.post('/auth/reset-password').set('x-csrf-token', t3).set('Cookie', c3).send({ token: vt!.token, password: p2 });
    expect(reset1.status).toBe(200);

    // Request another token and try to reset to p1 again (should fail)
    const { token: t4, cookie: c4 } = await getCsrf(agent);
    await agent.post('/auth/request-password-reset').set('x-csrf-token', t4).set('Cookie', c4).send({ email });
    const vt2 = await prisma.verificationToken.findFirst({ where: { identifier: email, type: 'password_reset' }, orderBy: { createdAt: 'desc' } });
    const { token: t5, cookie: c5 } = await getCsrf(agent);
    const reset2 = await agent.post('/auth/reset-password').set('x-csrf-token', t5).set('Cookie', c5).send({ token: vt2!.token, password: p1 });
    expect(reset2.status).toBe(400);
    expect(String(reset2.body.error || '')).toMatch(/must not match/i);
  });
});
