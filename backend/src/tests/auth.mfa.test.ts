import request from 'supertest';
import app from '../index';
import { PrismaClient, MfaFactorType } from '@prisma/client';
import { authenticator } from 'otplib';
import { resetRateLimits } from './helpers/rateLimit';

jest.setTimeout(30000);

const CSRF_HEADER = 'x-csrf-token';
const REGISTER_ROUTE = '/auth/register';
const LOGIN_ROUTE = '/auth/login';
const VERIFY_ROUTE = '/auth/mfa/verify';
const CSRF_ROUTE = '/auth/csrf';
const TEST_PASSWORD = 'Test1234!';

const prisma = new PrismaClient();
const agent = request.agent(app);
const unique = Date.now();
const testEmail = `mfa.user.${unique}@example.test`;
const deviceFingerprint = `fp-${unique}`;
const deviceName = 'MFA Test Device';
const devicePlatform = 'jest';
let userId: string;
let totpSecret: string;
let challengeId: string;

authenticator.options = { step: 30, digits: 6, window: 1 };

async function fetchCsrf() {
  const res = await agent.get(CSRF_ROUTE);
  const cookie = (res.headers['set-cookie'] || []).find((c: string) => c.startsWith('csrfToken='));
  return { token: res.body?.csrfToken, cookie };
}

describe('Auth MFA flow', () => {
  beforeEach(async () => {
    await resetRateLimits();
  });

  beforeAll(async () => {
    const { token, cookie } = await fetchCsrf();
    const register = await agent
      .post(REGISTER_ROUTE)
      .set(CSRF_HEADER, token)
      .set('Cookie', cookie || '')
      .send({ email: testEmail, password: TEST_PASSWORD, name: 'MFA Tester' });
    expect(register.status).toBe(201);

    const user = await prisma.user.update({ where: { email: testEmail }, data: { emailVerified: new Date() } });
    userId = user.id;
    totpSecret = authenticator.generateSecret();
    await prisma.userMfaFactor.create({
      data: {
        userId,
        type: MfaFactorType.TOTP,
        label: 'Test TOTP',
        secret: totpSecret,
        enabled: true,
      },
    });
  });

  afterAll(async () => {
    try {
      await prisma.user.delete({ where: { id: userId } });
    } catch {}
    await prisma.$disconnect();
  });

  it('responds with MFA challenge for enrolled users', async () => {
    const { token, cookie } = await fetchCsrf();
    const res = await agent
      .post(LOGIN_ROUTE)
      .set(CSRF_HEADER, token)
      .set('Cookie', cookie || '')
      .send({
        email: testEmail,
        password: TEST_PASSWORD,
        deviceFingerprint,
        deviceName,
        devicePlatform,
        trustThisDevice: true,
      });

    expect(res.status).toBe(202);
    expect(res.body.challengeRequired).toBe(true);
    expect(res.body.challenge).toBeTruthy();
    expect(res.body.challenge.device.fingerprint).toBe(deviceFingerprint);
    challengeId = res.body.challenge.id;
  });

  it('verifies MFA challenge and issues session cookies', async () => {
    const { token, cookie } = await fetchCsrf();
    const totpCode = authenticator.generate(totpSecret);
    const res = await agent
      .post(VERIFY_ROUTE)
      .set(CSRF_HEADER, token)
      .set('Cookie', cookie || '')
      .send({
        challengeId,
        code: totpCode,
        deviceFingerprint,
        deviceName,
        devicePlatform,
        trustThisDevice: true,
      });

    expect(res.status).toBe(200);
    expect(res.body.email).toBe(testEmail);
    const setCookies: string[] = res.headers['set-cookie'] || [];
    expect(setCookies.some(c => c.startsWith('accessToken='))).toBe(true);
    expect(setCookies.some(c => c.startsWith('refreshToken='))).toBe(true);

    const device = await prisma.userDevice.findFirst({ where: { userId, fingerprint: deviceFingerprint } });
    expect(device).toBeTruthy();
    expect(device?.trustedAt).toBeTruthy();
  });
});
