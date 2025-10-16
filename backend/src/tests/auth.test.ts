import request from 'supertest';
import app from '../index';
import { PrismaClient } from '@prisma/client';

const unique = Date.now();
const testEmail = `testuser+${unique}@example.com`;
const prisma: any = new PrismaClient();

describe('Auth Phase 1', () => {
  it('issues CSRF token', async () => {
    const res = await request(app).get('/auth/csrf');
    expect(res.status).toBe(200);
    expect(res.body.csrfToken).toBeTruthy();
    expect(res.headers['set-cookie']?.some((c: string) => c.startsWith('csrfToken='))).toBe(true);
  });

  it('registers a new user and sets cookies', async () => {
    // get csrf
    const csrf = await request(app).get('/auth/csrf');
    const csrfCookie = csrf.headers['set-cookie'].find((c: string) => c.startsWith('csrfToken='));
    const csrfToken = csrf.body.csrfToken;

    const res = await request(app)
      .post('/auth/register')
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
  .send({ email: testEmail, password: 'Test1234!', name: 'Test User' });

  expect(res.status).toBe(201);
  expect(res.body.email).toBe(testEmail);
    // accessToken and refreshToken cookies should be set
    const setCookies: string[] = res.headers['set-cookie'] || [];
    expect(setCookies.some(c => c.startsWith('accessToken='))).toBe(true);
    expect(setCookies.some(c => c.startsWith('refreshToken='))).toBe(true);
  });

  it('logs in an existing user and sets cookies', async () => {
    const csrf = await request(app).get('/auth/csrf');
    const csrfCookie = csrf.headers['set-cookie'].find((c: string) => c.startsWith('csrfToken='));
    const csrfToken = csrf.body.csrfToken;

    // Ensure the test account is email-verified to satisfy login policy
    await prisma.user.update({ where: { email: testEmail }, data: { emailVerified: new Date() } });

    const res = await request(app)
      .post('/auth/login')
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
  .send({ email: testEmail, password: 'Test1234!' });

    expect(res.status).toBe(200);
    const setCookies: string[] = res.headers['set-cookie'] || [];
    expect(setCookies.some(c => c.startsWith('accessToken='))).toBe(true);
    expect(setCookies.some(c => c.startsWith('refreshToken='))).toBe(true);
  });
});
