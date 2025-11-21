import request from 'supertest';
import app from '../index';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();
const agent = request.agent(app);
const CSRF_HEADER = 'x-csrf-token';
const CSRF_ROUTE = '/auth/csrf';
const legacyEmail = `legacy.bcrypt+${Date.now()}@example.com`;
const legacyPassword = 'LegacyPass123!';

async function fetchCsrf() {
  const res = await agent.get(CSRF_ROUTE);
  const csrfToken = res.body?.csrfToken;
  const csrfCookie: string | undefined = (res.headers['set-cookie'] || []).find((c: string) => c.startsWith('csrfToken='));
  return { csrfToken, csrfCookie };
}

describe('Auth legacy password hash handling', () => {
  beforeAll(async () => {
    const bcryptHash = await bcrypt.hash(legacyPassword, 10);
    await prisma.user.upsert({
      where: { email: legacyEmail },
      update: { passwordHash: bcryptHash, emailVerified: new Date(), name: 'Legacy Hash User' },
      create: { email: legacyEmail, passwordHash: bcryptHash, name: 'Legacy Hash User', emailVerified: new Date() },
    });
  });

  afterAll(async () => {
    const user = await prisma.user.findUnique({ where: { email: legacyEmail } });
    if (user) {
      await prisma.refreshToken.deleteMany({ where: { userId: user.id } });
      await prisma.user.delete({ where: { id: user.id } });
    }
    await prisma.$disconnect();
  });

  it('logs in with a bcrypt hash and upgrades it to argon2', async () => {
    const { csrfToken, csrfCookie } = await fetchCsrf();
    const res = await agent
      .post('/auth/login')
      .set(CSRF_HEADER, String(csrfToken))
      .set('Cookie', csrfCookie ?? '')
      .send({ email: legacyEmail, password: legacyPassword });

    expect(res.status).toBe(200);
    const updated = await prisma.user.findUnique({ where: { email: legacyEmail } });
    expect(updated?.passwordHash?.startsWith('$argon2')).toBe(true);
  });

  it('returns 401 instead of 500 for corrupt hashes', async () => {
    await prisma.user.update({ where: { email: legacyEmail }, data: { passwordHash: 'not-a-valid-hash' } });
    const { csrfToken, csrfCookie } = await fetchCsrf();
    const res = await agent
      .post('/auth/login')
      .set(CSRF_HEADER, String(csrfToken))
      .set('Cookie', csrfCookie ?? '')
      .send({ email: legacyEmail, password: legacyPassword });

    expect(res.status).toBe(401);
  });
});
