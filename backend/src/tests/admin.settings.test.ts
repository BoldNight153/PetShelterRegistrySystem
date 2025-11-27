import request from 'supertest';
import { PrismaClient } from '@prisma/client';
import app from '../index';
import { ensureRoleWithPermissionsForUser } from './helpers/rbac';
import { DEFAULT_AUTH_SETTINGS } from '../types/authSettings';
import { resetRateLimits } from './helpers/rateLimit';

jest.setTimeout(30000);

describe('Admin Authentication settings endpoints', () => {
  const prisma = new PrismaClient();
  const agent = request.agent(app);
  const password = 'Adm1n!Pass';
  const CSRF_ROUTE = '/auth/csrf';
  const CSRF_HEADER = 'x-csrf-token';
  let csrfToken: string | undefined;
  let userId: string | undefined;

  beforeAll(async () => {
    await resetRateLimits();
    const csrf = await agent.get(CSRF_ROUTE);
    csrfToken = csrf.body?.csrfToken;
    const email = `admin.settings.${Date.now()}@example.test`;
    await agent
      .post('/auth/register')
      .set(CSRF_HEADER, String(csrfToken))
      .send({ email, password, name: 'Auth Settings Admin' });

    const user = await prisma.user.findUnique({ where: { email } });
    userId = user?.id;
    if (userId) {
      await ensureRoleWithPermissionsForUser(prisma, userId, 'system_admin', []);
      await new Promise(resolve => setTimeout(resolve, 5));
      const csrf2 = await agent.get(CSRF_ROUTE);
      await agent
        .post('/auth/login')
        .set(CSRF_HEADER, String(csrf2.body?.csrfToken))
        .send({ email, password });
    }
  });

  const resetAuthSettings = async () => {
    await prisma.setting.deleteMany({ where: { category: 'auth' } });
    for (const [key, value] of Object.entries(DEFAULT_AUTH_SETTINGS)) {
      await prisma.setting.create({ data: { category: 'auth', key, value } });
    }
  };

  const fetchAllowedAuthenticatorIds = async () => {
    const rows = await prisma.authenticatorCatalog.findMany({
      where: { isArchived: false },
      orderBy: { sortOrder: 'asc' },
      select: { id: true },
    });
    return rows.map(row => row.id);
  };

  beforeEach(async () => {
    await resetRateLimits();
    await resetAuthSettings();
  });

  afterAll(async () => {
    await resetAuthSettings();
    await prisma.$disconnect();
  });

  it('returns normalized auth settings via GET /admin/settings, falling back when the saved list is empty', async () => {
    await prisma.setting.update({ where: { category_key: { category: 'auth', key: 'google' } }, data: { value: 'false' } });
    await prisma.setting.update({ where: { category_key: { category: 'auth', key: 'authenticators' } }, data: { value: [] } });

    const res = await agent.get('/admin/settings').query({ category: 'auth' });
    expect(res.status).toBe(200);
    expect(res.body.settings.auth.google).toBe(false);
    const allowedIds = await fetchAllowedAuthenticatorIds();
    expect(res.body.settings.auth.authenticators).toEqual(allowedIds);
  });

  it('keeps authenticator ids that are no longer in the catalog so admins can clean them up', async () => {
    const phantomId = `phantom-${Date.now()}`;
    await prisma.setting.update({
      where: { category_key: { category: 'auth', key: 'authenticators' } },
      data: { value: ['google', phantomId] },
    });

    const res = await agent.get('/admin/settings').query({ category: 'auth' });
    expect(res.status).toBe(200);
    expect(res.body.settings.auth.authenticators).toEqual(['google', phantomId]);
  });

  it('sanitizes payloads on PUT /admin/settings for auth category', async () => {
    const csrf = await agent.get(CSRF_ROUTE);
    const payload = {
      category: 'auth',
      entries: [
        { key: 'mode', value: 'jwt' },
        { key: 'google', value: 'false' },
        { key: 'authenticators', value: ['google', 'push_trusted', 'unknown'] },
      ],
    };
    const res = await agent
      .put('/admin/settings')
      .set(CSRF_HEADER, String(csrf.body?.csrfToken))
      .send(payload);

    expect(res.status).toBe(200);
    const rows = await prisma.setting.findMany({ where: { category: 'auth' } });
    const map: Record<string, any> = {};
    for (const row of rows) {
      map[row.key] = row.value;
    }
    expect(map.mode).toBe('jwt');
    expect(map.google).toBe(false);
    expect(map.authenticators).toEqual(['google', 'push_trusted']);
  });
});
