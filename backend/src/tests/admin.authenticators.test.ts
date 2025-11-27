import request from 'supertest';
import { PrismaClient } from '@prisma/client';
import app from '../index';
import { ensureRoleWithPermissionsForUser } from './helpers/rbac';
import { resetRateLimits } from './helpers/rateLimit';

jest.setTimeout(30000);

describe('Admin authenticator catalog endpoints', () => {
  const prisma = new PrismaClient();
  const agent = request.agent(app);
  const CSRF_ROUTE = '/auth/csrf';
  const CSRF_HEADER = 'x-csrf-token';
  const AUTHENTICATORS_ROUTE = '/admin/authenticators';
  const password = 'Adm1n!Authenticator';
  const createdIds = new Set<string>();

  async function fetchCsrf(authAgent = agent) {
    const res = await authAgent.get(CSRF_ROUTE);
    return res.body?.csrfToken as string | undefined;
  }

  async function ensureAdminSession() {
    const csrf = await fetchCsrf(agent);
    const email = `admin.authenticators.${Date.now()}@example.test`;
    await agent
      .post('/auth/register')
      .set(CSRF_HEADER, String(csrf))
      .send({ email, password, name: 'Authenticator Admin' });

    const user = await prisma.user.findUnique({ where: { email } });
    if (user) {
      await ensureRoleWithPermissionsForUser(prisma, user.id, 'system_admin', []);
      await new Promise(resolve => setTimeout(resolve, 5));
      await resetRateLimits();
      const csrfLogin = await fetchCsrf(agent);
      await agent
        .post('/auth/login')
        .set(CSRF_HEADER, String(csrfLogin))
        .send({ email, password });
    }
  }

  beforeAll(async () => {
    await resetRateLimits();
    await ensureAdminSession();
  });

  beforeEach(async () => {
    await resetRateLimits();
  });

  afterEach(async () => {
    if (createdIds.size > 0) {
      await prisma.authenticatorCatalog.deleteMany({ where: { id: { in: Array.from(createdIds) } } });
      createdIds.clear();
    }
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('creates and lists authenticator catalog entries', async () => {
    const id = `custom_totp_${Date.now()}`;
    createdIds.add(id);
    const csrf = await fetchCsrf();
    const payload = {
      id,
      label: 'Custom Authenticator',
      factorType: 'totp',
      helper: 'Scan with your authenticator app',
      tags: ['beta'],
      metadata: { issuer: 'Pet Shelter Registry' },
      sortOrder: 99,
    };

    const createRes = await agent
      .post(AUTHENTICATORS_ROUTE)
      .set(CSRF_HEADER, String(csrf))
      .send(payload);

    expect(createRes.status).toBe(201);
    expect(createRes.body?.authenticator?.id).toBe(id);
    expect(createRes.body?.authenticator?.tags).toEqual(['beta']);

  const listRes = await agent.get(AUTHENTICATORS_ROUTE);
    expect(listRes.status).toBe(200);
  const authenticators = (listRes.body?.authenticators ?? []) as Array<{ id: string }>;
  const ids = authenticators.map(item => item.id);
    expect(ids).toContain(id);
  });

  it('allows clearing optional string fields on update', async () => {
    const id = `clearable_${Date.now()}`;
    createdIds.add(id);
    const csrfCreate = await fetchCsrf();
    await agent
      .post(AUTHENTICATORS_ROUTE)
      .set(CSRF_HEADER, String(csrfCreate))
      .send({
        id,
        label: 'Clearable Authenticator',
        factorType: 'totp',
        description: 'Initial description',
        docsUrl: 'https://example.test/docs',
        helper: 'Some helper text',
        issuer: 'Pet Shelter Registry',
      });

    const csrfUpdate = await fetchCsrf();
    const updateRes = await agent
      .put(`${AUTHENTICATORS_ROUTE}/${id}`)
      .set(CSRF_HEADER, String(csrfUpdate))
      .send({
        description: '',
        docsUrl: '',
        helper: '',
        issuer: '',
      });

    expect(updateRes.status).toBe(200);
    const row = await prisma.authenticatorCatalog.findUnique({ where: { id } });
    expect(row?.description).toBeNull();
    expect(row?.docsUrl).toBeNull();
    expect(row?.helper).toBeNull();
    expect(row?.issuer).toBeNull();
  });

  it('archives and restores an authenticator entry', async () => {
    const id = `archivable_${Date.now()}`;
    createdIds.add(id);
    const csrfCreate = await fetchCsrf();
    await agent
      .post(AUTHENTICATORS_ROUTE)
      .set(CSRF_HEADER, String(csrfCreate))
      .send({ id, label: 'Archive Me', factorType: 'push' });

    const csrfArchive = await fetchCsrf();
    const archiveRes = await agent
      .post(`/admin/authenticators/${id}/archive`)
      .set(CSRF_HEADER, String(csrfArchive))
      .send();
    expect(archiveRes.status).toBe(200);
    const archived = await prisma.authenticatorCatalog.findUnique({ where: { id } });
    expect(archived?.isArchived).toBe(true);

    const csrfRestore = await fetchCsrf();
    const restoreRes = await agent
      .post(`/admin/authenticators/${id}/restore`)
      .set(CSRF_HEADER, String(csrfRestore))
      .send();
    expect(restoreRes.status).toBe(200);
    const restored = await prisma.authenticatorCatalog.findUnique({ where: { id } });
    expect(restored?.isArchived).toBe(false);
  });

  it('honors includeArchived flag when listing authenticator catalog entries', async () => {
    const id = `archived_filter_${Date.now()}`;
    createdIds.add(id);
    const csrfCreate = await fetchCsrf();
    await agent
      .post(AUTHENTICATORS_ROUTE)
      .set(CSRF_HEADER, String(csrfCreate))
      .send({ id, label: 'Archived Filter', factorType: 'totp' });

    const csrfArchive = await fetchCsrf();
    await agent
      .post(`/admin/authenticators/${id}/archive`)
      .set(CSRF_HEADER, String(csrfArchive))
      .send();

    const activeList = await agent.get(AUTHENTICATORS_ROUTE);
    const activeIds = ((activeList.body?.authenticators as Array<{ id: string }> | undefined) ?? []).map(row => row.id);
    expect(activeList.status).toBe(200);
    expect(activeIds).not.toContain(id);

    const archivedList = await agent.get(AUTHENTICATORS_ROUTE).query({ includeArchived: 'true' });
    expect(archivedList.status).toBe(200);
    const archivedEntries = (archivedList.body?.authenticators as Array<{ id: string; isArchived?: boolean }> | undefined) ?? [];
    const match = archivedEntries.find(entry => entry.id === id);
    expect(match).toBeDefined();
    expect(match?.isArchived).toBe(true);
  });

  it('prevents non admins from listing authenticators', async () => {
    const limitedAgent = request.agent(app);
    const csrf = await fetchCsrf(limitedAgent);
    const email = `limited.auth.${Date.now()}@example.test`;
    const limitedPassword = 'User!Pass123';
    await limitedAgent
      .post('/auth/register')
      .set(CSRF_HEADER, String(csrf))
      .send({ email, password: limitedPassword, name: 'Limited User' });

    const csrfLogin = await fetchCsrf(limitedAgent);
    await limitedAgent
      .post('/auth/login')
      .set(CSRF_HEADER, String(csrfLogin))
      .send({ email, password: limitedPassword });

    const res = await limitedAgent.get(AUTHENTICATORS_ROUTE);
    expect(res.status).toBe(403);
  });

  it('blocks non admins from creating authenticators', async () => {
    const limitedAgent = request.agent(app);
    const csrfRegister = await fetchCsrf(limitedAgent);
    const email = `limited.auth.create.${Date.now()}@example.test`;
    const limitedPassword = 'User!Pass123';
    await limitedAgent
      .post('/auth/register')
      .set(CSRF_HEADER, String(csrfRegister))
      .send({ email, password: limitedPassword, name: 'Limited Catalog User' });

    const csrfLogin = await fetchCsrf(limitedAgent);
    await limitedAgent
      .post('/auth/login')
      .set(CSRF_HEADER, String(csrfLogin))
      .send({ email, password: limitedPassword });

    const csrfAttempt = await fetchCsrf(limitedAgent);
    const id = `blocked_${Date.now()}`;
    const res = await limitedAgent
      .post(AUTHENTICATORS_ROUTE)
      .set(CSRF_HEADER, String(csrfAttempt))
      .send({ id, label: 'Should Not Create', factorType: 'sms' });
    expect(res.status).toBe(403);
    await prisma.authenticatorCatalog.delete({ where: { id } }).catch(() => undefined);
  });
});