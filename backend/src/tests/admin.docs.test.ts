import request from 'supertest';
import app from '../index';
import { PrismaClient } from '@prisma/client';
import { ensureRole, assignRoleToUser } from './helpers/rbac';

async function createUser(email: string, password = 'StrongP@ssw0rd!') {
  const agent = request.agent(app);
  const csrfRes = await agent.get('/auth/csrf');
  const csrf = csrfRes.body.csrfToken;
  const res = await agent
    .post('/auth/register')
    .set('x-csrf-token', csrf)
    .send({ email, password, name: 'Test User' });
  // The register endpoint returns the created user object as the response body
  return { agent, user: res.body };
}

describe('Admin Docs gating', () => {
  const prisma: any = new PrismaClient();
  afterAll(async () => {
    await prisma.$disconnect();
  });
  it('denies access to non-admin users (403)', async () => {
    const { agent } = await createUser(`user-${Date.now()}@example.com`);
    const res = await agent.get('/api-docs/admin/latest/openapi.json');
    expect(res.status).toBe(403);
  });

  it('allows system_admin to access admin docs JSON', async () => {
    const email = `sys-${Date.now()}@example.com`;
    const { agent, user } = await createUser(email);
    await ensureRole(prisma, 'system_admin', 999);
  await assignRoleToUser(prisma, String(user.id), 'system_admin');
    // re-login to refresh roles in access token context if needed
    const csrf2 = (await agent.get('/auth/csrf')).body.csrfToken;
    await agent
      .post('/auth/login')
      .set('x-csrf-token', csrf2)
      .send({ email, password: 'StrongP@ssw0rd!' });
    const res = await agent.get('/api-docs/admin/latest/openapi.json');
    expect(res.status).toBe(200);
    expect(res.body?.openapi).toBeDefined();
  // Title can be "Admin REST API" or similar; just ensure it contains Admin
  expect(String(res.body?.info?.title || '')).toMatch(/Admin/i);
  });
});
