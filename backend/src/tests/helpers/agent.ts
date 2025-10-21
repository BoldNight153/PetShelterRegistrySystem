import request from 'supertest';
import app from '../../index';
import { PrismaClient } from '@prisma/client';
import { ensureRoleWithPermissionsForUser } from './rbac';

const prisma: any = new PrismaClient();

export async function createLoggedInAdminAgent() {
  const agent = request.agent(app);
  const csrfRes = await agent.get('/auth/csrf');
  const csrfToken = csrfRes.body?.csrfToken;
  const email = `admin.${Date.now()}@example.test`;
  const password = 'P@ssw0rd!';

  await agent
    .post('/auth/register')
    .set('x-csrf-token', String(csrfToken))
    .send({ email, password, name: 'Admin Tester' });

  const adminUser = await prisma.user.findUnique({ where: { email } });
  if (!adminUser) throw new Error('failed to create admin test user');

  await ensureRoleWithPermissionsForUser(prisma, adminUser.id, 'system_admin', []);
  await new Promise(r => setTimeout(r, 5));
  const csrf2 = await agent.get('/auth/csrf');
  await agent
    .post('/auth/login')
    .set('x-csrf-token', String(csrf2.body?.csrfToken))
    .send({ email, password });

  return { agent, user: adminUser, email };
}
