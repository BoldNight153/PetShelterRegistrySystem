import request from 'supertest';
import app from '../src/index';
import { PrismaClient } from '@prisma/client';
import { ensureRoleWithPermissionsForUser } from '../src/tests/helpers/rbac';

async function main() {
  const agent = request.agent(app);
  const prisma = new PrismaClient();
  const email = `debug.${Date.now()}@example.test`;
  const password = 'P@ssw0rd!';
  const csrf = await agent.get('/auth/csrf');
  await agent.post('/auth/register').set('x-csrf-token', String(csrf.body?.csrfToken)).send({ email, password, name: 'Debug User' });
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) throw new Error('user not created');
  await ensureRoleWithPermissionsForUser(prisma, user.id, 'shelter_admin', ['owners.write', 'locations.write', 'medical.write', 'events.write']);
  await new Promise(res => setTimeout(res, 5));
  const csrf2 = await agent.get('/auth/csrf');
  await agent.post('/auth/login').set('x-csrf-token', String(csrf2.body?.csrfToken)).send({ email, password });
  const shelterRes = await agent.post('/shelters').send({ name: 'Debug Shelter' });
  console.log('shelter status', shelterRes.status, 'body', shelterRes.body);
  const createRes = await agent.post('/pets').send({ name: 'Buddy', species: 'dog', shelterId: shelterRes.body.id });
  console.log('pets status', createRes.status);
  console.log('pets body', createRes.body);
  console.log('pets text', createRes.text);
  await prisma.$disconnect();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
